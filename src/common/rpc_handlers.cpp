#include "rpc_handlers.h"
#include "metadata_sync.h"
#include "autocloud_bootstrap.h"
#include "autocloud_scan.h"
#include "autocloud_util.h"
#include "batch_tracker.h"
#include "cloud_intercept.h"
#include "local_storage.h"
#include "manifest_store.h"
#include "http_server.h"
#include "http_util.h"
#include "cloud_staging.h"
#include "app_state.h"
#include "cloud_storage.h"
#include "pending_ops_journal.h"
#include "file_util.h"
#include "remotecache_repair.h"
#include "steam_kv_injector.h"
#include "vdf.h"
#include "log.h"
#include "json.h"
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <sstream>
#include <thread>

#ifndef _WIN32
#include <unistd.h>
extern "C" void CR_SetCrashContext(const char* hook, const char* method, uint32_t appId);
#endif

namespace CloudIntercept {

bool RestorePlaytimeState(uint32_t appId, uint64_t playtime, uint64_t playtime2wks);
bool RestoreLastPlayedState(uint32_t appId, uint64_t lastPlayed);

static void RestoreInMemoryPlaytimeMetadata(uint32_t appId, uint64_t lastPlayed,
                                            uint64_t playtime, uint64_t playtime2wks) {
    RestoreLastPlayedState(appId, lastPlayed);
    RestorePlaytimeState(appId, playtime, playtime2wks);
}


// per-app upload batch tracking -- state lives in batch_tracker.cpp

static std::mutex g_conflictMutex;
static std::unordered_set<uint32_t> g_conflictKeepLocal;

void RecordConflictResolution(uint32_t appId, bool choseLocal) {
    std::lock_guard<std::mutex> lock(g_conflictMutex);
    if (choseLocal) {
        g_conflictKeepLocal.insert(appId);
        LOG("[NS] ConflictResolution app=%u: user chose keep-local, will skip pre-restore", appId);
    } else {
        g_conflictKeepLocal.erase(appId);
        LOG("[NS] ConflictResolution app=%u: user chose keep-cloud", appId);
    }
}

bool ConsumeConflictLocalChoice(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_conflictMutex);
    return g_conflictKeepLocal.erase(appId) > 0;
}

// Per-(account,app) cleanNames with confirmed-present remotecache.vdf rows.
// Pre-seeded persiststate=0 closes Steam's reconcile false-delete window.
static std::mutex g_remotecacheRepairMutex;
static std::unordered_map<uint64_t, std::unordered_set<std::string>> g_remotecachePlantedRows;

// Per-(account,app) IO lock for read+atomic-write of remotecache.vdf.
static std::mutex g_remotecacheRepairIoMapMutex;
static std::unordered_map<uint64_t, std::shared_ptr<std::mutex>> g_remotecacheRepairIoMutexes;

static std::shared_ptr<std::mutex> AcquireRemotecacheRepairIoMutex(uint64_t appKey) {
    std::lock_guard<std::mutex> lock(g_remotecacheRepairIoMapMutex);
    auto& slot = g_remotecacheRepairIoMutexes[appKey];
    if (!slot) slot = std::make_shared<std::mutex>();
    return slot;
}

static bool RequireAccountId(const char* op, uint32_t appId, uint32_t& accountId) {
    // Brief wait for the network thread to publish g_steamId.
    constexpr uint64_t timeoutMs = 200;
    constexpr uint32_t sleepMs = 5;

#ifdef _WIN32
    ULONGLONG deadline = GetTickCount64() + timeoutMs;
    do {
        accountId = GetAccountId();
        if (accountId != 0) return true;
        Sleep(sleepMs);
    } while (GetTickCount64() < deadline);
#else
    auto start = std::chrono::steady_clock::now();
    do {
        accountId = GetAccountId();
        if (accountId != 0) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    } while (std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count() < (int64_t)timeoutMs);
#endif

    LOG("[NS] %s app=%u no Steam account ID after %llums -- returning safe no-op",
        op, appId, timeoutMs);
    return false;
}

// Clamp file sizes at the wire boundary; Steam's protobuf fields are uint32.
static uint32_t ClampFileSizeToUint32(uint64_t rawSize, const char* fieldName,
                                      uint32_t appId, const std::string& filename) {
    if (rawSize > 0xFFFFFFFFull) {
        LOG("[Wire] %s for app %u file '%s' is %llu bytes; "
            "Steam's protobuf field is uint32, clamping to UINT32_MAX",
            fieldName, appId, filename.c_str(), (unsigned long long)rawSize);
        return 0xFFFFFFFFu;
    }
    return static_cast<uint32_t>(rawSize);
}


static void InvalidateTokenCaches(uint32_t accountId, uint32_t appId);

static void SetRpcCrashContext(const char* phase, const char* method, uint32_t appId) {
#ifndef _WIN32
    CR_SetCrashContext(phase, method, appId);
#else
    (void)phase;
    (void)method;
    (void)appId;
#endif
}

// Shutdown

void ShutdownRpcHandlers() {
    AutoCloudBootstrap::Shutdown();
}

static uint64_t ParsePlaytimeField(const Json::Value& value) {
    if (value.type == Json::Type::Number) {
        return value.number() > 0 ? static_cast<uint64_t>(value.number()) : 0;
    }
    if (value.type == Json::Type::String) {
        return strtoull(value.str().c_str(), nullptr, 10);
    }
    return 0;
}

static void ParsePlaytimeBlob(const std::string& blob, uint64_t& lastPlayed,
                              uint64_t& playtime, uint64_t& playtime2wks) {
    auto parsed = Json::Parse(blob);
    if (parsed.type == Json::Type::Object) {
        if (parsed.has("LastPlayed"))
            lastPlayed = ParsePlaytimeField(parsed["LastPlayed"]);
        if (parsed.has("Playtime"))
            playtime = ParsePlaytimeField(parsed["Playtime"]);
        if (parsed.has("Playtime2wks"))
            playtime2wks = ParsePlaytimeField(parsed["Playtime2wks"]);
        // 2wks > lifetime is corruption; zero rather than propagate.
        // 2wks==lifetime past the 14-day window is the legacy default-to-total bug.
        constexpr uint64_t kTwoWeeksMinutes = 14ULL * 24 * 60;
        if (playtime2wks > playtime ||
            (playtime2wks == playtime && playtime > kTwoWeeksMinutes))
            playtime2wks = 0;
        return;
    }

    std::istringstream blobStream(blob);
    std::string blobLine;
    while (std::getline(blobStream, blobLine)) {
        size_t tab = blobLine.find('\t');
        if (tab == std::string::npos) continue;
        std::string key = blobLine.substr(0, tab);
        std::string val = blobLine.substr(tab + 1);
        if (key == "LastPlayed") lastPlayed = strtoull(val.c_str(), nullptr, 10);
        else if (key == "Playtime") playtime = strtoull(val.c_str(), nullptr, 10);
        else if (key == "Playtime2wks") playtime2wks = strtoull(val.c_str(), nullptr, 10);
    }
    constexpr uint64_t kTwoWeeksMinutes = 14ULL * 24 * 60;
    if (playtime2wks > playtime ||
        (playtime2wks == playtime && playtime > kTwoWeeksMinutes))
        playtime2wks = 0;
}

// Per-app root tokens (e.g., "%GameInstall%") seen on uploads.
static std::unordered_map<uint64_t, std::unordered_set<std::string>> g_appRootTokens;
static std::mutex g_rootTokenMutex;

// Per-app file -> root-token. Each file is emitted only under its upload token.
static std::unordered_map<uint64_t, std::unordered_map<std::string, std::string>> g_fileTokens;
static std::mutex g_fileTokensMutex;

// Apps with batch-dirty file tokens; persisted once at HandleCompleteBatch.
static std::unordered_set<uint64_t> g_fileTokensDirtyApps;
static std::mutex g_fileTokensDirtyMutex;

// Per-batch AutoCloud canonical root map: resolve once, reuse across begin/commit.
static std::unordered_map<uint64_t, std::unordered_map<std::string, std::string>> g_batchCanonicalTokens;
static std::mutex g_batchCanonicalTokensMutex;

// Serializes token load-merge-save cycles.
static std::mutex g_tokenCaptureMutex;

// Forward declaration for Linux SetCloudSyncState.
static bool EnsureVdfSectionPath(std::string& vdfContent,
                                  const char* const* sections,
                                  size_t sectionCount);

#ifdef _WIN32
// Write cloud sync icon state to the registry key Steam reads at startup.
static void SetCloudSyncState(uint32_t appId, const char* state) {
    char subkey[128];
    snprintf(subkey, sizeof(subkey),
             "Software\\Valve\\Steam\\Apps\\%u\\cloud", appId);
    HKEY hk = nullptr;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, subkey, 0, nullptr,
                        0, KEY_SET_VALUE, nullptr, &hk, nullptr) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "last_sync_state", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(state),
                       static_cast<DWORD>(strlen(state) + 1));
        RegCloseKey(hk);
    }
}
void FlushPendingSyncStates() {} // Windows registry writes are immediate
#else
// Write cloud sync icon state to registry.vdf (Linux).
static std::mutex g_registryVdfMutex;
static std::unordered_map<uint32_t, std::string> g_pendingSyncStates;

// Applies all entries from |states| into registry.vdf atomically.
// Caller must hold g_registryVdfMutex.
static void WriteRegistryVdfSyncStates(
        const std::string& vdfPath,
        const std::unordered_map<uint32_t, std::string>& states) {
    if (states.empty()) return;

    std::string vdfContent;
    {
        std::ifstream f(vdfPath);
        if (!f) return;
        vdfContent = std::string(std::istreambuf_iterator<char>(f), {});
    }
    if (vdfContent.empty()) return;

    for (auto& [appId, state] : states) {
        std::string appIdStr = std::to_string(appId);
        const char* sections[] = {
            "Registry", "HKCU", "Software", "Valve", "Steam", "Apps",
            appIdStr.c_str(), "cloud"
        };
        constexpr size_t kSectionCount = 8;

        bool updated = false;
        VdfUtil::ForEachFieldInSection(vdfContent, sections, kSectionCount,
            [&](const VdfUtil::FieldInfo& fi) -> bool {
                if (fi.key == "last_sync_state") {
                    vdfContent.replace(fi.valStart, fi.valEnd - fi.valStart, state);
                    updated = true;
                    return false;
                }
                return true;
            });

        if (!updated) {
            if (!EnsureVdfSectionPath(vdfContent, sections, kSectionCount))
                continue;
            size_t sectionStart = 0, sectionEnd = 0;
            if (!VdfUtil::FindVdfSectionRange(vdfContent, sections, kSectionCount,
                                              sectionStart, sectionEnd))
                continue;
            std::string indent = "\t\t\t\t\t\t\t\t\t";
            size_t lineStart = vdfContent.rfind('\n', sectionEnd);
            if (lineStart != std::string::npos) {
                ++lineStart;
                size_t indentEnd = lineStart;
                while (indentEnd < vdfContent.size() &&
                       (vdfContent[indentEnd] == '\t' || vdfContent[indentEnd] == ' '))
                    ++indentEnd;
                indent.assign(vdfContent.data() + lineStart, indentEnd - lineStart);
                indent.push_back('\t');
            }
            std::string insertion = indent + "\"last_sync_state\"\t\t\"" + state + "\"\n";
            vdfContent.insert(sectionEnd, insertion);
        }
    }

    FileUtil::AtomicWriteText(vdfPath, vdfContent);
}

static void SetCloudSyncState(uint32_t appId, const char* state) {
    std::string steamPath = GetSteamPath();
    if (steamPath.empty()) return;

    std::string vdfPath = steamPath + "registry.vdf";
    std::lock_guard<std::mutex> lock(g_registryVdfMutex);

    g_pendingSyncStates[appId] = state;

    std::unordered_map<uint32_t, std::string> single{{appId, state}};
    WriteRegistryVdfSyncStates(vdfPath, single);
}

// Flush all tracked sync states to registry.vdf (called from OnUnload).
void FlushPendingSyncStates() {
    std::string steamPath = GetSteamPath();
    if (steamPath.empty()) return;

    std::string vdfPath = steamPath + "registry.vdf";
    std::lock_guard<std::mutex> lock(g_registryVdfMutex);

    if (g_pendingSyncStates.empty()) return;
    LOG("[SyncState] Flushing %zu pending sync states to registry.vdf",
        g_pendingSyncStates.size());
    WriteRegistryVdfSyncStates(vdfPath, g_pendingSyncStates);
}
#endif

// Namespace apps may lack PICS data (ufs.quota/maxnumfiles default to 0,
// causing over-quota eviction). Inject cached PICS values or fallback.
static constexpr uint64_t kFallbackQuotaBytes = 1073741824ULL; // 1 GB
static constexpr uint32_t kFallbackMaxFiles   = 10000;

static bool EnsureAppQuotaInjected(uint32_t accountId, uint32_t appId,
                                   CloudStorage::CloudAppState* cloudState) {
    if (!SteamKvInjector::IsReady()) {
        LOG("[NS] EnsureAppQuotaInjected app=%u: KV injector not ready", appId);
        return false;
    }

    uint64_t existingQuota = 0;
    uint32_t existingFiles = 0;
    bool readOk = SteamKvInjector::ReadAppQuota(appId, existingQuota, existingFiles);

        if (readOk && existingQuota > 0 && existingFiles > 0) {
        if (cloudState &&
            (cloudState->quota.quotaBytes != existingQuota ||
             cloudState->quota.maxNumFiles != existingFiles)) {
            cloudState->quota.quotaBytes = existingQuota;
            cloudState->quota.maxNumFiles = existingFiles;
            cloudState->quota.fetchedAtUnix = static_cast<uint64_t>(time(nullptr));
            cloudState->quota.lastSeenBuildId = cloudState->appBuildId;
            LOG("[NS] EnsureAppQuotaInjected app=%u: caching PICS quota=%llu files=%u (publish deferred to next batch)",
                appId, (unsigned long long)existingQuota, existingFiles);
            // Quota persisted on next CompleteBatch; async publish risks overwriting newer state.
        }
        LOG("[NS] EnsureAppQuotaInjected app=%u: Steam has quota=%llu files=%u",
            appId, (unsigned long long)existingQuota, existingFiles);
        return true;
    }

    uint64_t injectQuota = kFallbackQuotaBytes;
    uint32_t injectFiles = kFallbackMaxFiles;
    const char* source = "fallback";

    if (cloudState && CloudStorage::QuotaConfigIsUsable(cloudState->quota)) {
        injectQuota = cloudState->quota.quotaBytes;
        injectFiles = cloudState->quota.maxNumFiles;
        source = "cached";
    }

    LOG("[NS] EnsureAppQuotaInjected app=%u: no PICS quota (readOk=%d existing=%llu/%u) "
        "-- injecting %s %lluB / %u files",
        appId, readOk ? 1 : 0,
        (unsigned long long)existingQuota, existingFiles,
        source, (unsigned long long)injectQuota, injectFiles);

    return SteamKvInjector::InjectAppQuota(appId, injectQuota, injectFiles);
}

// Track (account, app) pairs that received a full manifest this session.
static std::unordered_set<uint64_t> g_fullManifestSentApps;
static std::mutex g_fullManifestSentMutex;

// Per-(account, app) cached CN and buildId for the fast repeat-call path.
static std::unordered_map<uint64_t, uint64_t> g_cachedCloudCN;
static std::unordered_map<uint64_t, uint64_t> g_cachedAppBuildIdHwm;

static uint64_t GetCachedCloudCN(uint32_t accountId, uint32_t appId) {
    auto it = g_cachedCloudCN.find(MakeAppAccountKey(accountId, appId));
    return (it != g_cachedCloudCN.end()) ? it->second : 0;
}
static uint64_t GetCachedAppBuildIdHwm(uint32_t accountId, uint32_t appId) {
    auto it = g_cachedAppBuildIdHwm.find(MakeAppAccountKey(accountId, appId));
    return (it != g_cachedAppBuildIdHwm.end()) ? it->second : 0;
}

// Inject savefiles rules so AC exit-sync builds a valid file-root tree.
// Without this, namespace apps get all files deleted ("no longer matches patterns").
static std::unordered_set<uint32_t> g_saveFilesInjected;
static std::mutex g_saveFilesInjectedMutex;

static void EnsureSaveFilesInjected(uint32_t appId) {
    {
        std::lock_guard<std::mutex> lock(g_saveFilesInjectedMutex);
        if (g_saveFilesInjected.count(appId)) return;
    }

    if (!SteamKvInjector::IsReady()) return;

    std::string steamPath = CloudIntercept::GetSteamPath();
    if (steamPath.empty()) return;

    auto rules = AutoCloudScan::GetRules(steamPath, appId);
    if (rules.empty()) return;

    std::vector<SteamKvInjector::SaveFileRule> kvRules;
    kvRules.reserve(rules.size());
    for (const auto& r : rules) {
        SteamKvInjector::SaveFileRule sr;
        sr.root = r.root;
        sr.path = r.path;
        sr.pattern = r.pattern;
        sr.recursive = r.recursive;
        sr.platforms = r.platforms;
        kvRules.push_back(std::move(sr));
    }

    if (SteamKvInjector::InjectSaveFiles(appId, kvRules)) {
        std::lock_guard<std::mutex> lock(g_saveFilesInjectedMutex);
        g_saveFilesInjected.insert(appId);
    }
}

// g_lastVerifiedCN removed -- session lock in unified state file prevents concurrent writes.

// Strip Steam root token prefix plus any \r\n between token and path.
// Sanitize control chars in RPC-sourced strings before logging to prevent log injection.
static std::string SanitizeForLog(const std::string& s) {
    std::string out = s;
    for (auto& c : out) { if (c == '\n' || c == '\r') c = '?'; }
    return out;
}

static std::string StripRootToken(const std::string& filename) {
    if (filename.size() >= 2 && filename[0] == '%') {
        size_t end = filename.find('%', 1);
        if (end != std::string::npos && end + 1 < filename.size()) {
            size_t start = end + 1;
            while (start < filename.size() && (filename[start] == '\r' || filename[start] == '\n'))
                ++start;
            return filename.substr(start);
        }
    }
    return filename;
}

// Extract the root token (e.g., "%GameInstall%") or empty string.
static std::string ExtractRootToken(const std::string& filename) {
    if (filename.size() >= 2 && filename[0] == '%') {
        size_t end = filename.find('%', 1);
        if (end != std::string::npos && end + 1 < filename.size()) {
            return filename.substr(0, end + 1);
        }
    }
    return "";
}

static void PrepareBatchCanonicalTokens(uint32_t accountId, uint32_t appId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    {
        std::lock_guard<std::mutex> lock(g_batchCanonicalTokensMutex);
        if (g_batchCanonicalTokens.find(key) != g_batchCanonicalTokens.end()) return;
    }

    // Try bootstrap cache first
    std::unordered_map<std::string, std::string> tokens = AutoCloudBootstrap::GetCachedTokens(accountId, appId);
    
    // Fall back to disk
    if (tokens.empty()) {
        tokens = CloudStorage::LoadFileTokens(accountId, appId);
    }
    
    // If still empty and bootstrap active, wait for it
    if (tokens.empty()) {
        if (AutoCloudBootstrap::IsActive(accountId, appId)) {
            AutoCloudBootstrap::WaitFor(accountId, appId);
            tokens = AutoCloudBootstrap::GetCachedTokens(accountId, appId);
        }
        if (tokens.empty()) return;
    }

    std::lock_guard<std::mutex> lock(g_batchCanonicalTokensMutex);
    g_batchCanonicalTokens.emplace(key, std::move(tokens));
}

static void ClearBatchCanonicalTokens(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_batchCanonicalTokensMutex);
    g_batchCanonicalTokens.erase(MakeAppAccountKey(accountId, appId));
}

static std::string CanonicalizeUploadRootToken(uint32_t accountId, uint32_t appId,
                                               const std::string& cleanName,
                                               const std::string& fallbackToken) {
    if (cleanName.empty()) return fallbackToken;

    // Check batch cache first (populated by PrepareBatchCanonicalTokens)
    std::string canonical;
    bool foundCanonical = false;
    {
        std::lock_guard<std::mutex> lock(g_batchCanonicalTokensMutex);
        auto appIt = g_batchCanonicalTokens.find(MakeAppAccountKey(accountId, appId));
        if (appIt != g_batchCanonicalTokens.end()) {
            auto tokenIt = appIt->second.find(cleanName);
            if (tokenIt != appIt->second.end()) {
                canonical = tokenIt->second;
                foundCanonical = true;
            }
        }
    }

    // Fall back to bootstrap module's live cache
    if (!foundCanonical) {
        canonical = AutoCloudBootstrap::CanonicalizeToken(accountId, appId, cleanName, fallbackToken);
        if (canonical != fallbackToken) {
            foundCanonical = true;
        }
    }

    if (!foundCanonical) return fallbackToken;
    if (canonical != fallbackToken) {
        LOG("[NS-TOK] Canonicalized upload token for account %u app %u file %s: %s -> %s",
            accountId, appId, cleanName.c_str(), fallbackToken.c_str(), canonical.c_str());
    }
    return canonical;
}

// Capture a per-app root token seen on an upload. Serializes against
// concurrent persist operations; unions memory + disk before save.
static bool TryCaptureRootToken(uint32_t accountId, uint32_t appId, const std::string& token) {
    if (token.empty()) return false;

    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> captureLock(g_tokenCaptureMutex);

    bool isNew = false;
    std::unordered_set<std::string> memorySnapshot;
    {
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        auto& tokenSet = g_appRootTokens[key];
        auto result = tokenSet.insert(token);
        isNew = result.second;
        if (isNew) {
            LOG("[NS-TOK] Captured root token for account %u app %u: %s (now %zu tokens)",
                accountId, appId, token.c_str(), tokenSet.size());
            memorySnapshot = tokenSet;
        }
    }
    if (!isNew) return false;

    auto diskTokens = LocalMetadataStore::LoadRootTokens(accountId, appId);
    size_t memoryOnlyCount = memorySnapshot.size();
    memorySnapshot.insert(diskTokens.begin(), diskTokens.end());
    if (memorySnapshot.size() > memoryOnlyCount) {
        LOG("[NS-TOK] Merged %zu extra root token(s) from disk for account %u app %u during capture",
            memorySnapshot.size() - memoryOnlyCount, accountId, appId);
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        auto& tokenSet = g_appRootTokens[key];
        tokenSet.insert(memorySnapshot.begin(), memorySnapshot.end());
        memorySnapshot = tokenSet;
    }
    if (!CloudStorage::SaveRootTokens(accountId, appId, memorySnapshot)) {
        LOG("[TryCaptureRootToken] root_token.dat local persist FAILED app %u -- in-memory set diverges from disk", appId);
    }
    return isNew;
}

// Record which root token a file was uploaded under.
static bool RecordFileToken(uint32_t accountId, uint32_t appId, const std::string& cleanName, const std::string& token) {
    if (cleanName.empty()) return false;
    if (IsReservedBlobFilename(cleanName)) return false;
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    auto& fileTokens = g_fileTokens[MakeAppAccountKey(accountId, appId)];
    auto it = fileTokens.find(cleanName);
    if (it != fileTokens.end() && it->second == token) return false;
    fileTokens[cleanName] = token;
    LOG("[NS-FT] Recorded file token: account=%u app=%u file=%s token=%s",
        accountId, appId, cleanName.c_str(), token.c_str());
    return true;
}

// Remove a file's token mapping (called on delete).
static bool RemoveFileToken(uint32_t accountId, uint32_t appId, const std::string& cleanName) {
    std::lock_guard<std::mutex> lock(g_fileTokensMutex);
    auto appIt = g_fileTokens.find(MakeAppAccountKey(accountId, appId));
    if (appIt != g_fileTokens.end()) {
        if (appIt->second.erase(cleanName) > 0) {
            LOG("[NS-FT] Removed file token: account=%u app=%u file=%s", accountId, appId, cleanName.c_str());
            return true;
        }
    }
    return false;
}

// Persist file -> root-token map (memory wins on key conflicts).
static void PersistFileTokens(uint32_t accountId, uint32_t appId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> captureLock(g_tokenCaptureMutex);

    std::unordered_map<std::string, std::string> snapshot;
    {
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        auto it = g_fileTokens.find(key);
        if (it != g_fileTokens.end()) snapshot = it->second;
    }

    auto diskTokens = CloudStorage::LoadFileTokens(accountId, appId);
    size_t mergedFromDisk = 0;
    for (auto& kv : diskTokens) {
        if (IsReservedBlobFilename(kv.first)) continue;
        if (snapshot.find(kv.first) == snapshot.end()) {
            snapshot.emplace(kv.first, kv.second);
            ++mergedFromDisk;
        }
    }
    if (mergedFromDisk > 0) {
        LOG("[NS-FT] PersistFileTokens account %u app %u: merged %zu extra entries from disk",
            accountId, appId, mergedFromDisk);
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        auto& mapRef = g_fileTokens[key];
        for (auto& kv : snapshot) {
            mapRef.emplace(kv.first, kv.second);
        }
        snapshot = mapRef;
    }
    if (!CloudStorage::SaveFileTokens(accountId, appId, snapshot)) {
        LOG("[RecordFileToken] file_tokens.dat local persist FAILED app %u -- in-memory mapping diverges from disk", appId);
    }
}

// Defer persistence to HandleCompleteBatch.
static void MarkFileTokensDirty(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_fileTokensDirtyMutex);
    g_fileTokensDirtyApps.insert(MakeAppAccountKey(accountId, appId));
}

static void ClearFileTokensDirty(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_fileTokensDirtyMutex);
    g_fileTokensDirtyApps.erase(MakeAppAccountKey(accountId, appId));
}

static void InvalidateTokenCaches(uint32_t accountId, uint32_t appId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    
    // Clear local caches
    {
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        g_appRootTokens.erase(key);
    }
    {
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        g_fileTokens.erase(key);
    }
    {
        std::lock_guard<std::mutex> lock(g_batchCanonicalTokensMutex);
        g_batchCanonicalTokens.erase(key);
    }
    {
        std::lock_guard<std::mutex> lock(g_remotecacheRepairMutex);
        g_remotecachePlantedRows.erase(key);
    }
    // Keep manifest/CN cache -- metadata restore doesn't change save CN, and clearing
    // mid-session would break exit-sync's is_only_delta=1 path.
    
    // Invalidate bootstrap module's cache (also resets attempted flag)
    AutoCloudBootstrap::InvalidateCache(accountId, appId);
}

static bool MergeStatsFile(uint32_t appId, uint32_t accountId,
                           const std::vector<uint8_t>& cloudData);

static bool InsertPlaytimeFieldInSection(std::string& vdfContent,
                                         const char* const* sections,
                                         size_t sectionCount,
                                         std::string_view fieldName,
                                         const std::string& value) {
    size_t sectionStart = 0;
    size_t sectionEnd = 0;
    if (!VdfUtil::FindVdfSectionRange(vdfContent, sections, sectionCount, sectionStart, sectionEnd)) {
        return false;
    }

    std::string indent = "\t";
    size_t lineStart = vdfContent.rfind('\n', sectionEnd);
    if (lineStart != std::string::npos) {
        ++lineStart;
        size_t indentEnd = lineStart;
        while (indentEnd < vdfContent.size() && (vdfContent[indentEnd] == '\t' || vdfContent[indentEnd] == ' ')) {
            ++indentEnd;
        }
        indent.assign(vdfContent.data() + lineStart, indentEnd - lineStart);
        indent.push_back('\t');
    }

    std::string insertion = indent + "\"" + std::string(fieldName) + "\"\t\t\"" + value + "\"\n";
    vdfContent.insert(sectionEnd, insertion);
    return true;
}

static bool EnsureVdfSectionPath(std::string& vdfContent,
                                 const char* const* sections,
                                 size_t sectionCount) {
    if (sectionCount == 0) return true;

    size_t sectionStart = 0;
    size_t sectionEnd = 0;
    if (VdfUtil::FindVdfSectionRange(vdfContent, sections, sectionCount, sectionStart, sectionEnd)) {
        return true;
    }

    if (sectionCount == 1) {
        const std::string snapshot = vdfContent;
        if (!vdfContent.empty() && vdfContent.back() != '\n') vdfContent.push_back('\n');
        vdfContent += "\"" + std::string(sections[0]) + "\"\n{\n}\n";
        // Roll back if the insertion isn't parseable.
        if (!VdfUtil::FindVdfSectionRange(vdfContent, sections, sectionCount, sectionStart, sectionEnd)) {
            vdfContent = snapshot;
            return false;
        }
        return true;
    }

    if (!EnsureVdfSectionPath(vdfContent, sections, sectionCount - 1)) {
        return false;
    }

    size_t parentStart = 0;
    size_t parentEnd = 0;
    if (!VdfUtil::FindVdfSectionRange(vdfContent, sections, sectionCount - 1, parentStart, parentEnd)) {
        return false;
    }

    std::string parentIndent = "\t";
    size_t lineStart = vdfContent.rfind('\n', parentEnd);
    if (lineStart != std::string::npos) {
        ++lineStart;
        size_t indentEnd = lineStart;
        while (indentEnd < vdfContent.size() && (vdfContent[indentEnd] == '\t' || vdfContent[indentEnd] == ' ')) {
            ++indentEnd;
        }
        parentIndent.assign(vdfContent.data() + lineStart, indentEnd - lineStart);
    }

    const std::string childIndent = parentIndent + "\t";
    std::string insertion;
    insertion += childIndent + "\"" + std::string(sections[sectionCount - 1]) + "\"\n";
    insertion += childIndent + "{\n";
    insertion += childIndent + "}\n";

    const std::string snapshot = vdfContent;
    vdfContent.insert(parentEnd, insertion);

    // Roll back if the new child isn't parseable.
    if (!VdfUtil::FindVdfSectionRange(vdfContent, sections, sectionCount, sectionStart, sectionEnd)) {
        vdfContent = snapshot;
        return false;
    }
    return true;
}

// Pre-seed remotecache.vdf rows so Steam doesn't default-construct them
// with persiststate=deleted. Add-only, atomic-write, stat-before/after.
static bool EnsureAndMarkRemotecacheRepaired(
        uint32_t accountId, uint32_t appId,
        const std::vector<RemotecacheCandidate>& candidates) {
    const uint64_t appKey = MakeAppAccountKey(accountId, appId);

    // Mark attempted on the empty path; HandleDeleteFile distinguishes
    // "no changelist yet" from "changelist ran, advertised nothing".
    if (candidates.empty()) {
        std::lock_guard<std::mutex> lock(g_remotecacheRepairMutex);
        (void)g_remotecachePlantedRows[appKey];
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(g_remotecacheRepairMutex);
        auto it = g_remotecachePlantedRows.find(appKey);
        if (it != g_remotecachePlantedRows.end()) {
            const auto& planted = it->second;
            bool allPlanted = true;
            for (const auto& c : candidates) {
                if (planted.count(c.cleanName) == 0) {
                    allPlanted = false;
                    break;
                }
            }
            if (allPlanted) return true;
        }
    }

    std::string steamPath = CloudIntercept::GetSteamPath();
    if (steamPath.empty()) return false;

#ifdef _WIN32
    std::string vdfPath = steamPath + "userdata\\" + std::to_string(accountId)
        + "\\" + std::to_string(appId) + "\\remotecache.vdf";
#else
    std::string vdfPath = steamPath + "userdata/" + std::to_string(accountId)
        + "/" + std::to_string(appId) + "/remotecache.vdf";
#endif

    auto ioMutex = AcquireRemotecacheRepairIoMutex(appKey);
    std::lock_guard<std::mutex> ioLock(*ioMutex);

    auto pathW = FileUtil::Utf8ToPath(vdfPath);
    std::error_code ec;

    auto sizeBefore = std::filesystem::file_size(pathW, ec);
    if (ec) {
        LOG("[NS-RC] remotecache.vdf missing for app %u (%s), deferring repair",
            appId, vdfPath.c_str());
        return false;
    }
    auto mtimeBefore = std::filesystem::last_write_time(pathW, ec);
    if (ec) {
        return false;
    }

    std::ifstream in(pathW);
    if (!in.is_open()) {
        LOG("[NS-RC] remotecache.vdf unreadable for app %u (%s), deferring repair",
            appId, vdfPath.c_str());
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::string repaired;
    size_t added = 0;
    if (!ApplyRemotecacheRepair(content, appId, candidates, repaired, added)) {
        LOG("[NS-RC] remotecache.vdf missing top section for app %u, skipping repair", appId);
        return false;
    }

    if (added == 0) {
        LOG("[NS-RC] remotecache.vdf already covers all advertised files for app %u "
            "(%zu entries already present)", appId, candidates.size());
        std::lock_guard<std::mutex> lock(g_remotecacheRepairMutex);
        auto& planted = g_remotecachePlantedRows[appKey];
        for (const auto& c : candidates) planted.insert(c.cleanName);
        return true;
    }

    // Bail if Steam rewrote the file under us.
    auto sizeAfter = std::filesystem::file_size(pathW, ec);
    auto mtimeAfter = ec ? std::filesystem::file_time_type{}
                         : std::filesystem::last_write_time(pathW, ec);
    if (ec || sizeAfter != sizeBefore || mtimeAfter != mtimeBefore) {
        LOG("[NS-RC] remotecache.vdf changed under us for app %u (%s); deferring repair",
            appId, vdfPath.c_str());
        return false;
    }

    if (!FileUtil::AtomicWriteText(vdfPath, repaired)) {
        LOG("[NS-RC] Failed to write repaired remotecache.vdf for app %u (%s)",
            appId, vdfPath.c_str());
        return false;
    }

    LOG("[NS-RC] Repaired remotecache.vdf for app %u: added %zu missing entries",
        appId, added);
    std::lock_guard<std::mutex> lock(g_remotecacheRepairMutex);
    auto& planted = g_remotecachePlantedRows[appKey];
    for (const auto& c : candidates) planted.insert(c.cleanName);
    return true;
}


static bool InsertPlaytimeAppSection(std::string& vdfContent,
                                     const char* const* sections,
                                     size_t sectionCount,
                                     const std::string& lastPlayed,
                                     const std::string& playtime,
                                     const std::string& playtime2wks) {
    if (!EnsureVdfSectionPath(vdfContent, sections, sectionCount)) {
        return false;
    }

    if (!InsertPlaytimeFieldInSection(vdfContent, sections, sectionCount, "LastPlayed", lastPlayed)) {
        return false;
    }
    if (!InsertPlaytimeFieldInSection(vdfContent, sections, sectionCount, "Playtime", playtime)) {
        return false;
    }
    if (!InsertPlaytimeFieldInSection(vdfContent, sections, sectionCount, "Playtime2wks", playtime2wks)) {
        return false;
    }
    return true;
}

static bool WriteLocalConfigWithRetry(const std::string& vdfPath, const std::string& vdfContent) {
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (FileUtil::AtomicWriteText(vdfPath, vdfContent)) {
            return true;
        }
#ifdef _WIN32
        Sleep(200);
#else
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
#endif
    }
    return false;
}

static void RestorePlaytimeMetadata(uint32_t accountId, uint32_t appId, const std::vector<uint8_t>& ptData) {
    if (ptData.empty()) return;

    std::string blob(reinterpret_cast<const char*>(ptData.data()), ptData.size());
    uint64_t cloudLastPlayed = 0, cloudPlaytime = 0, cloudPlaytime2wks = 0;
    ParsePlaytimeBlob(blob, cloudLastPlayed, cloudPlaytime, cloudPlaytime2wks);

    if (cloudLastPlayed == 0 && cloudPlaytime == 0 && cloudPlaytime2wks == 0) {
        LOG("[Playtime] Cloud blob empty/invalid for app %u, skipping merge", appId);
        return;
    }

#ifdef _WIN32
    std::string vdfPath = GetSteamPath() + "userdata\\" + std::to_string(accountId)
        + "\\config\\localconfig.vdf";
#else
    std::string vdfPath = GetSteamPath() + "userdata/" + std::to_string(accountId)
        + "/config/localconfig.vdf";
#endif

    // Shared read; Steam holds localconfig.vdf with no sharing during writes,
    // and std::ifstream uses dwShareMode=0 -> ERROR_SHARING_VIOLATION.
    std::string vdfContent;
    {
#ifdef _WIN32
        auto vdfPathWide = FileUtil::Utf8ToPath(vdfPath).wstring();
        HANDLE hFile = CreateFileW(vdfPathWide.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            LOG("[Playtime] Cannot open localconfig.vdf for reading (app %u, err=%lu)",
                appId, GetLastError());
            return;
        }
        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
            vdfContent.resize(fileSize);
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, vdfContent.data(), fileSize, &bytesRead, nullptr)) {
                LOG("[Playtime] ReadFile failed for localconfig.vdf (app %u, err=%lu)",
                    appId, GetLastError());
                CloseHandle(hFile);
                return;
            }
            vdfContent.resize(bytesRead);
        }
        CloseHandle(hFile);
#else
        // On Linux, no sharing violation issues with std::ifstream
        std::ifstream f(vdfPath);
        if (!f) {
            LOG("[Playtime] Cannot open localconfig.vdf for reading (app %u)", appId);
            return;
        }
        vdfContent = std::string(std::istreambuf_iterator<char>(f), {});
#endif
    }

    std::string appIdStr = std::to_string(appId);
    const char* sections[] = { "UserLocalConfigStore", "Software", "Valve", "Steam", "Apps", appIdStr.c_str() };
    uint64_t localLastPlayed = 0, localPlaytime = 0, localPlaytime2wks = 0;

    struct FieldLoc { size_t valStart; size_t valEnd; };
    FieldLoc lpLoc = {0, 0}, ptLoc = {0, 0}, pt2Loc = {0, 0};

    bool found = VdfUtil::ForEachFieldInSection(vdfContent, sections, 6,
        [&](const VdfUtil::FieldInfo& fi) {
            if (fi.key == "LastPlayed") {
                localLastPlayed = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                lpLoc = { fi.valStart, fi.valEnd };
            } else if (fi.key == "Playtime") {
                localPlaytime = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                ptLoc = { fi.valStart, fi.valEnd };
            } else if (fi.key == "Playtime2wks") {
                localPlaytime2wks = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                pt2Loc = { fi.valStart, fi.valEnd };
            }
            return true;
        });

    if (!found) {
        // Don't fabricate playtime sections for apps the user doesn't own.
        // Stale cloud blobs from prior installs / SteamTools-injected sessions
        // would otherwise resurrect ghost playtime in localconfig.vdf every login.
        if (!LocalStorage::IsAppInstalled(GetSteamPath(), appId)) {
            LOG("[Playtime] Skipping VDF synthesis for app %u: not installed locally", appId);
            return;
        }
        std::string newLP = std::to_string(cloudLastPlayed);
        std::string newPT = std::to_string(cloudPlaytime);
        std::string newPT2 = std::to_string(cloudPlaytime2wks);
        if (!InsertPlaytimeAppSection(vdfContent, sections, 6, newLP, newPT, newPT2)) {
            // Steam flushes in-memory state to localconfig.vdf on its own cycle.
            LOG("[Playtime] App %u section synthesis failed; seeding in-memory only", appId);
            RestoreInMemoryPlaytimeMetadata(appId, cloudLastPlayed, cloudPlaytime, cloudPlaytime2wks);
            return;
        }

        if (WriteLocalConfigWithRetry(vdfPath, vdfContent)) {
            RestoreInMemoryPlaytimeMetadata(appId, cloudLastPlayed, cloudPlaytime, cloudPlaytime2wks);
            LOG("[Playtime] Created playtime section for app %u: LastPlayed 0->%llu, Playtime 0->%llu, Playtime2wks 0->%llu",
                appId, cloudLastPlayed, cloudPlaytime, cloudPlaytime2wks);
        } else {
            // VDF write failed but cloud values are valid; seed in-memory anyway.
            RestoreInMemoryPlaytimeMetadata(appId, cloudLastPlayed, cloudPlaytime, cloudPlaytime2wks);
            LOG("[Playtime] Failed to write localconfig.vdf for app %u; seeded in-memory only", appId);
        }
        return;
    }

    uint64_t mergedLP = (cloudLastPlayed > localLastPlayed) ? cloudLastPlayed : localLastPlayed;
    uint64_t mergedPT = (cloudPlaytime > localPlaytime) ? cloudPlaytime : localPlaytime;
    uint64_t mergedPT2 = (cloudPlaytime2wks > localPlaytime2wks) ? cloudPlaytime2wks : localPlaytime2wks;
    // Recent playtime cannot exceed lifetime; reject any value that would.
    if (mergedPT2 > mergedPT)
        mergedPT2 = localPlaytime2wks <= mergedPT ? localPlaytime2wks : 0;
    if (mergedLP == localLastPlayed && mergedPT == localPlaytime && mergedPT2 == localPlaytime2wks) {
        RestoreInMemoryPlaytimeMetadata(appId, mergedLP, mergedPT, mergedPT2);
        LOG("[Playtime] Local playtime already up-to-date for app %u", appId);
        return;
    }

    std::string newLP = std::to_string(mergedLP);
    std::string newPT = std::to_string(mergedPT);
    std::string newPT2 = std::to_string(mergedPT2);
    bool lpValid = lpLoc.valEnd > lpLoc.valStart;
    bool ptValid = ptLoc.valEnd > ptLoc.valStart;
    bool pt2Valid = pt2Loc.valEnd > pt2Loc.valStart;

    struct Replacement { size_t start; size_t len; std::string text; };
    std::vector<Replacement> reps;
    if (lpValid) reps.push_back({lpLoc.valStart, lpLoc.valEnd - lpLoc.valStart, newLP});
    if (ptValid) reps.push_back({ptLoc.valStart, ptLoc.valEnd - ptLoc.valStart, newPT});
    if (pt2Valid) reps.push_back({pt2Loc.valStart, pt2Loc.valEnd - pt2Loc.valStart, newPT2});

    if (!reps.empty()) {
        std::sort(reps.begin(), reps.end(),
            [](const Replacement& a, const Replacement& b) { return a.start > b.start; });
        for (auto& r : reps)
            vdfContent.replace(r.start, r.len, r.text);
    }

    bool inserted = false;
    if (!lpValid) {
        inserted = InsertPlaytimeFieldInSection(vdfContent, sections, 6, "LastPlayed", newLP) || inserted;
    }
    if (!ptValid) {
        inserted = InsertPlaytimeFieldInSection(vdfContent, sections, 6, "Playtime", newPT) || inserted;
    }
    if (!pt2Valid) {
        inserted = InsertPlaytimeFieldInSection(vdfContent, sections, 6, "Playtime2wks", newPT2) || inserted;
    }
    if (!lpValid && !ptValid && !pt2Valid && !inserted) {
        LOG("[Playtime] App %u section has no playtime fields, skipping write", appId);
        return;
    }

    if (WriteLocalConfigWithRetry(vdfPath, vdfContent)) {
        RestoreInMemoryPlaytimeMetadata(appId, mergedLP, mergedPT, mergedPT2);
        LOG("[Playtime] Merged playtime for app %u: LastPlayed %llu->%llu, Playtime %llu->%llu, Playtime2wks %llu->%llu",
            appId, localLastPlayed, mergedLP, localPlaytime, mergedPT, localPlaytime2wks, mergedPT2);
    } else {
        // Merge succeeded but VDF write failed; in-memory seed is still safe.
        RestoreInMemoryPlaytimeMetadata(appId, mergedLP, mergedPT, mergedPT2);
        LOG("[Playtime] Failed to write localconfig.vdf for app %u; seeded in-memory only", appId);
    }
}

void RestoreAppMetadata(uint32_t accountId, uint32_t appId) {
    InvalidateTokenCaches(accountId, appId);

#ifdef _WIN32
    if (MetadataSync::syncAchievements.load(std::memory_order_relaxed)) {
        auto statsData = CloudStorage::RetrieveBlob(
            accountId, kAccountScopeAppId, AccountStatsFilename(appId));
        if (!statsData.empty())
            MergeStatsFile(appId, accountId, statsData);
    }
    if (MetadataSync::syncPlaytime.load(std::memory_order_relaxed)) {
        auto ptData = CloudStorage::RetrieveBlob(
            accountId, kAccountScopeAppId, AccountPlaytimeFilename(appId));
        RestorePlaytimeMetadata(accountId, appId, ptData);
    }
#endif
}


static std::string GetMachineName() {
#ifdef _WIN32
    char buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = sizeof(buf);
    if (GetComputerNameA(buf, &len))
        return std::string(buf, len);
    return "UNKNOWN";
#else
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0)
        return std::string(buf);
    return "UNKNOWN";
#endif
}


// Returns the blob-store file list; Steam compares vs. remotecache.vdf.
RpcResult HandleGetChangelist(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    SetRpcCrashContext("GetChangelist:entry", "Cloud.GetAppFileChangelist#1", appId);
    auto* cnField = PB::FindField(reqBody, 2);
    uint64_t clientChangeNumber = cnField ? cnField->varintVal : 0;

    uint32_t accountId = 0;
    SetRpcCrashContext("GetChangelist:account", "Cloud.GetAppFileChangelist#1", appId);
    if (!RequireAccountId("GetAppFileChangelist", appId, accountId)) {
        // is_only_delta=1 prevents Steam queuing ClientDeleteFile.
        PB::Writer body;
        body.WriteVarint(1, 0);                    // current_change_number
        body.WriteVarint(3, 1);                    // is_only_delta = 1
        body.WriteString(5, GetMachineName());     // machine_names
        body.WriteVarint(6, 0);                    // app_buildid_hwm
        return body;
    }
    uint64_t appKey = MakeAppAccountKey(accountId, appId);

    // Inject quota before ComputeLastKnownSyncState can run.
    EnsureAppQuotaInjected(accountId, appId, nullptr);
    EnsureSaveFilesInjected(appId);

    // Fast path: probe CN if full manifest already sent this session.
    {
        const uint64_t cacheKey = MakeAppAccountKey(accountId, appId);
        bool repeatCall = false;
        uint64_t cachedCN = 0;
        uint64_t cachedBuildId = 0;
        {
            std::lock_guard<std::mutex> lock(g_fullManifestSentMutex);
            if (g_fullManifestSentApps.count(cacheKey) > 0) {
                repeatCall = true;
                cachedCN = GetCachedCloudCN(accountId, appId);
                cachedBuildId = GetCachedAppBuildIdHwm(accountId, appId);
            }
        }
        if (repeatCall) {
            // CN probe; on change, invalidate cache and fall through to full fetch.
            bool probeNeeded = CloudStorage::IsCloudActive() && cachedCN > 0;
            uint64_t remoteCN = probeNeeded
                ? CloudStorage::FetchCloudCN(accountId, appId) : cachedCN;
            if (probeNeeded && remoteCN == 0) {
                // Probe failed; invalidate cache and fall through to full fetch.
                LOG("[NS-CL] GetAppFileChangelist app=%u: CN probe failed, invalidating cache",
                    appId);
                std::lock_guard<std::mutex> lock(g_fullManifestSentMutex);
                g_fullManifestSentApps.erase(cacheKey);
                g_cachedCloudCN.erase(cacheKey);
                g_cachedAppBuildIdHwm.erase(cacheKey);
                // Fall through to full fetch below
            } else if (remoteCN != cachedCN) {
                LOG("[NS-CL] GetAppFileChangelist app=%u: remote CN=%llu differs from cached CN=%llu, invalidating cache",
                    appId, remoteCN, cachedCN);
                std::lock_guard<std::mutex> lock(g_fullManifestSentMutex);
                g_fullManifestSentApps.erase(cacheKey);
                g_cachedCloudCN.erase(cacheKey);
                g_cachedAppBuildIdHwm.erase(cacheKey);
                // Fall through to full fetch below
            } else {
                LOG("[NS-CL] GetAppFileChangelist app=%u: repeat call, CN unchanged (%llu), returning cached empty delta",
                    appId, cachedCN);
                PB::Writer body;
                body.WriteVarint(1, cachedCN);
                body.WriteVarint(3, 1); // is_only_delta = 1
                body.WriteString(5, GetMachineName());
                body.WriteVarint(6, cachedBuildId);
                return body;
            }
        }
    }

    // Track whether we fetched fresh manifest from cloud this call
    CloudStorage::Manifest cloudManifest;
    std::unordered_map<std::string, CloudStorage::FileEntry> cloudFileEntries; // full per-file state from cloud
    bool haveCloudManifest = false;
    uint64_t cloudCN = 0;
    uint64_t appBuildIdHwm = 0;
    CloudStorage::CloudAppState fetchedState; // retained for quota caching
    bool haveFetchedState = false;

    if (CloudStorage::IsCloudActive()) {
        SetRpcCrashContext("GetChangelist:fetch-cloud", "Cloud.GetAppFileChangelist#1", appId);
        auto stateResult = CloudStorage::FetchCloudState(accountId, appId);
        if (stateResult.status == CloudStorage::StateFetchStatus::Ok) {
            auto& state = stateResult.state;
            cloudCN = state.cn;
            appBuildIdHwm = state.appBuildId;
            for (const auto& [name, fe] : state.files) {
                CloudStorage::ManifestEntry me;
                me.sha = fe.sha;
                me.timestamp = fe.timestamp;
                me.size = fe.size;
                cloudManifest[name] = std::move(me);
                cloudFileEntries[name] = fe;
            }
            haveCloudManifest = true;
            fetchedState = state;
            haveFetchedState = true;

            uint64_t localCN = LocalStorage::GetChangeNumber(accountId, appId);
            if (state.cn > localCN) {
                LOG("[NS-CL] GetAppFileChangelist app=%u: cloud CN=%llu > local CN=%llu, syncing local",
                    appId, state.cn, localCN);
                CloudStorage::SaveManifestLocal(accountId, appId, cloudManifest);
                LocalStorage::SetChangeNumber(accountId, appId, state.cn);
            }

            LOG("[NS-CL] GetAppFileChangelist app=%u: cloud state CN=%llu (%zu files)",
                appId, cloudCN, cloudManifest.size());
        } else if (stateResult.status == CloudStorage::StateFetchStatus::NotFound) {
            LOG("[NS-CL] GetAppFileChangelist app=%u: no cloud state (new app), using local",
                appId);
        } else {
            LOG("[NS-CL] GetAppFileChangelist app=%u: cloud state fetch failed (status=%d), using local",
                appId, static_cast<int>(stateResult.status));
        }
    }

    // Inject quota (cached PICS values or fallback).
    EnsureAppQuotaInjected(accountId, appId,
                           haveFetchedState ? &fetchedState : nullptr);

    if (!haveCloudManifest) {
        SetRpcCrashContext("GetChangelist:local-fallback", "Cloud.GetAppFileChangelist#1", appId);
        uint64_t localCN = LocalStorage::GetChangeNumber(accountId, appId);

        auto localManifest = CloudStorage::LoadLocalManifest(accountId, appId);
        if (!localManifest.empty()) {
            cloudCN = localCN;
            for (const auto& [name, me] : localManifest) {
                cloudManifest[name] = me;
            }
            haveCloudManifest = true;
        } else {
            cloudCN = 0;
        }

        LOG("[NS-CL] GetAppFileChangelist app=%u: local fallback CN=%llu (%zu files)",
            appId, cloudCN, cloudManifest.size());
    }

    // Async AutoCloud bootstrap; set is_only_delta=1 if active.
    SetRpcCrashContext("GetChangelist:bootstrap", "Cloud.GetAppFileChangelist#1", appId);
    AutoCloudBootstrap::Bootstrap(accountId, appId, /*wait=*/false);
    bool bootstrapActive = AutoCloudBootstrap::IsActive(accountId, appId);

    if (CloudStorage::IsCloudActive() && cloudCN == 0 && !bootstrapActive) {
        SetRpcCrashContext("GetChangelist:promote-local", "Cloud.GetAppFileChangelist#1", appId);
        uint64_t localCN = LocalStorage::GetChangeNumber(accountId, appId);
        if (localCN > 0) {
            CloudStorage::Manifest fullManifest =
                CloudStorage::BuildManifestFromLocalBlobs(accountId, appId);
            size_t nonReserved = 0;
            for (const auto& [name, entry] : fullManifest) {
                if (!IsReservedBlobFilename(name)) ++nonReserved;
            }
            if (nonReserved > 0) {
                LOG("[NS-CL] No cloud CN for app %u, publishing %zu local files at CN=%llu",
                    appId, nonReserved, localCN);
                CloudStorage::CloudAppState bootstrapState;
                bootstrapState.cn = localCN;
                for (const auto& [name, me] : fullManifest) {
                    if (IsReservedBlobFilename(name)) continue;
                    CloudStorage::FileEntry fe;
                    fe.sha = me.sha;
                    fe.timestamp = me.timestamp;
                    fe.size = me.size;
                    bootstrapState.files[name] = std::move(fe);
                }
                auto statePtr = std::make_shared<CloudStorage::CloudAppState>(std::move(bootstrapState));
                uint32_t asyncAcct = accountId;
                uint32_t asyncApp = appId;
                std::thread([statePtr, asyncAcct, asyncApp] {
                    CloudStorage::InflightSyncScope guard;
                    if (!guard.entered) return;
                    auto syncMtx = CloudStorage::AcquireAppSyncMutex(asyncAcct, asyncApp);
                    std::lock_guard<std::mutex> lock(*syncMtx);
                    auto existing = CloudStorage::FetchCloudState(asyncAcct, asyncApp);
                    if (existing.status == CloudStorage::StateFetchStatus::Ok &&
                        existing.state.cn >= statePtr->cn) {
                        LOG("[NS-CL] Bootstrap publish aborted for app %u: cloud CN %llu >= bootstrap CN %llu",
                            asyncApp, existing.state.cn, statePtr->cn);
                        return;
                    }
                    CloudStorage::PublishCloudState(asyncAcct, asyncApp, *statePtr);
                }).detach();
            }
        }
    }

    // Build file list - either from cloud manifest (fast path) or local blobs
    std::vector<LocalStorage::FileEntry> files;
    uint64_t serverChangeNumber = 0;  // Initialize to prevent UB in edge cases
    bool responseIsDelta = true;

    if (haveCloudManifest && cloudManifest.empty() && cloudCN == 0) {
        // New app at CN=0 -- return empty authoritative inventory
        serverChangeNumber = cloudCN;
        responseIsDelta = false;
        LOG("[NS-CL] GetAppFileChangelist app=%u: cloud manifest is empty at CN=%llu, returning empty authoritative inventory",
            appId, cloudCN);
    } else if (haveCloudManifest && !cloudManifest.empty()) {
        SetRpcCrashContext("GetChangelist:manifest-delta", "Cloud.GetAppFileChangelist#1", appId);
        // Steam-faithful delta: compute diff between clientCN snapshot and current manifest.
        // Steam's server returns only changed files -- not the full inventory.
        auto delta = CloudStorage::ComputeManifestDelta(accountId, appId,
                                                         clientChangeNumber, cloudCN,
                                                         cloudManifest);
        if (!delta.files.empty()) {
            serverChangeNumber = delta.serverCN;
            responseIsDelta = true;
            for (auto& fc : delta.files) {
                if (IsReservedBlobFilename(fc.filename)) continue;
                LocalStorage::FileEntry fe;
                fe.filename = std::move(fc.filename);
                fe.sha = std::move(fc.sha);
                fe.timestamp = fc.timestamp;
                fe.rawSize = fc.size;
                fe.deleted = fc.deleted;
                files.push_back(std::move(fe));
            }
            LOG("[NS-CL] GetAppFileChangelist app=%u delta clientCN=%llu serverCN=%llu (%zu changed)",
                appId, clientChangeNumber, cloudCN, files.size());
        } else {
            // No delta. First call: full manifest (populates root tokens).
            // Subsequent calls: empty delta (avoids stale SHA/timestamp conflicts).
            const uint64_t cacheKey = MakeAppAccountKey(accountId, appId);
            bool alreadySentFull;
            {
                std::lock_guard<std::mutex> lock(g_fullManifestSentMutex);
                alreadySentFull = g_fullManifestSentApps.count(cacheKey) > 0;
            }

            serverChangeNumber = cloudCN;

            if (alreadySentFull) {
                // Subsequent call: empty delta.
                responseIsDelta = true;
                LOG("[NS-CL] GetAppFileChangelist app=%u: already sent full manifest this session, returning empty delta at CN=%llu",
                    appId, cloudCN);
            } else {
                // First call: full manifest. Use cloud timestamp so subsequent
                // compares see the same remotetime (avoids false conflicts).
                responseIsDelta = false;

                for (const auto& [filename, entry] : cloudManifest) {
                    if (IsReservedBlobFilename(filename)) continue;
                    LocalStorage::FileEntry fe;
                    fe.filename = filename;
                    fe.sha = entry.sha;
                    fe.timestamp = entry.timestamp;
                    fe.rawSize = entry.size;
                    fe.deleted = false;
                    files.push_back(std::move(fe));
                }

                {
                    std::lock_guard<std::mutex> lock(g_fullManifestSentMutex);
                    g_fullManifestSentApps.insert(cacheKey);
                    g_cachedCloudCN[cacheKey] = cloudCN;
                    g_cachedAppBuildIdHwm[cacheKey] = appBuildIdHwm;
                }
                LOG("[NS-CL] GetAppFileChangelist app=%u: returning full manifest (%zu files) at CN=%llu (clientCN=%llu)",
                    appId, files.size(), cloudCN, clientChangeNumber);
            }
        }
    } else {
        // No cloud manifest -- serve local files as delta (don't trigger reconcile-deletes)
        SetRpcCrashContext("GetChangelist:local-files", "Cloud.GetAppFileChangelist#1", appId);
        
        if (bootstrapActive) {
            LOG("[NS-CL] GetAppFileChangelist app=%u: bootstrap active, returning empty list to avoid UI freeze", appId);
            files.clear();
            serverChangeNumber = 0;
            // responseIsDelta stays true so Steam does not reconcile-delete.
        } else {
            files = LocalStorage::GetFileList(accountId, appId);
            serverChangeNumber = LocalStorage::GetChangeNumber(accountId, appId);
            // cloud active but fetch failed -> delta (don't delete unverified); cloud inactive -> authoritative
            responseIsDelta = CloudStorage::IsCloudActive();
            
            files.erase(std::remove_if(files.begin(), files.end(),
                [](const LocalStorage::FileEntry& fe) {
                    return IsReservedBlobFilename(fe.filename);
                }), files.end());
        }
    }

    LOG("[NS-CL] GetAppFileChangelist app=%u clientCN=%llu serverCN=%llu files=%zu",
        appId, clientChangeNumber, serverChangeNumber, files.size());

    // Cache result so repeat calls (CM reconnects) skip cloud I/O entirely.
    // Don't cache placeholder bootstrap response (CN==0, empty files).
    if (serverChangeNumber > 0 || !files.empty()) {
        const uint64_t cacheKey = MakeAppAccountKey(accountId, appId);
        std::lock_guard<std::mutex> lock(g_fullManifestSentMutex);
        if (g_fullManifestSentApps.count(cacheKey) == 0) {
            g_fullManifestSentApps.insert(cacheKey);
            g_cachedCloudCN[cacheKey] = serverChangeNumber;
            g_cachedAppBuildIdHwm[cacheKey] = appBuildIdHwm;
        }
    }

    // build path_prefix table and file entries
    std::unordered_map<std::string, uint32_t> prefixMap;
    std::vector<std::string> prefixList;
    std::string machineName = GetMachineName();

    std::unordered_set<std::string> rootTokens;
    bool appHasUfsRules = true; // assume yes until proven otherwise
    {
        SetRpcCrashContext("GetChangelist:root-token-cache", "Cloud.GetAppFileChangelist#1", appId);
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        auto it = g_appRootTokens.find(appKey);
        if (it != g_appRootTokens.end()) {
            rootTokens = it->second;
        }
    }
    // Disk-only fallback (no cloud download yet); skip cache-write if worker straddles the read.
    if (rootTokens.empty()) {
        SetRpcCrashContext("GetChangelist:root-token-disk", "Cloud.GetAppFileChangelist#1", appId);
        bool bootstrapActiveBefore = AutoCloudBootstrap::IsActive(accountId, appId);
        rootTokens = LocalMetadataStore::LoadRootTokens(accountId, appId);
        bool bootstrapActiveAfter = AutoCloudBootstrap::IsActive(accountId, appId);
        bool bootstrapTouchedLoad = bootstrapActiveBefore || bootstrapActiveAfter;
        if (!rootTokens.empty() && !bootstrapTouchedLoad) {
            std::lock_guard<std::mutex> lock(g_rootTokenMutex);
            auto it = g_appRootTokens.find(appKey);
            if (it != g_appRootTokens.end()) {
                rootTokens = it->second;
            } else {
                g_appRootTokens[appKey] = rootTokens;
            }
        } else if (bootstrapTouchedLoad && !rootTokens.empty()) {
            LOG("[NS-CL] Skipping root-token cache-write for account %u app %u "
                "-- bootstrap worker was active during disk read", accountId, appId);
        }
    }
    // No disk tokens: skip cloud download for apps with no UFS rules.
    if (rootTokens.empty()) {
        std::string steamPath = CloudIntercept::GetSteamPath();
        if (!steamPath.empty()) {
            auto scanResult = AutoCloudScan::GetFileList(steamPath, accountId, appId);
            appHasUfsRules = scanResult.hasRules;
            if (appHasUfsRules) {
                // Has rules but no tokens on disk -- fall back to full cloud load.
                rootTokens = CloudStorage::LoadRootTokens(accountId, appId);
            }
            for (const auto& fe : scanResult.files) {
                if (!fe.rootToken.empty()) rootTokens.insert(fe.rootToken);
            }
            if (rootTokens.empty()) {
                rootTokens = std::move(scanResult.ruleRootTokens);
            }
        }
        if (rootTokens.empty()) {
            rootTokens.insert("");
        }
    }

    for (auto& t : rootTokens) {
        LOG("[NS-CL] Root token for app %u: '%s'", appId, t.c_str());
    }

    // Snapshot file -> root-token map; same straddle gate as root tokens.
    // No UFS rules: skip cloud download.
    std::unordered_map<std::string, std::string> fileTokenSnapshot;
    bool needsDiskLoad = false;
    {
        SetRpcCrashContext("GetChangelist:file-token-cache", "Cloud.GetAppFileChangelist#1", appId);
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        auto it = g_fileTokens.find(appKey);
        if (it != g_fileTokens.end()) {
            fileTokenSnapshot = it->second;
        } else {
            needsDiskLoad = true;
        }
    }
    if (needsDiskLoad) {
        SetRpcCrashContext("GetChangelist:file-token-disk", "Cloud.GetAppFileChangelist#1", appId);
        bool bootstrapActiveBefore = AutoCloudBootstrap::IsActive(accountId, appId);
        auto loaded = appHasUfsRules
            ? CloudStorage::LoadFileTokens(accountId, appId)
            : LocalMetadataStore::LoadFileTokens(accountId, appId);
        bool bootstrapActiveAfter = AutoCloudBootstrap::IsActive(accountId, appId);
        bool bootstrapTouchedLoad = bootstrapActiveBefore || bootstrapActiveAfter;
        std::lock_guard<std::mutex> lock(g_fileTokensMutex);
        auto it = g_fileTokens.find(appKey);
        if (it != g_fileTokens.end()) {
            fileTokenSnapshot = it->second;
        } else if (bootstrapTouchedLoad) {
            if (!loaded.empty()) {
                fileTokenSnapshot = loaded;
            }
            LOG("[NS-CL] Skipping file-token cache-write for account %u app %u "
                "-- bootstrap worker was active during disk read", accountId, appId);
        } else if (!loaded.empty()) {
            g_fileTokens[appKey] = std::move(loaded);
            LOG("[NS-CL] Loaded %zu file-token mappings for account %u app %u",
                g_fileTokens[appKey].size(), accountId, appId);
            fileTokenSnapshot = g_fileTokens[appKey];
        }
    }

    // Default token: prefer %GameInstall%, else lexicographically smallest.
    std::string defaultToken;
    if (!rootTokens.empty()) {
        if (rootTokens.count("%GameInstall%"))
            defaultToken = "%GameInstall%";
        else {
            std::vector<std::string> sorted(rootTokens.begin(), rootTokens.end());
            std::sort(sorted.begin(), sorted.end());
            defaultToken = sorted.front();
        }
    }


    struct PreparedFile {
        std::string leaf;
        uint32_t prefixIdx;
        const LocalStorage::FileEntry* entry;
    };
    std::vector<PreparedFile> prepared;

    std::vector<RemotecacheCandidate> remotecacheCandidates;
    remotecacheCandidates.reserve(files.size());

    SetRpcCrashContext("GetChangelist:prepare-files", "Cloud.GetAppFileChangelist#1", appId);
    for (auto& fe : files) {
        // split filename into directory prefix + leaf
        size_t lastSlash = fe.filename.rfind('/');
        std::string dirPrefix, leaf;
        if (lastSlash != std::string::npos) {
            dirPrefix = fe.filename.substr(0, lastSlash + 1);
            leaf = fe.filename.substr(lastSlash + 1);
        } else {
            leaf = fe.filename;
        }

        std::string fileToken;
        auto ftIt = fileTokenSnapshot.find(fe.filename);
        bool hasRecordedFileToken = ftIt != fileTokenSnapshot.end();
        if (hasRecordedFileToken) fileToken = ftIt->second;
        if (!hasRecordedFileToken) {
            fileToken = defaultToken;
            LOG("[NS-CL]   file: %s has no recorded token, using default '%s'",
                fe.filename.c_str(), fileToken.c_str());
        }

        std::string fullPrefix = fileToken + dirPrefix;

        uint32_t prefixIdx;
        auto it = prefixMap.find(fullPrefix);
        if (it != prefixMap.end()) {
            prefixIdx = it->second;
        } else {
            prefixIdx = (uint32_t)prefixList.size();
            prefixMap[fullPrefix] = prefixIdx;
            prefixList.push_back(fullPrefix);
        }

        prepared.push_back({leaf, prefixIdx, &fe});
        remotecacheCandidates.push_back(
            { fe.filename, fileToken, fe.sha, fe.timestamp, fe.rawSize });
        LOG("[NS-CL]   file: %s (prefix[%u]=%s, size=%llu, ts=%llu)",
            fe.filename.c_str(), prefixIdx, fullPrefix.c_str(), fe.rawSize, fe.timestamp);
    }

    // Don't pre-seed remotecache.vdf; let Steam manage it via GetChangelist diffs.
    // Pre-seeding caused conflicts (Steam interpreted it as "local changed").

    SetRpcCrashContext("GetChangelist:write-response", "Cloud.GetAppFileChangelist#1", appId);
    PB::Writer body;
    body.WriteVarint(1, serverChangeNumber);                     // current_change_number
    body.WriteVarint(3, responseIsDelta ? 1u : 0u);              // is_only_delta

    // file entries (field 2, repeated)
    for (auto& pf : prepared) {
        PB::Writer fileSub;
        fileSub.WriteString(1, pf.leaf);                        // file_name (leaf only)
        if (!pf.entry->sha.empty())
            fileSub.WriteBytes(2, pf.entry->sha.data(), pf.entry->sha.size()); // sha_file
        fileSub.WriteVarint(3, pf.entry->timestamp);            // time_stamp
        fileSub.WriteVarint(4, ClampFileSizeToUint32(pf.entry->rawSize,
                                                     "AppFileInfo.raw_file_size",
                                                     appId, pf.entry->filename));
        // persist_state: 0=Persisted, 2=Deleted; platforms_to_sync: 0xFFFFFFFF=all
        uint32_t persistState = pf.entry->deleted ? 2u : pf.entry->persistState;
        uint32_t platforms = pf.entry->platformsToSync;
        auto cfeIt = cloudFileEntries.find(pf.entry->filename);
        if (cfeIt != cloudFileEntries.end()) {
            if (!pf.entry->deleted) persistState = cfeIt->second.persistState;
            platforms = cfeIt->second.platformsToSync;
        }
        fileSub.WriteVarint(5, persistState);                    // persist_state
        fileSub.WriteVarint(6, platforms);                       // platforms_to_sync
        fileSub.WriteVarint(7, pf.prefixIdx);                    // path_prefix_index
        fileSub.WriteVarint(8, 0);                              // machine_name_index
        body.WriteSubmessage(2, fileSub);
    }

    // path_prefixes (field 4, repeated)
    for (auto& p : prefixList) {
        body.WriteString(4, p);
    }

    // machine_names (field 5, repeated)
    body.WriteString(5, machineName);

    // app_buildid_hwm (field 6) - not critical, set to 0
    body.WriteVarint(6, appBuildIdHwm);

    LOG("[NS-CL] Response: %zu files, %zu prefixes, CN=%llu",
        prepared.size(), prefixList.size(), serverChangeNumber);


#ifdef DEBUG_HEX_DUMP
    {
        auto& ourData = body.Data();
        LOG("[NS-CL-HEX] Our changelist response: %zu bytes", ourData.size());
        for (size_t off = 0; off < ourData.size(); off += 32) {
            char hexLine[200];
            int pos = 0;
            size_t end = (off + 32 < ourData.size()) ? off + 32 : ourData.size();
            for (size_t i = off; i < end; i++) {
                pos += snprintf(hexLine + pos, sizeof(hexLine) - pos, "%02X ", ourData[i]);
            }
            LOG("[NS-CL-HEX] offset=%04X: %s", (unsigned)off, hexLine);
        }
    }
#endif

    return body;
}

// Binary KV reader/writer for UserGameStats merge
enum BkvType : uint8_t {
    BKV_SECTION   = 0x00,
    BKV_STRING    = 0x01,
    BKV_INT       = 0x02,
    BKV_FLOAT     = 0x03,
    BKV_UINT64    = 0x07,
    BKV_END       = 0x08,
    BKV_INT64     = 0x0A,
};

struct BkvNode {
    BkvType type;
    std::string name;
    // value storage (union-like, depends on type)
    uint32_t intVal = 0;
    float floatVal = 0.0f;
    uint64_t uint64Val = 0;
    int64_t int64Val = 0;
    std::string strVal;
    std::vector<BkvNode> children; // for BKV_SECTION
};

static constexpr int BKV_MAX_DEPTH = 128;
static constexpr size_t BKV_MAX_NODES = 100000;

static bool BkvRead(const uint8_t* data, size_t len, size_t& pos, std::vector<BkvNode>& out, int depth, size_t& totalNodes) {
    if (depth > BKV_MAX_DEPTH) {
        LOG("[Stats] BKV nesting too deep (%d), aborting parse", depth);
        return false;
    }
    while (pos < len) {
        uint8_t tag = data[pos++];
        if (tag == BKV_END)
            return true;

        BkvNode node;
        node.type = static_cast<BkvType>(tag);

        // read null-terminated name
        const char* nameStart = reinterpret_cast<const char*>(data + pos);
        size_t nameEnd = pos;
        while (nameEnd < len && data[nameEnd] != 0) nameEnd++;
        if (nameEnd >= len) return false;
        node.name.assign(nameStart, nameEnd - pos);
        pos = nameEnd + 1;

        switch (node.type) {
        case BKV_SECTION:
            if (!BkvRead(data, len, pos, node.children, depth + 1, totalNodes))
                return false;
            break;
        case BKV_STRING: {
            const char* s = reinterpret_cast<const char*>(data + pos);
            size_t end = pos;
            while (end < len && data[end] != 0) end++;
            if (end >= len) return false;
            node.strVal.assign(s, end - pos);
            pos = end + 1;
            break;
        }
        case BKV_INT:
        case BKV_FLOAT:
            if (pos + 4 > len) return false;
            if (node.type == BKV_INT)
                memcpy(&node.intVal, data + pos, 4);
            else
                memcpy(&node.floatVal, data + pos, 4);
            pos += 4;
            break;
        case BKV_UINT64:
            if (pos + 8 > len) return false;
            memcpy(&node.uint64Val, data + pos, 8);
            pos += 8;
            break;
        case BKV_INT64:
            if (pos + 8 > len) return false;
            memcpy(&node.int64Val, data + pos, 8);
            pos += 8;
            break;
        default:
            LOG("[Stats] Unknown BKV tag 0x%02X at offset %zu", tag, pos - 1);
            return false;
        }
        if (++totalNodes > BKV_MAX_NODES) {
            LOG("[Stats] BKV node limit exceeded (%zu), aborting parse", totalNodes);
            return false;
        }
        out.push_back(std::move(node));
    }
    return depth == 0;
}

static void BkvWrite(const std::vector<BkvNode>& nodes, std::vector<uint8_t>& out) {
    for (auto& n : nodes) {
        out.push_back(static_cast<uint8_t>(n.type));
        out.insert(out.end(), n.name.begin(), n.name.end());
        out.push_back(0);

        switch (n.type) {
        case BKV_SECTION:
            BkvWrite(n.children, out);
            out.push_back(BKV_END);
            break;
        case BKV_STRING:
            out.insert(out.end(), n.strVal.begin(), n.strVal.end());
            out.push_back(0);
            break;
        case BKV_INT:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.intVal),
                       reinterpret_cast<const uint8_t*>(&n.intVal) + 4);
            break;
        case BKV_FLOAT:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.floatVal),
                       reinterpret_cast<const uint8_t*>(&n.floatVal) + 4);
            break;
        case BKV_UINT64:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.uint64Val),
                       reinterpret_cast<const uint8_t*>(&n.uint64Val) + 8);
            break;
        case BKV_INT64:
            out.insert(out.end(), reinterpret_cast<const uint8_t*>(&n.int64Val),
                       reinterpret_cast<const uint8_t*>(&n.int64Val) + 8);
            break;
        default:
            break;
        }
    }
}

static BkvNode* BkvFind(std::vector<BkvNode>& nodes, const std::string& name) {
    for (auto& n : nodes)
        if (n.name == name) return &n;
    return nullptr;
}

// Merge cloud stats into local stats (monotonic: more achievements/stats wins).
// Returns merged node tree ready to write.
static std::vector<BkvNode> MergeStats(
    std::vector<BkvNode>& local, std::vector<BkvNode>& cloud)
{
    // Top level should be a single "cache" section in each
    BkvNode* localCache = BkvFind(local, "cache");
    BkvNode* cloudCache = BkvFind(cloud, "cache");
    if (!localCache || !cloudCache) {
        if (cloudCache) return std::move(cloud);
        return std::move(local);
    }

    // Walk cloud stat sections and merge into local
    for (auto& cloudStat : cloudCache->children) {
        if (cloudStat.type != BKV_SECTION) continue;
        // skip non-stat sections (crc, PendingChanges are INT not SECTION)

        BkvNode* localStat = BkvFind(localCache->children, cloudStat.name);
        if (!localStat) {
            // stat exists in cloud but not locally - take it
            localCache->children.push_back(cloudStat);
            continue;
        }

        BkvNode* localData = BkvFind(localStat->children, "data");
        BkvNode* cloudData = BkvFind(cloudStat.children, "data");
        if (!localData || !cloudData) continue;

        BkvNode* cloudAchTimes = BkvFind(cloudStat.children, "AchievementTimes");
        BkvNode* localAchTimes = BkvFind(localStat->children, "AchievementTimes");

        if (cloudAchTimes || localAchTimes) {
            // Achievement bitfield OR; intVal only valid when type==BKV_INT.
            if (localData->type != BKV_INT || cloudData->type != BKV_INT) {
                LOG("[MergeStats] skipping achievement OR for %s: type mismatch "
                    "(local=%d cloud=%d)", cloudStat.name.c_str(),
                    (int)localData->type, (int)cloudData->type);
                continue;
            }
            localData->intVal |= cloudData->intVal;

            // Create AchievementTimes section if missing
            if (!localAchTimes) {
                localStat->children.push_back(BkvNode{BKV_SECTION, "AchievementTimes"});
                localAchTimes = &localStat->children.back();
            }

            // Merge timestamps: for each bit index, keep earliest nonzero
            if (cloudAchTimes) {
                for (auto& ct : cloudAchTimes->children) {
                    if (ct.type != BKV_INT) continue;
                    BkvNode* lt = BkvFind(localAchTimes->children, ct.name);
                    if (!lt) {
                        localAchTimes->children.push_back(ct);
                    } else if (ct.intVal != 0 && (lt->intVal == 0 || ct.intVal < lt->intVal)) {
                        lt->intVal = ct.intVal;
                    }
                }
            }
        } else {
            // Regular stat: take max
            if (localData->type == BKV_INT && cloudData->type == BKV_INT) {
                if (cloudData->intVal > localData->intVal)
                    localData->intVal = cloudData->intVal;
            } else if (localData->type == BKV_FLOAT && cloudData->type == BKV_FLOAT) {
                if (cloudData->floatVal > localData->floatVal)
                    localData->floatVal = cloudData->floatVal;
            } else if (localData->type == BKV_UINT64 && cloudData->type == BKV_UINT64) {
                if (cloudData->uint64Val > localData->uint64Val)
                    localData->uint64Val = cloudData->uint64Val;
            } else if (localData->type == BKV_INT64 && cloudData->type == BKV_INT64) {
                if (cloudData->int64Val > localData->int64Val)
                    localData->int64Val = cloudData->int64Val;
            }
        }
    }

    // Recalculate CRC: set to 0 so Steam recalculates on load
    BkvNode* crc = BkvFind(localCache->children, "crc");
    if (crc && crc->type == BKV_INT)
        crc->intVal = 0;

    return std::move(local);
}

static bool HasNonZeroStatsData(const std::vector<BkvNode>& nodes) {
    for (const auto& n : nodes) {
        if (n.name == "data") {
            if (n.type == BKV_INT && n.intVal != 0) return true;
            if (n.type == BKV_FLOAT && n.floatVal != 0.0f) return true;
            if (n.type == BKV_UINT64 && n.uint64Val != 0) return true;
            if (n.type == BKV_INT64 && n.int64Val != 0) return true;
        }
        if (!n.children.empty() && HasNonZeroStatsData(n.children)) return true;
    }
    return false;
}

// Merge cloud stats into the local stats file on disk.
static bool MergeStatsFile(uint32_t appId, uint32_t accountId,
                           const std::vector<uint8_t>& cloudData)
{
#ifdef _WIN32
    std::string statsPath = GetSteamPath() + "appcache\\stats\\UserGameStats_"
        + std::to_string(accountId) + "_" + std::to_string(appId) + ".bin";
#else
    std::string statsPath = GetSteamPath() + "appcache/stats/UserGameStats_"
        + std::to_string(accountId) + "_" + std::to_string(appId) + ".bin";
#endif

    // Parse cloud data
    size_t cloudPos = 0;
    size_t cloudNodeCount = 0;
    std::vector<BkvNode> cloudNodes;
    if (!BkvRead(cloudData.data(), cloudData.size(), cloudPos, cloudNodes, 0, cloudNodeCount)) {
        LOG("[Stats] Failed to parse cloud stats for app %u, skipping merge", appId);
        return false;
    }

    std::ifstream localFile(FileUtil::Utf8ToPath(statsPath), std::ios::binary | std::ios::ate);
    if (!localFile.is_open()) {
        if (!HasNonZeroStatsData(cloudNodes)) {
            LOG("[Stats] No local stats and cloud has no positive stats for app %u, skipping restore", appId);
            return false;
        }
        // No local file: rewrite parsed cloud to strip junk.
        std::vector<uint8_t> outBuf;
        BkvWrite(cloudNodes, outBuf);
        outBuf.push_back(BKV_END);
        if (!FileUtil::AtomicWriteBinary(statsPath, outBuf.data(), outBuf.size())) {
            LOG("[Stats] Failed to create stats file for app %u", appId);
            return false;
        }
        LOG("[Stats] No local stats, wrote cloud stats for app %u (%zu bytes)", appId, outBuf.size());
        return true;
    }

    auto localSize = localFile.tellg();
    if (localSize <= 0) {
        localFile.close();
        if (!HasNonZeroStatsData(cloudNodes)) {
            LOG("[Stats] Local stats empty and cloud has no positive stats for app %u, skipping restore", appId);
            return false;
        }
        std::vector<uint8_t> outBuf;
        BkvWrite(cloudNodes, outBuf);
        outBuf.push_back(BKV_END);
        if (!FileUtil::AtomicWriteBinary(statsPath, outBuf.data(), outBuf.size()))
            return false;
        LOG("[Stats] Local stats empty, wrote cloud stats for app %u (%zu bytes)", appId, outBuf.size());
        return true;
    }

    std::vector<uint8_t> localData(static_cast<size_t>(localSize));
    localFile.seekg(0);
    localFile.read(reinterpret_cast<char*>(localData.data()), localSize);
    auto localGcount = localFile.gcount();
    bool localReadOk = !localFile.fail() &&
                       static_cast<std::streamsize>(localGcount) == localSize;
    localFile.close();

    if (!localReadOk) {
        LOG("[Stats] short read on local stats for app %u (expected %lld, got %lld), skipping restore",
            appId, (long long)localSize, (long long)localGcount);
        return false;
    }

    // Parse local data
    size_t localPos = 0;
    size_t localNodeCount = 0;
    std::vector<BkvNode> localNodes;
    if (!BkvRead(localData.data(), localData.size(), localPos, localNodes, 0, localNodeCount)) {
        LOG("[Stats] Failed to parse local stats for app %u, skipping restore", appId);
        return false;
    }

    // Merge
    auto merged = MergeStats(localNodes, cloudNodes);

    // Serialize
    std::vector<uint8_t> outBuf;
    BkvWrite(merged, outBuf);
    outBuf.push_back(BKV_END);

    if (!FileUtil::AtomicWriteBinary(statsPath, outBuf.data(), outBuf.size())) {
        LOG("[Stats] Failed to write merged stats for app %u", appId);
        return false;
    }

    LOG("[Stats] Merged stats for app %u (local=%zu cloud=%zu merged=%zu bytes)",
        appId, localData.size(), cloudData.size(), outBuf.size());
    return true;
}

// SignalAppLaunchIntent: return pending_remote_operations.
// Also pre-restores cloud files to game folders so Steam's sync finds them on disk.
RpcResult HandleLaunchIntent(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    LOG("[NS] SignalAppLaunchIntent app=%u", appId);

    RecordLaunchTime(appId);
    uint32_t accountId = 0;
    if (!RequireAccountId("SignalAppLaunchIntent", appId, accountId)) {
        PB::Writer body;
        return body;
    }
    EnsureAppQuotaInjected(accountId, appId, nullptr);
    EnsureSaveFilesInjected(appId);

    // Fetch cloud state (SHAs for cache-first restore + session management).
    CloudStorage::StateFetchResult stateResult;
    if (CloudStorage::IsCloudActive()) {
        stateResult = CloudStorage::FetchCloudState(accountId, appId);
    }

    ConsumeConflictLocalChoice(appId);

    if (CloudStorage::IsCloudActive()) {
        uint32_t asyncAcct = accountId;
        uint32_t asyncApp = appId;
        std::thread([asyncAcct, asyncApp] {
            CloudStorage::InflightSyncScope guard;
            if (!guard.entered) return;
            RestoreAppMetadata(asyncAcct, asyncApp);
        }).detach();
    }

    // Launch intent should not block on per-file bootstrap existence checks.
    // GetAppFileChangelist already tolerates bootstrap running in the background.
    AutoCloudBootstrap::Bootstrap(accountId, appId, /*wait=*/false);

    PendingOpsJournal::Entry currentSession;
    currentSession.machineName = GetMachineName();
    currentSession.timeLastUpdated = static_cast<uint32_t>(time(nullptr));
    bool ignorePendingOperations = false;
    for (const auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::Varint) currentSession.clientId = f.varintVal;
        if (f.fieldNum == 3 && f.wireType == PB::LengthDelimited) {
            currentSession.machineName.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
        }
        if (f.fieldNum == 4 && f.wireType == PB::Varint) ignorePendingOperations = f.varintVal != 0;
        if (f.fieldNum == 5 && f.wireType == PB::Varint) currentSession.osType = static_cast<uint32_t>(f.varintVal);
        if (f.fieldNum == 6 && f.wireType == PB::Varint) currentSession.deviceType = static_cast<uint32_t>(f.varintVal);
    }

    // Cloud session management -- reuse stateResult from above (already fetched).
    PB::Writer body;
    bool sessionConflict = false;
    if (stateResult.status == CloudStorage::StateFetchStatus::Ok) {
        // Sync mutex: serialize state RMW to prevent interleaved publishes.
        auto syncMtx = CloudStorage::AcquireAppSyncMutex(accountId, appId);
        std::lock_guard<std::mutex> syncLock(*syncMtx);

        auto& state = stateResult.state;
        uint64_t now = static_cast<uint64_t>(time(nullptr));

        if (state.hasActiveSession() &&
            state.session.clientId != currentSession.clientId) {
            // Another machine holds session lock; EResult=108 triggers conflict UI.
            LOG("[NS] LaunchIntent app=%u: another session active (machine=%s, client=%llu, age=%llus)",
                appId, state.session.machineName.c_str(),
                state.session.clientId,
                now - state.session.timeLastUpdated);
            PB::Writer op;
            op.WriteVarint(1, 1); // operation = AppSessionActive
            op.WriteString(2, state.session.machineName);
            op.WriteVarint(3, state.session.clientId);
            op.WriteVarint(4, static_cast<uint32_t>(state.session.timeLastUpdated));
            body.WriteSubmessage(1, op);

            if (!ignorePendingOperations) {
                // Steam expects EResult=108 to trigger the conflict UI.
                sessionConflict = true;
            } else {
                // "Play anyway" -- override stale session.
                state.session.clientId = currentSession.clientId;
                state.session.machineName = currentSession.machineName;
                state.session.timeLastUpdated = now;
                state.session.operation = "active";
                if (!CloudStorage::PublishCloudState(accountId, appId, state, stateResult.etag)) {
                    // Retry once without etag.
                    if (!CloudStorage::PublishCloudState(accountId, appId, state)) {
                        LOG("[NS] LaunchIntent app=%u: session override publish failed after retry", appId);
                    }
                }
                LOG("[NS] LaunchIntent app=%u: forced session override (machine=%s, client=%llu)",
                    appId, currentSession.machineName.c_str(), currentSession.clientId);
            }
        } else {
            state.session.clientId = currentSession.clientId;
            state.session.machineName = currentSession.machineName;
            state.session.timeLastUpdated = now;
            state.session.operation = "active";
            if (!CloudStorage::PublishCloudState(accountId, appId, state, stateResult.etag)) {
                // Retry without etag (stale from racing ReleaseCloudSession).
                LOG("[NS] LaunchIntent app=%u: session acquire publish failed, retrying without etag", appId);
                auto freshResult = CloudStorage::FetchCloudState(accountId, appId);
                if (freshResult.status == CloudStorage::StateFetchStatus::Ok) {
                    auto& freshState = freshResult.state;
                    if (freshState.hasActiveSession() &&
                        freshState.session.clientId != currentSession.clientId) {
                        // Another machine acquired the session in the window.
                        LOG("[NS] LaunchIntent app=%u: another machine acquired session during retry", appId);
                        sessionConflict = !ignorePendingOperations;
                    } else {
                        freshState.session = state.session;
                        if (!CloudStorage::PublishCloudState(accountId, appId, freshState)) {
                            LOG("[NS] LaunchIntent app=%u: session acquire retry also failed", appId);
                        }
                    }
                }
            }
            LOG("[NS] LaunchIntent app=%u: acquired session (machine=%s, client=%llu)",
                appId, currentSession.machineName.c_str(), currentSession.clientId);
        }
    }

    auto pending = PendingOpsJournal::RecordLaunchIntent(
        accountId, appId, currentSession, ignorePendingOperations);

    // Launch intent clears pending-upload state.
    PendingOpsJournal::ClearUploadPending(accountId, appId);

    for (const auto& entry : pending) {
        PB::Writer op;
        op.WriteVarint(1, static_cast<uint32_t>(entry.operation));
        if (!entry.machineName.empty()) op.WriteString(2, entry.machineName);
        if (entry.clientId != 0) op.WriteVarint(3, entry.clientId);
        if (entry.timeLastUpdated != 0) op.WriteVarint(4, entry.timeLastUpdated);
        if (entry.osType != 0) op.WriteVarint(5, entry.osType);
        if (entry.deviceType != 0) op.WriteVarint(6, entry.deviceType);
        body.WriteSubmessage(1, op);
    }
    return RpcResult(std::move(body), sessionConflict ? kEResultDisabled : kEResultOK);
}

RpcResult HandleSuspendSession(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    LOG("[NS] SuspendAppSession app=%u", appId);

    uint32_t accountId = 0;
    if (!RequireAccountId("SuspendAppSession", appId, accountId)) {
        return PB::Writer();
    }

    PendingOpsJournal::Entry session;
    session.operation = PendingOpsJournal::Operation::AppSessionSuspended;
    session.machineName = GetMachineName();
    session.timeLastUpdated = static_cast<uint32_t>(time(nullptr));
    bool cloudSyncCompleted = false;
    for (const auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::Varint) session.clientId = f.varintVal;
        if (f.fieldNum == 3 && f.wireType == PB::LengthDelimited) {
            session.machineName.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
        }
        if (f.fieldNum == 4 && f.wireType == PB::Varint) cloudSyncCompleted = f.varintVal != 0;
    }

    PendingOpsJournal::RecordSuspendState(accountId, appId, session, cloudSyncCompleted);
    return PB::Writer();
}

RpcResult HandleResumeSession(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    LOG("[NS] ResumeAppSession app=%u", appId);

    uint32_t accountId = 0;
    if (!RequireAccountId("ResumeAppSession", appId, accountId)) {
        return PB::Writer();
    }

    uint64_t clientId = 0;
    for (const auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::Varint) {
            clientId = f.varintVal;
        }
    }

    PendingOpsJournal::RecordResumeState(accountId, appId, clientId);
    return PB::Writer();
}

// ClientGetAppQuotaUsage
RpcResult HandleQuotaUsage(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint32_t accountId = 0;
    if (!RequireAccountId("ClientGetAppQuotaUsage", appId, accountId)) {
        PB::Writer body;
        body.WriteVarint(1, 0);
        body.WriteVarint(2, 0);
        body.WriteVarint(3, 10000);
        body.WriteVarint(4, 1073741824ULL);
        return body;
    }

    AutoCloudBootstrap::Bootstrap(accountId, appId);

    // count from manifest, not blob cache -- blobs may be orphaned/stale
    auto manifest = CloudStorage::LoadLocalManifest(accountId, appId);
    size_t fileCount = 0;
    uint64_t totalBytes = 0;
    for (const auto& [name, entry] : manifest) {
        if (IsReservedBlobFilename(name)) continue;
        ++fileCount;
        totalBytes += entry.size;
    }

    // Report quota from PICS KV injection.
    uint64_t maxBytes = kFallbackQuotaBytes;
    uint32_t maxFiles = kFallbackMaxFiles;
    uint64_t kvQuota = 0;
    uint32_t kvFiles = 0;
    if (SteamKvInjector::IsReady() &&
        SteamKvInjector::ReadAppQuota(appId, kvQuota, kvFiles) &&
        kvQuota > 0 && kvFiles > 0) {
        maxBytes = kvQuota;
        maxFiles = kvFiles;
    }

    PB::Writer body;
    body.WriteVarint(1, ClampFileSizeToUint32((uint64_t)fileCount,
                                              "QuotaUsage.existing_files",
                                              appId, std::string{}));  // existing_files
    body.WriteVarint(2, totalBytes);                 // existing_bytes
    body.WriteVarint(3, maxFiles);                   // max_num_files
    body.WriteVarint(4, maxBytes);                   // max_num_bytes

    LOG("[NS] QuotaUsage app=%u files=%zu bytes=%llu (max %u/%llu)",
        appId, fileCount, totalBytes, maxFiles, (unsigned long long)maxBytes);
    return body;
}

// BeginAppUploadBatch
RpcResult HandleBeginBatch(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint64_t batchId = BatchTracker_NextId();
    uint32_t accountId = 0;
    if (!RequireAccountId("BeginAppUploadBatch", appId, accountId)) {
        // Fail early: error skips CompleteBatch, preventing orphaned local blobs.
        return RpcResult(PB::Writer(), kEResultFail);
    }

    uint64_t currentCN = LocalStorage::GetChangeNumber(accountId, appId);
    uint64_t assignedCN = currentCN + 1;
    uint64_t appBuildId = 0;
    PrepareBatchCanonicalTokens(accountId, appId);
    PendingOpsJournal::RecordUploadBatchStart(accountId, appId);

    int uploadCount = 0, deleteCount = 0;
    for (auto& f : reqBody) {
        if (f.fieldNum == 3 && f.wireType == PB::LengthDelimited) {
            std::string name(reinterpret_cast<const char*>(f.data), f.dataLen);
            LOG("[NS-BATCH]   upload: %s", SanitizeForLog(name).c_str());
            TryCaptureRootToken(accountId, appId,
                CanonicalizeUploadRootToken(accountId, appId, StripRootToken(name), ExtractRootToken(name)));
            ++uploadCount;
        }
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited) {
            std::string name(reinterpret_cast<const char*>(f.data), f.dataLen);
            LOG("[NS-BATCH]   delete: %s", SanitizeForLog(name).c_str());
            TryCaptureRootToken(accountId, appId,
                CanonicalizeUploadRootToken(accountId, appId, StripRootToken(name), ExtractRootToken(name)));
            ++deleteCount;
        }
        if (f.fieldNum == 6 && f.wireType == PB::Varint) appBuildId = f.varintVal;
    }

    BatchTracker_Begin(accountId, appId, batchId, assignedCN, appBuildId);

    PB::Writer body = CloudRpcUtils::BuildBeginBatchResponseBody(batchId, assignedCN);

    LOG("[NS] BeginBatch app=%u batchId=%llu assignedCN=%llu appBuildId=%llu uploads=%d deletes=%d",
        appId, batchId, assignedCN, (unsigned long long)appBuildId, uploadCount, deleteCount);
    return body;
}

// ClientBeginFileUpload
// Tell Steam to PUT the file to our local HTTP server.
RpcResult HandleBeginFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    // extract request fields
    uint64_t fileSize = 0, rawFileSize = 0;
    std::string filename;
    std::vector<uint8_t> fileSha;
    uint64_t timestamp = 0;
    uint32_t platformsToSync = 0xFFFFFFFFu;

    for (auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::Varint) fileSize = f.varintVal;
        if (f.fieldNum == 3 && f.wireType == PB::Varint) rawFileSize = f.varintVal;
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited)
            fileSha.assign(f.data, f.data + f.dataLen);
        if (f.fieldNum == 5 && f.wireType == PB::Varint) timestamp = f.varintVal;
        if (f.fieldNum == 6 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
        if (f.fieldNum == 7 && f.wireType == PB::Varint) platformsToSync = (uint32_t)f.varintVal;
    }

    uint16_t port = HttpServer::GetPort();
    uint32_t accountId = 0;
    if (!RequireAccountId("ClientBeginFileUpload", appId, accountId)) {
        return PB::Writer();
    }
    std::string urlHost = "127.0.0.1:" + std::to_string(port);
    std::string rootToken = ExtractRootToken(filename);
    std::string cleanName = StripRootToken(filename);
    if (cleanName.empty()) {
        LOG("[NS-UP] BeginFileUpload app=%u REJECTED: empty filename after token strip", appId);
        return PB::Writer();
    }
    PrepareBatchCanonicalTokens(accountId, appId);
    rootToken = CanonicalizeUploadRootToken(accountId, appId, cleanName, rootToken);

    std::string urlPath = "/upload/" + std::to_string(accountId) + "/" + std::to_string(appId)
        + "/" + HttpUtil::UrlEncode(cleanName, true);

    TryCaptureRootToken(accountId, appId, rootToken);
    BatchTracker_RecordFilePlatforms(accountId, appId, cleanName, platformsToSync);

    LOG("[NS-UP] BeginFileUpload app=%u file=%s (clean=%s) size=%llu rawSize=%llu platforms=0x%08X -> %s%s",
        appId, filename.c_str(), cleanName.c_str(), fileSize, rawFileSize, platformsToSync, urlHost.c_str(), urlPath.c_str());

    uint64_t blockLen = fileSize > 0 ? fileSize : rawFileSize;

    // build block request submessage (ClientCloudFileUploadBlockDetails)
    PB::Writer blockReq;
    blockReq.WriteString(1, urlHost);                // url_host
    blockReq.WriteString(2, urlPath);                // url_path
    blockReq.WriteVarint(3, 0);                      // use_https = false
    blockReq.WriteVarint(4, 4);                      // http_method = PUT (EHTTPMethod: 4)
    // no request_headers needed for our simple server
    blockReq.WriteVarint(6, 0);                      // block_offset = 0
    blockReq.WriteVarint(7, blockLen);               // block_length

    PB::Writer body;
    body.WriteVarint(1, 0);                          // encrypt_file = false
    body.WriteSubmessage(2, blockReq);               // block_requests (repeated, just 1)

    // hex dump response for debugging upload failures
#ifdef DEBUG_HEX_DUMP
    {
        auto& d = body.Data();
        std::string hex;
        for (size_t i = 0; i < d.size(); i++) {
            char tmp[4]; snprintf(tmp, sizeof(tmp), "%02X ", d[i]);
            hex += tmp;
        }
        LOG("[NS-UP] Response hex (%zu bytes): %s", d.size(), hex.c_str());
        auto& bd = blockReq.Data();
        std::string bhex;
        for (size_t i = 0; i < bd.size(); i++) {
            char tmp[4]; snprintf(tmp, sizeof(tmp), "%02X ", bd[i]);
            bhex += tmp;
        }
        LOG("[NS-UP] BlockReq hex (%zu bytes): %s", bd.size(), bhex.c_str());
    }
#endif

    return body;
}

// ClientCommitFileUpload
// The file has been PUT to our HTTP server. Update local metadata.
RpcResult HandleCommitFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    bool transferSucceeded = false;
    std::string filename;

    for (auto& f : reqBody) {
        if (f.fieldNum == 1 && f.wireType == PB::Varint) transferSucceeded = (f.varintVal != 0);
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
    }

    LOG("[NS-UP] CommitFileUpload app=%u file=%s succeeded=%d",
        appId, filename.c_str(), transferSucceeded);

    std::string cleanName = StripRootToken(filename);

    if (cleanName.empty()) {
        LOG("[NS-UP] CommitFileUpload app=%u REJECTED: empty filename after token strip",
            appId);
        PB::Writer body;
        body.WriteVarint(1, 0);  // file_committed = false
        return body;
    }

    // Reject reserved blob names: internal metadata and any `.cloudredirect`
    // file/segment belong outside the per-app save namespace.
    if (IsReservedBlobFilename(cleanName)) {
        LOG("[NS-UP] CommitFileUpload app=%u REJECTED: '%s' is a reserved /blobs/ name",
            appId, cleanName.c_str());
        // Defer blob cleanup: accountId is not yet known at this point.
        // The second check after RequireAccountId below handles the actual
        // cleanup and rejection.
    }
    
    bool committed = false;
    uint32_t accountId = 0;
    if (!RequireAccountId("ClientCommitFileUpload", appId, accountId)) {
        PB::Writer body;
        body.WriteVarint(1, 0);
        return body;
    }

    if (IsReservedBlobFilename(cleanName)) {
        if (HttpServer::HasBlob(accountId, appId, cleanName)) {
            HttpServer::DeleteBlob(accountId, appId, cleanName);
        }
        PB::Writer body;
        body.WriteVarint(1, 0);  // file_committed = false
        return body;
    }

    std::string rootToken = ExtractRootToken(filename);
    PrepareBatchCanonicalTokens(accountId, appId);
    rootToken = CanonicalizeUploadRootToken(accountId, appId, cleanName, rootToken);

    if (transferSucceeded) {
        if (HttpServer::HasBlob(accountId, appId, cleanName)) {
            committed = true;

            // Trust the localhost PUT (Steam server doesn't re-verify SHA either).
            auto blobData = HttpServer::ReadBlob(accountId, appId, cleanName);
            LOG("[NS-UP]   committed: %s (%zu bytes)", cleanName.c_str(), blobData.size());

            {
                const uint8_t* blobPtr = blobData.empty() ? nullptr : blobData.data();
                uint64_t batchId = BatchTracker_ActiveId(accountId, appId);
                bool isStaged = (batchId != 0);
                bool stored = isStaged
                    ? CloudStorage::StoreBlobStaged(accountId, appId, batchId,
                        cleanName, blobPtr, blobData.size())
                    : CloudStorage::StoreBlob(accountId, appId, cleanName,
                        blobPtr, blobData.size());
                if (!stored) {
                    LOG("[NS-UP]   ERROR: failed to store blob for %s", cleanName.c_str());
                    committed = false;
                    HttpServer::DeleteBlob(accountId, appId, cleanName);
                } else if (!isStaged) {
                    auto entry = LocalStorage::GetFileEntry(accountId, appId, cleanName);
                    if (entry) {
                        CloudStorage::UpdateManifestEntry(accountId, appId, cleanName,
                            entry->sha, entry->timestamp, entry->rawSize);
                    }
                }
            }

            if (committed) {
                if (RecordFileToken(accountId, appId, cleanName, rootToken)) {
                    MarkFileTokensDirty(accountId, appId);
                }
                BatchTracker_RecordUpload(accountId, appId, cleanName);
            }
        } else {
            LOG("[NS-UP]   WARNING: blob not found after PUT for %s (clean=%s)", filename.c_str(), cleanName.c_str());
        }

    } else {
        // Don't delete blobs on transfer failure -- orphans are cleaned at batch completion.
        LOG("[NS-UP]   transfer failed for %s, skipping blob cleanup (concurrent PUT may have succeeded)",
            cleanName.c_str());
    }

    PB::Writer body;
    body.WriteVarint(1, committed ? 1 : 0);          // file_committed
    return body;
}

// CompleteAppUploadBatchBlocking
RpcResult HandleCompleteBatch(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    auto completeInfo = CloudRpcUtils::ParseCompleteBatchRequest(reqBody);

    // Increment CN once per batch; cloud publish detached.
    uint32_t accountId = 0;
    if (!RequireAccountId("CompleteAppUploadBatchBlocking", appId, accountId)) {
        return PB::Writer();
    }

    UploadBatchState batch = BatchTracker_Get(accountId, appId, completeInfo.batchId);
    if (batch.batchId == 0) {
        LOG("[NS] CompleteBatch app=%u requested batch %llu but no active batch exists",
            appId, (unsigned long long)completeInfo.batchId);
        PendingOpsJournal::RecordUploadBatchInterrupted(accountId, appId);
        ClearBatchCanonicalTokens(accountId, appId);
        return PB::Writer();
    }
    if (completeInfo.hasResult && completeInfo.result != 1) {
        LOG("[NS] CompleteBatch app=%u batch=%llu reported Steam upload result %u; refusing CN advance",
            appId, (unsigned long long)batch.batchId, completeInfo.result);
        PendingOpsJournal::RecordUploadBatchInterrupted(accountId, appId);
        BatchTracker_Clear(accountId, appId, batch.batchId);
        ClearBatchCanonicalTokens(accountId, appId);
        ClearFileTokensDirty(accountId, appId);
        return PB::Writer();
    }

    // Drain deferred file-token persists for this app only.
    {
        uint64_t key = MakeAppAccountKey(accountId, appId);
        bool wasDirty = false;
        {
            std::lock_guard<std::mutex> lock(g_fileTokensDirtyMutex);
            wasDirty = g_fileTokensDirtyApps.erase(key) > 0;
        }
        if (wasDirty) {
            PersistFileTokens(accountId, appId);
        }
    }
    std::vector<std::string> uploads(batch.uploads.begin(), batch.uploads.end());
    std::vector<std::string> deletes(batch.deletes.begin(), batch.deletes.end());
    if (!CloudStorage::PromoteStagedBatchForCommit(accountId, appId,
            batch.batchId, uploads, deletes)) {
        LOG("[NS] CompleteBatch app=%u refused CN advance: staged promotion failed",
            appId);
        PendingOpsJournal::RecordUploadBatchInterrupted(accountId, appId);
        BatchTracker_Clear(accountId, appId, batch.batchId);
        ClearFileTokensDirty(accountId, appId);
        ClearBatchCanonicalTokens(accountId, appId);
        return PB::Writer();
    }

    uint64_t newCN = batch.assignedCN;
    {
        // Sync mutex: serialize CN set + state publish.
        auto syncMtx = CloudStorage::AcquireAppSyncMutex(accountId, appId);
        std::lock_guard<std::mutex> syncLock(*syncMtx);

        // Fetch existing cloud state; fall back to local manifest.
        CloudStorage::CloudAppState state;
        bool haveCloudBase = false;
        if (CloudStorage::IsCloudActive()) {
            auto result = CloudStorage::FetchCloudState(accountId, appId);
            if (result.status == CloudStorage::StateFetchStatus::Ok) {
                state = std::move(result.state);
                haveCloudBase = true;
            }
        }
        // If cloud CN is behind local, rebuild file list from manifest (keep session/quota).
        uint64_t localCN = LocalStorage::GetChangeNumber(accountId, appId);
        if (!haveCloudBase || state.cn < localCN) {
            if (haveCloudBase && state.cn < localCN) {
                LOG("[NS] CompleteBatch app %u: cloud CN %llu < local CN %llu, rebuilding file list from local manifest",
                    appId, (unsigned long long)state.cn, (unsigned long long)localCN);
            }
            state.files.clear();
            auto localManifest = CloudStorage::LoadLocalManifest(accountId, appId);
            for (const auto& [name, me] : localManifest) {
                CloudStorage::FileEntry fe;
                fe.sha = me.sha;
                fe.timestamp = me.timestamp;
                fe.size = me.size;
                state.files[name] = std::move(fe);
            }
        }

        for (const auto& filename : deletes)
            state.files.erase(filename);

        for (const auto& filename : uploads) {
            if (IsReservedBlobFilename(filename)) continue;
            auto entry = LocalStorage::GetFileEntry(accountId, appId, filename);
            if (!entry.has_value()) continue;
            CloudStorage::FileEntry fe;
            fe.sha = entry->sha;
            fe.timestamp = entry->timestamp;
            fe.size = entry->rawSize;
            auto ptIt = batch.filePlatforms.find(filename);
            fe.platformsToSync = (ptIt != batch.filePlatforms.end())
                ? ptIt->second : 0xFFFFFFFFu;
            state.files[filename] = std::move(fe);
        }

        state.cn = newCN;
        state.appBuildId = batch.appBuildId;

        LocalStorage::SetChangeNumber(accountId, appId, newCN);
        CloudStorage::Manifest updatedManifest;
        for (const auto& [name, fe] : state.files) {
            CloudStorage::ManifestEntry me;
            me.sha = fe.sha;
            me.timestamp = fe.timestamp;
            me.size = fe.size;
            updatedManifest[name] = std::move(me);
        }
        CloudStorage::SaveManifestLocal(accountId, appId, updatedManifest);
        CloudStorage::SaveManifestSnapshot(accountId, appId, newCN);

        // Synchronous first attempt (must finish before ExitSyncDone).
        // Steam ignores CompleteBatch eresult, so retry async on failure.
        if (!CloudStorage::PublishCloudState(accountId, appId, state)) {
            LOG("[NS] CompleteBatch: state publish failed for app %u; scheduling async retry", appId);
            // Capture file data only; retry re-fetches live state.
            auto filesToMerge = std::make_shared<std::unordered_map<std::string, CloudStorage::FileEntry>>(state.files);
            uint64_t retryCN = state.cn;
            uint64_t retryBuildId = state.appBuildId;
            std::thread([filesToMerge, retryCN, retryBuildId, accountId, appId] {
                CloudStorage::InflightSyncScope guard;
                if (!guard.entered) return;
                constexpr int kMaxRetries = 3;
                constexpr int kBaseDelayMs = 2000;
                for (int attempt = 1; attempt <= kMaxRetries; ++attempt) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(kBaseDelayMs * attempt));
                    // Re-fetch live state under sync mutex to preserve session changes.
                    auto syncMtx = CloudStorage::AcquireAppSyncMutex(accountId, appId);
                    std::lock_guard<std::mutex> lock(*syncMtx);
                    auto result = CloudStorage::FetchCloudState(accountId, appId);
                    if (result.status != CloudStorage::StateFetchStatus::Ok) {
                        // Cloud fetch failed; skip to avoid erasing session lock.
                        LOG("[NS] CompleteBatch: retry %d/%d skipped for app %u: cloud fetch failed",
                            attempt, kMaxRetries, appId);
                        continue;
                    }
                    CloudStorage::CloudAppState retryState = std::move(result.state);
                    // Abort if a newer CN already committed.
                    if (retryState.cn > retryCN) {
                        LOG("[NS] CompleteBatch: retry aborted for app %u: cloud CN %llu > batch CN %llu",
                            appId, retryState.cn, retryCN);
                        return;
                    }
                    retryState.files = *filesToMerge;
                    retryState.cn = retryCN;
                    retryState.appBuildId = retryBuildId;
                    if (CloudStorage::PublishCloudState(accountId, appId, retryState)) {
                        LOG("[NS] CompleteBatch: async retry %d/%d succeeded for app %u",
                            attempt, kMaxRetries, appId);
                        return;
                    }
                    LOG("[NS] CompleteBatch: async retry %d/%d failed for app %u",
                        attempt, kMaxRetries, appId);
                }
                LOG("[NS] CompleteBatch: all retries exhausted for app %u; "
                    "remote state stale until next sync", appId);
            }).detach();
        }
    }

    BatchTracker_Clear(accountId, appId, batch.batchId);
    PendingOpsJournal::RecordUploadBatchEnd(accountId, appId);
    LOG("[NS] CompleteBatch app=%u CN=%llu (state published atomically)", appId, newCN);

    ClearBatchCanonicalTokens(accountId, appId);

    // Fire-and-forget GC after successful commit.
    std::thread([accountId, appId]() {
        CloudStorage::InflightSyncScope guard;
        if (!guard.entered) return;
        CloudStorage::GarbageCollectBlobs(accountId, appId);
    }).detach();

    PB::Writer body; // empty response
    return body;
}

// ClientFileDownload
// Tell Steam to GET the file from our local HTTP server.
RpcResult HandleFileDownload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    std::string filename;
    for (auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
    }

    uint32_t accountId = 0;
    if (!RequireAccountId("ClientFileDownload", appId, accountId)) {
        return PB::Writer();
    }
    uint16_t port = HttpServer::GetPort();
    std::string urlHost = "127.0.0.1:" + std::to_string(port);
    std::string cleanName = StripRootToken(filename);
    if (cleanName.empty()) {
        LOG("[NS-DL] FileDownload app=%u REJECTED: empty filename after token strip", appId);
        return PB::Writer();
    }
    std::string urlPath = "/download/" + std::to_string(accountId) + "/" + std::to_string(appId)
        + "/" + HttpUtil::UrlEncode(cleanName, true);

    uint64_t fileSize = 0;    uint64_t timestamp = 0;
    std::vector<uint8_t> sha;

    auto manifest = CloudStorage::LoadLocalManifest(accountId, appId);
    auto it = manifest.find(cleanName);
    if (it != manifest.end()) {
        fileSize = it->second.size;
        timestamp = it->second.timestamp;
        sha = it->second.sha;
    } else {
        auto entry = LocalStorage::GetFileEntry(accountId, appId, cleanName);
        if (entry) {
            fileSize = entry->rawSize;
            timestamp = entry->timestamp;
            sha = entry->sha;
        } else {
            fileSize = HttpServer::GetBlobSize(accountId, appId, cleanName);
        }
    }

    // If we still have no size, the file likely exists only in the cloud and
    // the local manifest hasn't been populated yet (e.g. an app just migrated
    // from the legacy manifest.dat layout, published at CN=0, so the local
    // sync was skipped). Declaring size=0 makes Steam's download stall/time
    // out. Consult the cloud state, which is authoritative for size/sha, and
    // persist it locally so subsequent lookups are cheap.
    if (fileSize == 0 && sha.empty() && CloudStorage::IsCloudActive()) {
        auto stateResult = CloudStorage::FetchCloudState(accountId, appId);
        if (stateResult.status == CloudStorage::StateFetchStatus::Ok) {
            auto fit = stateResult.state.files.find(cleanName);
            if (fit != stateResult.state.files.end() && fit->second.size > 0) {
                fileSize = fit->second.size;
                timestamp = fit->second.timestamp;
                sha = fit->second.sha;
                CloudStorage::ManifestEntry me;
                me.sha = fit->second.sha;
                me.timestamp = fit->second.timestamp;
                me.size = fit->second.size;
                manifest[cleanName] = std::move(me);
                CloudStorage::SaveManifestLocal(accountId, appId, manifest);
                LOG("[NS-DL] FileDownload app=%u file=%s: resolved size=%llu from cloud state",
                    appId, cleanName.c_str(), (unsigned long long)fileSize);
            }
        }
    }

    LOG("[NS-DL] FileDownload app=%u file=%s (clean=%s) size=%llu -> %s%s",
        appId, filename.c_str(), cleanName.c_str(), fileSize, urlHost.c_str(), urlPath.c_str());

    uint32_t clampedSize = ClampFileSizeToUint32(fileSize,
                                                 "FileDownload_Response.file_size",
                                                 appId, filename);
    PB::Writer body;
    body.WriteVarint(1, appId);
    body.WriteVarint(2, clampedSize);
    body.WriteVarint(3, clampedSize);
    if (!sha.empty())
        body.WriteBytes(4, sha.data(), sha.size());
    body.WriteVarint(5, timestamp);
    body.WriteVarint(6, 0);
    body.WriteString(7, urlHost);
    body.WriteString(8, urlPath);
    body.WriteVarint(9, 0);
    body.WriteVarint(11, 0);

    return body;
}

// ClientDeleteFile
RpcResult HandleDeleteFile(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    std::string filename;
    for (auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
    }

    std::string cleanName = StripRootToken(filename);
    LOG("[NS] DeleteFile app=%u file=%s (clean=%s)", appId, filename.c_str(), cleanName.c_str());

    if (cleanName.empty()) {
        LOG("[NS] DeleteFile app=%u REJECTED: empty filename", appId);
        return PB::Writer();
    }

    if (IsReservedBlobFilename(cleanName)) {
        LOG("[NS] DeleteFile app=%u ignored for reserved /blobs/ name %s", appId, cleanName.c_str());
        return PB::Writer();
    }

    uint32_t accountId = 0;
    if (!RequireAccountId("ClientDeleteFile", appId, accountId)) {
        return PB::Writer();
    }

    HttpServer::DeleteBlob(accountId, appId, cleanName);
    uint64_t batchId = BatchTracker_ActiveId(accountId, appId);
    bool deleted = batchId == 0
        ? CloudStorage::DeleteBlob(accountId, appId, cleanName)
        : CloudStorage::DeleteBlobStaged(accountId, appId, cleanName);

    if (RemoveFileToken(accountId, appId, cleanName)) {
        MarkFileTokensDirty(accountId, appId);
    }
    if (deleted) BatchTracker_RecordDelete(accountId, appId, cleanName);
    
    // Staged batches publish a full manifest at CompleteBatch, so only live
    // deletes update committed manifest state immediately.
    if (batchId == 0) {
        CloudStorage::RemoveManifestEntry(accountId, appId, cleanName);
    }

    PB::Writer body; // empty response
    return body;
}

} // namespace CloudIntercept
