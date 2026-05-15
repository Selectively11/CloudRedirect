#include "rpc_handlers.h"
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
#include "cloud_storage.h"
#include "pending_ops_journal.h"
#include "file_util.h"
#include "remotecache_repair.h"
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


// per-app upload batch tracking — state lives in batch_tracker.cpp

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

// ============================================================================
// Shutdown
// ============================================================================

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

    auto sizePreWrite = std::filesystem::file_size(pathW, ec);
    auto mtimePreWrite = ec ? std::filesystem::file_time_type{}
                            : std::filesystem::last_write_time(pathW, ec);
    if (ec || sizePreWrite != sizeBefore || mtimePreWrite != mtimeBefore) {
        LOG("[NS-RC] remotecache.vdf changed during repair for app %u, aborting", appId);
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

// Update remotecache.vdf's ChangeNumber field after a batch upload completes.
// This keeps Steam's local CN in sync with our cloud CN since we suppress
// SignalAppExitSyncDone which would normally trigger Steam's CN update.
static bool UpdateRemotecacheVdfChangeNumber(uint32_t accountId, uint32_t appId,
                                             uint64_t newChangeNumber) {
    std::string steamPath = CloudIntercept::GetSteamPath();
    if (steamPath.empty()) return false;

#ifdef _WIN32
    std::string vdfPath = steamPath + "userdata\\" + std::to_string(accountId)
        + "\\" + std::to_string(appId) + "\\remotecache.vdf";
#else
    std::string vdfPath = steamPath + "userdata/" + std::to_string(accountId)
        + "/" + std::to_string(appId) + "/remotecache.vdf";
#endif

    const uint64_t appKey = MakeAppAccountKey(accountId, appId);
    auto ioMutex = AcquireRemotecacheRepairIoMutex(appKey);
    std::lock_guard<std::mutex> ioLock(*ioMutex);

    auto pathW = FileUtil::Utf8ToPath(vdfPath);
    std::error_code ec;

    auto sizeBefore = std::filesystem::file_size(pathW, ec);
    if (ec) {
        LOG("[NS-RC] remotecache.vdf missing for CN update app %u", appId);
        return false;
    }
    auto mtimeBefore = std::filesystem::last_write_time(pathW, ec);
    if (ec) return false;

    std::ifstream in(pathW);
    if (!in.is_open()) {
        LOG("[NS-RC] remotecache.vdf unreadable for CN update app %u", appId);
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::string updated;
    if (!UpdateRemotecacheChangeNumber(content, appId, newChangeNumber, updated)) {
        LOG("[NS-RC] ChangeNumber field not found in remotecache.vdf for app %u", appId);
        return false;
    }

    if (updated == content) {
        LOG("[NS-RC] remotecache.vdf CN already %llu for app %u",
            (unsigned long long)newChangeNumber, appId);
        return true;
    }

    auto sizeAfter = std::filesystem::file_size(pathW, ec);
    auto mtimeAfter = ec ? std::filesystem::file_time_type{}
                         : std::filesystem::last_write_time(pathW, ec);
    if (ec || sizeAfter != sizeBefore || mtimeAfter != mtimeBefore) {
        LOG("[NS-RC] remotecache.vdf changed under us during CN update for app %u", appId);
        return false;
    }

    if (!FileUtil::AtomicWriteText(vdfPath, updated)) {
        LOG("[NS-RC] Failed to write CN-updated remotecache.vdf for app %u", appId);
        return false;
    }

    LOG("[NS-RC] Updated remotecache.vdf ChangeNumber to %llu for app %u",
        (unsigned long long)newChangeNumber, appId);
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
    // Playtime/Stats sync is Windows-only for now.

    // Account-scope only; per-app fallback would re-cache cleaned pollution.
    auto statsData = CloudStorage::RetrieveBlob(
        accountId, kAccountScopeAppId, AccountStatsFilename(appId));
    if (!statsData.empty()) {
        MergeStatsFile(appId, accountId, statsData);
    }

    auto ptData = CloudStorage::RetrieveBlob(
        accountId, kAccountScopeAppId, AccountPlaytimeFilename(appId));
    RestorePlaytimeMetadata(accountId, appId, ptData);
#else
    (void)accountId;
    (void)appId;
    LOG("[Playtime] Skipping playtime/stats sync on Linux (not implemented)");
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
PB::Writer HandleGetChangelist(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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
    bool useCommittedLocalInventory = false;
    std::vector<LocalStorage::FileEntry> committedFiles;
    uint64_t committedChangeNumber = 0;

    SetRpcCrashContext("GetChangelist:interrupted-inventory", "Cloud.GetAppFileChangelist#1", appId);
    useCommittedLocalInventory = CloudStorage::TryBuildCommittedInventoryForInterruptedUpload(
        accountId, appId, committedFiles, committedChangeNumber);
    if (useCommittedLocalInventory) {
        LOG("[NS-CL] app %u preserving committed inventory during interrupted upload recovery",
            appId);
    }

    // Track whether we fetched fresh manifest from cloud this call
    CloudStorage::Manifest cloudManifest;
    bool haveCloudManifest = false;
    uint64_t cloudCN = 0;

    // Fetch cloud CN and manifest to ensure we return accurate file metadata.
    // Steam compares SHA/timestamps from our response against its local cache.
    if (!useCommittedLocalInventory && CloudStorage::IsCloudActive()) {
        SetRpcCrashContext("GetChangelist:cloud-cn", "Cloud.GetAppFileChangelist#1", appId);
        uint64_t localCN = LocalStorage::GetChangeNumber(accountId, appId);
        cloudCN = CloudStorage::FetchCloudCN(accountId, appId);
        
        LOG("[NS-CL] Cloud check for app %u: localCN=%llu, cloudCN=%llu",
            appId, localCN, cloudCN);
        
        // Only treat cloud as authoritative when its CN advances beyond local.
        // Unlike Steam's server inventory, our manifest is a provider blob and
        // can become visible before cn.cloudredirect publishes a completed batch.
        if (cloudCN > localCN) {
            SetRpcCrashContext("GetChangelist:cloud-manifest", "Cloud.GetAppFileChangelist#1", appId);
            cloudManifest = CloudStorage::FetchCloudManifest(accountId, appId);

            if (!cloudManifest.empty()) {
                SetRpcCrashContext("GetChangelist:manifest-repair", "Cloud.GetAppFileChangelist#1", appId);
                auto repairStatus = CloudStorage::RepairCloudManifest(
                    accountId, appId, cloudManifest, /*pruneAbsentRemote=*/true);
                if (repairStatus != CloudStorage::ManifestRepairStatus::Incomplete) {
                    // The RepairCloudManifest already cross-referenced the manifest
                    // against the actual remote blob listing. Trust the repaired result
                    // unless it's empty while local blobs have real (non-reserved) files
                    // — that signals a provider listing failure masquerading as success.
                    CloudStorage::Manifest localManifest = CloudStorage::BuildManifestFromLocalBlobs(accountId, appId);
                    size_t localNonReserved = 0;
                    for (const auto& [name, entry] : localManifest) {
                        if (!IsReservedBlobFilename(name)) ++localNonReserved;
                    }
                    if (cloudManifest.size() > 0 || localNonReserved == 0) {
                        LOG("[NS-CL] Got cloud manifest with %zu files for app %u",
                            cloudManifest.size(), appId);
                        haveCloudManifest = true;
                        LocalStorage::SetChangeNumber(accountId, appId, cloudCN);
                        UpdateRemotecacheVdfChangeNumber(accountId, appId, cloudCN);
                        if (repairStatus == CloudStorage::ManifestRepairStatus::Complete &&
                            !CloudStorage::SaveManifestLocal(accountId, appId, cloudManifest)) {
                            LOG("[NS-CL] Failed to persist local cloud manifest for app %u", appId);
                        }
                    } else if (cloudManifest.empty()) {
                        LOG("[NS-CL] Cloud manifest is empty but local has %zu blobs for app %u; falling back to local inventory",
                            localNonReserved, appId);
                    }
                } else {
                    LOG("[NS-CL] Cloud manifest for app %u could not be repaired to a complete inventory; using local data",
                        appId);
                }
            } else {
                // Migration path: cloud has newer CN but no manifest, do full sync
                LOG("[NS-CL] No manifest in cloud for app %u (cloudCN=%llu > localCN=%llu), doing full sync...",
                    appId, cloudCN, localCN);
                SetRpcCrashContext("GetChangelist:sync-from-cloud", "Cloud.GetAppFileChangelist#1", appId);
                CloudStorage::ForegroundSyncScope foregroundSync;
                CloudStorage::SyncFromCloud(accountId, appId);
                // SyncFromCloud advances local CN; sync remotecache.vdf to match
                // so Steam doesn't see a stale CN and trigger an upload.
                uint64_t postSyncCN = LocalStorage::GetChangeNumber(accountId, appId);
                if (postSyncCN > localCN) {
                    UpdateRemotecacheVdfChangeNumber(accountId, appId, postSyncCN);
                }

                // Build manifest from downloaded blobs and upload for next time
                auto builtManifest = CloudStorage::BuildManifestFromLocalBlobs(accountId, appId);
                if (!builtManifest.empty()) {
                    CloudStorage::SaveManifest(accountId, appId, builtManifest);
                    LOG("[NS-CL] Built and uploaded manifest with %zu files for app %u",
                        builtManifest.size(), appId);
                }
                LOG("[NS-CL] Migration sync complete for app %u", appId);
            }
        } else if (cloudCN == localCN) {
            LOG("[NS-CL] Local CN matches cloud CN=%llu for app %u, using local inventory",
                localCN, appId);
        } else {
            LOG("[NS-CL] Local CN=%llu > cloud CN=%llu for app %u, using local data (unsynced changes)",
                localCN, cloudCN, appId);
        }
    }

    // Async AutoCloud bootstrap; set is_only_delta=1 if active.
    SetRpcCrashContext("GetChangelist:bootstrap", "Cloud.GetAppFileChangelist#1", appId);
    AutoCloudBootstrap::Bootstrap(accountId, appId, /*wait=*/false);
    bool bootstrapActive = AutoCloudBootstrap::IsActive(accountId, appId);

    // Build file list - either from cloud manifest (fast path) or local blobs
    std::vector<LocalStorage::FileEntry> files;
    uint64_t serverChangeNumber = 0;  // Initialize to prevent UB in edge cases
    
    if (useCommittedLocalInventory) {
        SetRpcCrashContext("GetChangelist:committed-files", "Cloud.GetAppFileChangelist#1", appId);
        serverChangeNumber = committedChangeNumber;
        files = committedFiles;
        LOG("[NS-CL] GetAppFileChangelist app=%u using committed local manifest during interrupted upload (%zu files)",
            appId, files.size());
    } else if (haveCloudManifest && !cloudManifest.empty()) {
        SetRpcCrashContext("GetChangelist:manifest-delta", "Cloud.GetAppFileChangelist#1", appId);
        // Steam-faithful delta: compute diff between clientCN snapshot and current manifest.
        // Steam's server returns only changed files — not the full inventory.
        auto delta = CloudStorage::ComputeManifestDelta(accountId, appId,
                                                         clientChangeNumber, cloudCN,
                                                         cloudManifest);
        if (!delta.files.empty()) {
            serverChangeNumber = delta.serverCN;
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
        } else if (clientChangeNumber == cloudCN) {
            serverChangeNumber = cloudCN;
            for (const auto& [filename, entry] : cloudManifest) {
                if (IsReservedBlobFilename(filename)) continue;
                auto local = LocalStorage::GetFileEntry(accountId, appId, filename);
                if (local && local->sha == entry.sha) continue;
                LocalStorage::FileEntry fe;
                fe.filename = filename;
                fe.sha = local ? local->sha : entry.sha;
                fe.timestamp = local ? local->timestamp : entry.timestamp;
                fe.rawSize = local ? local->rawSize : entry.size;
                fe.deleted = false;
                files.push_back(std::move(fe));
            }
            LOG("[NS-CL] GetAppFileChangelist app=%u: same CN=%llu, %zu files changed locally",
                appId, cloudCN, files.size());
        } else {
            // No delta and CNs differ. Check if snapshot exists at clientCN
            // (baseline present, no file changes) vs snapshot missing (first sync).
            bool snapshotExists = CloudStorage::ManifestSnapshotExists(accountId, appId, clientChangeNumber);
            if (snapshotExists) {
                // Baseline existed and files didn't change — already synced.
                serverChangeNumber = cloudCN;
                LOG("[NS-CL] GetAppFileChangelist app=%u: no changes since clientCN=%llu, synced at CN=%llu",
                    appId, clientChangeNumber, cloudCN);
            } else {
                // No delta and CNs differ: snapshot missing at clientCN (first sync).
                serverChangeNumber = cloudCN;
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
                LOG("[NS-CL] GetAppFileChangelist app=%u using cloud manifest (%zu files)",
                    appId, files.size());
            }
        }
    } else {
        // Normal path: read from local blob cache
        SetRpcCrashContext("GetChangelist:local-files", "Cloud.GetAppFileChangelist#1", appId);
        
        if (bootstrapActive) {
            LOG("[NS-CL] GetAppFileChangelist app=%u: bootstrap active, returning empty list to avoid UI freeze", appId);
            files.clear();
            serverChangeNumber = 0;
        } else {
            files = LocalStorage::GetFileList(accountId, appId);
            serverChangeNumber = LocalStorage::GetChangeNumber(accountId, appId);

            // If cloud CN is ahead but the manifest was rejected, attempt self-repair
            // by publishing a full manifest from local blobs so next GetChangelist
            // on any machine can use the fast path.
            if (cloudCN > serverChangeNumber && !files.empty()) {
                LOG("[NS-CL] GetAppFileChangelist app=%u: cloud CN=%llu ahead of local CN=%llu — publishing full manifest self-repair",
                    appId, cloudCN, serverChangeNumber);
                CloudStorage::Manifest fullManifest = CloudStorage::BuildManifestFromLocalBlobs(accountId, appId);
                if (!fullManifest.empty()) {
                    CloudStorage::SaveManifest(accountId, appId, fullManifest);
                }
            }
            
            files.erase(std::remove_if(files.begin(), files.end(),
                [](const LocalStorage::FileEntry& fe) {
                    return IsReservedBlobFilename(fe.filename);
                }), files.end());
        }
    }

    LOG("[NS-CL] GetAppFileChangelist app=%u clientCN=%llu serverCN=%llu files=%zu",
        appId, clientChangeNumber, serverChangeNumber, files.size());

    // build path_prefix table and file entries
    std::unordered_map<std::string, uint32_t> prefixMap;
    std::vector<std::string> prefixList;
    std::string machineName = GetMachineName();

    std::unordered_set<std::string> rootTokens;
    {
        SetRpcCrashContext("GetChangelist:root-token-cache", "Cloud.GetAppFileChangelist#1", appId);
        std::lock_guard<std::mutex> lock(g_rootTokenMutex);
        auto it = g_appRootTokens.find(appKey);
        if (it != g_appRootTokens.end()) {
            rootTokens = it->second;
        }
    }
    // Disk fallback; skip cache-write if worker straddles the read.
    if (rootTokens.empty()) {
        SetRpcCrashContext("GetChangelist:root-token-disk", "Cloud.GetAppFileChangelist#1", appId);
        bool bootstrapActiveBefore = AutoCloudBootstrap::IsActive(accountId, appId);
        rootTokens = CloudStorage::LoadRootTokens(accountId, appId);
        bool bootstrapActiveAfter = AutoCloudBootstrap::IsActive(accountId, appId);
        bool bootstrapTouchedLoad = bootstrapActiveBefore || bootstrapActiveAfter;
        if (!rootTokens.empty() && !bootstrapTouchedLoad) {
            std::lock_guard<std::mutex> lock(g_rootTokenMutex);
            // Prefer in-memory if another caller populated it during I/O.
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
    if (rootTokens.empty()) {
        rootTokens.insert("");
    }

    for (auto& t : rootTokens) {
        LOG("[NS-CL] Root token for app %u: '%s'", appId, t.c_str());
    }

    // Snapshot file -> root-token map; same straddle gate as root tokens.
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
        auto loaded = CloudStorage::LoadFileTokens(accountId, appId);
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
    // is_only_delta=1 suppresses reconcile during bootstrap.
    body.WriteVarint(3, bootstrapActive ? 1u : 0u);

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
        fileSub.WriteVarint(5, pf.entry->deleted ? 1u : 0u);      // persist_state: 1=deleted
        fileSub.WriteVarint(6, 0xFFFFFFFF);                     // platforms_to_sync = all
        fileSub.WriteVarint(7, pf.prefixIdx);                    // path_prefix_index (0 = first real prefix)
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
    body.WriteVarint(6, 0);

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

            // Ensure local has an AchievementTimes section
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
// No cloud sync here; Steam fetches files on-demand via ClientFileDownload.
PB::Writer HandleLaunchIntent(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    LOG("[NS] SignalAppLaunchIntent app=%u", appId);

    RecordLaunchTime(appId);
    uint32_t accountId = 0;
    if (!RequireAccountId("SignalAppLaunchIntent", appId, accountId)) {
        PB::Writer body;
        return body;
    }
    
    // Restore metadata (stats, playtime) - lightweight, no blob downloads
    if (CloudStorage::IsCloudActive()) {
        RestoreAppMetadata(accountId, appId);
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

    auto pending = PendingOpsJournal::RecordLaunchIntent(
        accountId, appId, currentSession, ignorePendingOperations);

    PB::Writer body;
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
    return body;
}

PB::Writer HandleSuspendSession(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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

PB::Writer HandleResumeSession(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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
PB::Writer HandleQuotaUsage(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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

    auto files = LocalStorage::GetFileList(accountId, appId);
    files.erase(std::remove_if(files.begin(), files.end(),
        [](const LocalStorage::FileEntry& fe) {
            return IsReservedBlobFilename(fe.filename);
        }), files.end());
    uint64_t totalBytes = 0;
    for (auto& f : files) totalBytes += f.rawSize;

    PB::Writer body;
    body.WriteVarint(1, ClampFileSizeToUint32((uint64_t)files.size(),
                                              "QuotaUsage.existing_files",
                                              appId, std::string{}));  // existing_files
    body.WriteVarint(2, totalBytes);                 // existing_bytes (uint64 on Steam's side, no clamp)
    body.WriteVarint(3, 10000);                      // max_num_files
    body.WriteVarint(4, 1073741824ULL);              // max_num_bytes (1 GB)

    LOG("[NS] QuotaUsage app=%u files=%zu bytes=%llu", appId, files.size(), totalBytes);
    return body;
}

// BeginAppUploadBatch
PB::Writer HandleBeginBatch(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint64_t batchId = BatchTracker_NextId();
    uint32_t accountId = 0;
    if (!RequireAccountId("BeginAppUploadBatch", appId, accountId)) {
        return CloudRpcUtils::BuildBeginBatchResponseBody(batchId, 0);
    }

    uint64_t changeNumber = LocalStorage::GetChangeNumber(accountId, appId);
    PrepareBatchCanonicalTokens(accountId, appId);
    BatchTracker_Begin(accountId, appId, batchId);
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
    }

    PB::Writer body = CloudRpcUtils::BuildBeginBatchResponseBody(batchId, changeNumber);

    LOG("[NS] BeginBatch app=%u batchId=%llu uploads=%d deletes=%d",
        appId, batchId, uploadCount, deleteCount);
    return body;
}

// ClientBeginFileUpload
// Tell Steam to PUT the file to our local HTTP server.
PB::Writer HandleBeginFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    // extract request fields
    uint64_t fileSize = 0, rawFileSize = 0;
    std::string filename;
    std::vector<uint8_t> fileSha;
    uint64_t timestamp = 0;

    for (auto& f : reqBody) {
        if (f.fieldNum == 2 && f.wireType == PB::Varint) fileSize = f.varintVal;
        if (f.fieldNum == 3 && f.wireType == PB::Varint) rawFileSize = f.varintVal;
        if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited)
            fileSha.assign(f.data, f.data + f.dataLen);
        if (f.fieldNum == 5 && f.wireType == PB::Varint) timestamp = f.varintVal;
        if (f.fieldNum == 6 && f.wireType == PB::LengthDelimited)
            filename.assign(reinterpret_cast<const char*>(f.data), f.dataLen);
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

    LOG("[NS-UP] BeginFileUpload app=%u file=%s (clean=%s) size=%llu rawSize=%llu -> %s%s",
        appId, filename.c_str(), cleanName.c_str(), fileSize, rawFileSize, urlHost.c_str(), urlPath.c_str());

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
PB::Writer HandleCommitFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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
        // Drop any partial blob from the aborted PUT.
        if (HttpServer::HasBlob(accountId, appId, cleanName)) {
            HttpServer::DeleteBlob(accountId, appId, cleanName);
        }
    }

    PB::Writer body;
    body.WriteVarint(1, committed ? 1 : 0);          // file_committed
    return body;
}

// CompleteAppUploadBatchBlocking
PB::Writer HandleCompleteBatch(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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

    if (!CloudStorage::PublishManifestDeltaForCommit(accountId, appId, uploads, deletes)) {
        LOG("[NS] CompleteBatch app=%u: manifest publish failed, incrementing CN to prevent orphaned blobs",
            appId);
        uint64_t newCN = LocalStorage::IncrementChangeNumber(accountId, appId);
        CloudStorage::SaveManifestSnapshot(accountId, appId, newCN);
        CloudStorage::CommitCNAsync(accountId, appId, newCN);
        PendingOpsJournal::RecordUploadBatchEnd(accountId, appId);
        BatchTracker_Clear(accountId, appId, batch.batchId);
        ClearFileTokensDirty(accountId, appId);
        ClearBatchCanonicalTokens(accountId, appId);
        UpdateRemotecacheVdfChangeNumber(accountId, appId, newCN);
        return PB::Writer();
    }

    BatchTracker_Clear(accountId, appId, batch.batchId);

    uint64_t newCN = LocalStorage::IncrementChangeNumber(accountId, appId);
    CloudStorage::SaveManifestSnapshot(accountId, appId, newCN);
    CloudStorage::CommitCNAsync(accountId, appId, newCN);
    PendingOpsJournal::RecordUploadBatchEnd(accountId, appId);
    LOG("[NS] CompleteBatch app=%u CN=%llu (drain+publish detached)", appId, newCN);

    // Update remotecache.vdf's ChangeNumber to match. We suppress SignalAppExitSyncDone
    // which would normally trigger Steam's CN update, so we must do it ourselves.
    UpdateRemotecacheVdfChangeNumber(accountId, appId, newCN);

    ClearBatchCanonicalTokens(accountId, appId);
    PB::Writer body; // empty response
    return body;
}

// ClientFileDownload
// Tell Steam to GET the file from our local HTTP server.
PB::Writer HandleFileDownload(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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

    // Check local manifest FIRST - this is saved from cloud during GetChangelist
    // and represents what we told Steam the file looks like. Must match what we serve.
    auto manifest = CloudStorage::LoadLocalManifest(accountId, appId);
    auto it = manifest.find(cleanName);
    if (it != manifest.end()) {
        fileSize = it->second.size;
        timestamp = it->second.timestamp;
        sha = it->second.sha;
    } else {
        // Fallback: check local storage (for files uploaded locally but not yet in manifest)
        auto entry = LocalStorage::GetFileEntry(accountId, appId, cleanName);
        if (entry) {
            fileSize = entry->rawSize;
            timestamp = entry->timestamp;
            sha = entry->sha;
        } else {
            // Last resort: check blob size on disk
            fileSize = HttpServer::GetBlobSize(accountId, appId, cleanName);
        }
    }

    LOG("[NS-DL] FileDownload app=%u file=%s (clean=%s) size=%llu -> %s%s",
        appId, filename.c_str(), cleanName.c_str(), fileSize, urlHost.c_str(), urlPath.c_str());

    uint32_t clampedSize = ClampFileSizeToUint32(fileSize,
                                                 "FileDownload_Response.file_size",
                                                 appId, filename);
    PB::Writer body;
    body.WriteVarint(1, appId);                      // appid
    body.WriteVarint(2, clampedSize);                // file_size (compressed = same)
    body.WriteVarint(3, clampedSize);                // raw_file_size
    if (!sha.empty())
        body.WriteBytes(4, sha.data(), sha.size());  // sha_file
    body.WriteVarint(5, timestamp);                  // time_stamp
    body.WriteVarint(6, 0);                          // is_explicit_delete = false
    body.WriteString(7, urlHost);                    // url_host
    body.WriteString(8, urlPath);                    // url_path
    body.WriteVarint(9, 0);                          // use_https = false
    // no request_headers (field 10)
    body.WriteVarint(11, 0);                         // encrypted = false

    return body;
}

// ClientDeleteFile
PB::Writer HandleDeleteFile(uint32_t appId, const std::vector<PB::Field>& reqBody) {
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

    // NOTE: The pre-changelist gate was removed because EnsureAndMarkRemotecacheRepaired
    // is no longer called, so g_remotecachePlantedRows is never populated.
    // Deletes are now gated by the batch tracker (staged inside a batch, live outside).

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
