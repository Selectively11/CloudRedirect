#include "cloud_storage.h"
#include "app_state.h"
#include "local_storage.h"
#include "local_disk_provider.h"
#include "google_drive_provider.h"
#include "onedrive_provider.h"
#include "cloud_metadata_paths.h"
#include "cloud_staging.h"
#include "file_util.h"
#include "legacy_metadata_cleanup.h"
#include "log.h"
#include "common.h"
#include "json.h"
#include <fstream>
#include <filesystem>
#include <sstream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <list>
#include <algorithm>
#include <limits>
#include <unordered_set>
#ifdef _WIN32
#include <Windows.h>
#endif

using CloudIntercept::kManifestFilename;
using CloudIntercept::kLegacyManifestFilename;
using CloudIntercept::kCNFilename;
using CloudIntercept::kLegacyCNFilename;
using CloudIntercept::kRootTokenFilename;
using CloudIntercept::kLegacyRootTokenFilename;
using CloudIntercept::kFileTokensFilename;
using CloudIntercept::kLegacyFileTokensFilename;
using CloudIntercept::kDeletedFilename;
using CloudIntercept::kLegacyDeletedFilename;

namespace CloudStorage {

std::string CanonicalizeInternalMetadataName(std::string_view filename) {
    if (filename == CloudIntercept::kLegacyPlaytimeMetadataPath) {
        return CloudIntercept::kPlaytimeMetadataPath;
    }
    if (filename == CloudIntercept::kLegacyStatsMetadataPath) {
        return CloudIntercept::kStatsMetadataPath;
    }
    return std::string(filename);
}


static std::string                       g_localRoot;     // local cache root (e.g. "C:\Games\Steam\cloud_redirect\")
static std::unique_ptr<ICloudProvider>   g_provider;      // may be nullptr (local-only mode)
static std::mutex                        g_mutex;

// Cache confirmed-missing metadata paths to avoid repeated API round trips.
static std::mutex                        g_missingMetadataMutex;
static std::unordered_set<std::string>   g_missingMetadataPaths;

// Per-app blob path index: maps filename -> resolved cloud path (avoids fallback chain).
static std::mutex                        g_blobIndexMutex;
struct BlobIndex {
    std::unordered_map<std::string, std::string> filenameToPath; // filename -> full cloud path
    // sha1hex -> a cloud path holding that content. Identical-content files store
    // bytes only under the FIRST filename that uploaded the sha; retrieval by another
    // filename 404s. This map lets RetrieveBlob find bytes by content hash instead.
    std::unordered_map<std::string, std::string> shaToPath;      // sha1hex -> full cloud path
    bool populated = false;
};
static std::unordered_map<uint64_t, BlobIndex> g_blobIndex; // key = (accountId<<32)|appId

// Session-scoped set of CAS hashes (sha1hex) provider-confirmed durable this process
// lifetime. The session lock (LaunchIntent EResult=108) blocks other machines from
// GC-ing them, so a hash durable earlier this session is still durable now. Lets
// VerifyAndHealManifestForPublish skip its slow blob listing. Keyed by sha (CAS blobs
// are immutable), in-memory only; a fresh launch re-verifies.
static std::mutex                                            g_durableBlobsMutex;
static std::unordered_map<uint64_t, std::unordered_set<std::string>> g_durableBlobs; // (acct<<32|app) -> {sha1hex}

static void RecordDurableBlobShas(uint32_t accountId, uint32_t appId,
                                  const std::vector<std::string>& shaHexes) {
    if (shaHexes.empty()) return;
    uint64_t key = (static_cast<uint64_t>(accountId) << 32) | appId;
    std::lock_guard<std::mutex> lk(g_durableBlobsMutex);
    auto& set = g_durableBlobs[key];
    for (const auto& s : shaHexes)
        if (s.size() == 40) set.insert(s);
}

static bool IsBlobShaDurableThisSession(uint32_t accountId, uint32_t appId,
                                        const std::string& shaHex) {
    if (shaHex.size() != 40) return false;
    uint64_t key = (static_cast<uint64_t>(accountId) << 32) | appId;
    std::lock_guard<std::mutex> lk(g_durableBlobsMutex);
    auto it = g_durableBlobs.find(key);
    return it != g_durableBlobs.end() && it->second.count(shaHex) > 0;
}

// Serializes token persistence (root_token.dat, file_tokens.dat) across
// concurrent callers (rpc_handlers batch operations).
// Per-(account,app) sync mutex registry (Steam-parity). Non-reentrant: SyncFromCloudInner-reachable callers go direct.
static std::mutex                                              g_syncMutexRegistryMutex;
static std::unordered_map<uint64_t, std::shared_ptr<std::mutex>> g_syncMutexRegistry;

// Shutdown waits on these counters before tearing down g_provider so a
// long-running Download/Upload doesn't return into freed memory.
static std::atomic<int>  g_inflightSyncCount{0};
static std::atomic<bool> g_shuttingDown{false};

InflightSyncScope::InflightSyncScope() {
    g_inflightSyncCount.fetch_add(1, std::memory_order_seq_cst);
    if (g_shuttingDown.load(std::memory_order_seq_cst)) {
        g_inflightSyncCount.fetch_sub(1, std::memory_order_seq_cst);
        return;
    }
    entered = true;
}
InflightSyncScope::~InflightSyncScope() {
    if (entered) g_inflightSyncCount.fetch_sub(1, std::memory_order_seq_cst);
}

// Foreground-sync gate. Background sweeps park here while a launch-intent
// sync is in flight to avoid HTTP contention against the provider.
static std::atomic<int>     g_foregroundSyncCount{0};
static std::mutex           g_foregroundSyncMutex;
static std::condition_variable g_foregroundSyncCV;

ForegroundSyncScope::ForegroundSyncScope() {
    g_foregroundSyncCount.fetch_add(1, std::memory_order_seq_cst);
}

ForegroundSyncScope::~ForegroundSyncScope() {
    int prev = g_foregroundSyncCount.fetch_sub(1, std::memory_order_seq_cst);
    if (prev == 1) {
        std::lock_guard<std::mutex> g(g_foregroundSyncMutex);
        g_foregroundSyncCV.notify_all();
    }
}

// Returns true if the gate is clear and the caller may proceed,
// false if shutdown started or the 30s cap fired.
static bool WaitForForegroundSyncIdle(const char* context) {
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;
    if (g_foregroundSyncCount.load(std::memory_order_seq_cst) == 0) return true;
    auto waitStart = std::chrono::steady_clock::now();
    std::unique_lock<std::mutex> lk(g_foregroundSyncMutex);
    bool woken = g_foregroundSyncCV.wait_for(lk, std::chrono::seconds(30), []{
        return g_shuttingDown.load(std::memory_order_seq_cst)
            || g_foregroundSyncCount.load(std::memory_order_seq_cst) == 0;
    });
    auto waitedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - waitStart).count();
    if (!woken) {
        LOG("[CloudStorage] %s: 30s cap fired waiting for foreground sync -- abandoning background work this cycle", context);
        return false;
    }
    if (waitedMs > 50) {
        LOG("[CloudStorage] %s: yielded %lld ms to foreground sync", context, (long long)waitedMs);
    }
    return !g_shuttingDown.load(std::memory_order_seq_cst);
}

std::shared_ptr<std::mutex> AcquireAppSyncMutex(uint32_t accountId, uint32_t appId) {
    uint64_t key = (static_cast<uint64_t>(accountId) << 32) | appId;
    std::lock_guard<std::mutex> g(g_syncMutexRegistryMutex);
    auto it = g_syncMutexRegistry.find(key);
    if (it == g_syncMutexRegistry.end()) {
        it = g_syncMutexRegistry.emplace(key, std::make_shared<std::mutex>()).first;
    }
    return it->second;
}

// Show an immediate dialog for critical auth failures (token refresh broken).
// Guarded by std::once_flag so the user sees it at most once per Steam session.
static std::once_flag g_authFailureOnce;
void NotifyAuthFailure(const std::string& providerName) {
    std::call_once(g_authFailureOnce, [&providerName] {
        CloudWorkQueue::ShowErrorDialog(
            providerName + " authentication failed!\n\n"
            "CloudRedirect cannot refresh your access token.\n"
            "Cloud sync is disabled until this is resolved.\n\n"
            "Re-authenticate using the CloudRedirect setup tool.");
    });
}

// WorkItem/EnqueueWork/queue infra moved to cloud_work_queue.h/.cpp.
static std::string LocalStoragePath(uint32_t accountId, uint32_t appId);

static std::string CreateLocalConflictCopy(uint32_t accountId, uint32_t appId,
                                           const std::string& filename,
                                           const std::string& localPath) {
#ifdef _WIN32
    std::string conflictsRoot = g_localRoot + "conflicts\\";
    std::string appConflictRoot = conflictsRoot + std::to_string(accountId) + "\\" +
        std::to_string(appId) + "\\";
#else
    std::string conflictsRoot = g_localRoot + "conflicts/";
    std::string appConflictRoot = conflictsRoot + std::to_string(accountId) + "/" +
        std::to_string(appId) + "/";
#endif
    auto stamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string conflictPath = appConflictRoot + filename + "." + std::to_string(stamp) + ".local";
#ifdef _WIN32
    for (auto& c : conflictPath) { if (c == '/') c = '\\'; }
#endif
    std::error_code ec;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appConflictRoot), ec);
    if (ec) return {};
    if (!FileUtil::IsPathWithin(appConflictRoot, conflictPath)) return {};

    std::filesystem::create_directories(FileUtil::Utf8ToPath(conflictPath).parent_path(), ec);
    if (ec) return {};
    std::filesystem::copy_file(FileUtil::Utf8ToPath(localPath), FileUtil::Utf8ToPath(conflictPath),
        std::filesystem::copy_options::none, ec);
    if (!ec) {
        LOG("[CloudStorage] Preserved local conflict copy for app %u file %s at %s",
            appId, filename.c_str(), conflictPath.c_str());
        return conflictPath;
    }
    LOG("[CloudStorage] Failed to preserve local conflict copy for app %u file %s: %s",
        appId, filename.c_str(), ec.message().c_str());
    return {};
}

static bool PreserveLocalConflictCopy(uint32_t accountId, uint32_t appId,
                                      const std::string& filename,
                                      const std::string& localPath) {
    return !CreateLocalConflictCopy(accountId, appId, filename, localPath).empty();
}

static void RemoveLocalBlobsNotInCloud(uint32_t accountId, uint32_t appId,
                                       const std::unordered_set<std::string>& cloudBlobNames) {
    std::string localBlobDir = LocalStoragePath(accountId, appId);
    std::error_code ec;
    auto localBlobDirPath = FileUtil::Utf8ToPath(localBlobDir);
    if (!std::filesystem::exists(localBlobDirPath, ec) || !std::filesystem::is_directory(localBlobDirPath, ec)) return;

    int removed = 0;
    std::string blobDirPrefix = FileUtil::MakePathPrefix(FileUtil::PathToUtf8(localBlobDirPath));
    // Defer empty-dir cleanup: MSVC's recursive_directory_iterator caches
    // dir handles and removing dirs mid-walk leaves the iterator undefined.
    std::unordered_set<std::string> removedParents;
    // Manual increment: mid-walk errors stay in error_code instead of escaping and calling std::terminate.
    std::filesystem::recursive_directory_iterator it(localBlobDirPath, ec);
    if (ec) return;
    const std::filesystem::recursive_directory_iterator end;
    while (it != end) {
        const auto& entry = *it;
        std::error_code regEc;
        if (entry.is_regular_file(regEc)) {
            std::string entryUtf8 = FileUtil::PathToUtf8(entry.path());
            FileUtil::NormalizeSlashesInPlace(entryUtf8);
            std::string rel;
            if (!FileUtil::RelativeUtf8Path(entryUtf8, blobDirPrefix, &rel)) {
                rel = FileUtil::PathToUtf8(entry.path().filename());
            }
            {
                bool skipReserved = (rel == kCNFilename || rel == kLegacyCNFilename ||
                                     rel == kRootTokenFilename || rel == kLegacyRootTokenFilename ||
                                     rel == kFileTokensFilename || rel == kLegacyFileTokensFilename ||
                                     rel == kDeletedFilename || rel == kLegacyDeletedFilename ||
                                     rel == kManifestFilename || rel == kLegacyManifestFilename ||
                                     CloudIntercept::IsReservedBlobFilename(rel));
                // Canonicalize so a legacy-named local blob still matches its
                // canonical cloud sibling (cloudBlobNames is canonicalized).
                std::string canonRel = CanonicalizeInternalMetadataName(rel);
                if (!skipReserved && !cloudBlobNames.count(canonRel) &&
                    PreserveLocalConflictCopy(accountId, appId, rel, FileUtil::PathToUtf8(entry.path()))) {
                    std::filesystem::path parentPath = entry.path().parent_path();
                    std::error_code rmEc;
                    std::filesystem::remove(entry.path(), rmEc);
                    if (!rmEc) {
                        ++removed;
                        removedParents.insert(FileUtil::PathToUtf8(parentPath));
                    }
                }
            }
        }
        std::error_code stepEc;
        it.increment(stepEc);
        if (stepEc) break;
    }
    if (removed > 0) {
        LOG("[CloudStorage] SyncFromCloud app %u: removed %d stale local blob(s) absent from newer cloud CN",
            appId, removed);
    }

    if (!removedParents.empty()) {
        std::vector<std::string> parents(removedParents.begin(), removedParents.end());
        LocalStorage::CleanupEmptyCacheDirs(accountId, appId, std::move(parents));
    }
}


// Hex-encode a 20-byte SHA1 as a 40-char lowercase hex string.
static std::string ShaToHex(const std::vector<uint8_t>& sha) {
    std::string hex;
    hex.reserve(sha.size() * 2);
    for (uint8_t b : sha) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

// CAS blob path: "{accountId}/{appId}/blobs/{filename}/{sha1hex}"
static std::string CloudBlobPathByNameAndSHA(uint32_t accountId, uint32_t appId,
                                             const std::string& filename,
                                             const std::string& shaHex) {
    return std::to_string(accountId) + "/" + std::to_string(appId) +
           "/blobs/" + filename + "/" + shaHex;
}

// Legacy CAS path: "{account}/{app}/blobs/{sha1hex}" (migration read-only)
static std::string CloudBlobPathBySHA(uint32_t accountId, uint32_t appId,
                                      const std::string& shaHex) {
    return std::to_string(accountId) + "/" + std::to_string(appId) +
           "/blobs/" + shaHex;
}

// Filename-addressed path. Used for account-scope metadata (appId=0) and
// pre-CAS legacy blobs.
// Cloud provider paths use forward slashes: "{accountId}/{appId}/blobs/{filename}"
static std::string CloudBlobPath(uint32_t accountId, uint32_t appId,
                                 const std::string& filename) {
    return std::to_string(accountId) + "/" + std::to_string(appId) +
           "/blobs/" + filename;
}

static std::string CloudStagedBlobPath(uint32_t accountId, uint32_t appId,
                                       uint64_t batchId,
                                       const std::string& filename) {
    return std::to_string(accountId) + "/" + std::to_string(appId) +
           "/staging/" + std::to_string(batchId) + "/blobs/" + filename;
}

static bool ParseU32(const std::string& s, uint32_t& out) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    try {
        unsigned long long v = std::stoull(s);
        if (v > (std::numeric_limits<uint32_t>::max)()) return false;
        out = static_cast<uint32_t>(v);
        return true;
    } catch (...) { return false; }
}

static bool TryExtractAccountMetadataAppId(const std::string& path,
                                           uint32_t accountId,
                                           uint32_t& appId) {
    std::string prefix = std::to_string(accountId) + "/" +
        std::to_string(CloudIntercept::kAccountScopeAppId) + "/blobs/";
    if (path.rfind(prefix, 0) != 0) return false;

    std::string name = path.substr(prefix.size());
    const char* dirs[] = { "UserGameStats/", "Playtime/" };
    for (const char* dir : dirs) {
        size_t dirLen = strlen(dir);
        if (name.rfind(dir, 0) != 0) continue;
        std::string leaf = name.substr(dirLen);
        const std::string ext = ".bin";
        if (leaf.size() <= ext.size() || leaf.substr(leaf.size() - ext.size()) != ext) return false;
        if (!ParseU32(leaf.substr(0, leaf.size() - ext.size()), appId)) return false;
        return appId != CloudIntercept::kAccountScopeAppId;
    }
    return false;
}

static void EnumerateLocalAccountMetadataAppIds(const std::filesystem::path& accountRootPath,
                                                std::unordered_set<uint32_t>& appIds) {
    auto accountScopePath = accountRootPath / std::to_string(CloudIntercept::kAccountScopeAppId);
    const char* dirs[] = { "UserGameStats", "Playtime" };
    for (const char* dir : dirs) {
        std::error_code ec;
        auto metadataDir = accountScopePath / dir;
        if (!std::filesystem::exists(metadataDir, ec) || !std::filesystem::is_directory(metadataDir, ec)) {
            continue;
        }

        std::filesystem::directory_iterator it(metadataDir, ec);
        if (ec) continue;
        const std::filesystem::directory_iterator end;
        while (it != end) {
            const auto& entry = *it;
            std::error_code fileEc;
            if (entry.is_regular_file(fileEc)) {
                std::string leaf = FileUtil::PathToUtf8(entry.path().filename());
                const std::string ext = ".bin";
                uint32_t parsed = 0;
                if (leaf.size() > ext.size() && leaf.substr(leaf.size() - ext.size()) == ext &&
                    ParseU32(leaf.substr(0, leaf.size() - ext.size()), parsed) &&
                    parsed != CloudIntercept::kAccountScopeAppId) {
                    appIds.insert(parsed);
                }
            }
            std::error_code stepEc;
            it.increment(stepEc);
            if (stepEc) break;
        }
    }
}

// Extract logical filename from a blob path, stripping SHA leaf for canonical paths.
// Returns trailing component as-is for legacy layouts.
bool ParseCloudBlobPath(const std::string& cloudPath,
                               uint32_t& accountId, uint32_t& appId,
                               std::string& filename) {
    size_t p1 = cloudPath.find('/');
    if (p1 == std::string::npos || p1 == 0) return false;
    size_t p2 = cloudPath.find('/', p1 + 1);
    if (p2 == std::string::npos || p2 == p1 + 1) return false;
    const std::string kBlobs = "/blobs/";
    if (cloudPath.compare(p2, kBlobs.size(), kBlobs) != 0) return false;
    size_t fileStart = p2 + kBlobs.size();
    if (fileStart >= cloudPath.size()) return false;

    if (!ParseU32(cloudPath.substr(0, p1), accountId)) return false;
    if (!ParseU32(cloudPath.substr(p1 + 1, p2 - p1 - 1), appId)) return false;
    std::string rest = cloudPath.substr(fileStart);
    if (rest.empty()) return false;

    // Canonical: blobs/{filename}/{sha}. Strip SHA leaf if present.
    size_t lastSlash = rest.rfind('/');
    if (lastSlash != std::string::npos && lastSlash + 1 < rest.size()) {
        std::string leaf = rest.substr(lastSlash + 1);
        if (leaf.size() == 40 &&
            leaf.find_first_not_of("0123456789abcdef") == std::string::npos) {
            filename = rest.substr(0, lastSlash);
            return !filename.empty();
        }
    }
    filename = std::move(rest);
    return true;
}

static bool ParseCloudStagedBlobPath(const std::string& cloudPath,
                                     uint32_t& accountId, uint32_t& appId,
                                     uint64_t& batchId,
                                     std::string& filename) {
    size_t p1 = cloudPath.find('/');
    if (p1 == std::string::npos || p1 == 0) return false;
    size_t p2 = cloudPath.find('/', p1 + 1);
    if (p2 == std::string::npos || p2 == p1 + 1) return false;
    const std::string staging = "/staging/";
    if (cloudPath.compare(p2, staging.size(), staging) != 0) return false;
    size_t batchStart = p2 + staging.size();
    size_t batchEnd = cloudPath.find('/', batchStart);
    if (batchEnd == std::string::npos || batchEnd == batchStart) return false;
    const std::string blobs = "/blobs/";
    if (cloudPath.compare(batchEnd, blobs.size(), blobs) != 0) return false;
    size_t fileStart = batchEnd + blobs.size();
    if (fileStart >= cloudPath.size()) return false;

    if (!ParseU32(cloudPath.substr(0, p1), accountId)) return false;
    if (!ParseU32(cloudPath.substr(p1 + 1, p2 - p1 - 1), appId)) return false;
    try {
        batchId = std::stoull(cloudPath.substr(batchStart, batchEnd - batchStart));
    } catch (...) {
        return false;
    }
    filename = cloudPath.substr(fileStart);
    return !filename.empty();
}

std::string CloudMetadataPath(uint32_t accountId, uint32_t appId,
                                      const std::string& name) {
    return std::to_string(accountId) + "/" + std::to_string(appId) + "/" + name;
}

static bool IsKnownMissingMetadataPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_missingMetadataMutex);
    return g_missingMetadataPaths.count(path) != 0;
}

static void MarkMissingMetadataPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_missingMetadataMutex);
    g_missingMetadataPaths.insert(path);
}

static void ClearMissingMetadataForApp(uint32_t accountId, uint32_t appId) {
    std::string prefix = std::to_string(accountId) + "/" + std::to_string(appId) + "/";
    std::lock_guard<std::mutex> lock(g_missingMetadataMutex);
    for (auto it = g_missingMetadataPaths.begin(); it != g_missingMetadataPaths.end(); ) {
        if (it->rfind(prefix, 0) == 0) it = g_missingMetadataPaths.erase(it);
        else ++it;
    }
}

static void ClearMissingMetadataPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_missingMetadataMutex);
    g_missingMetadataPaths.erase(path);
}

bool UploadCloudMetadataText(uint32_t accountId, uint32_t appId,
                                     const char* name,
                                     const std::string& content) {
    if (!g_provider || !g_provider->IsAuthenticated()) return false;
    std::string path = CloudMetadataPath(accountId, appId, name);
    const uint8_t emptyByte = 0;
    const uint8_t* data = content.empty()
        ? &emptyByte
        : reinterpret_cast<const uint8_t*>(content.data());
    bool uploaded = g_provider->Upload(path, data, content.size());
    if (uploaded) ClearMissingMetadataPath(path);
    return uploaded;
}

// Queue an upload on the cloud work queue: thread-safe, unlike the sync variant
// which races other curl calls off the work thread (libcurl init isn't reentrant).
void UploadCloudMetadataTextAsync(uint32_t accountId, uint32_t appId,
                                  const char* name, const std::string& content) {
    if (!g_provider) return;
    std::string path = CloudMetadataPath(accountId, appId, name);
    ClearMissingMetadataPath(path);
    CloudWorkQueue::WorkItem wi;
    wi.type = CloudWorkQueue::WorkItem::Upload;
    wi.cloudPath = std::move(path);
    wi.data.assign(content.begin(), content.end());
    CloudWorkQueue::EnqueueWork(std::move(wi));
}

void RemoveCloudMetadataIfPresent(uint32_t accountId, uint32_t appId,
                                          const char* name) {
    if (!g_provider || !g_provider->IsAuthenticated()) return;
    std::string path = CloudMetadataPath(accountId, appId, name);
    if (IsKnownMissingMetadataPath(path)) return;
    auto status = g_provider->CheckExists(path);
    if (status == ICloudProvider::ExistsStatus::Missing) {
        MarkMissingMetadataPath(path);
        return;
    }
    if (status == ICloudProvider::ExistsStatus::Error) {
        LOG("[CloudStorage] metadata existence check failed for %s", path.c_str());
        return;
    }
    if (g_provider->Remove(path)) {
        LOG("[CloudStorage] removed obsolete remote metadata %s", path.c_str());
    } else {
        LOG("[CloudStorage] failed to remove obsolete remote metadata %s", path.c_str());
    }
}

void RemoveLegacyCloudMetadataIfCanonicalExists(uint32_t accountId, uint32_t appId,
                                                       const char* canonicalName,
                                                       const char* legacyName) {
    if (!g_provider || !g_provider->IsAuthenticated()) return;
    std::string canonicalPath = CloudMetadataPath(accountId, appId, canonicalName);
    auto status = g_provider->CheckExists(canonicalPath);
    if (status == ICloudProvider::ExistsStatus::Error) {
        LOG("[CloudStorage] metadata existence check failed for %s", canonicalPath.c_str());
        return;
    }
    if (status == ICloudProvider::ExistsStatus::Exists) {
        RemoveCloudMetadataIfPresent(accountId, appId, legacyName);
    }
}

bool DownloadCloudMetadataWithLegacyFallback(uint32_t accountId, uint32_t appId,
                                                      const char* canonicalName,
                                                      const char* legacyName,
                                                      std::vector<uint8_t>& outData,
                                                      bool* outUsedLegacy) {
    outData.clear();
    if (outUsedLegacy) *outUsedLegacy = false;
    if (!g_provider || !g_provider->IsAuthenticated()) return false;

    std::string canonicalPath = CloudMetadataPath(accountId, appId, canonicalName);
    const bool cacheableMissing =
        std::string_view(canonicalName) != kCNFilename &&
        std::string_view(canonicalName) != kManifestFilename;

    if (cacheableMissing && IsKnownMissingMetadataPath(canonicalPath)) {
        if (!legacyName || !*legacyName) return false;
        std::string legacyPath = CloudMetadataPath(accountId, appId, legacyName);
        if (IsKnownMissingMetadataPath(legacyPath)) return false;
        if (!g_provider->Download(legacyPath, outData)) return false;
        if (outUsedLegacy) *outUsedLegacy = true;
        ClearMissingMetadataPath(legacyPath);
        return true;
    }

    if (g_provider->Download(canonicalPath, outData)) {
        ClearMissingMetadataPath(canonicalPath);
        return true;
    }

    if (!legacyName || !*legacyName) return false;
    auto canonicalStatus = g_provider->CheckExists(canonicalPath);
    if (canonicalStatus != ICloudProvider::ExistsStatus::Missing) {
        return false;
    }
    if (cacheableMissing) MarkMissingMetadataPath(canonicalPath);

    std::string legacyPath = CloudMetadataPath(accountId, appId, legacyName);
    if (cacheableMissing && IsKnownMissingMetadataPath(legacyPath)) return false;
    if (!g_provider->Download(legacyPath, outData)) {
        return false;
    }
    if (outUsedLegacy) *outUsedLegacy = true;
    ClearMissingMetadataPath(legacyPath);
    return true;
}

bool DownloadLegacyPlaytimeBlob(uint32_t accountId, uint32_t appId,
                                std::vector<uint8_t>& outData) {
    outData.clear();
    if (!g_provider || !g_provider->IsAuthenticated()) return false;
    std::string path = CloudBlobPath(accountId, CloudIntercept::kAccountScopeAppId,
                                     CloudIntercept::AccountPlaytimeFilename(appId));
    return g_provider->Download(path, outData) && !outData.empty();
}

static void EnqueueCloudDelete(const std::string& cloudPath) {
    CloudWorkQueue::WorkItem wi;
    wi.type = CloudWorkQueue::WorkItem::Delete;
    wi.cloudPath = cloudPath;
    CloudWorkQueue::EnqueueWork(std::move(wi));
}

static bool TryMapInternalBlobToCanonicalCloudPath(uint32_t accountId, uint32_t appId,
                                                   std::string_view filename,
                                                   std::string& outPath) {
    if (filename == CloudIntercept::kPlaytimeMetadataPath ||
        filename == CloudIntercept::kLegacyPlaytimeMetadataPath) {
        outPath = CloudBlobPath(accountId, CloudIntercept::kAccountScopeAppId,
                                CloudIntercept::AccountPlaytimeFilename(appId));
        return true;
    }
    if (filename == CloudIntercept::kStatsMetadataPath ||
        filename == CloudIntercept::kLegacyStatsMetadataPath) {
        outPath = CloudBlobPath(accountId, CloudIntercept::kAccountScopeAppId,
                                CloudIntercept::AccountStatsFilename(appId));
        return true;
    }
    if (filename == kManifestFilename || filename == kLegacyManifestFilename) {
        outPath = CloudMetadataPath(accountId, appId, kManifestFilename);
        return true;
    }
    if (filename == kCNFilename || filename == kLegacyCNFilename) {
        outPath = CloudMetadataPath(accountId, appId, kCNFilename);
        return true;
    }
    if (filename == kRootTokenFilename || filename == kLegacyRootTokenFilename) {
        outPath = CloudMetadataPath(accountId, appId, kRootTokenFilename);
        return true;
    }
    if (filename == kFileTokensFilename || filename == kLegacyFileTokensFilename) {
        outPath = CloudMetadataPath(accountId, appId, kFileTokensFilename);
        return true;
    }
    return false;
}

static void CleanupInternalBlobEntry(uint32_t accountId, uint32_t appId,
                                     const ICloudProvider::FileInfo& blobInfo,
                                     std::string_view filename) {
    if (!g_provider || !g_provider->IsAuthenticated()) return;

    if (filename == kDeletedFilename || filename == kLegacyDeletedFilename) {
        EnqueueCloudDelete(blobInfo.path);
        return;
    }

    std::string canonicalPath;
    if (!TryMapInternalBlobToCanonicalCloudPath(accountId, appId, filename, canonicalPath)) {
        LOG("[CloudStorage] SyncFromCloud app %u: deleting reserved blob %s",
            appId, blobInfo.path.c_str());
        EnqueueCloudDelete(blobInfo.path);
        return;
    }

    auto status = g_provider->CheckExists(canonicalPath);
    if (status == ICloudProvider::ExistsStatus::Error) {
        LOG("[CloudStorage] SyncFromCloud app %u: cannot verify canonical path for obsolete blob %s",
            appId, blobInfo.path.c_str());
        return;
    }

    if (status == ICloudProvider::ExistsStatus::Missing) {
        std::vector<uint8_t> data;
        if (!g_provider->Download(blobInfo.path, data)) {
            LOG("[CloudStorage] SyncFromCloud app %u: failed to read obsolete internal blob %s for migration",
                appId, blobInfo.path.c_str());
            return;
        }

        const uint8_t emptyByte = 0;
        const uint8_t* writeData = data.empty() ? &emptyByte : data.data();
        if (!g_provider->Upload(canonicalPath, writeData, data.size())) {
            LOG("[CloudStorage] SyncFromCloud app %u: failed to migrate obsolete internal blob %s -> %s",
                appId, blobInfo.path.c_str(), canonicalPath.c_str());
            return;
        }

        LOG("[CloudStorage] SyncFromCloud app %u: migrated obsolete internal blob %s -> %s",
            appId, blobInfo.path.c_str(), canonicalPath.c_str());
    }

    EnqueueCloudDelete(blobInfo.path);
}

static std::string LocalStoragePath(uint32_t accountId, uint32_t appId) {
    return g_localRoot + "storage" + kPathSepStr + std::to_string(accountId) + kPathSepStr +
           std::to_string(appId) + kPathSepStr;
}

static std::unordered_set<uint32_t> EnumerateLocalAppIds(uint32_t accountId) {
    std::unordered_set<uint32_t> appIds;
    std::string accountRoot = g_localRoot + "storage" + kPathSepStr + std::to_string(accountId) + kPathSepStr;
    std::error_code ec;
    auto accountRootPath = FileUtil::Utf8ToPath(accountRoot);
    if (!std::filesystem::exists(accountRootPath, ec) || !std::filesystem::is_directory(accountRootPath, ec)) {
        return appIds;
    }

    std::filesystem::directory_iterator it(accountRootPath, ec);
    if (ec) return appIds;
    EnumerateLocalAccountMetadataAppIds(accountRootPath, appIds);
    const std::filesystem::directory_iterator end;
    while (it != end) {
        const auto& entry = *it;
        std::error_code dirEc;
        if (entry.is_directory(dirEc)) {
            const std::string name = FileUtil::PathToUtf8(entry.path().filename());
            uint32_t parsed = 0;
            if (ParseU32(name, parsed) && parsed != CloudIntercept::kAccountScopeAppId) {
                appIds.insert(parsed);
            }
        }
        std::error_code stepEc;
        it.increment(stepEc);
        if (stepEc) break;
    }
    return appIds;
}

static std::string LocalBlobPath(uint32_t accountId, uint32_t appId,
                                 const std::string& filename) {
    // CloudStorage must be initialized before use
    if (g_localRoot.empty()) {
        LOG("[CloudStorage] ERROR: LocalBlobPath called but CloudStorage not initialized");
        return {};
    }
#ifdef _WIN32
    std::string path = g_localRoot + "storage\\" + std::to_string(accountId) +
                       "\\" + std::to_string(appId) + "\\" + filename;
    for (auto& c : path) { if (c == '/') c = '\\'; }
    std::string storageRoot = g_localRoot + "storage\\";
#else
    std::string path = g_localRoot + "storage/" + std::to_string(accountId) +
                       "/" + std::to_string(appId) + "/" + filename;
    std::string storageRoot = g_localRoot + "storage/";
#endif
    if (!FileUtil::IsPathWithin(storageRoot, path)) {
        LOG("[CloudStorage] BLOCKED path traversal: '%s' root='%s'",
            filename.c_str(), storageRoot.c_str());
        return {};
    }

    return path;
}


// Enqueue a cloud upload of the current CN value for this app.
// Dedup in EnqueueWork will coalesce multiple calls during a batch.
// --- manifest utilities needed by SyncFromCloudInner ---
// ManifestToJson lives in manifest_store.cpp; SyncFromCloudWithFlag uses
// SaveManifestLocal / SaveManifest which call through to ManifestStore.


// Drop stale conflict-copy files (>30 days) from cloud_redirect\conflicts\.
// Best-effort startup cleanup; must not escape exceptions into Init().
static void PruneStaleConflictCopies(const std::string& localRoot) {
    if (localRoot.empty()) return;
    std::string conflictsRoot = localRoot + "conflicts" + kPathSepStr;
    int removed = 0;

    try {
        std::error_code ec;
        auto conflictsRootPath = FileUtil::Utf8ToPath(conflictsRoot);
        if (!std::filesystem::exists(conflictsRootPath, ec) || ec) return;

        constexpr auto kRetention = std::chrono::hours(24 * 30);
        auto now = std::filesystem::file_time_type::clock::now();

        std::filesystem::recursive_directory_iterator it(
            conflictsRootPath, std::filesystem::directory_options::skip_permission_denied, ec);
        std::filesystem::recursive_directory_iterator end;
        if (ec) {
            LOG("[CloudStorage] PruneStaleConflictCopies: cannot open conflicts root: %s",
                ec.message().c_str());
            return;
        }
        while (it != end) {
            std::error_code entryEc;
            const auto& entry = *it;
            bool isFile = entry.is_regular_file(entryEc);
            if (!entryEc && isFile) {
                auto mtime = std::filesystem::last_write_time(entry.path(), entryEc);
                if (!entryEc && now - mtime >= kRetention) {
                    std::filesystem::remove(entry.path(), entryEc);
                    if (!entryEc) ++removed;
                }
            }
            std::error_code stepEc;
            it.increment(stepEc);
            if (stepEc) {
                LOG("[CloudStorage] PruneStaleConflictCopies: stopping early after iterator "
                    "error: %s (%d file(s) removed this run)", stepEc.message().c_str(), removed);
                break;
            }
        }
    } catch (const std::exception& ex) {
        LOG("[CloudStorage] PruneStaleConflictCopies: aborted on exception: %s", ex.what());
    } catch (...) {
        LOG("[CloudStorage] PruneStaleConflictCopies: aborted on unknown exception");
    }

    if (removed > 0) {
        LOG("[CloudStorage] PruneStaleConflictCopies: removed %d stale conflict copy file(s) from %s",
            removed, conflictsRoot.c_str());
    }
}

void Init(const std::string& localRoot, std::unique_ptr<ICloudProvider> provider) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_localRoot = localRoot;
#ifdef _WIN32
    if (!g_localRoot.empty() && g_localRoot.back() != '\\')
        g_localRoot += '\\';
#else
    if (!g_localRoot.empty() && g_localRoot.back() != '/')
        g_localRoot += '/';
#endif

    // Re-arm in case Shutdown ran earlier (in-process restart path).
    g_shuttingDown.store(false, std::memory_order_seq_cst);
    {
        std::lock_guard<std::mutex> missingLock(g_missingMetadataMutex);
        g_missingMetadataPaths.clear();
    }
    {
        std::lock_guard<std::mutex> lk(g_blobIndexMutex);
        g_blobIndex.clear();
    }
    // Do NOT zero g_foregroundSyncCount: a late ForegroundSyncScope dtor
    // would underflow it; the counter self-balances across restart.

    g_provider = std::move(provider);

    ManifestStore_Init(g_localRoot, g_provider.get());
    TokenStore_Init(g_localRoot, g_provider.get());
    AppState_Init(g_provider.get());

    LOG("[CloudStorage] Initialized. localRoot=%s provider=%s",
        g_localRoot.c_str(), g_provider ? g_provider->Name() : "none (local-only)");

    // Prune stale conflict copies once per process launch (best-effort).
    PruneStaleConflictCopies(g_localRoot);

    // Drop legacy-named Playtime.bin/UserGameStats.bin in the local blob cache
    // whenever the canonical `.cloudredirect\` sibling already exists.
    LegacyMetadataCleanup::PruneLocalBlobCache(g_localRoot);
    LegacyMetadataCleanup::PruneLocalLegacyAppMetadata(g_localRoot);

    // Start background workers via the work queue module
    CloudWorkQueue::Init(g_provider.get());
}

void Shutdown() {
    LOG("[CloudStorage] Shutting down...");
    g_shuttingDown.store(true, std::memory_order_seq_cst);
    {
        std::lock_guard<std::mutex> missingLock(g_missingMetadataMutex);
        g_missingMetadataPaths.clear();
    }

    // Signal CloudWorkQueue workers to drain and exit.
    CloudWorkQueue::SetShuttingDown();

    // Shut down background workers, clear queue, join dialog threads
    CloudWorkQueue::Shutdown();

    // Wake any thread parked on the foreground-sync gate so it observes
    // g_shuttingDown and exits before the inflight wait below.
    {
        std::lock_guard<std::mutex> g(g_foregroundSyncMutex);
        g_foregroundSyncCV.notify_all();
    }

    // Drain in-flight ops before g_provider teardown (no internal cancel). 5s cap so session switches don't lag.
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (g_inflightSyncCount.load(std::memory_order_seq_cst) > 0
               && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        int residualSync = g_inflightSyncCount.load(std::memory_order_seq_cst);
        if (residualSync > 0) {
            LOG("[CloudStorage] Shutdown: %d in-flight SyncFromCloud call(s) did not "
                "drain within 5s; leaking provider to avoid UAF", residualSync);
            (void)g_provider.release();
            g_provider = nullptr;
            return;
        }
    }

    // Null sub-module provider refs after in-flight ops have drained
    // but before destroying the provider.
    ManifestStore_Init("", nullptr);
    TokenStore_Init("", nullptr);
    AppState_Shutdown();

    if (g_provider) {
        g_provider->Shutdown();
        g_provider.reset();
    }

    LOG("[CloudStorage] Shutdown complete");
}

bool IsCloudActive() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_provider && g_provider->IsAuthenticated();
}

bool StoreBlob(uint32_t accountId, uint32_t appId,
               const std::string& filename,
               const uint8_t* data, size_t len) {
    ClearMissingMetadataForApp(accountId, appId);
    return StoreBlobStaged(accountId, appId, 0, filename, data, len);
}

static void PruneStaleCloudStaging(uint32_t accountId) {
    if (!g_provider || !g_provider->IsAuthenticated()) return;

    constexpr uint64_t STAGING_TTL_SECONDS = 24ULL * 60 * 60;
    std::string prefix = std::to_string(accountId) + "/";
    std::vector<ICloudProvider::FileInfo> files;
    bool complete = false;
    if (!g_provider->ListChecked(prefix, files, &complete) || !complete) {
        LOG("[CloudStorage] PruneStaleCloudStaging: account %u listing unavailable/incomplete; skipping",
            accountId);
        return;
    }

    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    auto stale = ClassifyStaleStagingBlobs(accountId, files, now, STAGING_TTL_SECONDS);
    size_t removed = 0;
    for (const auto& path : stale) {
        if (g_provider->Remove(path)) {
            ++removed;
        } else {
            LOG("[CloudStorage] PruneStaleCloudStaging: failed to remove %s", path.c_str());
        }
    }

    if (removed > 0) {
        LOG("[CloudStorage] PruneStaleCloudStaging: removed %zu stale staging blob(s) for account %u",
            removed, accountId);
    }
}

static bool TryReadCachedBlob(const std::string& localPath,
                              const std::string& filename,
                              std::vector<uint8_t>& out);

bool StoreBlobStaged(uint32_t accountId, uint32_t appId, uint64_t batchId,
                     const std::string& filename,
                     const uint8_t* data, size_t len) {
    if (CloudIntercept::IsReservedBlobFilename(filename)) {
        LOG("[CloudStorage] StoreBlob: rejecting reserved /blobs/ filename app=%u batch=%llu file=%s",
            appId, (unsigned long long)batchId, filename.c_str());
        return false;
    }

    // Skip re-write if cached blob has identical content (dedup by SHA).
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (!localPath.empty()) {
        std::vector<uint8_t> cached;
        if (TryReadCachedBlob(localPath, filename, cached)) {
            if (cached.size() == len &&
                (len == 0 || std::memcmp(cached.data(), data, len) == 0)) {
                LOG("[CloudStorage] StoreBlob: already cached with identical content, skipping write: %s (%zu bytes)",
                    filename.c_str(), len);
                return true;
            }
        }
    }

    // Synchronous local write via LocalStorage::WriteFileNoIncrement so it
    // serializes against SyncFromCloud staged-blob promotion under g_mutex.
    if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename, data, len)) {
        LOG("[CloudStorage] StoreBlob: local write failed: app=%u file=%s (%zu bytes)",
            appId, filename.c_str(), len);
        return false;
    }
    LOG("[CloudStorage] StoreBlob: cached locally: %s (%zu bytes)", filename.c_str(), len);

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

    if (g_provider && batchId == 0) {
        CloudWorkQueue::WorkItem wi;
        wi.type = CloudWorkQueue::WorkItem::Upload;
        if (appId == CloudIntercept::kAccountScopeAppId) {
            // Account-scope metadata: filename-addressed, no CAS.
            wi.cloudPath = CloudBlobPath(accountId, appId, filename);
        } else {
            // CAS: upload to blobs/{filename}/{sha}.
            auto sha = FileUtil::SHA1(data, len);
            std::string shaHex = ShaToHex(sha);
            wi.cloudPath = CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex);
            wi.skipIfExists = true;
        }
        wi.data.assign(data, data + len);
        CloudWorkQueue::EnqueueWork(std::move(wi));
    }

    return true;
}

// Reads the local cache copy. Returns true if the file exists and reads cleanly.
static bool TryReadCachedBlob(const std::string& localPath,
                              const std::string& filename,
                              std::vector<uint8_t>& out) {
    std::ifstream f(FileUtil::Utf8ToPath(localPath), std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto rawSize = f.tellg();
    if (rawSize < 0) {
        LOG("[CloudStorage] RetrieveBlob: cache tellg failed for %s",
            filename.c_str());
        return false;
    }
    auto size = static_cast<std::streamoff>(rawSize);
    out.resize(static_cast<size_t>(size));
    if (size == 0) return true;
    f.seekg(0, std::ios::beg);
    f.read(reinterpret_cast<char*>(out.data()), size);
    if (f.fail() || f.gcount() != size) {
        LOG("[CloudStorage] RetrieveBlob: cache read failed for %s (gcount=%lld of %lld, fail=%d)",
            filename.c_str(),
            static_cast<long long>(f.gcount()),
            static_cast<long long>(size),
            f.fail() ? 1 : 0);
        out.clear();
        return false;
    }
    return true;
}

// Resolve the actual cloud path for a blob by consulting the per-app index.
// Populates the index with a single ListChecked on first call per app.
// Returns empty string if the blob is not found in the listing.
static std::string ResolveBlobCloudPath(uint32_t accountId, uint32_t appId,
                                        const std::string& filename) {
    uint64_t key = (static_cast<uint64_t>(accountId) << 32) | appId;
    {
        std::lock_guard<std::mutex> lk(g_blobIndexMutex);
        auto it = g_blobIndex.find(key);
        if (it != g_blobIndex.end() && it->second.populated) {
            auto fit = it->second.filenameToPath.find(filename);
            if (fit != it->second.filenameToPath.end())
                return fit->second;
            return {};
        }
    }

    // Not populated yet -- list all blobs for this app.
    std::string blobPrefix = std::to_string(accountId) + "/" +
                             std::to_string(appId) + "/blobs/";
    std::vector<ICloudProvider::FileInfo> remoteBlobs;
    bool complete = false;
    if (!g_provider || !g_provider->ListChecked(blobPrefix, remoteBlobs, &complete) || !complete) {
        return {}; // listing failed; caller falls through to trial-and-error
    }

    LOG("[CloudStorage] BlobIndex: listed %zu blobs for acct %u app %u",
        remoteBlobs.size(), accountId, appId);

    BlobIndex idx;
    idx.populated = true;

    auto isHexSha = [](const std::string& s) {
        return s.size() == 40 &&
               s.find_first_not_of("0123456789abcdef") == std::string::npos;
    };

    for (const auto& fi : remoteBlobs) {
        if (fi.path.size() <= blobPrefix.size()) continue;
        std::string rel = fi.path.substr(blobPrefix.size());

        // Canonical CAS: filename/sha (leaf is 40-char hex)
        size_t lastSlash = rel.rfind('/');
        if (lastSlash != std::string::npos) {
            std::string leaf = rel.substr(lastSlash + 1);
            if (isHexSha(leaf)) {
                std::string fname = rel.substr(0, lastSlash);
                // Canonical always wins over legacy (unconditional overwrite).
                idx.filenameToPath[fname] = fi.path;
                // first writer wins; all copies byte-identical.
                idx.shaToPath.emplace(leaf, fi.path);
                continue;
            }
        }

        // Legacy SHA-only: blobs/{sha}
        if (isHexSha(rel)) {
            idx.shaToPath.emplace(rel, fi.path); // usable by content hash
            continue; // can't map to filename without manifest
        }

        // Legacy filename-only: blobs/{filename} -- only if canonical not already set.
        idx.filenameToPath.emplace(rel, fi.path);
    }

    std::string result;
    auto fit = idx.filenameToPath.find(filename);
    if (fit != idx.filenameToPath.end())
        result = fit->second;

    {
        std::lock_guard<std::mutex> lk(g_blobIndexMutex);
        // Only store if not already populated (avoids overwriting a fresher index
        // from a concurrent thread or re-inserting after invalidation).
        auto existing = g_blobIndex.find(key);
        if (existing == g_blobIndex.end() || !existing->second.populated)
            g_blobIndex[key] = std::move(idx);
    }
    return result;
}

// Resolve a blob path by CONTENT HASH (sha1hex), independent of filename. Used
// as a fallback when the {filename}/{sha} path misses because the identical
// content was uploaded under a different filename. Reuses the same index/listing
// as ResolveBlobCloudPath (no extra network on a populated index).
static std::string ResolveBlobCloudPathBySHA(uint32_t accountId, uint32_t appId,
                                             const std::string& shaHex) {
    if (shaHex.size() != 40) return {};
    uint64_t key = (static_cast<uint64_t>(accountId) << 32) | appId;
    {
        std::lock_guard<std::mutex> lk(g_blobIndexMutex);
        auto it = g_blobIndex.find(key);
        if (it != g_blobIndex.end() && it->second.populated) {
            auto sit = it->second.shaToPath.find(shaHex);
            if (sit != it->second.shaToPath.end()) return sit->second;
            return {};
        }
    }
    // Populate the index (filename resolver does the listing + fills shaToPath),
    // then re-check by sha.
    ResolveBlobCloudPath(accountId, appId, /*filename=*/std::string());
    std::lock_guard<std::mutex> lk(g_blobIndexMutex);
    auto it = g_blobIndex.find(key);
    if (it != g_blobIndex.end() && it->second.populated) {
        auto sit = it->second.shaToPath.find(shaHex);
        if (sit != it->second.shaToPath.end()) return sit->second;
    }
    return {};
}

// Invalidate the blob index for an app (called after uploads/promotions change the layout).
static void InvalidateBlobIndex(uint32_t accountId, uint32_t appId) {
    uint64_t key = (static_cast<uint64_t>(accountId) << 32) | appId;
    std::lock_guard<std::mutex> lk(g_blobIndexMutex);
    g_blobIndex.erase(key);
}

std::vector<uint8_t> RetrieveBlob(uint32_t accountId, uint32_t appId,
                                   const std::string& filename,
                                   bool* found,
                                   const std::string& expectedShaHex) {
    if (found) *found = false;
    
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return {}; // path traversal blocked

    InflightSyncScope guard;
    const bool cloudActive = guard && g_provider;

    // Account-scope: filename-addressed.
    if (cloudActive && appId == CloudIntercept::kAccountScopeAppId) {
        std::string cloudPath = CloudBlobPath(accountId, appId, filename);
        std::vector<uint8_t> data;
        if (g_provider->Download(cloudPath, data)) {
            LOG("[CloudStorage] RetrieveBlob: fetched account-scope blob: %s (%zu bytes)",
                filename.c_str(), data.size());
            const uint8_t* writeData = data.empty() ? nullptr : data.data();
            LocalStorage::WriteFileNoIncrement(accountId, appId, filename, writeData, data.size());
            if (found) *found = true;
            return data;
        }
        // Fall through to local cache
        std::vector<uint8_t> cached;
        if (TryReadCachedBlob(localPath, filename, cached)) {
            LOG("[CloudStorage] RetrieveBlob: serving account-scope from cache: %s (%zu bytes)",
                filename.c_str(), cached.size());
            if (found) *found = true;
            return cached;
        }
        LOG("[CloudStorage] RetrieveBlob: account-scope blob not found: %s", filename.c_str());
        return {};
    }

    // CAS: resolve filename->SHA, download by SHA.
    if (cloudActive) {
        // Prefer the SHA from cloud state (the record the changelist served Steam);
        // the local manifest is a cache and goes stale before a download. Priority:
        // cloud state -> local manifest (offline) -> caller's expectedShaHex.
        std::string shaHex;
        auto cloud = FetchCloudStateForServe(accountId, appId);
        if (cloud.status == StateFetchStatus::Ok) {
            auto cit = cloud.state.files.find(filename);
            if (cit != cloud.state.files.end() && !cit->second.sha.empty())
                shaHex = ShaToHex(cit->second.sha);
        }
        if (shaHex.empty()) {
            // Cloud state unavailable -> fall back to the local manifest cache.
            Manifest manifest = LoadLocalManifest(accountId, appId);
            auto mit = manifest.find(filename);
            if (mit != manifest.end() && !mit->second.sha.empty()) {
                shaHex = ShaToHex(mit->second.sha);
                LOG("[CloudStorage] RetrieveBlob: cloud state unavailable, using local manifest SHA for %s",
                    filename.c_str());
            }
        }
        if (shaHex.empty() && !expectedShaHex.empty()) {
            shaHex = expectedShaHex;
            LOG("[CloudStorage] RetrieveBlob: using caller expectedShaHex for %s", filename.c_str());
        }

        // Cache-first: caller supplied cloud-authoritative SHA (from FetchCloudState).
        // If local blob matches, skip network entirely.
        if (!expectedShaHex.empty() && expectedShaHex == shaHex) {
            std::vector<uint8_t> cached;
            if (TryReadCachedBlob(localPath, filename, cached) &&
                ShaToHex(FileUtil::SHA1(cached.data(), cached.size())) == expectedShaHex) {
                LOG("[CloudStorage] RetrieveBlob: cache hit (cloud SHA match): %s (%zu bytes)",
                    filename.c_str(), cached.size());
                if (found) *found = true;
                return cached;
            }
        }

        if (!shaHex.empty()) {
            std::vector<uint8_t> data;
            std::string canonicalPath = CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex);

            // Fast path: use blob index to resolve actual path in one call.
            std::string resolved = ResolveBlobCloudPath(accountId, appId, filename);
            if (!resolved.empty() && g_provider->Download(resolved, data)) {
                // Verify content SHA matches the manifest-expected hash.
                std::string actualSha = ShaToHex(FileUtil::SHA1(data.data(), data.size()));
                if (actualSha != shaHex) {
                    LOG("[CloudStorage] RetrieveBlob: SHA MISMATCH via index %s: expected=%s actual=%s, rejecting",
                        resolved.c_str(), shaHex.c_str(), actualSha.c_str());
                    data.clear();
                    // Fall through to the manual fallback paths below.
                } else {
                bool isCanonical = (resolved == canonicalPath);
                LOG("[CloudStorage] RetrieveBlob: fetched via index (%s): %s (%zu bytes)",
                    isCanonical ? "CAS" : "legacy", filename.c_str(), data.size());
                const uint8_t* writeData = data.empty() ? nullptr : data.data();
                LocalStorage::WriteFileNoIncrement(accountId, appId, filename, writeData, data.size());
                // Promote non-canonical to CAS in background.
                // (actualSha already verified == shaHex above)
                if (!isCanonical) {
                    CloudWorkQueue::WorkItem upload;
                    upload.type = CloudWorkQueue::WorkItem::Upload;
                    upload.cloudPath = canonicalPath;
                    upload.data = data;
                    upload.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(upload));

                    CloudWorkQueue::WorkItem del;
                    del.type = CloudWorkQueue::WorkItem::Delete;
                    del.cloudPath = resolved;
                    del.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(del));
                }
                if (found) *found = true;
                return data;
                } // end SHA-match else
            }

            // Fallback: index miss or download failed -- try each path variant.

            // 1. Canonical: blobs/{filename}/{sha}
            if (g_provider->Download(canonicalPath, data)) {
                // SHA verification: provider should serve content matching
                // the SHA-addressed path. Mismatch indicates provider corruption or bug.
                std::string actualSha = ShaToHex(FileUtil::SHA1(data.data(), data.size()));
                if (actualSha != shaHex) {
                    LOG("[CloudStorage] RetrieveBlob: SHA MISMATCH on canonical path %s: expected=%s actual=%s, rejecting",
                        canonicalPath.c_str(), shaHex.c_str(), actualSha.c_str());
                    data.clear();
                } else {
                    LOG("[CloudStorage] RetrieveBlob: fetched from cloud (CAS %s): %s (%zu bytes)",
                        shaHex.c_str(), filename.c_str(), data.size());
                    const uint8_t* writeData = data.empty() ? nullptr : data.data();
                    if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                                        writeData, data.size())) {
                        LOG("[CloudStorage] RetrieveBlob: WARNING - failed to cache %s locally, serving from cloud only",
                            filename.c_str());
                    }
                    if (found) *found = true;
                    return data;
                }
            }

            // 2. Legacy CAS layout: blobs/{sha} (from previous SHA-only CAS).
            std::string legacyShaPath = CloudBlobPathBySHA(accountId, appId, shaHex);
            if (g_provider->Download(legacyShaPath, data)) {
                std::string actualSha = ShaToHex(FileUtil::SHA1(data.data(), data.size()));
                if (actualSha != shaHex) {
                    LOG("[CloudStorage] RetrieveBlob: SHA MISMATCH on legacy CAS path %s: expected=%s actual=%s, rejecting",
                        legacyShaPath.c_str(), shaHex.c_str(), actualSha.c_str());
                    data.clear();
                } else {
                    LOG("[CloudStorage] RetrieveBlob: fetched from legacy CAS path (sha=%s): %s (%zu bytes)",
                        shaHex.c_str(), filename.c_str(), data.size());
                    const uint8_t* writeData = data.empty() ? nullptr : data.data();
                    if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                                        writeData, data.size())) {
                        LOG("[CloudStorage] RetrieveBlob: WARNING - failed to cache %s locally (legacy CAS fallback)",
                            filename.c_str());
                    }
                    // Promote to canonical CAS path in background.
                    CloudWorkQueue::WorkItem upload;
                    upload.type = CloudWorkQueue::WorkItem::Upload;
                    upload.cloudPath = canonicalPath;
                    upload.data = data;
                    upload.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(upload));

                    CloudWorkQueue::WorkItem del;
                    del.type = CloudWorkQueue::WorkItem::Delete;
                    del.cloudPath = legacyShaPath;
                    del.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(del));

                    if (found) *found = true;
                    return data;
                }
            }

            // 3. Pre-CAS legacy: blobs/{filename}
            std::string legacyPath = CloudBlobPath(accountId, appId, filename);
            if (g_provider->Download(legacyPath, data)) {
                std::string actualSha = ShaToHex(FileUtil::SHA1(data.data(), data.size()));
                if (actualSha != shaHex) {
                    LOG("[CloudStorage] RetrieveBlob: SHA MISMATCH on legacy path %s: expected=%s actual=%s, rejecting",
                        legacyPath.c_str(), shaHex.c_str(), actualSha.c_str());
                    data.clear();
                } else {
                    LOG("[CloudStorage] RetrieveBlob: fetched from legacy filename path: %s (%zu bytes)",
                        filename.c_str(), data.size());
                    const uint8_t* writeData = data.empty() ? nullptr : data.data();
                    if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                                        writeData, data.size())) {
                        LOG("[CloudStorage] RetrieveBlob: WARNING - failed to cache %s locally (legacy fallback)",
                            filename.c_str());
                    }
                    // Promote to CAS in background so next download hits on first try.
                    CloudWorkQueue::WorkItem upload;
                    upload.type = CloudWorkQueue::WorkItem::Upload;
                    upload.cloudPath = canonicalPath;
                    upload.data = data;
                    upload.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(upload));

                    CloudWorkQueue::WorkItem del;
                    del.type = CloudWorkQueue::WorkItem::Delete;
                    del.cloudPath = legacyPath;
                    del.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(del));

                    if (found) *found = true;
                    return data;
                }
            }

            // 4. Content-hash fallback: bytes for this SHA may live under a different
            //    filename's CAS dir (see shaToPath). Serve any path holding the SHA --
            //    byte-identical by definition.
            std::string shaPath = ResolveBlobCloudPathBySHA(accountId, appId, shaHex);
            if (!shaPath.empty() && shaPath != canonicalPath &&
                g_provider->Download(shaPath, data)) {
                std::string actualSha = ShaToHex(FileUtil::SHA1(data.data(), data.size()));
                if (actualSha != shaHex) {
                    LOG("[CloudStorage] RetrieveBlob: SHA MISMATCH on content-hash path %s: expected=%s actual=%s, rejecting",
                        shaPath.c_str(), shaHex.c_str(), actualSha.c_str());
                    data.clear();
                } else {
                    LOG("[CloudStorage] RetrieveBlob: fetched by content hash (sha=%s, stored under other filename %s): %s (%zu bytes)",
                        shaHex.c_str(), shaPath.c_str(), filename.c_str(), data.size());
                    const uint8_t* writeData = data.empty() ? nullptr : data.data();
                    LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                                       writeData, data.size());
                    // Promote a copy to this filename's canonical path so the next
                    // request hits first try. Don't delete the source -- another
                    // filename references it.
                    CloudWorkQueue::WorkItem upload;
                    upload.type = CloudWorkQueue::WorkItem::Upload;
                    upload.cloudPath = canonicalPath;
                    upload.data = data;
                    upload.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(upload));

                    if (found) *found = true;
                    return data;
                }
            }
        } else {
            // No SHA in manifest -- try legacy filename path.
            std::string legacyPath = CloudBlobPath(accountId, appId, filename);
            std::vector<uint8_t> data;
            if (g_provider->Download(legacyPath, data)) {
                LOG("[CloudStorage] RetrieveBlob: fetched from legacy path (no manifest SHA): %s (%zu bytes)",
                    filename.c_str(), data.size());
                const uint8_t* writeData = data.empty() ? nullptr : data.data();
                if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                                    writeData, data.size())) {
                    LOG("[CloudStorage] RetrieveBlob: WARNING - failed to cache %s locally (legacy, no SHA)",
                        filename.c_str());
                }
                if (found) *found = true;
                return data;
            }
        }

        // Cloud failed -- fall back to the local cache only if its SHA matches what
        // the server published. Serving mismatched bytes would look synced but be
        // stale, so prefer failing the download (Steam retries) over that.
        std::vector<uint8_t> cached;
        if (TryReadCachedBlob(localPath, filename, cached)) {
            if (!shaHex.empty()) {
                auto cachedSha = ShaToHex(FileUtil::SHA1(cached.data(), cached.size()));
                if (cachedSha == shaHex) {
                    // The download failed but our cache matches the manifest SHA.
                    // Native, on a download 404 with a local copy present, flags the
                    // file to UPLOAD (heal). Mirror that only when the blob is
                    // genuinely absent (confirmed Missing) -- not on a transient
                    // provider error, where the blob still exists and re-uploading
                    // would be wasteful. CheckExists is one extra round-trip, but we
                    // are already on the degraded path (every Download above failed).
                    std::string casPath =
                        CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex);
                    if (g_provider->CheckExists(casPath) ==
                            ICloudProvider::ExistsStatus::Missing) {
                        LOG("[CloudStorage] RetrieveBlob: cloud blob missing, healing from cache "
                            "(re-upload) and serving: %s (%zu bytes)", filename.c_str(), cached.size());
                        CloudWorkQueue::WorkItem heal;
                        heal.type = CloudWorkQueue::WorkItem::Upload;
                        heal.cloudPath = std::move(casPath);
                        heal.data = cached;
                        heal.bestEffort = true;
                        CloudWorkQueue::EnqueueWork(std::move(heal));
                    } else {
                        LOG("[CloudStorage] RetrieveBlob: cloud unavailable (transient), serving cache: "
                            "%s (%zu bytes)", filename.c_str(), cached.size());
                    }
                    if (found) *found = true;
                    return cached;
                }
                LOG("[CloudStorage] RetrieveBlob: cloud unavailable, cache SHA MISMATCH (have %s, need %s): %s -- not serving stale",
                    cachedSha.c_str(), shaHex.c_str(), filename.c_str());
            } else {
                LOG("[CloudStorage] RetrieveBlob: cloud unavailable, no authoritative SHA for %s, serving cached (%zu bytes)",
                    filename.c_str(), cached.size());
                if (found) *found = true;
                return cached;
            }
        }
        
        LOG("[CloudStorage] RetrieveBlob: not found anywhere: %s", filename.c_str());
        return {};
    }

    // Cloud not active - use local cache only
    std::vector<uint8_t> cached;
    if (TryReadCachedBlob(localPath, filename, cached)) {
        LOG("[CloudStorage] RetrieveBlob: cache hit (no cloud): %s (%zu bytes)",
            filename.c_str(), cached.size());
        if (found) *found = true;
        return cached;
    }

    LOG("[CloudStorage] RetrieveBlob: not found (no cloud): %s", filename.c_str());
    return {};
}

bool DeleteBlob(uint32_t accountId, uint32_t appId,
                const std::string& filename) {
    if (!DeleteBlobStaged(accountId, appId, filename)) return false;
    if (g_provider) {
        if (appId == CloudIntercept::kAccountScopeAppId) {
            // Account-scope: filename-addressed, immediate cloud delete.
            CloudWorkQueue::WorkItem wi;
            wi.type = CloudWorkQueue::WorkItem::Delete;
            wi.cloudPath = CloudBlobPath(accountId, appId, filename);
            CloudWorkQueue::EnqueueWork(std::move(wi));
        }
        // CAS: don't delete cloud blobs inline; GC reclaims orphans.
    }
    return true;
}

bool DeleteBlobStaged(uint32_t accountId, uint32_t appId,
                      const std::string& filename) {
    if (CloudIntercept::IsReservedBlobFilename(filename)) {
        LOG("[CloudStorage] DeleteBlob: rejecting reserved /blobs/ filename app=%u file=%s",
            appId, filename.c_str());
        return false;
    }

    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return false; // path traversal blocked
    std::error_code ec;
    std::filesystem::remove(FileUtil::Utf8ToPath(localPath), ec);

    // Empty-parent cleanup routed through LocalStorage to share the
    // WriteFileNoIncrement mutex (avoids TOCTOU on concurrent writes).
    std::filesystem::path fileParent = FileUtil::Utf8ToPath(localPath).parent_path();
    LocalStorage::CleanupEmptyCacheDirs(accountId, appId, {FileUtil::PathToUtf8(fileParent)});

    LOG("[CloudStorage] DeleteBlob: removed local cache: %s", filename.c_str());

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

    return true;
}

// Ensure every file in `state` has its blob durable on the provider before the
// manifest is published: re-upload from the local cache (heal) or drop the entry
// (forget) rather than advertise a blob that 404s elsewhere. Returns false only
// when the cloud listing is unavailable (can't tell durable from phantom).
bool VerifyAndHealManifestForPublish(uint32_t accountId, uint32_t appId,
                                     CloudAppState& state,
                                     const std::unordered_set<std::string>* confirmedDurable) {
    if (state.files.empty()) return true;

    InflightSyncScope guard;
    if (!guard) return true;                 // shutting down: leave state untouched
    if (!g_provider || !g_provider->IsAuthenticated())
        return true;                         // local-only: nothing to verify against

    // Account-scope metadata is filename-addressed, not CAS; skip.
    if (appId == CloudIntercept::kAccountScopeAppId) return true;

    // Skip blob re-listing for a file whose content hash is in the session durable
    // cache. Sha-keyed only: the cache holds the shas the promote actually uploaded
    // (RecordDurableBlobShas, populated before this runs). Filename is not trusted --
    // fe.sha may differ from the uploaded sha, which could skip a stale CAS path. If
    // every file qualifies the ~20s GDrive walk is skipped; a mixed state still lists
    // the unconfirmed remainder. confirmedDurable is kept for ABI but no longer read.
    auto durableWithoutListing = [&](const std::string& filename,
                                     const FileEntry& fe) -> bool {
        (void)filename;
        (void)confirmedDurable;
        std::string shaHex = fe.sha.empty() ? std::string() : ShaToHex(fe.sha);
        return !shaHex.empty() && IsBlobShaDurableThisSession(accountId, appId, shaHex);
    };

    {
        bool allConfirmed = true;
        for (const auto& [filename, fe] : state.files) {
            if (!durableWithoutListing(filename, fe)) { allConfirmed = false; break; }
        }
        if (allConfirmed) {
            LOG("[CloudStorage] VerifyManifest app %u: all %zu file(s) confirmed durable "
                "this session; skipping blob listing",
                appId, state.files.size());
            return true;
        }
    }

    std::string blobPrefix = std::to_string(accountId) + "/" +
                             std::to_string(appId) + "/blobs/";
    std::vector<ICloudProvider::FileInfo> remoteBlobs;
    bool complete = false;
    if (!g_provider->ListChecked(blobPrefix, remoteBlobs, &complete) || !complete) {
        LOG("[CloudStorage] VerifyManifest app %u: blob listing unavailable; not publishing",
            appId);
        return false;
    }

    // Build the set of SHAs and legacy paths actually present on the provider.
    auto isHexSha = [](const std::string& s) {
        return s.size() == 40 &&
               s.find_first_not_of("0123456789abcdef") == std::string::npos;
    };
    std::unordered_set<std::string> cloudShas;        // sha hex present (canonical or legacy CAS)
    std::unordered_set<std::string> cloudFilenames;   // legacy filename-addressed blobs present
    for (const auto& fi : remoteBlobs) {
        if (fi.path.size() <= blobPrefix.size()) continue;
        std::string rel = fi.path.substr(blobPrefix.size());
        size_t lastSlash = rel.rfind('/');
        if (lastSlash != std::string::npos && isHexSha(rel.substr(lastSlash + 1))) {
            cloudShas.insert(rel.substr(lastSlash + 1));         // canonical filename/sha
        } else if (isHexSha(rel)) {
            cloudShas.insert(rel);                               // legacy blobs/sha
        } else {
            cloudFilenames.insert(rel);                          // legacy blobs/filename
        }
    }

    std::vector<std::string> healed, dropped;
    for (auto it = state.files.begin(); it != state.files.end(); ) {
        const std::string& filename = it->first;
        const FileEntry& fe = it->second;

        // Sha confirmed durable this session: durable by definition, no need to consult
        // the listing (it may even race a just-completed upload's eventual-consistency
        // window). Trust the upload 2xx, exactly as native trusts EResult.
        if (durableWithoutListing(filename, fe)) { ++it; continue; }

        std::string shaHex = fe.sha.empty() ? std::string() : ShaToHex(fe.sha);
        bool present = (!shaHex.empty() && cloudShas.count(shaHex) > 0) ||
                       cloudFilenames.count(filename) > 0;
        if (present) { ++it; continue; }

        // Blob missing on cloud. Heal from the local cache only if it still hashes
        // to the entry's SHA; otherwise it diverged, so drop the entry.
        if (!shaHex.empty()) {
            std::vector<uint8_t> local = LocalStorage::ReadFile(accountId, appId, filename);
            bool localMatches = (ShaToHex(FileUtil::SHA1(local.data(), local.size())) == shaHex);
            if (localMatches) {
                ICloudProvider::UploadItem item;
                item.path = CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex);
                item.data = std::move(local);
                std::vector<ICloudProvider::UploadItem> one;
                one.push_back(std::move(item));
                if (g_provider->UploadBatch(one)) {
                    healed.push_back(filename);
                    ++it;
                    continue;
                }
                LOG("[CloudStorage] VerifyManifest app %u: heal upload failed for %s",
                    appId, filename.c_str());
                // Upload failed -> not durable; drop so we never advertise it.
            }
        }

        dropped.push_back(filename);
        it = state.files.erase(it);
    }

    if (!healed.empty() || !dropped.empty()) {
        InvalidateBlobIndex(accountId, appId);
        LOG("[CloudStorage] VerifyManifest app %u: healed %zu, dropped %zu phantom file(s)",
            appId, healed.size(), dropped.size());
    }
    return true;
}

bool PromoteStagedBatchForCommit(uint32_t accountId, uint32_t appId,
                                  uint64_t batchId,
                                  const std::vector<std::string>& uploads,
                                  const std::vector<std::string>& deletes) {
    InflightSyncScope syncGuard;
    if (!syncGuard) return false;

    auto mtx = AcquireAppSyncMutex(accountId, appId);
    std::lock_guard<std::mutex> lock(*mtx);

    if (!CloudWorkQueue::DrainQueueForApp(accountId, appId)) {
        LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: pre-promotion drain failed",
            appId, (unsigned long long)batchId);
        return false;
    }

    if (!g_provider || !g_provider->IsAuthenticated()) {
        LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: cloud provider unavailable, failing batch",
            appId, (unsigned long long)batchId);
        return false;
    }

    // CAS: no rollback needed -- re-upload is idempotent, GC reclaims orphans.

    std::vector<ICloudProvider::UploadItem> batchItems;
    batchItems.reserve(uploads.size());
    std::vector<std::string> batchShaHexes;       // content hashes promoted this batch
    batchShaHexes.reserve(uploads.size());

    for (const auto& filename : uploads) {
        if (CloudIntercept::IsReservedBlobFilename(filename)) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: rejecting reserved /blobs/ filename %s",
                appId, (unsigned long long)batchId, filename.c_str());
            return false;
        }

        std::string localPath = LocalBlobPath(accountId, appId, filename);
        std::vector<uint8_t> data;
        if (!TryReadCachedBlob(localPath, filename, data)) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: cached upload missing for %s",
                appId, (unsigned long long)batchId, filename.c_str());
            return false;
        }

        // CAS: upload to blobs/{filename}/{sha}; skip if already exists.
        auto sha = FileUtil::SHA1(data.data(), data.size());
        std::string shaHex = ShaToHex(sha);
        ICloudProvider::UploadItem item;
        item.path = CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex);
        item.data = std::move(data);
        batchItems.push_back(std::move(item));
        batchShaHexes.push_back(std::move(shaHex));
    }

    if (!batchItems.empty()) {
        // CAS dedup is now done per-file INSIDE UploadBatch's parallel workers
        // (native-faithful: mirrors ClientBeginFileUpload's server-side EResult-29
        // short-circuit), so the prior serial CheckExists pre-pass is gone -- it
        // was ~100 sequential round-trips on Steam's thread before the parallel
        // upload even started.
        if (!g_provider->UploadBatch(batchItems)) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: batch upload failed",
                appId, (unsigned long long)batchId);
            return false;
        }
        // UploadBatch==true => every blob is provider-confirmed durable (2xx or
        // CAS-Exists). Record their hashes so a later batch's publish can skip
        // re-listing them (the session lock guarantees no other machine removes them).
        RecordDurableBlobShas(accountId, appId, batchShaHexes);
    }

    // CAS: deletes don't remove cloud blobs; GC reclaims orphans.
    if (!deletes.empty()) {
        LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: %zu delete(s) deferred to GC",
            appId, (unsigned long long)batchId, deletes.size());
    }

    LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: promoted %zu upload(s), %zu delete(s)",
        appId, (unsigned long long)batchId, uploads.size(), deletes.size());
    InvalidateBlobIndex(accountId, appId);
    return true;
}

std::vector<uint64_t> ListStagedBatchIds(uint32_t accountId, uint32_t appId) {
    std::vector<uint64_t> batchIds;
    InflightSyncScope guard;
    if (!guard) return batchIds;
    if (!g_provider || !g_provider->IsAuthenticated()) return batchIds;

    std::string prefix = std::to_string(accountId) + "/" + std::to_string(appId) + "/staging/";
    std::vector<ICloudProvider::FileInfo> files;
    bool complete = false;
    if (!g_provider->ListChecked(prefix, files, &complete) || !complete) {
        LOG("[CloudStorage] ListStagedBatchIds app %u: provider staging listing unavailable/incomplete",
            appId);
        return {};
    }

    std::unordered_set<uint64_t> seen;
    for (const auto& file : files) {
        uint32_t parsedAccountId = 0;
        uint32_t parsedAppId = 0;
        uint64_t parsedBatchId = 0;
        std::string filename;
        if (!ParseCloudStagedBlobPath(file.path, parsedAccountId, parsedAppId, parsedBatchId, filename)) {
            continue;
        }
        if (parsedAccountId != accountId || parsedAppId != appId) continue;
        if (seen.insert(parsedBatchId).second) {
            batchIds.push_back(parsedBatchId);
        }
    }
    std::sort(batchIds.begin(), batchIds.end());
    return batchIds;
}

bool RemoveStagedBatch(uint32_t accountId, uint32_t appId, uint64_t batchId) {
    auto mtx = AcquireAppSyncMutex(accountId, appId);
    std::lock_guard<std::mutex> lock(*mtx);

    InflightSyncScope guard;
    if (!guard) return false;
    if (!g_provider || !g_provider->IsAuthenticated()) return true;

    std::string prefix = std::to_string(accountId) + "/" + std::to_string(appId) +
                         "/staging/" + std::to_string(batchId) + "/blobs/";
    std::vector<ICloudProvider::FileInfo> files;
    bool complete = false;
    if (!g_provider->ListChecked(prefix, files, &complete) || !complete) {
        LOG("[CloudStorage] RemoveStagedBatch app %u batch %llu: listing unavailable/incomplete",
            appId, (unsigned long long)batchId);
        return false;
    }

    for (const auto& file : files) {
        if (!g_provider->Remove(file.path)) {
            LOG("[CloudStorage] RemoveStagedBatch app %u batch %llu: failed to remove %s",
                appId, (unsigned long long)batchId, file.path.c_str());
            return false;
        }
    }
    return true;
}

ICloudProvider::ExistsStatus CheckBlobExists(uint32_t accountId, uint32_t appId,
                                             const std::string& filename) {
    // Check local cache first
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return ICloudProvider::ExistsStatus::Error;  // path traversal rejected
    // Single status() call avoids the exists()/is_regular_file() TOCTOU race.
    std::error_code statEc;
    auto st = std::filesystem::status(FileUtil::Utf8ToPath(localPath), statEc);
    if (!statEc && std::filesystem::is_regular_file(st))
        return ICloudProvider::ExistsStatus::Exists;

    // Check cloud
    InflightSyncScope guard;
    if (guard && g_provider) {
        if (appId == CloudIntercept::kAccountScopeAppId) {
            // Account-scope: filename-addressed.
            return g_provider->CheckExists(CloudBlobPath(accountId, appId, filename));
        }
        // CAS: resolve filename->SHA, probe canonical/legacy-CAS/legacy-filename.
        Manifest manifest = LoadLocalManifest(accountId, appId);
        auto mit = manifest.find(filename);
        if (mit != manifest.end() && !mit->second.sha.empty()) {
            std::string shaHex = ShaToHex(mit->second.sha);
            std::string canonicalPath = CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex);
            auto status = g_provider->CheckExists(canonicalPath);
            if (status == ICloudProvider::ExistsStatus::Exists) return status;

            std::string legacyShaPath = CloudBlobPathBySHA(accountId, appId, shaHex);
            status = g_provider->CheckExists(legacyShaPath);
            if (status == ICloudProvider::ExistsStatus::Exists) return status;
        }
        // No SHA or probes missed -- try pre-CAS filename path.
        std::string legacyPath = CloudBlobPath(accountId, appId, filename);
        return g_provider->CheckExists(legacyPath);
    }

    return ICloudProvider::ExistsStatus::Missing;
}

bool ListRemoteBlobNames(uint32_t accountId, uint32_t appId,
                         std::unordered_set<std::string>& outNames) {
    outNames.clear();

    // CAS: manifest is authoritative for filename->SHA mapping.
    // Trust manifest (published after blobs uploaded) rather than per-file probes.
    Manifest manifest = LoadLocalManifest(accountId, appId);
    for (const auto& [filename, entry] : manifest) {
        if (CloudIntercept::IsReservedBlobFilename(filename)) continue;
        if (entry.sha.empty()) continue;
        outNames.insert(filename);
    }

    // Also check for legacy filename-addressed blobs from pre-CAS layout.
    InflightSyncScope guard;
    if (guard && g_provider && g_provider->IsAuthenticated()) {
        std::string blobPrefix = std::to_string(accountId) + "/" +
                                 std::to_string(appId) + "/blobs/";
        std::vector<ICloudProvider::FileInfo> remoteBlobs;
        bool complete = false;
        if (g_provider->ListChecked(blobPrefix, remoteBlobs, &complete) && complete) {
            for (const auto& fi : remoteBlobs) {
                uint32_t parsedAccountId = 0;
                uint32_t parsedAppId = 0;
                std::string remoteName;
                if (!ParseCloudBlobPath(fi.path, parsedAccountId, parsedAppId, remoteName)) continue;
                if (parsedAccountId != accountId || parsedAppId != appId) continue;
                // Legacy blobs have filename-like names (contain '/' or '.').
                // CAS blobs are pure 40-char hex. Skip CAS SHA names.
                if (remoteName.size() == 40 &&
                    remoteName.find_first_not_of("0123456789abcdef") == std::string::npos) {
                    continue; // SHA-addressed blob, already covered by manifest
                }
                remoteName = CanonicalizeInternalMetadataName(remoteName);
                if (CloudIntercept::IsReservedBlobFilename(remoteName)) continue;
                outNames.insert(std::move(remoteName));
            }
        }
    }

    return true;
}

// Mirror of CheckBlobExists's local-stat half; kept in sync so the
// BootstrapAutoCloudFilesWorker pre/post-lock checks agree on cache state.
bool HasLocalBlob(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return false;
    std::error_code statEc;
    auto st = std::filesystem::status(FileUtil::Utf8ToPath(localPath), statEc);
    return !statEc && std::filesystem::is_regular_file(st);
}


// GC: delete unreferenced blobs. Keeps manifest-referenced canonical and
// legacy-SHA blobs; deletes everything else. Requires complete listing.
// Returns count deleted, or -1 on error.
int GarbageCollectBlobs(uint32_t accountId, uint32_t appId) {
    if (appId == CloudIntercept::kAccountScopeAppId) {
        LOG("[GC] Skipping GC for account-scope (appId=0) -- filename-addressed");
        return 0;
    }

    InflightSyncScope guard;
    if (!guard || !g_provider || !g_provider->IsAuthenticated()) {
        LOG("[GC] app=%u: provider unavailable, skipping", appId);
        return -1;
    }

    std::string blobPrefix = std::to_string(accountId) + "/" +
                             std::to_string(appId) + "/blobs/";
    std::vector<ICloudProvider::FileInfo> remoteBlobs;
    bool complete = false;
    if (!g_provider->ListChecked(blobPrefix, remoteBlobs, &complete) || !complete) {
        LOG("[GC] app=%u: listing incomplete or failed, refusing GC", appId);
        return -1;
    }

    if (remoteBlobs.empty()) {
        LOG("[GC] app=%u: no cloud blobs, nothing to GC", appId);
        return 0;
    }

    // Build the keep-set from the authoritative cloud state, not the local manifest.
    // The manifest is only a cache and is routinely incomplete (2nd device, post-wipe),
    // so using it caused GC to delete blobs other machines still reference. If we
    // can't see the authoritative reference set, we must not delete anything.
    CloudStorage::StateFetchResult cloudState = FetchCloudState(accountId, appId);
    if (cloudState.status != CloudStorage::StateFetchStatus::Ok) {
        LOG("[GC] app=%u: cloud state unavailable (status=%d) -- refusing GC to avoid deleting referenced blobs",
            appId, (int)cloudState.status);
        return -1;
    }

    // Keep-set = union of cloud-state files and local manifest (local may hold a
    // freshly-uploaded file not yet in the fetched state). Keyed by both canonical
    // path AND content SHA (see step 1 below for why the SHA key matters).
    std::unordered_set<std::string> keepCanonicalPaths;
    std::unordered_set<std::string> keepLegacySHAs;   // also: any referenced content SHA
    struct ManifestRef {
        std::string canonicalPath;
        std::string shaHex;
    };
    std::unordered_map<std::string, ManifestRef> filenameToManifestRef;

    auto addRef = [&](const std::string& filename, const std::vector<uint8_t>& sha) {
        if (sha.empty()) return;
        std::string shaHex = ShaToHex(sha);
        std::string canonPath =
            CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex);
        keepCanonicalPaths.insert(canonPath);
        keepLegacySHAs.insert(shaHex);
        filenameToManifestRef[filename] = {canonPath, shaHex};
    };

    for (const auto& [filename, fe] : cloudState.state.files)
        addRef(filename, fe.sha);

    Manifest manifest = LoadLocalManifest(accountId, appId);
    for (const auto& [filename, entry] : manifest)
        addRef(filename, entry.sha);

    // Collect the set of canonical paths that actually exist on the provider.
    std::unordered_set<std::string> existingCanonicalPaths;

    auto isHexSha = [](const std::string& s) {
        return s.size() == 40 &&
               s.find_first_not_of("0123456789abcdef") == std::string::npos;
    };

    for (const auto& fi : remoteBlobs) {
        if (fi.path.size() <= blobPrefix.size()) continue;
        std::string rel = fi.path.substr(blobPrefix.size());
        size_t lastSlash = rel.rfind('/');
        if (lastSlash != std::string::npos) {
            std::string leaf = rel.substr(lastSlash + 1);
            if (isHexSha(leaf) && keepCanonicalPaths.count(fi.path)) {
                existingCanonicalPaths.insert(fi.path);
            }
        }
    }

    std::vector<std::string> orphans;
    // Legacy blobs whose canonical CAS equivalent is missing -- promote these.
    struct PromoteEntry {
        std::string legacyPath;
        std::string canonicalPath;
        std::string expectedShaHex;
    };
    std::vector<PromoteEntry> promotions;

    for (const auto& fi : remoteBlobs) {
        if (fi.path.size() <= blobPrefix.size()) continue;
        std::string rel = fi.path.substr(blobPrefix.size());

        // 1. Canonical path blobs/{filename}/{sha}: keep iff the exact path is
        //    referenced OR its content SHA is referenced by ANY file. The SHA
        //    check is essential: identical-content files share ONE physical blob
        //    (stored under the first filename), so the other filenames' canonical
        //    paths don't exist on Drive -- without the SHA keep, the shared blob
        //    would be deleted and every referencing file would 404.
        size_t lastSlash = rel.rfind('/');
        if (lastSlash != std::string::npos) {
            std::string leaf = rel.substr(lastSlash + 1);
            if (isHexSha(leaf)) {
                bool referenced = keepCanonicalPaths.count(fi.path) != 0 ||
                                  keepLegacySHAs.count(leaf) != 0;
                if (!referenced) {
                    orphans.push_back(fi.path);
                }
                continue;
            }
        }

        // 2. Legacy CAS: blobs/{sha} -- keep iff sha referenced.
        if (isHexSha(rel)) {
            if (keepLegacySHAs.count(rel) == 0) {
                orphans.push_back(fi.path);
            }
            continue;
        }

        // 3. Pre-CAS filename-only blob.
        auto it = filenameToManifestRef.find(rel);
        if (it != filenameToManifestRef.end() &&
            existingCanonicalPaths.count(it->second.canonicalPath) == 0) {
            // Manifest references this file but canonical CAS blob is missing.
            // Promote legacy blob to canonical path instead of deleting.
            promotions.push_back({fi.path, it->second.canonicalPath, it->second.shaHex});
        } else {
            orphans.push_back(fi.path);
        }
    }

    // Promote legacy blobs to canonical CAS paths (with SHA verification).
    int promoted = 0;
    for (const auto& p : promotions) {
        std::vector<uint8_t> data;
        if (!g_provider->Download(p.legacyPath, data)) {
            LOG("[GC] app=%u: promote failed (download): %s", appId, p.legacyPath.c_str());
            continue;
        }
        // Verify content matches the manifest SHA before promoting.
        std::string actualSha = ShaToHex(FileUtil::SHA1(data.data(), data.size()));
        if (actualSha != p.expectedShaHex) {
            LOG("[GC] app=%u: promote skipped (SHA mismatch): %s actual=%s expected=%s",
                appId, p.legacyPath.c_str(), actualSha.c_str(), p.expectedShaHex.c_str());
            // Stale blob -- delete it like a normal orphan.
            g_provider->Remove(p.legacyPath);
            continue;
        }
        if (!g_provider->Upload(p.canonicalPath, data.data(), data.size())) {
            LOG("[GC] app=%u: promote failed (upload): %s -> %s",
                appId, p.legacyPath.c_str(), p.canonicalPath.c_str());
            continue;
        }
        // Legacy copy is now redundant -- delete it.
        g_provider->Remove(p.legacyPath);
        ++promoted;
        LOG("[GC] app=%u: promoted legacy blob: %s -> %s",
            appId, p.legacyPath.c_str(), p.canonicalPath.c_str());
    }
    if (promoted > 0) {
        LOG("[GC] app=%u: promoted %d/%zu legacy blob(s) to CAS",
            appId, promoted, promotions.size());
    }

    if (orphans.empty()) {
        LOG("[GC] app=%u: all %zu cloud blobs are referenced, nothing to GC",
            appId, remoteBlobs.size());
        return promoted;
    }

    LOG("[GC] app=%u: found %zu orphaned blobs out of %zu total, deleting...",
        appId, orphans.size(), remoteBlobs.size());

    int deleted = 0;
    for (const auto& path : orphans) {
        if (g_provider->Remove(path)) {
            ++deleted;
        } else {
            LOG("[GC] app=%u: failed to delete blob %s", appId, path.c_str());
        }
    }

    LOG("[GC] app=%u: deleted %d/%zu orphaned blobs", appId, deleted, orphans.size());
    InvalidateBlobIndex(accountId, appId);
    return deleted + promoted;
}

// Atomic small-text write (.tmp + rename) into local storage.
static bool WriteLocalText(const std::string& path, const std::string& content) {
    auto parent = FileUtil::Utf8ToPath(path).parent_path();
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        LOG("[CloudStorage] WriteLocalText: failed to create parent %s: %s",
            FileUtil::PathToUtf8(parent).c_str(), ec.message().c_str());
        return false;
    }
    return FileUtil::AtomicWriteText(path, content);
}




// Foreground sync (isSweep=false) never parks itself.
static bool SweepShouldYield(bool isSweep, const char* context) {
    if (!isSweep) return true;
    return WaitForForegroundSyncIdle(context);
}

static bool SyncFromCloudInner(uint32_t accountId, uint32_t appId, bool isSweep) {
    if (!g_provider || !g_provider->IsAuthenticated()) return false;
    // appId=0 is the account-scope sentinel; per-app reconcile must not run on it.
    if (appId == CloudIntercept::kAccountScopeAppId) return false;

    auto syncStart = std::chrono::steady_clock::now();
    bool hadNewer = false;
    bool cloudHadNewerCN = false;
    bool cloudCNFound = false;
    bool cloudRootTokensFound = false;
    bool cloudFileTokensFound = false;
    std::unordered_set<std::string> cloudFileTokenNames;
    uint64_t localCN = 0;
    uint64_t cloudCN = 0;
    std::string storagePath = LocalStoragePath(accountId, appId);
    {
        std::error_code ec;
        std::filesystem::create_directories(FileUtil::Utf8ToPath(storagePath), ec);
        if (ec) {
            LOG("[CloudStorage] SyncFromCloud app %u: failed to create local storage "
                "dir %s: %s -- aborting sync", appId, storagePath.c_str(), ec.message().c_str());
            return false;
        }
    }
    std::unordered_set<std::string> originalRootTokens;
    std::unordered_map<std::string, std::string> originalFileTokens;
    std::unordered_set<std::string> mergedCloudRootTokens;
    std::unordered_map<std::string, std::string> mergedCloudFileTokens;
    bool haveOriginalTokenMetadata = false;
    bool haveMergedCloudRootTokens = false;
    bool haveMergedCloudFileTokens = false;
    bool rolledBackNewerCloudState = false;

    // Sync CN: take max of local and cloud.
    {
        localCN = LocalStorage::GetChangeNumber(accountId, appId);

        if (!SweepShouldYield(isSweep, "SyncFromCloud (pre-cn)")) return false;

        std::vector<uint8_t> cloudData;
        bool usedLegacyCN = false;
        if (DownloadCloudMetadataWithLegacyFallback(accountId, appId,
                kCNFilename, kLegacyCNFilename, cloudData, &usedLegacyCN)) {
            cloudCNFound = true;
            std::string s(cloudData.begin(), cloudData.end());
            bool parsedCloudCN = false;
            try {
                cloudCN = std::stoull(s);
                parsedCloudCN = true;
            } catch (...) {}
            if (usedLegacyCN) {
                if (parsedCloudCN &&
                    UploadCloudMetadataText(accountId, appId, kCNFilename, std::to_string(cloudCN))) {
                    RemoveCloudMetadataIfPresent(accountId, appId, kLegacyCNFilename);
                } else if (!parsedCloudCN) {
                    LOG("[CloudStorage] SyncFromCloud app %u: legacy cloud CN was invalid; leaving legacy copy in place",
                        appId);
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: failed to migrate legacy cloud CN",
                        appId);
                }
            } else {
                RemoveCloudMetadataIfPresent(accountId, appId, kLegacyCNFilename);
            }
        }

        if (cloudCN > localCN) {
            LOG("[CloudStorage] SyncFromCloud app %u: cloud CN=%llu > local CN=%llu, using cloud (deferred until blobs promote)",
                appId, cloudCN, localCN);
            // CN persistence deferred to after blob promotion so a crash mid-sync
            // doesn't leave localCN==cloudCN with stale blobs (next sync would skip reconcile).
            hadNewer = true;
            cloudHadNewerCN = true;
        } else if (localCN > cloudCN) {
            LOG("[CloudStorage] SyncFromCloud app %u: local CN=%llu > cloud CN=%llu, leaving provider unchanged until Steam uploads",
                appId, localCN, cloudCN);
        } else {
            LOG("[CloudStorage] SyncFromCloud app %u: CN in sync (local=%llu, cloud=%llu)",
                appId, localCN, cloudCN);
        }
    }

    // Snapshot unconditionally so rollbackNewerCloudState can always restore.
    originalRootTokens = LocalMetadataStore::LoadRootTokens(accountId, appId);
    originalFileTokens = LocalMetadataStore::LoadFileTokens(accountId, appId);
    haveOriginalTokenMetadata = true;

    bool cnPersisted = false; // set true after deferred SetChangeNumber succeeds
    auto rollbackNewerCloudState = [&](const char* reason) {
        if (cnPersisted) {
            uint64_t currentCN = LocalStorage::GetChangeNumber(accountId, appId);
            if (currentCN == cloudCN) {
                LocalStorage::SetChangeNumber(accountId, appId, localCN);
            } else {
                LOG("[CloudStorage] SyncFromCloud app %u: preserving local CN=%llu during rollback; expected cloud CN=%llu",
                    appId, currentCN, cloudCN);
            }
        }
        // Vacuously true when nothing was merged; otherwise must be set
        // explicitly by a successful Save below.
        bool rootRolledBack = !haveMergedCloudRootTokens;
        bool fileRolledBack = !haveMergedCloudFileTokens;
        if (haveOriginalTokenMetadata) {
            if (haveMergedCloudRootTokens) {
                if (LocalMetadataStore::LoadRootTokens(accountId, appId) == mergedCloudRootTokens) {
                    if (LocalMetadataStore::SaveRootTokens(accountId, appId, originalRootTokens)) {
                        rootRolledBack = true;
                    } else {
                        LOG("[CloudStorage] SyncFromCloud app %u: rollback SaveRootTokens failed -- merged tokens remain on disk",
                            appId);
                    }
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: rollback skipped for root tokens -- disk set no longer matches merged snapshot",
                        appId);
                }
            }
            if (haveMergedCloudFileTokens) {
                if (LocalMetadataStore::LoadFileTokens(accountId, appId) == mergedCloudFileTokens) {
                    if (LocalMetadataStore::SaveFileTokens(accountId, appId, originalFileTokens)) {
                        fileRolledBack = true;
                    } else {
                        LOG("[CloudStorage] SyncFromCloud app %u: rollback SaveFileTokens failed -- merged tokens remain on disk",
                            appId);
                    }
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: rollback skipped for file tokens -- disk set no longer matches merged snapshot",
                        appId);
                }
            }
        }
        cloudHadNewerCN = false;
        hadNewer = false;
        rolledBackNewerCloudState = rootRolledBack && fileRolledBack;
        LOG("[CloudStorage] SyncFromCloud app %u: rolled back newer cloud state because %s (root=%d file=%d)",
            appId, reason, (int)rootRolledBack, (int)fileRolledBack);
    };

    // Sync root_token: merge cloud tokens into local set.
    {
        // Skip park if cloudHadNewerCN: local CN advertises newer state with blobs pending; bailing would strand stale blobs under CN-in-sync.
        if (!cloudHadNewerCN &&
            !SweepShouldYield(isSweep, "SyncFromCloud (pre-root_token)")) return false;

        std::vector<uint8_t> cloudData;
        bool usedLegacyRootTokens = false;
        if (DownloadCloudMetadataWithLegacyFallback(accountId, appId,
                kRootTokenFilename, kLegacyRootTokenFilename,
                cloudData, &usedLegacyRootTokens)) {
            cloudRootTokensFound = true;
            std::unordered_set<std::string> cloudTokens;
            bool cloudHadCorruption = false;
            std::istringstream iss(std::string(cloudData.begin(), cloudData.end()));
            std::string line;
            while (std::getline(iss, line)) {
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (!line.empty()) cloudTokens.insert(line);
            }

            // CRLF-duplicate detection: raw line count > clean token count.
            {
                size_t rawCount = 0;
                std::istringstream iss2(std::string(cloudData.begin(), cloudData.end()));
                std::string rawLine;
                while (std::getline(iss2, rawLine)) {
                    if (!rawLine.empty()) rawCount++;
                }
                if (rawCount > cloudTokens.size()) {
                    cloudHadCorruption = true;
                    LOG("[CloudStorage] SyncFromCloud app %u: cloud root_token had %zu raw entries but only %zu clean tokens -- pushing cleaned version",
                        appId, rawCount, cloudTokens.size());
                }
            }

            auto localTokens = LocalMetadataStore::LoadRootTokens(accountId, appId);
            size_t beforeSize = localTokens.size();
            localTokens.insert(cloudTokens.begin(), cloudTokens.end());

            if (localTokens.size() > beforeSize) {
                LOG("[CloudStorage] SyncFromCloud app %u: merged %zu new root tokens from cloud",
                    appId, localTokens.size() - beforeSize);
                // Only record for rollback-predicate matching if disk persist succeeded.
                if (LocalMetadataStore::SaveRootTokens(accountId, appId, localTokens)) {
                    mergedCloudRootTokens = localTokens;
                    haveMergedCloudRootTokens = true;
                    hadNewer = true;
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: merged root-token persist failed -- skipping rollback predicate bookkeeping",
                        appId);
                }
            }

            // Push the cleaned *cloud* set, not the local-merged superset:
            // This is a serialization repair only; must not leak local tokens.
            if (cloudHadCorruption || usedLegacyRootTokens) {
                std::string cleaned;
                for (auto& t : cloudTokens) {
                    cleaned += t + "\n";
                }
                if (UploadCloudMetadataText(accountId, appId, kRootTokenFilename, cleaned)) {
                    RemoveCloudMetadataIfPresent(accountId, appId, kLegacyRootTokenFilename);
                    LOG("[CloudStorage] SyncFromCloud app %u: pushed cleaned root_token to cloud (%zu tokens)",
                        appId, cloudTokens.size());
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: FAILED to push cleaned root_token to cloud",
                        appId);
                }
            } else {
                RemoveCloudMetadataIfPresent(accountId, appId, kLegacyRootTokenFilename);
            }
        }
    }

    // 2b. Sync file_tokens: merge cloud file-token mappings into local.
    // Get valid root tokens for validation (merged set from step 2).
    auto validRootTokens = LocalMetadataStore::LoadRootTokens(accountId, appId);
    {
        if (!cloudHadNewerCN &&
            !SweepShouldYield(isSweep, "SyncFromCloud (pre-file_tokens)")) return false;

        std::vector<uint8_t> cloudData;
        bool usedLegacyFileTokens = false;
        if (DownloadCloudMetadataWithLegacyFallback(accountId, appId,
                kFileTokensFilename, kLegacyFileTokensFilename,
                cloudData, &usedLegacyFileTokens)) {
            cloudFileTokensFound = true;
            std::unordered_map<std::string, std::string> cloudFileTokens;
            if (!cloudData.empty()) {
                // Parse cloud file_tokens
                size_t rejectedCount = 0;
                std::istringstream iss(std::string(cloudData.begin(), cloudData.end()));
                std::string line;
                while (std::getline(iss, line)) {
                    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                        line.pop_back();
                    if (line.empty()) continue;
                    auto tab = line.find('\t');
                    if (tab == std::string::npos) continue;
                    std::string cleanName = line.substr(0, tab);
                    std::string token = line.substr(tab + 1);
                    if (cleanName.empty()) continue;
                    
                    // Validate: token must be in app's valid root token set
                    if (!validRootTokens.empty() && !token.empty() && !validRootTokens.count(token)) {
                        LOG("[CloudStorage] SyncFromCloud app %u: rejecting cloud file token '%s' -> '%s' (not in valid root set)",
                            appId, cleanName.c_str(), token.c_str());
                        ++rejectedCount;
                        continue;
                    }
                    cloudFileTokens[cleanName] = token;
                }
                
                if (rejectedCount > 0) {
                    LOG("[CloudStorage] SyncFromCloud app %u: rejected %zu cloud file tokens with invalid root tokens",
                        appId, rejectedCount);
                }

                // Merge: cloud entries fill in any gaps in local
                auto localFileTokens = LocalMetadataStore::LoadFileTokens(accountId, appId);
                size_t beforeSize = localFileTokens.size();
                bool changed = false;
                for (auto& [name, token] : cloudFileTokens) {
                    cloudFileTokenNames.insert(name);
                    auto localIt = localFileTokens.find(name);
                    if (localIt == localFileTokens.end() ||
                        (cloudHadNewerCN && localIt->second != token)) {
                        localFileTokens[name] = token;
                        changed = true;
                    }
                }
                if (changed) {
                    LOG("[CloudStorage] SyncFromCloud app %u: merged/updated file-token mappings from cloud (local %zu -> %zu)",
                        appId, beforeSize, localFileTokens.size());
                    if (LocalMetadataStore::SaveFileTokens(accountId, appId, localFileTokens)) {
                        mergedCloudFileTokens = localFileTokens;
                        haveMergedCloudFileTokens = true;
                        hadNewer = true;
                    } else {
                        LOG("[CloudStorage] SyncFromCloud app %u: merged file-token persist failed -- skipping rollback predicate bookkeeping",
                            appId);
                    }
                }
            }
            if (usedLegacyFileTokens) {
                std::string cleaned;
                for (const auto& [cleanName, token] : cloudFileTokens) {
                    cleaned += cleanName + "\t" + token + "\n";
                }
                if (UploadCloudMetadataText(accountId, appId, kFileTokensFilename, cleaned)) {
                    RemoveCloudMetadataIfPresent(accountId, appId, kLegacyFileTokensFilename);
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: FAILED to migrate legacy file_tokens to cloud",
                        appId);
                }
            } else {
                RemoveCloudMetadataIfPresent(accountId, appId, kLegacyFileTokensFilename);
            }
        }
    }

    // Download-only sync (uploads come from Steam's batch flow). Bounded by
    // BLOB_SYNC_TIMEOUT_SEC.
    constexpr int BLOB_SYNC_TIMEOUT_SEC = 120;
    std::string blobPrefix = std::to_string(accountId) + "/" +
                             std::to_string(appId) + "/blobs/";
    std::vector<ICloudProvider::FileInfo> cloudBlobs;
    // Distinguishes a verified-complete listing from a truncated one;
    // prune/recovery refuse to run on incomplete listings.
    bool cloudListComplete = false;
    // Suppressed under cloudHadNewerCN so promote/rollback runs to completion.
    if (!cloudHadNewerCN &&
        !SweepShouldYield(isSweep, "SyncFromCloud (pre-list)")) return false;
    bool cloudListSucceeded = g_provider->ListChecked(blobPrefix, cloudBlobs, &cloudListComplete);
    if (!cloudListSucceeded) {
        if (cloudHadNewerCN) {
            rollbackNewerCloudState("blob listing failed");
        }
        LOG("[CloudStorage] SyncFromCloud app %u: provider blob listing failed; skipping blob download/prune/recovery",
            appId);
        cloudBlobs.clear();
        cloudListComplete = false;
    } else if (!cloudListComplete) {
        LOG("[CloudStorage] SyncFromCloud app %u: provider blob listing returned partial results "
            "(e.g. recursion cap); downloads proceed but prune/gap-repair are skipped",
            appId);
    }

    if (cloudListSucceeded && cloudListComplete) {
        std::vector<ICloudProvider::FileInfo> appEntries;
        bool appEntriesComplete = false;
        std::string appPrefix = std::to_string(accountId) + "/" + std::to_string(appId) + "/";
        if (!g_provider->ListChecked(appPrefix, appEntries, &appEntriesComplete)) {
            LOG("[CloudStorage] SyncFromCloud app %u: provider app-root listing failed; skipping metadata cleanup",
                appId);
        } else if (!appEntriesComplete) {
            LOG("[CloudStorage] SyncFromCloud app %u: provider app-root listing incomplete; skipping metadata cleanup",
                appId);
        } else {
            for (const auto& entry : appEntries) {
                auto expectedPrefix = appPrefix + "blobs/";
                if (entry.path.rfind(expectedPrefix, 0) == 0) continue;

                uint32_t parsedAccountId = 0;
                uint32_t parsedAppId = 0;
                std::string metadataName;
                size_t p1 = entry.path.find('/');
                size_t p2 = (p1 == std::string::npos) ? std::string::npos : entry.path.find('/', p1 + 1);
                size_t p3 = (p2 == std::string::npos) ? std::string::npos : entry.path.find('/', p2 + 1);
                if (p1 == std::string::npos || p2 == std::string::npos || p3 != std::string::npos) continue;
                if (!ParseU32(entry.path.substr(0, p1), parsedAccountId)) continue;
                if (!ParseU32(entry.path.substr(p1 + 1, p2 - p1 - 1), parsedAppId)) continue;
                metadataName = entry.path.substr(p2 + 1);
                if (parsedAccountId != accountId || parsedAppId != appId || metadataName.empty()) continue;

                if (metadataName == kDeletedFilename || metadataName == kLegacyDeletedFilename) {
                    EnqueueCloudDelete(entry.path);
                    continue;
                }

                const char* legacyName = nullptr;
                if (metadataName == kCNFilename) legacyName = kLegacyCNFilename;
                else if (metadataName == kManifestFilename) legacyName = kLegacyManifestFilename;
                else if (metadataName == kRootTokenFilename) legacyName = kLegacyRootTokenFilename;
                else if (metadataName == kFileTokensFilename) legacyName = kLegacyFileTokensFilename;

                if (legacyName) {
                    RemoveCloudMetadataIfPresent(accountId, appId, legacyName);
                    continue;
                }
            }
        }
    }

    // Build name sets from cloud listing and manifest.
    std::unordered_set<std::string> cloudBlobSHAs;  // SHA hex strings on cloud
    std::unordered_set<std::string> cloudBlobNames;  // filenames covered by manifest
    bool cloudListingHasBlobs = false;  // true if cloud has ANY blob (CAS or legacy)
    for (auto& fi : cloudBlobs) {
        auto blobsPos = fi.path.find("/blobs/");
        if (blobsPos == std::string::npos) continue;
        std::string leaf = fi.path.substr(blobsPos + 7);
        cloudListingHasBlobs = true;
        // CAS blobs are pure 40-char hex; legacy blobs contain '/' or '.'.
        if (leaf.size() == 40 &&
            leaf.find_first_not_of("0123456789abcdef") == std::string::npos) {
            cloudBlobSHAs.insert(leaf);
        } else {
            std::string canonicalName = CanonicalizeInternalMetadataName(leaf);
            if (CloudIntercept::IsReservedBlobFilename(canonicalName)) continue;
            cloudBlobNames.insert(canonicalName);
        }
    }
    // The manifest-referenced filenames are considered present in cloud.
    Manifest syncManifest = LoadLocalManifest(accountId, appId);
    for (const auto& [fn, entry] : syncManifest) {
        if (entry.sha.empty()) continue;
        if (CloudIntercept::IsReservedBlobFilename(fn)) continue;
        cloudBlobNames.insert(fn);
    }

    if (cloudListSucceeded && cloudListComplete) {
        // Clean up internal/reserved blobs from the cloud listing.
        for (const auto& fi : cloudBlobs) {
            auto blobsPos = fi.path.find("/blobs/");
            if (blobsPos == std::string::npos) continue;
            std::string leaf = fi.path.substr(blobsPos + 7);
            // Skip CAS SHA blobs.
            if (leaf.size() == 40 &&
                leaf.find_first_not_of("0123456789abcdef") == std::string::npos) {
                continue;
            }
            std::string canonicalName = CanonicalizeInternalMetadataName(leaf);
            if (CloudIntercept::IsReservedBlobFilename(canonicalName)) {
                CleanupInternalBlobEntry(accountId, appId, fi, leaf);
            }
        }
    }

    // Cloud-side legacy-blob cleanup. Requires a complete listing so the
    // classifier can confirm the canonical sibling exists.
    if (cloudListSucceeded && cloudListComplete) {
        std::vector<std::string> rawPaths;
        rawPaths.reserve(cloudBlobs.size());
        for (auto& fi : cloudBlobs) rawPaths.push_back(fi.path);
        auto legacyToDelete = LegacyMetadataCleanup::ClassifyLegacyCloudBlobsToDelete(rawPaths);

        for (auto& legacyPath : legacyToDelete) {
            LOG("[CloudStorage] SyncFromCloud app %u: enqueueing delete of legacy cloud blob %s",
                appId, legacyPath.c_str());
            CloudWorkQueue::WorkItem wi;
            wi.type = CloudWorkQueue::WorkItem::Delete;
            wi.cloudPath = std::move(legacyPath);
            CloudWorkQueue::EnqueueWork(std::move(wi));
        }
    }

    // Download: manifest-driven (CAS) or listing-driven (legacy).
    {
        struct StagedBlob {
            std::string filename;
            std::vector<uint8_t> data;
        };
        std::vector<StagedBlob> stagedNewerBlobs;
        int downloaded = 0, skipped = 0, failed = 0;
        bool timedOut = false;

        // Work list: manifest entries (CAS) or cloud listing (legacy).
        struct DownloadItem {
            std::string filename;
            std::string cloudPath;
        };
        std::vector<DownloadItem> downloadItems;
        if (!syncManifest.empty()) {
            // CAS: download by canonical filename/{sha}; RetrieveBlob handles legacy fallback.
            for (const auto& [filename, entry] : syncManifest) {
                if (entry.sha.empty()) continue;
                if (CloudIntercept::IsReservedBlobFilename(filename)) continue;
                std::string shaHex = ShaToHex(entry.sha);
                downloadItems.push_back({
                    filename,
                    CloudBlobPathByNameAndSHA(accountId, appId, filename, shaHex)
                });
            }
        } else {
            // Legacy: listing-driven, filename-addressed blobs.
            for (auto& fi : cloudBlobs) {
                auto blobsPos = fi.path.find("/blobs/");
                if (blobsPos == std::string::npos) continue;
                std::string leaf = fi.path.substr(blobsPos + 7);
                // Skip CAS SHA blobs (no manifest to resolve them).
                if (leaf.size() == 40 &&
                    leaf.find_first_not_of("0123456789abcdef") == std::string::npos) {
                    continue;
                }
                std::string filename = CanonicalizeInternalMetadataName(leaf);
                if (CloudIntercept::IsReservedBlobFilename(filename)) continue;
                downloadItems.push_back({ filename, fi.path });
            }
        }

        auto blobStart = std::chrono::steady_clock::now();
        for (auto& item : downloadItems) {
            // Check timeout
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - blobStart).count();
            if (elapsed >= BLOB_SYNC_TIMEOUT_SEC) {
                int remaining = (int)downloadItems.size() - downloaded - skipped;
                LOG("[CloudStorage] SyncFromCloud app %u: blob download TIMEOUT after %llds, "
                    "%d downloaded, %d skipped, ~%d remaining",
                    appId, (long long)elapsed, downloaded, skipped, remaining);
                timedOut = true;
                break;
            }
            if (isSweep && g_foregroundSyncCount.load(std::memory_order_seq_cst) > 0) {
                int remaining = (int)downloadItems.size() - downloaded - skipped;
                LOG("[CloudStorage] SyncFromCloud app %u: sweep yielding blob loop to foreground sync (downloaded=%d skipped=%d remaining=%d)",
                    appId, downloaded, skipped, remaining);
                timedOut = true;
                break;
            }

            std::string localBlobFile = LocalBlobPath(accountId, appId, item.filename);
            std::error_code existsEc;
            bool localExists = std::filesystem::exists(FileUtil::Utf8ToPath(localBlobFile), existsEc);
            if (existsEc) localExists = false;
            if (localExists && !cloudHadNewerCN) {
                skipped++;
                continue; // already cached
            }

            LOG("[CloudStorage] SyncFromCloud app %u: downloading blob %s...", appId, item.filename.c_str());
            std::vector<uint8_t> data;
            if (g_provider->Download(item.cloudPath, data)) {
                if (cloudHadNewerCN) {
                    stagedNewerBlobs.push_back({ item.filename, std::move(data) });
                    downloaded++;
                    continue;
                }

                const uint8_t* writeData = data.empty() ? nullptr : data.data();
                if (LocalStorage::WriteFileNoIncrement(accountId, appId, item.filename,
                                                       writeData, data.size())) {
                    downloaded++;
                    LOG("[CloudStorage] SyncFromCloud app %u: blob %s downloaded (%zu bytes)",
                        appId, item.filename.c_str(), data.size());
                } else {
                    failed++;
                    LOG("[CloudStorage] SyncFromCloud app %u: failed to write blob %s",
                        appId, item.filename.c_str());
                    continue;
                }
            } else if (!syncManifest.empty()) {
                // Canonical failed -- cascade: legacy CAS, then pre-CAS filename.
                auto mit = syncManifest.find(item.filename);
                std::string fallbackPath;
                if (mit != syncManifest.end() && !mit->second.sha.empty()) {
                    fallbackPath = CloudBlobPathBySHA(accountId, appId,
                                                     ShaToHex(mit->second.sha));
                }
                bool fellBack = false;
                if (!fallbackPath.empty() && g_provider->Download(fallbackPath, data)) {
                    fellBack = true;
                    LOG("[CloudStorage] SyncFromCloud app %u: blob %s downloaded from legacy CAS path (%zu bytes)",
                        appId, item.filename.c_str(), data.size());
                } else {
                    std::string legacyPath = CloudBlobPath(accountId, appId, item.filename);
                    if (g_provider->Download(legacyPath, data)) {
                        fellBack = true;
                        LOG("[CloudStorage] SyncFromCloud app %u: blob %s downloaded from legacy filename path (%zu bytes)",
                            appId, item.filename.c_str(), data.size());
                    }
                }
                if (fellBack) {
                    if (cloudHadNewerCN) {
                        stagedNewerBlobs.push_back({ item.filename, std::move(data) });
                        downloaded++;
                        continue;
                    }
                    const uint8_t* writeData = data.empty() ? nullptr : data.data();
                    if (LocalStorage::WriteFileNoIncrement(accountId, appId, item.filename,
                                                           writeData, data.size())) {
                        downloaded++;
                    } else {
                        failed++;
                        LOG("[CloudStorage] SyncFromCloud app %u: failed to write blob %s (legacy fallback)",
                            appId, item.filename.c_str());
                    }
                } else {
                    failed++;
                    LOG("[CloudStorage] SyncFromCloud app %u: FAILED to download blob %s",
                        appId, item.filename.c_str());
                }
            } else {
                failed++;
                LOG("[CloudStorage] SyncFromCloud app %u: FAILED to download blob %s",
                    appId, item.filename.c_str());
            }
        }

        if (cloudHadNewerCN && failed == 0 && !timedOut) {
            struct PromotedBlob {
                std::string filename;
                std::string backupPath;
                std::vector<uint8_t> promotedData;
                bool hadOriginal = false;
            };
            std::vector<PromotedBlob> promoted;
            for (auto& staged : stagedNewerBlobs) {
                std::string localBlobFile = LocalBlobPath(accountId, appId, staged.filename);
                // A transient stat error must fail the batch, not be treated
                // as "no local file" (which would skip the conflict-copy backup).
                std::error_code promoteEc;
                bool localExists = std::filesystem::exists(FileUtil::Utf8ToPath(localBlobFile), promoteEc);
                if (promoteEc) {
                    LOG("[CloudStorage] SyncFromCloud app %u: stat failed for %s during "
                        "promotion (%s); failing batch to preserve local state",
                        appId, staged.filename.c_str(), promoteEc.message().c_str());
                    failed++;
                    break;
                }
                std::string backupPath;
                if (localExists) {
                    backupPath = CreateLocalConflictCopy(accountId, appId, staged.filename, localBlobFile);
                    if (backupPath.empty()) {
                        failed++;
                        break;
                    }
                }

                // Promotion, StoreBlob, and rollback share LocalStorage::g_mutex (rename vs compare-and-restore mutually exclusive).
                const uint8_t* writeData = staged.data.empty() ? nullptr : staged.data.data();
                if (!LocalStorage::WriteFileNoIncrement(accountId, appId, staged.filename,
                                                       writeData, staged.data.size())) {
                    failed++;
                    LOG("[CloudStorage] SyncFromCloud app %u: failed to promote staged blob %s",
                        appId, staged.filename.c_str());
                    break;
                }
                promoted.push_back({ staged.filename, backupPath, staged.data, localExists });
                LOG("[CloudStorage] SyncFromCloud app %u: blob %s downloaded (%zu bytes)",
                    appId, staged.filename.c_str(), staged.data.size());
            }
            if (failed > 0) {
                for (auto it = promoted.rbegin(); it != promoted.rend(); ++it) {
                    LocalStorage::RestoreFileIfUnchanged(accountId, appId,
                                                        it->filename,
                                                        it->promotedData,
                                                        it->backupPath,
                                                        it->hadOriginal);
                }
            } else if (!timedOut) {
                // Blobs are on disk; persist CN now so a crash mid-sync can't leave
                // localCN==cloudCN with stale blobs (next sync would skip reconcile).
                LocalStorage::SetChangeNumber(accountId, appId, cloudCN);
                cnPersisted = true;
                SaveManifestSnapshot(accountId, appId, cloudCN);
            }
        }

        if (cloudHadNewerCN && (failed > 0 || timedOut)) {
            rollbackNewerCloudState("blob sync was incomplete");
        }
        if (downloaded > 0 && !rolledBackNewerCloudState) {
            LOG("[CloudStorage] SyncFromCloud app %u: downloaded %d blobs from cloud (skipped %d cached)",
                appId, downloaded, skipped);
            hadNewer = true;
        }
        // Prune requires a verified-complete listing; a partial listing
        // would silently delete blobs that exist above the recursion cap.
        if (cloudHadNewerCN && cloudListSucceeded && cloudListComplete && !cloudBlobNames.empty()) {
            RemoveLocalBlobsNotInCloud(accountId, appId, cloudBlobNames);
        } else if (cloudHadNewerCN && cloudListSucceeded && cloudListComplete && cloudBlobNames.empty()) {
            LOG("[CloudStorage] SyncFromCloud app %u: empty blob listing is not explicit enough to prune local blobs",
                appId);
        } else if (cloudHadNewerCN && cloudListSucceeded && !cloudListComplete) {
            LOG("[CloudStorage] SyncFromCloud app %u: skipping local-blob prune because provider listing was incomplete",
                appId);
        }
    }

    // Gap-repair from local cache; verified-complete listing only (an incomplete sub-tree looks identical to empty).
    bool providerLooksUninitialized = cloudListSucceeded && cloudListComplete &&
                                      !cloudCNFound && !cloudRootTokensFound &&
                                      !cloudFileTokensFound && !cloudListingHasBlobs;
    bool canRepairProviderGaps = cloudListSucceeded && cloudListComplete &&
                                 localCN > 0 && providerLooksUninitialized;
    if (canRepairProviderGaps) {
        std::string localBlobDir = g_localRoot + "storage" + kPathSepStr +
                                   std::to_string(accountId) + kPathSepStr +
                                   std::to_string(appId) + kPathSepStr;
        auto localBlobDirPath = FileUtil::Utf8ToPath(localBlobDir);
        int seeded = 0;
        std::error_code gapEc;
        bool dirExists = std::filesystem::exists(localBlobDirPath, gapEc);
        if (gapEc) {
            LOG("[CloudStorage] SyncFromCloud app %u: gap-repair skipped -- stat failed for %s: %s",
                appId, localBlobDir.c_str(), gapEc.message().c_str());
            dirExists = false;
        }
        std::string gapBlobPrefix = FileUtil::MakePathPrefix(FileUtil::PathToUtf8(localBlobDirPath));
        if (dirExists) {
            std::error_code iterEc;
            std::filesystem::recursive_directory_iterator it(localBlobDirPath, iterEc);
            std::filesystem::recursive_directory_iterator end;
            if (iterEc) {
                LOG("[CloudStorage] SyncFromCloud app %u: gap-repair skipped -- cannot open %s: %s",
                    appId, localBlobDir.c_str(), iterEc.message().c_str());
            } else {
                for (; !iterEc && it != end; it.increment(iterEc)) {
                    std::error_code entryEc;
                    const auto& entry = *it;
                    bool isFile = entry.is_regular_file(entryEc);
                    if (entryEc || !isFile) continue;

                    std::string entryUtf8 = FileUtil::PathToUtf8(entry.path());
                    FileUtil::NormalizeSlashesInPlace(entryUtf8);
                    std::string rel;
                    if (!FileUtil::RelativeUtf8Path(entryUtf8, gapBlobPrefix, &rel)) {
                        continue;
                    }
                    if (rel == kCNFilename || rel == kLegacyCNFilename ||
                        rel == kRootTokenFilename || rel == kLegacyRootTokenFilename ||
                        rel == kFileTokensFilename || rel == kLegacyFileTokensFilename ||
                        rel == kDeletedFilename || rel == kLegacyDeletedFilename) continue;
                    if (CloudIntercept::IsReservedBlobFilename(rel)) continue;
                    // Canonicalize so a legacy-named local blob isn't re-uploaded when its canonical sibling is already in cloud.
                    if (cloudBlobNames.count(CanonicalizeInternalMetadataName(rel))) continue;

                    std::ifstream f(entry.path(), std::ios::binary);
                    if (!f) continue;
                    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                              std::istreambuf_iterator<char>());
                    // CAS: upload to blobs/{filename}/{sha}.
                    auto sha = FileUtil::SHA1(data.data(), data.size());
                    std::string shaHex = ShaToHex(sha);
                    CloudWorkQueue::WorkItem wi;
                    wi.type = CloudWorkQueue::WorkItem::Upload;
                    wi.cloudPath = CloudBlobPathByNameAndSHA(accountId, appId, rel, shaHex);
                    wi.data = std::move(data);
                    wi.skipIfExists = true;
                    wi.bestEffort = true;
                    CloudWorkQueue::EnqueueWork(std::move(wi));
                    seeded++;
                }
                if (iterEc) {
                    LOG("[CloudStorage] SyncFromCloud app %u: gap-repair iteration aborted after %d seeded: %s",
                        appId, seeded, iterEc.message().c_str());
                }
            }
        }

        auto seedMeta = [&](const char* filename) {
            std::string localFile = storagePath + filename;
            std::error_code metaEc;
            auto localFilePath = FileUtil::Utf8ToPath(localFile);
            if (!std::filesystem::exists(localFilePath, metaEc) || metaEc) return;

            std::ifstream f(localFilePath, std::ios::binary);
            if (!f) return;
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());

            CloudWorkQueue::WorkItem wi;
            wi.type = CloudWorkQueue::WorkItem::Upload;
            wi.cloudPath = CloudMetadataPath(accountId, appId, filename);
            wi.data = std::move(data);
            wi.skipIfExists = true;
            wi.bestEffort = true;
            CloudWorkQueue::EnqueueWork(std::move(wi));
            seeded++;
        };

        if (!cloudRootTokensFound) seedMeta(kRootTokenFilename);
        if (!cloudFileTokensFound) seedMeta(kFileTokensFilename);
        if (!cloudCNFound) seedMeta(kCNFilename);

        if (seeded > 0) {
            LOG("[CloudStorage] SyncFromCloud app %u: recovered %d missing local cache file(s) to provider (%s)",
                appId, seeded, g_provider->Name());
        }
    }

    auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - syncStart).count();
    LOG("[CloudStorage] SyncFromCloud app %u: completed in %lld ms (hadNewer=%d)",
        appId, (long long)totalMs, hadNewer);

    return hadNewer;
}

// isSweep enables in-app gate-park; foreground signature stays unchanged.
static bool SyncFromCloudWithFlag(uint32_t accountId, uint32_t appId, bool isSweep) {
    if (appId == CloudIntercept::kAccountScopeAppId) return false;
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;

    // seq_cst increment + re-check pairs with Shutdown's "set flag, drain
    // counter" handshake; release/acquire would allow the IRIW pattern.
    g_inflightSyncCount.fetch_add(1, std::memory_order_seq_cst);
    struct InflightGuard {
        ~InflightGuard() { g_inflightSyncCount.fetch_sub(1, std::memory_order_seq_cst); }
    } inflightGuard;

    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;

    auto m = AcquireAppSyncMutex(accountId, appId);
    std::unique_lock<std::mutex> g(*m, std::defer_lock);
    if (isSweep) {
        // Sweep syncs skip if another sync is already running for this app.
        // The active sync will cover both, and we avoid serializing network I/O.
        if (!g.try_lock()) {
            LOG("[CloudStorage] SyncFromCloud app %u: sweep skipping, another sync in progress",
                appId);
            return false;
        }
    } else {
        auto waitStart = std::chrono::steady_clock::now();
        g.lock();
        auto waitedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - waitStart).count();
        if (waitedMs > 50) {
            LOG("[CloudStorage] SyncFromCloud app %u: waited %lld ms for in-flight sync on the same app",
                appId, (long long)waitedMs);
        }
    }
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;
    bool hadNewer = SyncFromCloudInner(accountId, appId, isSweep);
    
    if (hadNewer && !g_shuttingDown.load(std::memory_order_seq_cst)) {
        auto stateResult = FetchCloudState(accountId, appId);
        if (stateResult.status == StateFetchStatus::Ok && !stateResult.state.files.empty()) {
            Manifest cloudManifest;
            for (const auto& [name, fe] : stateResult.state.files) {
                ManifestEntry me;
                me.sha = fe.sha;
                me.timestamp = fe.timestamp;
                me.size = fe.size;
                cloudManifest[name] = std::move(me);
            }
            SaveManifestLocal(accountId, appId, cloudManifest);
            LOG("[CloudStorage] SyncFromCloud app %u: applied cloud state with %zu files",
                appId, cloudManifest.size());
        } else {
            LOG("[CloudStorage] SyncFromCloud app %u: cloud state unavailable (status=%d), keeping local manifest",
                appId, (int)stateResult.status);
        }
    }
    
    return hadNewer;
}

bool SyncFromCloud(uint32_t accountId, uint32_t appId) {
    return SyncFromCloudWithFlag(accountId, appId, /*isSweep=*/false);
}

std::vector<uint32_t> SyncAllFromCloud(uint32_t accountId) {
    std::vector<uint32_t> syncedApps;
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return syncedApps;

    // Same inflight gate as SyncFromCloud; both List/IsAuthenticated and the
    // per-app calls below dereference g_provider.
    g_inflightSyncCount.fetch_add(1, std::memory_order_seq_cst);
    struct InflightGuard {
        ~InflightGuard() { g_inflightSyncCount.fetch_sub(1, std::memory_order_seq_cst); }
    } inflightGuard;
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return syncedApps;

    if (!g_provider || !g_provider->IsAuthenticated()) return syncedApps;

    if (!WaitForForegroundSyncIdle("SyncAllFromCloud (pre-List)")) return syncedApps;

    PruneStaleCloudStaging(accountId);

    LOG("[CloudStorage] SyncAllFromCloud: scanning for apps belonging to account %u...", accountId);

    std::unordered_set<uint32_t> appIds;

    // List all items under the account prefix to discover apps
    std::string prefix = std::to_string(accountId) + "/";
    auto items = g_provider->List(prefix);

    // Extract unique app IDs from paths like "54303850/1229490/cn.dat"
    for (auto& fi : items) {
        // path: "{accountId}/{appId}/..."
        auto firstSlash = fi.path.find('/');
        if (firstSlash == std::string::npos) continue;
        auto secondSlash = fi.path.find('/', firstSlash + 1);
        if (secondSlash == std::string::npos) continue;
        std::string appStr = fi.path.substr(firstSlash + 1, secondSlash - firstSlash - 1);
        uint32_t parsed = 0;
        if (ParseU32(appStr, parsed)) {
            if (parsed == CloudIntercept::kAccountScopeAppId) {
                uint32_t metadataAppId = 0;
                if (TryExtractAccountMetadataAppId(fi.path, accountId, metadataAppId)) {
                    appIds.insert(metadataAppId);
                }
                continue;
            }
            appIds.insert(parsed);
        }
    }

    if (appIds.empty()) {
        auto localAppIds = EnumerateLocalAppIds(accountId);
        if (!localAppIds.empty()) {
            LOG("[CloudStorage] SyncAllFromCloud: provider returned 0 apps, falling back to %zu local app(s)",
                localAppIds.size());
            appIds.insert(localAppIds.begin(), localAppIds.end());
        }
    }

    LOG("[CloudStorage] SyncAllFromCloud: found %zu apps in cloud", appIds.size());
    for (uint32_t appId : appIds) {
        // Park between apps; per-app body also parks at HTTP boundaries.
        if (!WaitForForegroundSyncIdle("SyncAllFromCloud (per-app)")) break;
        SyncFromCloudWithFlag(accountId, appId, /*isSweep=*/true);
        syncedApps.push_back(appId);
    }

    return syncedApps;
}

} // namespace CloudStorage

// Factory implementation (declared in cloud_provider.h)
std::unique_ptr<ICloudProvider> CreateCloudProvider(const std::string& name) {
    // case-insensitive compare
    std::string lower = name;
    for (auto& c : lower) c = (char)tolower((unsigned char)c);

    if (lower == "local" || lower == "folder") {
        return std::make_unique<LocalDiskProvider>();
    }
    // Wire the auth-failure callback at construction so CloudProviderBase
    // doesn't reverse-depend on CloudStorage.
    auto wireAuthCallback = [](std::unique_ptr<CloudProviderBase> p)
        -> std::unique_ptr<ICloudProvider> {
        p->SetAuthFailureCallback(&CloudStorage::NotifyAuthFailure);
        return p;
    };
    if (lower == "gdrive") {
        return wireAuthCallback(std::make_unique<GoogleDriveProvider>());
    }
    if (lower == "onedrive") {
        return wireAuthCallback(std::make_unique<OneDriveProvider>());
    }
    LOG("[CloudStorage] CreateCloudProvider: unknown provider '%s'", name.c_str());
    return nullptr;
}
