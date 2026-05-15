#include "cloud_storage.h"
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

// Serializes token persistence (root_token.dat, file_tokens.dat) across
// concurrent callers (rpc_handlers batch operations, AutoCloudBootstrap).
// Per-(account,app) sync mutex registry (Steam-parity). Non-reentrant: SyncFromCloudInner-reachable callers go direct.
static std::mutex                                              g_syncMutexRegistryMutex;
static std::unordered_map<uint64_t, std::shared_ptr<std::mutex>> g_syncMutexRegistry;

// Shutdown waits on these counters before tearing down g_provider so a
// long-running Download/Upload doesn't return into freed memory.
static std::atomic<int>  g_inflightSyncCount{0};
static std::atomic<bool> g_shuttingDown{false};
static std::atomic<int>  g_inflightCommitDrainCount{0};

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
void NotifyAuthFailure(const std::string& providerName) {
    CloudWorkQueue::ShowErrorDialog(
        providerName + " authentication failed!\n\n"
        "CloudRedirect cannot refresh your access token.\n"
        "Cloud sync is disabled until this is resolved.\n\n"
        "Re-authenticate using the CloudRedirect setup tool.");
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
            // UTF-8 throughout; rel is compared against the cloud listing.
            std::error_code relEc;
            std::string rel = FileUtil::PathToUtf8(
                std::filesystem::relative(entry.path(), localBlobDirPath, relEc));
            if (!relEc) {
                for (auto& c : rel) { if (c == '\\') c = '/'; }
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
                std::string leaf = entry.path().filename().string();
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

// Inverse of CloudBlobPath. Rejects metadata paths and any non-canonical decimal.
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
    filename = cloudPath.substr(fileStart);
    return !filename.empty();
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

static void EnqueueCloudDelete(const std::string& cloudPath) {
    CloudWorkQueue::WorkItem wi;
    wi.type = CloudWorkQueue::WorkItem::Delete;
    wi.cloudPath = cloudPath;
    wi.suppressTombstoneClear = true;
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
            const std::string name = entry.path().filename().string();
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
void PushCNToCloud(uint32_t accountId, uint32_t appId, uint64_t cn) {
    ClearMissingMetadataPath(CloudMetadataPath(accountId, appId, kCNFilename));
    std::string cnStr = std::to_string(cn);
    CloudWorkQueue::WorkItem wi;
    wi.type = CloudWorkQueue::WorkItem::Upload;
    wi.cloudPath = CloudMetadataPath(accountId, appId, kCNFilename);
    wi.data.assign(cnStr.begin(), cnStr.end());
    CloudWorkQueue::EnqueueWork(std::move(wi));
}

bool PushCNToCloudSync(uint32_t accountId, uint32_t appId, uint64_t cn) {
    InflightSyncScope guard;
    if (!guard) return false;
    if (!g_provider) return true;
    std::string cnStr = std::to_string(cn);
    if (!UploadCloudMetadataText(accountId, appId, kCNFilename, cnStr)) {
        return false;
    }
    RemoveCloudMetadataIfPresent(accountId, appId, kLegacyCNFilename);
    return true;
}

uint64_t FetchCloudCN(uint32_t accountId, uint32_t appId) {
    InflightSyncScope guard;
    if (!guard) return 0;
    if (!g_provider || !g_provider->IsAuthenticated()) return 0;

    std::vector<uint8_t> data;
    bool usedLegacy = false;
    if (!DownloadCloudMetadataWithLegacyFallback(accountId, appId,
            kCNFilename, kLegacyCNFilename, data, &usedLegacy)) {
        return 0;
    }

    std::string s(data.begin(), data.end());
    try {
        uint64_t cn = std::stoull(s);
        if (usedLegacy) {
            if (UploadCloudMetadataText(accountId, appId, kCNFilename, std::to_string(cn))) {
                RemoveCloudMetadataIfPresent(accountId, appId, kLegacyCNFilename);
            } else {
                LOG("[CloudStorage] FetchCloudCN app %u: failed to migrate legacy cloud CN", appId);
            }
        } else {
            RemoveCloudMetadataIfPresent(accountId, appId, kLegacyCNFilename);
        }
        return cn;
    } catch (...) {
        return 0;
    }
}

// ============================================================================



bool CommitCNWithRetry(uint32_t accountId, uint32_t appId, uint64_t cn) {
    bool drained = CloudWorkQueue::DrainQueueForApp(accountId, appId);
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;
    bool cnPublished = drained && PushCNToCloudSync(accountId, appId, cn);
    if (cnPublished) return true;
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;
    LOG("[CloudStorage] CommitCNWithRetry app %u CN=%llu drained=%d: deferring to async retry",
        appId, (unsigned long long)cn, drained ? 1 : 0);
    PushCNToCloud(accountId, appId, cn);
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;
    CloudWorkQueue::DrainQueueForApp(accountId, appId);
    return false;
}

// --- manifest utilities needed by SyncFromCloudInner ---
// ManifestToJson lives in manifest_store.cpp; SyncFromCloudWithFlag uses
// SaveManifestLocal / SaveManifest which call through to ManifestStore.


// Detached: don't block Steam's RPC dispatch. Per-app sync mutex orders against SyncFromCloud and prevents older CNs landing after newer.
void CommitCNAsync(uint32_t accountId, uint32_t appId, uint64_t cn) {
    g_inflightCommitDrainCount.fetch_add(1, std::memory_order_seq_cst);
    if (g_shuttingDown.load(std::memory_order_seq_cst)) {
        g_inflightCommitDrainCount.fetch_sub(1, std::memory_order_seq_cst);
        return;
    }
    try {
        std::thread([accountId, appId, cn]() {
            struct Guard {
                ~Guard() { g_inflightCommitDrainCount.fetch_sub(1, std::memory_order_seq_cst); }
            } guard;
            if (g_shuttingDown.load(std::memory_order_seq_cst)) return;
            auto m = AcquireAppSyncMutex(accountId, appId);
            std::lock_guard<std::mutex> lk(*m);
            if (g_shuttingDown.load(std::memory_order_seq_cst)) return;
            // No WaitForForegroundSyncIdle: per-app mutex covers ordering; a cross-app park here would deadlock or invert FIFO.
            (void)CommitCNWithRetry(accountId, appId, cn);
        }).detach();
    } catch (...) {
        g_inflightCommitDrainCount.fetch_sub(1, std::memory_order_seq_cst);
        LOG("[CloudStorage] CommitCNAsync: std::thread construction failed for app %u CN=%llu",
            appId, (unsigned long long)cn);
    }
}


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
    // Do NOT zero g_foregroundSyncCount: a late ForegroundSyncScope dtor
    // would underflow it; the counter self-balances across restart.

    g_provider = std::move(provider);

    ManifestStore_Init(g_localRoot, g_provider.get());
    TokenStore_Init(g_localRoot, g_provider.get());

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
        while ((g_inflightSyncCount.load(std::memory_order_seq_cst) > 0
                || g_inflightCommitDrainCount.load(std::memory_order_seq_cst) > 0)
               && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        int residualSync   = g_inflightSyncCount.load(std::memory_order_seq_cst);
        int residualCommit = g_inflightCommitDrainCount.load(std::memory_order_seq_cst);
        if (residualSync > 0 || residualCommit > 0) {
            LOG("[CloudStorage] Shutdown: %d in-flight SyncFromCloud and %d CommitCNAsync "
                "call(s) did not drain within 5s; leaking provider to avoid UAF",
                residualSync, residualCommit);
            (void)g_provider.release();
            g_provider = nullptr;
            return;
        }
    }

    // Null sub-module provider refs after in-flight ops have drained
    // but before destroying the provider.
    ManifestStore_Init("", nullptr);
    TokenStore_Init("", nullptr);

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

bool StoreBlobStaged(uint32_t accountId, uint32_t appId, uint64_t batchId,
                     const std::string& filename,
                     const uint8_t* data, size_t len) {
    if (CloudIntercept::IsReservedBlobFilename(filename)) {
        LOG("[CloudStorage] StoreBlob: rejecting reserved /blobs/ filename app=%u batch=%llu file=%s",
            appId, (unsigned long long)batchId, filename.c_str());
        return false;
    }

    // Synchronous local write via LocalStorage::WriteFileNoIncrement so it
    // serializes against SyncFromCloud staged-blob promotion under g_mutex.
    if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename, data, len)) {
        LOG("[CloudStorage] StoreBlob: local write failed: app=%u file=%s (%zu bytes)",
            appId, filename.c_str(), len);
        return false;
    }
    LOG("[CloudStorage] StoreBlob: cached locally: %s (%zu bytes)", filename.c_str(), len);

    // Drop any stale tombstone (canonicalized to match DeleteBlob's MarkDeleted key).
    LocalMetadataStore::ClearDeleted(accountId, appId,
                               CanonicalizeInternalMetadataName(filename));

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

    if (g_provider && batchId == 0) {
        CloudWorkQueue::WorkItem wi;
        wi.type = CloudWorkQueue::WorkItem::Upload;
        wi.cloudPath = CloudBlobPath(accountId, appId, filename);
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

std::vector<uint8_t> RetrieveBlob(uint32_t accountId, uint32_t appId,
                                  const std::string& filename,
                                  bool* found) {
    if (found) *found = false;
    
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return {}; // path traversal blocked

    InflightSyncScope guard;
    const bool cloudActive = guard && g_provider;

    // Cloud-first: always fetch from cloud when active.
    // The manifest system means we already know what files exist and their SHA.
    // Steam only requests files that need syncing, so fetch fresh from cloud.
    // Local cache is just a fallback for network errors.
    if (cloudActive) {
        std::string cloudPath = CloudBlobPath(accountId, appId, filename);
        std::vector<uint8_t> data;
        if (g_provider->Download(cloudPath, data)) {
            LOG("[CloudStorage] RetrieveBlob: fetched from cloud: %s (%zu bytes)",
                filename.c_str(), data.size());
            // Update local cache
            const uint8_t* writeData = data.empty() ? nullptr : data.data();
            if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                               writeData, data.size())) {
                LOG("[CloudStorage] RetrieveBlob: WARNING - failed to cache %s locally, serving from cloud only",
                    filename.c_str());
            }
            if (found) *found = true;
            return data;
        }
        
        // Cloud download failed - check if file is missing vs network error
        auto status = g_provider->CheckExists(cloudPath);
        if (status == ICloudProvider::ExistsStatus::Missing) {
            // File doesn't exist in cloud - check local cache as fallback
            // (may be a file that was just uploaded locally but not yet synced)
            std::vector<uint8_t> cached;
            if (TryReadCachedBlob(localPath, filename, cached)) {
                LOG("[CloudStorage] RetrieveBlob: not in cloud, using local cache: %s (%zu bytes)",
                    filename.c_str(), cached.size());
                if (found) *found = true;
                return cached;
            }
            LOG("[CloudStorage] RetrieveBlob: not found in cloud: %s", filename.c_str());
        } else {
            // Network error - fall back to local cache
            std::vector<uint8_t> cached;
            if (TryReadCachedBlob(localPath, filename, cached)) {
                LOG("[CloudStorage] RetrieveBlob: cloud error, using local cache: %s (%zu bytes)",
                    filename.c_str(), cached.size());
                if (found) *found = true;
                return cached;
            }
            LOG("[CloudStorage] RetrieveBlob: cloud error and no local cache: %s", filename.c_str());
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
                const std::string& filename,
                bool keepTombstoneOnSuccess) {
    if (!DeleteBlobStaged(accountId, appId, filename)) return false;
    if (g_provider) {
        CloudWorkQueue::WorkItem wi;
        wi.type = CloudWorkQueue::WorkItem::Delete;
        wi.cloudPath = CloudBlobPath(accountId, appId, filename);
        wi.suppressTombstoneClear = keepTombstoneOnSuccess;
        CloudWorkQueue::EnqueueWork(std::move(wi));
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

    // Stamp tombstone BEFORE enqueueing the cloud delete; cleared on success.
    // CN is captured so a cross-machine re-save with higher CN can override.
    uint64_t cnAtDelete = LocalStorage::GetChangeNumber(accountId, appId);
    LocalMetadataStore::MarkDeleted(accountId, appId,
                              CanonicalizeInternalMetadataName(filename), cnAtDelete);

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

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

    if (!g_provider || !g_provider->IsAuthenticated()) return true;

    auto PromoteRollback = [&](uint32_t acct, uint32_t app, const std::vector<std::string>& soFar) {
        size_t failed = 0;
        for (const auto& f : soFar) {
            if (!g_provider->Remove(CloudBlobPath(acct, app, f))) {
                LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: rollback Remove failed for %s",
                    app, (unsigned long long)batchId, f.c_str());
                ++failed;
            }
        }
        if (failed > 0) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: CRITICAL - %zu file(s) remain in cloud after failed rollback",
                app, (unsigned long long)batchId, failed);
            // These orphaned files will be cleaned up on next sync when manifest repair detects them
        }
        LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: rolled back %zu/%zu promoted upload(s)",
            app, (unsigned long long)batchId, soFar.size() - failed, soFar.size());
    };
    std::vector<std::string> promoted;

    std::vector<ICloudProvider::UploadItem> batchItems;
    batchItems.reserve(uploads.size());
    std::vector<std::string> batchFilenames;
    batchFilenames.reserve(uploads.size());

    for (const auto& filename : uploads) {
        if (CloudIntercept::IsReservedBlobFilename(filename)) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: rejecting reserved /blobs/ filename %s",
                appId, (unsigned long long)batchId, filename.c_str());
            PromoteRollback(accountId, appId, promoted);
            return false;
        }

        std::string localPath = LocalBlobPath(accountId, appId, filename);
        std::vector<uint8_t> data;
        if (!TryReadCachedBlob(localPath, filename, data)) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: cached upload missing for %s",
                appId, (unsigned long long)batchId, filename.c_str());
            PromoteRollback(accountId, appId, promoted);
            return false;
        }

        ICloudProvider::UploadItem item;
        item.path = CloudBlobPath(accountId, appId, filename);
        item.data = std::move(data);
        batchItems.push_back(std::move(item));
        batchFilenames.push_back(filename);
    }

    if (!batchItems.empty()) {
        if (!g_provider->UploadBatch(batchItems)) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: batch upload failed",
                appId, (unsigned long long)batchId);
            PromoteRollback(accountId, appId, promoted);
            return false;
        }
        for (const auto& filename : batchFilenames) {
            promoted.push_back(filename);
        }
    }

    for (const auto& filename : deletes) {
        std::string livePath = CloudBlobPath(accountId, appId, filename);
        if (!g_provider->Remove(livePath)) {
            LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: live delete failed for %s",
                appId, (unsigned long long)batchId, filename.c_str());
            PromoteRollback(accountId, appId, promoted);
            return false;
        }
    }

    for (const auto& filename : uploads) {
        LocalMetadataStore::ClearDeleted(accountId, appId,
                                   CanonicalizeInternalMetadataName(filename));
    }

    LOG("[CloudStorage] PromoteStagedBatch app %u batch %llu: promoted %zu upload(s), %zu delete(s)",
        appId, (unsigned long long)batchId, uploads.size(), deletes.size());
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
        std::string cloudPath = CloudBlobPath(accountId, appId, filename);
        return g_provider->CheckExists(cloudPath);
    }

    return ICloudProvider::ExistsStatus::Missing;
}

bool ListRemoteBlobNames(uint32_t accountId, uint32_t appId,
                         std::unordered_set<std::string>& outNames) {
    outNames.clear();

    InflightSyncScope guard;
    if (!guard) return false;
    if (!g_provider || !g_provider->IsAuthenticated()) return true;

    std::string blobPrefix = std::to_string(accountId) + "/" +
                             std::to_string(appId) + "/blobs/";
    std::vector<ICloudProvider::FileInfo> remoteBlobs;
    bool complete = false;
    if (!g_provider->ListChecked(blobPrefix, remoteBlobs, &complete) || !complete) {
        return false;
    }

    for (const auto& fi : remoteBlobs) {
        uint32_t parsedAccountId = 0;
        uint32_t parsedAppId = 0;
        std::string remoteName;
        if (!ParseCloudBlobPath(fi.path, parsedAccountId, parsedAppId, remoteName)) continue;
        if (parsedAccountId != accountId || parsedAppId != appId) continue;
        remoteName = CanonicalizeInternalMetadataName(remoteName);
        if (CloudIntercept::IsReservedBlobFilename(remoteName)) continue;
        outNames.insert(std::move(remoteName));
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
                    if (!validRootTokens.empty() && !validRootTokens.count(token)) {
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
    // Capture timestamp BEFORE the listing so tombstone eviction can protect
    // any MarkDeleted that fires after the listing snapshot was frozen.
    uint64_t listingCapturedAtUnix = static_cast<uint64_t>(std::time(nullptr));
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

    std::unordered_set<std::string> cloudBlobNames;
    for (auto& fi : cloudBlobs) {
        auto blobsPos = fi.path.find("/blobs/");
        if (blobsPos == std::string::npos) continue;
        std::string filename = fi.path.substr(blobsPos + 7);
        std::string canonicalName = CanonicalizeInternalMetadataName(filename);
        if (CloudIntercept::IsReservedBlobFilename(canonicalName)) continue;
        cloudBlobNames.insert(canonicalName);
    }

    if (cloudListSucceeded && cloudListComplete) {
        std::vector<ICloudProvider::FileInfo> filteredCloudBlobs;
        filteredCloudBlobs.reserve(cloudBlobs.size());
        std::unordered_set<std::string> filteredCloudBlobNames;
        for (const auto& fi : cloudBlobs) {
            auto blobsPos = fi.path.find("/blobs/");
            if (blobsPos == std::string::npos) continue;
            std::string filename = fi.path.substr(blobsPos + 7);
            std::string canonicalName = CanonicalizeInternalMetadataName(filename);
            if (CloudIntercept::IsReservedBlobFilename(canonicalName)) {
                CleanupInternalBlobEntry(accountId, appId, fi, filename);
                continue;
            }
            filteredCloudBlobNames.insert(canonicalName);
            filteredCloudBlobs.push_back(fi);
        }
        cloudBlobs = std::move(filteredCloudBlobs);
        cloudBlobNames = std::move(filteredCloudBlobNames);
    }

    // Cloud-side legacy-blob cleanup. Requires a complete listing so the
    // classifier can confirm the canonical sibling exists. Filters legacy
    // paths out of cloudBlobs before the download loop so the concurrent
    // delete worker can't race a 404 into the failed counter.
    if (cloudListSucceeded && cloudListComplete) {
        std::vector<std::string> rawPaths;
        rawPaths.reserve(cloudBlobs.size());
        for (auto& fi : cloudBlobs) rawPaths.push_back(fi.path);
        auto legacyToDelete = LegacyMetadataCleanup::ClassifyLegacyCloudBlobsToDelete(rawPaths);

        std::unordered_set<std::string> legacyPathSet(legacyToDelete.begin(), legacyToDelete.end());
        if (!legacyPathSet.empty()) {
            cloudBlobs.erase(
                std::remove_if(cloudBlobs.begin(), cloudBlobs.end(),
                    [&](const ICloudProvider::FileInfo& fi) {
                        return legacyPathSet.count(fi.path) > 0;
                    }),
                cloudBlobs.end());
        }

        for (auto& legacyPath : legacyToDelete) {
            LOG("[CloudStorage] SyncFromCloud app %u: enqueueing delete of legacy cloud blob %s",
                appId, legacyPath.c_str());
            CloudWorkQueue::WorkItem wi;
            wi.type = CloudWorkQueue::WorkItem::Delete;
            wi.cloudPath = std::move(legacyPath);
            wi.suppressTombstoneClear = true;
            CloudWorkQueue::EnqueueWork(std::move(wi));
        }
    }

    // Tombstones hold until cloud CN advances AND blob mtime is newer (skew grace). MigrateDeletedKeys canonicalizes legacy keys under g_mutex.
    std::unordered_map<std::string, LocalMetadataStore::TombstoneInfo> deletedTombstones;
    {
        size_t migratedCount = 0;
        LocalMetadataStore::MigrateDeletedKeys(
            accountId, appId,
            [](const std::string& k) {
                return CanonicalizeInternalMetadataName(k);
            },
            deletedTombstones, migratedCount);
        if (migratedCount > 0) {
            LOG("[CloudStorage] SyncFromCloud app %u: canonicalized %zu legacy tombstone key(s)",
                appId, migratedCount);
        }
    }

    {
        struct StagedBlob {
            std::string filename;
            std::vector<uint8_t> data;
        };
        std::vector<StagedBlob> stagedNewerBlobs;
        int downloaded = 0, skipped = 0, failed = 0;
        bool timedOut = false;
        auto blobStart = std::chrono::steady_clock::now();
        for (auto& fi : cloudBlobs) {
            // Check timeout
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - blobStart).count();
            if (elapsed >= BLOB_SYNC_TIMEOUT_SEC) {
                int remaining = (int)cloudBlobs.size() - downloaded - skipped;
                LOG("[CloudStorage] SyncFromCloud app %u: blob download TIMEOUT after %llds, "
                    "%d downloaded, %d skipped, ~%d remaining",
                    appId, (long long)elapsed, downloaded, skipped, remaining);
                timedOut = true;
                break;
            }
            // Yielding mid-loop reuses the timeout exit so any newer-cloud-CN
            // promotion (gated on failed==0 && !timedOut) defers to the next sync.
            if (isSweep && g_foregroundSyncCount.load(std::memory_order_seq_cst) > 0) {
                int remaining = (int)cloudBlobs.size() - downloaded - skipped;
                LOG("[CloudStorage] SyncFromCloud app %u: sweep yielding blob loop to foreground sync (downloaded=%d skipped=%d remaining=%d)",
                    appId, downloaded, skipped, remaining);
                timedOut = true;
                break;
            }

            // fi.path: "{accountId}/{appId}/blobs/{filename}"
            auto blobsPos = fi.path.find("/blobs/");
            if (blobsPos == std::string::npos) continue;
            std::string filename = CanonicalizeInternalMetadataName(fi.path.substr(blobsPos + 7));

            // Override: cloud CN advance AND blob mtime > tombstone (5-min skew grace); missing mtime -> CN-only.
            auto tombIt = deletedTombstones.find(filename);
            if (tombIt != deletedTombstones.end()) {
                constexpr uint64_t kTombstoneSkewSec = 300;
                bool cnAdvanced = cloudCNFound && cloudCN > tombIt->second.cn;
                bool haveBlobTime = tombIt->second.createTimeUnix > 0 && fi.modifiedTime > 0;
                bool blobNewerThanTombstone = haveBlobTime &&
                    fi.modifiedTime > tombIt->second.createTimeUnix + kTombstoneSkewSec;
                bool overrideTomb = false;
                if (cnAdvanced) {
                    overrideTomb = haveBlobTime ? blobNewerThanTombstone : true;
                }
                if (overrideTomb) {
                    LOG("[CloudStorage] SyncFromCloud app %u: tombstone for %s overridden "
                        "(cloudCn=%llu > tombCn=%llu, blobMtime=%llu > tombCreate=%llu) -- clearing and downloading",
                        appId, filename.c_str(),
                        (unsigned long long)cloudCN,
                        (unsigned long long)tombIt->second.cn,
                        (unsigned long long)fi.modifiedTime,
                        (unsigned long long)tombIt->second.createTimeUnix);
                    LocalMetadataStore::ClearDeleted(accountId, appId, filename);
                    deletedTombstones.erase(tombIt);
                    // fall through to normal download path
                } else {
                    skipped++;
                    LOG("[CloudStorage] SyncFromCloud app %u: skipping tombstoned blob %s "
                        "(tombCn=%llu tombCreate=%llu cloudCn=%llu blobMtime=%llu cnAdvanced=%d blobNewer=%d)",
                        appId, filename.c_str(),
                        (unsigned long long)tombIt->second.cn,
                        (unsigned long long)tombIt->second.createTimeUnix,
                        (unsigned long long)cloudCN,
                        (unsigned long long)fi.modifiedTime,
                        cnAdvanced ? 1 : 0, blobNewerThanTombstone ? 1 : 0);
                    continue;
                }
            }

            std::string localBlobFile = LocalBlobPath(accountId, appId, filename);
            std::error_code existsEc;
            bool localExists = std::filesystem::exists(FileUtil::Utf8ToPath(localBlobFile), existsEc);
            if (existsEc) localExists = false;
            if (localExists && !cloudHadNewerCN) {
                skipped++;
                continue; // already cached
            }

            // Download to local cache (atomic write)
            LOG("[CloudStorage] SyncFromCloud app %u: downloading blob %s...", appId, filename.c_str());
            std::vector<uint8_t> data;
            if (g_provider->Download(fi.path, data)) {
                if (cloudHadNewerCN) {
                    stagedNewerBlobs.push_back({ filename, std::move(data) });
                    downloaded++;
                    continue;
                }

                // CN was already advanced in step 1; per-file write doesn't increment.
                const uint8_t* writeData = data.empty() ? nullptr : data.data();
                if (LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                                       writeData, data.size())) {
                    downloaded++;
                    LOG("[CloudStorage] SyncFromCloud app %u: blob %s downloaded (%zu bytes)",
                        appId, filename.c_str(), data.size());
                } else {
                    failed++;
                    LOG("[CloudStorage] SyncFromCloud app %u: failed to write blob %s",
                        appId, filename.c_str());
                    continue;
                }
            } else {
                failed++;
                LOG("[CloudStorage] SyncFromCloud app %u: FAILED to download blob %s",
                    appId, filename.c_str());
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

    // Evict tombstones for names absent from the (complete) cloud listing.
    if (cloudListSucceeded && cloudListComplete) {
        LocalMetadataStore::EvictTombstonesNotIn(accountId, appId, cloudBlobNames,
                                           listingCapturedAtUnix);
    }

    // Gap-repair from local cache; verified-complete listing only (an incomplete sub-tree looks identical to empty).
    bool providerLooksUninitialized = cloudListSucceeded && cloudListComplete &&
                                      !cloudCNFound && !cloudRootTokensFound &&
                                      !cloudFileTokensFound && cloudBlobNames.empty();
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

                    // UTF-8 throughout so non-ASCII blob names round-trip.
                std::string rel = FileUtil::PathToUtf8(
                        std::filesystem::relative(entry.path(), localBlobDirPath, entryEc));
                    if (entryEc) continue;
                    for (auto& c : rel) { if (c == '\\') c = '/'; }
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
                    CloudWorkQueue::WorkItem wi;
                    wi.type = CloudWorkQueue::WorkItem::Upload;
                    wi.cloudPath = CloudBlobPath(accountId, appId, rel);
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
    
    // When cloud had newer data, fetch cloud manifest to preserve correct timestamps.
    // Don't rebuild from local blobs - that would lose original file timestamps since
    // WriteFileNoIncrement sets mtime to current time.
    if (hadNewer && !g_shuttingDown.load(std::memory_order_seq_cst)) {
        Manifest cloudManifest = FetchCloudManifest(accountId, appId);
        if (!cloudManifest.empty()) {
            // Cross-check: don't overwrite a richer local manifest with a
            // suspiciously incomplete cloud manifest (same guard as HandleGetChangelist).
            Manifest localManifest = LoadLocalManifest(accountId, appId);
            if (!localManifest.empty() && cloudManifest.size() < localManifest.size()) {
                LOG("[CloudStorage] SyncFromCloud app %u: cloud manifest (%zu files) "
                    "smaller than local (%zu files), keeping local",
                    appId, cloudManifest.size(), localManifest.size());
            } else {
                // Cloud manifest is authoritative after a cloud-newer sync.
                // Start from cloud, then add local-only entries that still
                // have blobs in the cache (not yet uploaded to this provider).
                Manifest merged = cloudManifest;
                for (const auto& [name, entry] : localManifest) {
                    if (merged.find(name) == merged.end() &&
                        HasLocalBlob(accountId, appId, name)) {
                        merged[name] = entry;
                    }
                }
                SaveManifestLocal(accountId, appId, merged);
                LOG("[CloudStorage] SyncFromCloud app %u: merged manifest with %zu files (cloud=%zu, local-only=%zu)",
                    appId, merged.size(), cloudManifest.size(), merged.size() - cloudManifest.size());
            }
        } else {
            // Fallback: build from local blobs if cloud manifest unavailable
            auto manifest = BuildManifestFromLocalBlobs(accountId, appId);
            if (!manifest.empty()) {
                SaveManifest(accountId, appId, manifest);
            }
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
