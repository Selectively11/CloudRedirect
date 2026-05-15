#include "autocloud_bootstrap.h"
#include "autocloud_scan.h"
#include "cloud_intercept.h"
#include "cloud_storage.h"
#include "file_util.h"
#include "local_storage.h"
#include "local_metadata_store.h"
#include "log.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <future>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace AutoCloudBootstrap {

// ============================================================================
// Internal state
// ============================================================================

// g_importMutex > g_tokenCacheMutex > g_bootstrapMutex. Network/disk I/O runs unlocked.
static std::mutex g_tokenCacheMutex;
static std::unordered_map<uint64_t, std::unordered_map<std::string, std::string>> g_canonicalTokenCache;
static std::unordered_map<uint64_t, uint64_t> g_canonicalTokenGeneration;

static std::mutex g_importMutex;

static std::mutex g_bootstrapMutex;
static std::condition_variable g_bootstrapCV;
static std::unordered_set<uint64_t> g_attemptedApps;
static std::unordered_set<uint64_t> g_activeApps;
static std::vector<std::future<void>> g_futures;
static bool g_shuttingDown = false;
// Live orchestrator frames; shutdown waits on this + active.empty().
static int g_orchestratorCount = 0;

static constexpr uint64_t kMaxImportBytes = 128ULL * 1024 * 1024;

// ============================================================================
// Helpers
// ============================================================================

static uint64_t MakeAppKey(uint32_t accountId, uint32_t appId) {
    return CloudIntercept::MakeAppAccountKey(accountId, appId);
}

static bool LooksLikeForeignAppPollution(const std::string& filename, uint32_t appId) {
    size_t pos = filename.find_first_of("/\\");
    if (pos != std::string::npos && pos >= 3 && pos <= 10) {
        const std::string prefix = filename.substr(0, pos);
        if (std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) {
            try {
                unsigned long parsed = std::stoul(prefix);
                if (parsed > 0xFFFFFFFFUL) return false; // Not a valid app ID
                uint32_t embeddedAppId = static_cast<uint32_t>(parsed);
                if (embeddedAppId != 0 && embeddedAppId != appId) return true;
            } catch (...) {}
        }
    }

    size_t underscore = filename.find("_%");
    if (underscore != std::string::npos && underscore >= 3 && underscore <= 10) {
        const std::string prefix = filename.substr(0, underscore);
        if (std::all_of(prefix.begin(), prefix.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) {
            try {
                unsigned long parsed = std::stoul(prefix);
                if (parsed > 0xFFFFFFFFUL) return false; // Not a valid app ID
                uint32_t embeddedAppId = static_cast<uint32_t>(parsed);
                if (embeddedAppId != 0 && embeddedAppId != appId) return true;
            } catch (...) {}
        }
    }

    return false;
}

static std::vector<uint8_t> ReadWholeFile(const std::string& path, bool& ok) {
    ok = false;
    std::ifstream f(FileUtil::Utf8ToPath(path), std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto size = f.tellg();
    if (size < 0) return {};
    if (static_cast<uint64_t>(size) > kMaxImportBytes) {
        LOG("[AutoCloudImport] Skipping oversized source: %s (%llu bytes)",
            path.c_str(), static_cast<unsigned long long>(size));
        return {};
    }
    if (!f.seekg(0, std::ios::beg)) return {};
    std::vector<uint8_t> data(static_cast<size_t>(size));
    if (!data.empty() && !f.read(reinterpret_cast<char*>(data.data()), size)) return {};
    ok = true;
    return data;
}

// ============================================================================
// Token cache management
// ============================================================================

static void CacheCanonicalTokens(uint32_t accountId, uint32_t appId,
                                 const std::vector<AutoCloudScan::FileEntry>& candidates,
                                 uint64_t generation) {
    std::unordered_map<std::string, std::string> tokens;
    for (const auto& fe : candidates) {
        if (!fe.relativePath.empty()) tokens.emplace(fe.relativePath, fe.rootToken);
    }
    std::lock_guard<std::mutex> lock(g_tokenCacheMutex);
    uint64_t key = MakeAppKey(accountId, appId);
    if (g_canonicalTokenGeneration[key] != generation) return;
    g_canonicalTokenCache[key] = std::move(tokens);
}

static void ClearCanonicalTokens(uint32_t accountId, uint32_t appId, uint64_t generation) {
    std::lock_guard<std::mutex> lock(g_tokenCacheMutex);
    uint64_t key = MakeAppKey(accountId, appId);
    if (g_canonicalTokenGeneration[key] != generation) return;
    g_canonicalTokenCache.erase(key);
}

static uint64_t GetTokenGeneration(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_tokenCacheMutex);
    return g_canonicalTokenGeneration[MakeAppKey(accountId, appId)];
}

// ============================================================================
// Bootstrap lifecycle
// ============================================================================

static bool TryBeginBootstrap(uint32_t accountId, uint32_t appId) {
    uint64_t appKey = MakeAppKey(accountId, appId);
    std::lock_guard<std::mutex> lock(g_bootstrapMutex);
    
    // Prune completed futures
    for (auto it = g_futures.begin(); it != g_futures.end(); ) {
        if (it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            try { it->get(); } catch (...) {}
            it = g_futures.erase(it);
        } else {
            ++it;
        }
    }
    
    if (g_shuttingDown || g_attemptedApps.count(appKey) || g_activeApps.count(appKey)) {
        return false;
    }
    g_activeApps.insert(appKey);
    return true;
}

static void FinishBootstrap(uint32_t accountId, uint32_t appId,
                            bool markAttempted, uint64_t generation) {
    uint64_t appKey = MakeAppKey(accountId, appId);
    uint64_t curGen;
    {
        std::lock_guard<std::mutex> tokenLock(g_tokenCacheMutex);
        curGen = g_canonicalTokenGeneration[appKey];
    }
    std::lock_guard<std::mutex> lock(g_bootstrapMutex);
    bool generationCurrent = (curGen == generation);
    g_activeApps.erase(appKey);
    if (markAttempted && generationCurrent) g_attemptedApps.insert(appKey);
    g_bootstrapCV.notify_all();
}

static void WaitForBootstrapInternal(uint32_t accountId, uint32_t appId) {
    uint64_t appKey = MakeAppKey(accountId, appId);
    std::unique_lock<std::mutex> lock(g_bootstrapMutex);
    g_bootstrapCV.wait(lock, [&] {
        return !g_activeApps.count(appKey);
    });
}

static bool IsBootstrapActiveInternal(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_bootstrapMutex);
    return g_activeApps.count(MakeAppKey(accountId, appId)) != 0;
}

static bool IsShuttingDownInternal() {
    std::lock_guard<std::mutex> lock(g_bootstrapMutex);
    return g_shuttingDown;
}

// ============================================================================
// Worker implementation
// ============================================================================

static void BootstrapWorker(uint32_t accountId, uint32_t appId, uint64_t cacheGeneration) {
    struct FinishGuard {
        uint32_t accountId;
        uint32_t appId;
        uint64_t generation;
        bool markAttempted;
        bool fired;
        ~FinishGuard() {
            if (!fired) {
                LOG("[AutoCloudImport] Worker aborted via exception for app %u -- releasing bootstrap slot", appId);
                FinishBootstrap(accountId, appId, markAttempted, generation);
            }
        }
    };
    FinishGuard guard{accountId, appId, cacheGeneration, /*markAttempted=*/false, /*fired=*/false};
    auto finish = [&](bool markAttempted, uint64_t generation) {
        guard.fired = true;
        FinishBootstrap(accountId, appId, markAttempted, generation);
    };

    if (IsShuttingDownInternal()) {
        LOG("[AutoCloudImport] Aborting bootstrap for app %u -- shutdown in progress", appId);
        ClearCanonicalTokens(accountId, appId, cacheGeneration);
        finish(false, cacheGeneration);
        return;
    }

    AutoCloudScan::ScanResult scan;
    try {
        scan = AutoCloudScan::GetFileList(CloudIntercept::GetSteamPath(), accountId, appId);
    } catch (const std::exception& ex) {
        LOG("[AutoCloudImport] Scan failed for app %u: %s", appId, ex.what());
        ClearCanonicalTokens(accountId, appId, cacheGeneration);
        finish(false, cacheGeneration);
        return;
    } catch (...) {
        LOG("[AutoCloudImport] Scan failed for app %u", appId);
        ClearCanonicalTokens(accountId, appId, cacheGeneration);
        finish(false, cacheGeneration);
        return;
    }

    if (scan.hasRootCollision) {
        LOG("[AutoCloudImport] Root collision detected for app %u; aborting bootstrap", appId);
        ClearCanonicalTokens(accountId, appId, cacheGeneration);
        finish(true, cacheGeneration);
        return;
    }
    // Reject incomplete scans (resource cap or root collision).
    if (!scan.complete) {
        LOG("[AutoCloudImport] Scan limit hit for app %u (%zu files observed); "
            "refusing partial import, preserving canonical token cache",
            appId, scan.files.size());
        finish(false, cacheGeneration);
        return;
    }

    std::vector<AutoCloudScan::FileEntry>& candidates = scan.files;
    if (candidates.empty()) {
        ClearCanonicalTokens(accountId, appId, cacheGeneration);
        finish(true, cacheGeneration);
        return;
    }

    // Check for obvious pollution (files from other apps)
    size_t definitePollution = 0;
    for (const auto& fe : candidates) {
        if (LooksLikeForeignAppPollution(fe.relativePath, appId)) {
            LOG("[AutoCloudImport] Definite pollution candidate for app %u: %s", appId, fe.relativePath.c_str());
            ++definitePollution;
        }
    }
    if (definitePollution > 0) {
        LOG("[AutoCloudImport] Aborting import for app %u: %zu obvious pollution file(s) detected",
            appId, definitePollution);
        ClearCanonicalTokens(accountId, appId, cacheGeneration);
        finish(true, cacheGeneration);
        return;
    }

    // Build map of existing cached files
    std::unordered_map<std::string, LocalStorage::FileEntry> existing;
    for (const auto& fe : LocalStorage::GetFileList(accountId, appId)) {
        existing[fe.filename] = fe;
    }

    auto fileTokens = CloudStorage::LoadFileTokens(accountId, appId);
    auto rootTokens = CloudStorage::LoadRootTokens(accountId, appId);
    auto tombstoneSnapshot = LocalMetadataStore::LoadDeleted(accountId, appId);
    std::unordered_set<std::string> remoteBlobNames;
    if (!CloudStorage::ListRemoteBlobNames(accountId, appId, remoteBlobNames)) {
        LOG("[AutoCloudImport] Aborting import for app %u: could not list remote blobs",
            appId);
        ClearCanonicalTokens(accountId, appId, cacheGeneration);
        finish(false, cacheGeneration);
        return;
    }

    struct PendingImport {
        std::string filename;
        std::string sourcePath;
        uint64_t timestamp = 0;
        std::string rootToken;
        bool refresh = false;
        std::vector<uint8_t> expectedSha;
    };
    std::vector<PendingImport> pendingImports;
    bool tokenMetadataChanged = false;

    for (const auto& fe : candidates) {
        if (IsShuttingDownInternal()) {
            LOG("[AutoCloudImport] Aborting existence checks for app %u -- shutdown in progress", appId);
            ClearCanonicalTokens(accountId, appId, cacheGeneration);
            finish(false, cacheGeneration);
            return;
        }
        if (fe.relativePath.empty() || fe.fullPath.empty()) continue;
        if (CloudIntercept::IsInternalMetadataFile(fe.relativePath)) continue;

        auto it = existing.find(fe.relativePath);
        bool isRefresh = false;
        if (it != existing.end()) {
            const bool contentMatches =
                (it->second.sha == fe.sha && it->second.rawSize == fe.size);
            if (!contentMatches) {
                // Prefer non-zero local file over zero-byte cloud stub.
                const bool cloudIsZeroByteStub = (it->second.rawSize == 0 && fe.size > 0);
                const bool diskIsNewer = (fe.modifiedTime > it->second.timestamp);
                const bool timestampsEqual = (fe.modifiedTime == it->second.timestamp);
                
                if (diskIsNewer || cloudIsZeroByteStub || timestampsEqual) {
                    LOG("[AutoCloudImport] Refreshing app %u file %s: disk mtime %llu vs cached %llu (size %llu->%llu)%s%s",
                        appId, fe.relativePath.c_str(),
                        (unsigned long long)fe.modifiedTime,
                        (unsigned long long)it->second.timestamp,
                        (unsigned long long)it->second.rawSize,
                        (unsigned long long)fe.size,
                        cloudIsZeroByteStub ? " [cloud zero-byte stub]" : "",
                        timestampsEqual ? " [equal timestamps, preferring disk]" : "");
                    isRefresh = true;
                } else {
                    LOG("[AutoCloudImport] Skipping existing app %u file %s: disk mtime %llu < cached %llu",
                        appId, fe.relativePath.c_str(),
                        (unsigned long long)fe.modifiedTime,
                        (unsigned long long)it->second.timestamp);
                    continue;
                }
            } else {
                // Identical content: reconcile root-token metadata only.
                auto existingToken = fileTokens.find(fe.relativePath);
                if (existingToken == fileTokens.end() || existingToken->second != fe.rootToken) {
                    fileTokens[fe.relativePath] = fe.rootToken;
                    tokenMetadataChanged = true;
                    LOG("[AutoCloudImport] Canonical root token for app %u file %s: '%s'",
                        appId, fe.relativePath.c_str(), fe.rootToken.c_str());
                }
                if (!fe.rootToken.empty() && !rootTokens.count(fe.rootToken)) {
                    rootTokens.insert(fe.rootToken);
                    tokenMetadataChanged = true;
                }
                continue;
            }
        }

        if (!isRefresh) {
            if (remoteBlobNames.count(fe.relativePath) > 0) {
                LOG("[AutoCloudImport] Skipping app %u file %s because blob already exists in cache/cloud",
                    appId, fe.relativePath.c_str());
                continue;
            }
            if (tombstoneSnapshot.count(fe.relativePath) > 0) {
                LOG("[AutoCloudImport] Skipping app %u file %s because it has a delete tombstone",
                    appId, fe.relativePath.c_str());
                continue;
            }
        }

        pendingImports.push_back({ fe.relativePath, fe.fullPath, fe.modifiedTime, fe.rootToken, isRefresh, fe.sha });
    }

    if (pendingImports.empty() && !tokenMetadataChanged) {
        finish(true, cacheGeneration);
        return;
    }

    uint64_t publishGeneration = 0;
    size_t imported = 0;
    uint64_t cn = 0;

    // Import lock covers local writes only; network runs unlocked.
    std::unique_lock<std::mutex> importLock(g_importMutex);
    
    // Bump generation atomically
    bool generationStale = false;
    {
        std::lock_guard<std::mutex> lock(g_tokenCacheMutex);
        uint64_t key = MakeAppKey(accountId, appId);
        if (g_canonicalTokenGeneration[key] != cacheGeneration) {
            generationStale = true;
        } else {
            g_canonicalTokenCache.erase(key);
            publishGeneration = ++g_canonicalTokenGeneration[key];
        }
    }
    if (generationStale) {
        finish(false, cacheGeneration);
        return;
    }

    // Last abort point before StoreBlob writes.
    if (IsShuttingDownInternal()) {
        LOG("[AutoCloudImport] Aborting pre-commit for app %u -- shutdown in progress", appId);
        ClearCanonicalTokens(accountId, appId, publishGeneration);
        finish(false, publishGeneration);
        return;
    }

    for (auto& pending : pendingImports) {
        if (IsShuttingDownInternal()) {
            LOG("[AutoCloudImport] Aborting mid-import for app %u -- shutdown in progress", appId);
            break;
        }
        if (LocalMetadataStore::IsDeleted(accountId, appId, pending.filename)) {
            LOG("[AutoCloudImport] Skipping app %u file %s because tombstone appeared before commit",
                appId, pending.filename.c_str());
            continue;
        }
        if (!pending.refresh && CloudStorage::HasLocalBlob(accountId, appId, pending.filename)) {
            LOG("[AutoCloudImport] Skipping app %u file %s because blob appeared before commit",
                appId, pending.filename.c_str());
            continue;
        }

        bool readOk = false;
        auto data = ReadWholeFile(pending.sourcePath, readOk);
        if (!readOk) {
            LOG("[AutoCloudImport] Failed to read source before commit for app %u: %s",
                appId, pending.sourcePath.c_str());
            continue;
        }

        const uint8_t* ptr = data.empty() ? nullptr : data.data();
        if (pending.expectedSha.empty()) {
            LOG("[AutoCloudImport] Skipping app %u file %s: no SHA from scan",
                appId, pending.filename.c_str());
            continue;
        }
        if (LocalStorage::SHA1(ptr, data.size()) != pending.expectedSha) {
            LOG("[AutoCloudImport] Skipping app %u file %s: source content changed between scan and commit",
                appId, pending.filename.c_str());
            continue;
        }

        if (!CloudStorage::StoreBlob(accountId, appId, pending.filename, ptr, data.size())) {
            LOG("[AutoCloudImport] Failed to cache app %u file %s", appId, pending.filename.c_str());
            continue;
        }

        // Restore original timestamp to cached file.
        LocalStorage::SetFileTimestamp(accountId, appId, pending.filename, pending.timestamp);

        // Update manifest with original file metadata from scan.
        if (!CloudStorage::UpdateManifestEntry(accountId, appId, pending.filename,
                pending.expectedSha, pending.timestamp, data.size())) {
            LOG("[AutoCloudImport] Manifest update FAILED for app %u file %s",
                appId, pending.filename.c_str());
            LocalStorage::DeleteFile(accountId, appId, pending.filename);
            continue;
        }

        auto existingToken = fileTokens.find(pending.filename);
        if (existingToken == fileTokens.end() || existingToken->second != pending.rootToken) {
            fileTokens[pending.filename] = pending.rootToken;
            tokenMetadataChanged = true;
            LOG("[AutoCloudImport] Canonical root token for app %u file %s: '%s'",
                appId, pending.filename.c_str(), pending.rootToken.c_str());
        }
        if (!pending.rootToken.empty() && !rootTokens.count(pending.rootToken)) {
            rootTokens.insert(pending.rootToken);
            tokenMetadataChanged = true;
        }
        ++imported;
        LOG("[AutoCloudImport] %s app %u file %s",
            pending.refresh ? "Refreshed" : "Imported",
            appId, pending.filename.c_str());
    }

    if (imported == 0 && !tokenMetadataChanged) {
        finish(true, publishGeneration);
        return;
    }

    if (!rootTokens.empty() && !CloudStorage::SaveRootTokens(accountId, appId, rootTokens)) {
        LOG("[AutoCloudImport] root_token.dat local persist FAILED app %u -- next restart will load stale set", appId);
    }
    if ((!fileTokens.empty() || tokenMetadataChanged) &&
        !CloudStorage::SaveFileTokens(accountId, appId, fileTokens)) {
        LOG("[AutoCloudImport] file_tokens.dat local persist FAILED app %u -- next restart will load stale set", appId);
    }

    importLock.unlock();

    if (GetTokenGeneration(accountId, appId) != publishGeneration) {
        finish(false, publishGeneration);
        return;
    }

    uint64_t oldCN = LocalStorage::GetChangeNumber(accountId, appId);
    cn = LocalStorage::IncrementChangeNumber(accountId, appId);
    if (cn <= oldCN) {
        LOG("[AutoCloudImport] CN increment FAILED for app %u; aborting commit", appId);
        ClearCanonicalTokens(accountId, appId, publishGeneration);
        finish(false, publishGeneration);
        return;
    }
    CloudStorage::CommitCNWithRetry(accountId, appId, cn);

    // Re-check generation; concurrent invalidation bumps it.
    if (GetTokenGeneration(accountId, appId) != publishGeneration) {
        finish(false, publishGeneration);
        return;
    }

    CacheCanonicalTokens(accountId, appId, candidates, publishGeneration);
    LOG("[AutoCloudImport] Imported %zu AutoCloud file(s), updatedTokens=%u for app %u, CN=%llu",
        imported, tokenMetadataChanged ? 1 : 0, appId, cn);
    finish(true, publishGeneration);
}

// ============================================================================
// Public API
// ============================================================================

void Bootstrap(uint32_t accountId, uint32_t appId, bool wait) {
    uint64_t cacheGeneration = GetTokenGeneration(accountId, appId);
    if (!TryBeginBootstrap(accountId, appId)) {
        if (wait) WaitForBootstrapInternal(accountId, appId);
        return;
    }

    if (wait) {
        BootstrapWorker(accountId, appId, cacheGeneration);
        return;
    }

    if (IsShuttingDownInternal()) {
        FinishBootstrap(accountId, appId, /*markAttempted=*/false, cacheGeneration);
        return;
    }

    // Claim slot before spawn so shutdown waits on post-spawn ops.
    {
        std::lock_guard<std::mutex> lock(g_bootstrapMutex);
        ++g_orchestratorCount;
    }
    struct OrchestratorGuard {
        ~OrchestratorGuard() {
            std::lock_guard<std::mutex> lock(g_bootstrapMutex);
            --g_orchestratorCount;
            g_bootstrapCV.notify_all();
        }
    } orchestratorGuard;

    // Spawn unlocked; thread creation can block 100s of ms on Windows.
    std::future<void> future;
    try {
        future = std::async(std::launch::async, [accountId, appId, cacheGeneration]() {
            BootstrapWorker(accountId, appId, cacheGeneration);
        });
    } catch (...) {
        LOG("[AutoCloudImport] Failed to spawn bootstrap worker for app %u", appId);
        FinishBootstrap(accountId, appId, /*markAttempted=*/false, cacheGeneration);
        return;
    }

    // Stash for shutdown join.
    {
        std::unique_lock<std::mutex> lock(g_bootstrapMutex);
        if (!g_shuttingDown) {
            g_futures.push_back(std::move(future));
            return;
        }
    }
    try {
        future.wait();
    } catch (...) {}
}

void WaitFor(uint32_t accountId, uint32_t appId) {
    WaitForBootstrapInternal(accountId, appId);
}

bool IsActive(uint32_t accountId, uint32_t appId) {
    return IsBootstrapActiveInternal(accountId, appId);
}

std::string CanonicalizeToken(uint32_t accountId, uint32_t appId,
                              const std::string& cleanName,
                              const std::string& fallbackToken) {
    if (cleanName.empty()) return fallbackToken;

    std::lock_guard<std::mutex> lock(g_tokenCacheMutex);
    auto appIt = g_canonicalTokenCache.find(MakeAppKey(accountId, appId));
    if (appIt != g_canonicalTokenCache.end()) {
        auto tokenIt = appIt->second.find(cleanName);
        if (tokenIt != appIt->second.end()) {
            if (tokenIt->second != fallbackToken) {
                LOG("[NS-TOK] Canonicalized token for account %u app %u file %s: %s -> %s",
                    accountId, appId, cleanName.c_str(), fallbackToken.c_str(), tokenIt->second.c_str());
            }
            return tokenIt->second;
        }
    }
    return fallbackToken;
}

uint64_t GetCacheGeneration(uint32_t accountId, uint32_t appId) {
    return GetTokenGeneration(accountId, appId);
}

std::unordered_map<std::string, std::string> GetCachedTokens(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_tokenCacheMutex);
    auto it = g_canonicalTokenCache.find(MakeAppKey(accountId, appId));
    if (it != g_canonicalTokenCache.end()) {
        return it->second;
    }
    return {};
}

void InvalidateCache(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> importLock(g_importMutex);
    uint64_t key = MakeAppKey(accountId, appId);
    {
        std::lock_guard<std::mutex> lock(g_tokenCacheMutex);
        g_canonicalTokenCache.erase(key);
        ++g_canonicalTokenGeneration[key];
    }
    {
        std::lock_guard<std::mutex> lock(g_bootstrapMutex);
        g_attemptedApps.erase(key);
    }
}

void ResetAttempted(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_bootstrapMutex);
    g_attemptedApps.erase(MakeAppKey(accountId, appId));
}

int RestoreBlobsToGameFolder(uint32_t accountId, uint32_t appId,
                              const std::string& steamPath) {
    auto fileTokens = CloudStorage::LoadFileTokens(accountId, appId);
    if (fileTokens.empty()) {
        LOG("[AutoCloudRestore] app %u: no file tokens, skipping restore", appId);
        return 0;
    }

    auto rootDirs = AutoCloudScan::GetRootTokenDirectories(steamPath, appId, accountId);
    if (rootDirs.empty()) {
        LOG("[AutoCloudRestore] app %u: no root directories resolved", appId);
        return 0;
    }

    auto files = LocalStorage::GetFileList(accountId, appId);
    if (files.empty()) {
        LOG("[AutoCloudRestore] app %u: no blobs in local storage", appId);
        return 0;
    }

    int restored = 0;
    for (const auto& fe : files) {
        if (fe.deleted) continue;
        if (CloudIntercept::IsInternalMetadataFile(fe.filename)) continue;

        auto tokenIt = fileTokens.find(fe.filename);
        if (tokenIt == fileTokens.end() || tokenIt->second.empty()) {
            continue;
        }

        auto dirIt = rootDirs.find(tokenIt->second);
        if (dirIt == rootDirs.end() || dirIt->second.empty()) {
            LOG("[AutoCloudRestore] app %u file %s: unknown root token '%s'",
                appId, fe.filename.c_str(), tokenIt->second.c_str());
            continue;
        }

        std::string targetPath = dirIt->second + fe.filename;
        for (auto& c : targetPath) {
            if (c == '/') {
#ifdef _WIN32
                c = '\\';
#endif
            }
        }

        if (!FileUtil::IsPathWithin(dirIt->second, targetPath)) {
            LOG("[AutoCloudRestore] app %u file %s: path traversal blocked (root=%s)",
                appId, fe.filename.c_str(), dirIt->second.c_str());
            continue;
        }

        std::error_code ec;
        auto targetFsPath = FileUtil::Utf8ToPath(targetPath);
        bool exists = std::filesystem::exists(targetFsPath, ec);

        if (exists && !ec) {
            auto diskTime = std::filesystem::last_write_time(targetFsPath, ec);
            if (!ec) {
                auto diskSeconds = AutoCloudUtil::FileTimeToUnixSeconds(diskTime);
                // Skip restore only if disk file is newer AND non-empty.
                // A zero-byte file (e.g., from a game crash mid-write) should
                // not block restoration of a valid blob.
                std::error_code sizeEc;
                auto diskSize = std::filesystem::file_size(targetFsPath, sizeEc);
                if (diskSeconds > fe.timestamp && !sizeEc && diskSize > 0) {
                    continue;
                }
            }
        }

        auto blobData = LocalStorage::ReadFile(accountId, appId, fe.filename);
        if (blobData.empty() && fe.rawSize > 0) {
            LOG("[AutoCloudRestore] app %u file %s: failed to read blob",
                appId, fe.filename.c_str());
            continue;
        }

        auto parentDir = targetFsPath.parent_path();
        if (!parentDir.empty()) {
            std::filesystem::create_directories(parentDir, ec);
            if (ec) {
                LOG("[AutoCloudRestore] app %u file %s: failed to create directory %s: %s",
                    appId, fe.filename.c_str(),
                    FileUtil::PathToUtf8(parentDir).c_str(), ec.message().c_str());
                continue;
            }
        }

        // Use atomic write to minimize TOCTOU window
        if (!FileUtil::AtomicWriteBinary(targetPath, blobData.data(), blobData.size())) {
            LOG("[AutoCloudRestore] app %u file %s: failed to write: %s",
                appId, fe.filename.c_str(), targetPath.c_str());
            continue;
        }

        if (fe.timestamp > 0) {
            auto targetTime = AutoCloudUtil::UnixSecondsToFileTime(fe.timestamp);
            std::filesystem::last_write_time(targetFsPath, targetTime, ec);
            if (ec) {
                LOG("[AutoCloudRestore] app %u file %s: failed to set mtime: %s",
                    appId, fe.filename.c_str(), ec.message().c_str());
            }
        }

        restored++;
        LOG("[AutoCloudRestore] app %u: restored %s -> %s (%zu bytes, ts=%llu)",
            appId, fe.filename.c_str(), targetPath.c_str(),
            blobData.size(), (unsigned long long)fe.timestamp);
    }

    if (restored > 0) {
        LOG("[AutoCloudRestore] app %u: restored %d file(s) to game folder", appId, restored);
    }
    return restored;
}

void Shutdown() {
    std::vector<std::future<void>> futures;
    {
        std::lock_guard<std::mutex> lock(g_bootstrapMutex);
        g_shuttingDown = true;
        futures.swap(g_futures);
    }
    for (auto& future : futures) {
        try { future.get(); } catch (...) {}
    }
    std::unique_lock<std::mutex> lock(g_bootstrapMutex);
    g_bootstrapCV.wait(lock, [] {
        return g_activeApps.empty() && g_orchestratorCount == 0;
    });
}

} // namespace AutoCloudBootstrap
