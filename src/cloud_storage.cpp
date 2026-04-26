#include "cloud_storage.h"
#include "local_storage.h"
#include "local_disk_provider.h"
#include "google_drive_provider.h"
#include "onedrive_provider.h"
#include "cloud_metadata_paths.h"
#include "file_util.h"
#include "legacy_metadata_cleanup.h"
#include "log.h"
#include <fstream>
#include <filesystem>
#include <sstream>
#include <chrono>
#include <ctime>
#include <list>
#include <algorithm>
#include <limits>
#include <Windows.h>

namespace CloudStorage {

static std::string CanonicalizeInternalMetadataName(std::string_view filename) {
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

// Per-(account,app) sync mutex registry (Steam-parity). Non-reentrant: SyncFromCloudInner-reachable callers go direct.
static std::mutex                                              g_syncMutexRegistryMutex;
static std::unordered_map<uint64_t, std::shared_ptr<std::mutex>> g_syncMutexRegistry;

// Shutdown waits on these counters before tearing down g_provider so a
// long-running Download/Upload doesn't return into freed memory.
static std::atomic<int>  g_inflightSyncCount{0};
static std::atomic<bool> g_shuttingDown{false};
static std::atomic<int>  g_inflightCommitDrainCount{0};

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

static std::shared_ptr<std::mutex> AcquireAppSyncMutex(uint32_t accountId, uint32_t appId) {
    uint64_t key = (static_cast<uint64_t>(accountId) << 32) | appId;
    std::lock_guard<std::mutex> g(g_syncMutexRegistryMutex);
    auto it = g_syncMutexRegistry.find(key);
    if (it == g_syncMutexRegistry.end()) {
        it = g_syncMutexRegistry.emplace(key, std::make_shared<std::mutex>()).first;
    }
    return it->second;
}

// Cloud-failure dialog: fires once after FAIL_THRESHOLD, then COOLDOWN_SECS suppression.

static constexpr int    FAIL_THRESHOLD   = 3;
static constexpr int    COOLDOWN_SECS    = 300; // 5 minutes

static std::atomic<int> g_consecutiveFails{0};
static std::atomic<int64_t> g_lastDialogTime{0};
static std::mutex g_dialogMutex;
// Tracked so Shutdown can join all outstanding dialog threads before unload.
static std::vector<std::thread> g_dialogThreads;
static std::atomic<bool> g_dialogShuttingDown{false};

static void ShowCloudError(const std::string& message) {
    if (g_dialogShuttingDown.load(std::memory_order_acquire)) return;
    // check cooldown
    int64_t now = (int64_t)time(nullptr);
    int64_t last = g_lastDialogTime.load();
    if (last > 0 && now - last < COOLDOWN_SECS) return;
    g_lastDialogTime.store(now);

    LOG("[CloudStorage] Showing error dialog: %s", message.c_str());

    std::lock_guard<std::mutex> lock(g_dialogMutex);
    if (g_dialogShuttingDown.load(std::memory_order_acquire)) return;
    // MessageBoxW so non-ASCII paths render regardless of the system ACP.
    std::wstring wmsg;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, message.c_str(),
                                   static_cast<int>(message.size()), nullptr, 0);
    if (wlen > 0) {
        wmsg.resize(static_cast<size_t>(wlen));
        MultiByteToWideChar(CP_UTF8, 0, message.c_str(),
                            static_cast<int>(message.size()),
                            wmsg.data(), wlen);
    }
    g_dialogThreads.emplace_back([wmsg]() {
        MessageBoxW(nullptr, wmsg.c_str(),
                    L"CloudRedirect - Cloud Sync Error",
                    MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
    });
}

// Call after a cloud operation fails. Shows dialog after N consecutive failures.
static void OnCloudFailure(const char* operation, const std::string& path) {
    int fails = ++g_consecutiveFails;
    if (fails == FAIL_THRESHOLD) {
        std::string provName = g_provider ? g_provider->Name() : "Cloud";
        ShowCloudError(
            provName + " sync error: " + std::string(operation) +
            " has failed " + std::to_string(fails) + " times.\n\n"
            "Your saves may not be syncing to the cloud.\n"
            "Check your internet connection and cloud_redirect.log for details.\n\n"
            "Last failed path: " + path);
    }
}

static void OnCloudSuccess() {
    g_consecutiveFails.store(0);
}

// Show an immediate dialog for critical auth failures (token refresh broken).
void NotifyAuthFailure(const std::string& providerName) {
    ShowCloudError(
        providerName + " authentication failed!\n\n"
        "CloudRedirect cannot refresh your access token.\n"
        "Cloud sync is disabled until this is resolved.\n\n"
        "Re-authenticate using the CloudRedirect setup tool.");
}

// background work queue
struct WorkItem {
    enum Type { Upload, Delete };
    Type        type;
    std::string cloudPath;          // relative path for provider
    std::vector<uint8_t> data;      // only for Upload
    bool        skipIfExists = false;
    int         existsCheckRetries = 0;  // Upload-only: retries of CheckExists before skipIfExists upload
    int         transferRetries = 0;     // Upload/Delete: retries of the actual Upload/Remove call
    int         drainRequeues = 0;       // Times this item was requeued via RequeueFailedWorkForPrefixLocked
    // Delete-only path skips canonicalize-on-clear: an internal legacy-sibling cleanup must not erase a concurrent user DeleteBlob's tombstone.
    bool        suppressTombstoneClear = false;
};

// Queue mutex must never be held across a provider call or LocalStorage::* call.
static std::list<WorkItem>               g_workQueue;
static std::mutex                        g_queueMutex;
static std::condition_variable           g_queueCV;
// O(1) dedup index for Upload items.
static std::unordered_map<std::string, std::list<WorkItem>::iterator> g_uploadIndex;
static std::vector<std::thread>          g_workerThreads;
static std::atomic<bool>                 g_workerRunning{false};
static std::atomic<int>                  g_activeWorkers{0};
static std::unordered_map<std::string, int> g_activePaths;
// Retriable failures only; poisoned items are removed once they exhaust MAX_DRAIN_REQUEUES.
static std::unordered_set<std::string>   g_failedPaths;
// Dead-letter record of every failed item including poisoned ones.
static std::unordered_map<std::string, WorkItem> g_failedWorkItems;
static std::condition_variable           g_drainCV;       // signaled when a worker finishes an item
static constexpr int                     WORKER_THREAD_COUNT = 4;

static bool HasPendingWorkForPrefix(const std::string& prefix) {
    for (const auto& item : g_workQueue) {
        if (item.cloudPath.rfind(prefix, 0) == 0) return true;
    }
    for (const auto& [path, count] : g_activePaths) {
        if (count > 0 && path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

static bool HasFailedWorkForPrefix(const std::string& prefix) {
    for (const auto& path : g_failedPaths) {
        if (path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

static void ClearFailedWorkForPrefix(const std::string& prefix) {
    for (auto it = g_failedPaths.begin(); it != g_failedPaths.end(); ) {
        if (it->rfind(prefix, 0) == 0) it = g_failedPaths.erase(it);
        else ++it;
    }
}

// Cap on per-item drain requeues so a permanently-broken item is poisoned.
static constexpr int MAX_DRAIN_REQUEUES = 3;

static void RequeueFailedWorkForPrefixLocked(const std::string& prefix) {
    for (auto it = g_failedWorkItems.begin(); it != g_failedWorkItems.end(); ) {
        if (it->first.rfind(prefix, 0) != 0) {
            ++it;
            continue;
        }
        if (it->second.drainRequeues >= MAX_DRAIN_REQUEUES) {
            // Poison item: drop from g_failedPaths so drains stop blocking,
            // keep in g_failedWorkItems so a fresh EnqueueWork must supersede it.
            g_failedPaths.erase(it->first);
            if (!it->second.data.empty()) {
                std::vector<uint8_t>().swap(it->second.data);
            }
            ++it;
            continue;
        }
        WorkItem item = std::move(it->second);
        // Fresh inline-retry budget; drain-requeue counter preserved for the cap.
        item.existsCheckRetries = 0;
        item.transferRetries = 0;
        ++item.drainRequeues;
        g_failedPaths.erase(it->first);
        if (!g_activePaths.count(item.cloudPath)) {
            g_workQueue.push_back(std::move(item));
            auto queued = std::prev(g_workQueue.end());
            if (queued->type == WorkItem::Upload) {
                g_uploadIndex[queued->cloudPath] = queued;
            }
        }
        it = g_failedWorkItems.erase(it);
    }
}

static void EnqueueWork(WorkItem item);
// Worker-only retry. Returns false if a fresher caller-enqueued upload supersedes this; EnqueueWork's last-writer-wins is wrong for stale retries.
static bool RequeueFromWorker(WorkItem item);
static std::string LocalStoragePath(uint32_t accountId, uint32_t appId);

static std::string CreateLocalConflictCopy(uint32_t accountId, uint32_t appId,
                                           const std::string& filename,
                                           const std::string& localPath) {
    std::string conflictsRoot = g_localRoot + "conflicts\\";
    std::string appConflictRoot = conflictsRoot + std::to_string(accountId) + "\\" +
        std::to_string(appId) + "\\";
    auto stamp = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string conflictPath = appConflictRoot + filename + "." + std::to_string(stamp) + ".local";
    for (auto& c : conflictPath) { if (c == '/') c = '\\'; }
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
    // Manual increment so mid-walk errors stay in error_code; an escaped
    // filesystem_error from a worker would kill the host process.
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
                bool skipReserved = (rel == "cn.dat" || rel == "root_token.dat" ||
                                     rel == "file_tokens.dat" || rel == "deleted.dat");
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

// Inverse of CloudBlobPath. Rejects metadata paths and any non-canonical decimal.
static bool ParseCloudBlobPath(const std::string& cloudPath,
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

    auto parseU32 = [](const std::string& s, uint32_t& out) -> bool {
        if (s.empty()) return false;
        for (char c : s) {
            if (c < '0' || c > '9') return false; // no sign, whitespace, or letters
        }
        try {
            unsigned long long v = std::stoull(s);
            if (v > (std::numeric_limits<uint32_t>::max)()) return false;
            out = static_cast<uint32_t>(v);
            return true;
        } catch (...) { return false; }
    };

    if (!parseU32(cloudPath.substr(0, p1), accountId)) return false;
    if (!parseU32(cloudPath.substr(p1 + 1, p2 - p1 - 1), appId)) return false;
    filename = cloudPath.substr(fileStart);
    return !filename.empty();
}

static std::string CloudMetadataPath(uint32_t accountId, uint32_t appId,
                                     const std::string& name) {
    return std::to_string(accountId) + "/" + std::to_string(appId) + "/" + name;
}

// {g_localRoot}\storage\{accountId}\{appId}\{filename}
static std::string LocalStoragePath(uint32_t accountId, uint32_t appId) {
    return g_localRoot + "storage\\" + std::to_string(accountId) + "\\" +
           std::to_string(appId) + "\\";
}

static std::unordered_set<uint32_t> EnumerateLocalAppIds(uint32_t accountId) {
    std::unordered_set<uint32_t> appIds;
    std::string accountRoot = g_localRoot + "storage\\" + std::to_string(accountId) + "\\";
    std::error_code ec;
    auto accountRootPath = FileUtil::Utf8ToPath(accountRoot);
    if (!std::filesystem::exists(accountRootPath, ec) || !std::filesystem::is_directory(accountRootPath, ec)) {
        return appIds;
    }

    // Manual increment so a mid-walk filesystem_error doesn't escape and
    // call std::terminate from the detached startup thread.
    std::filesystem::directory_iterator it(accountRootPath, ec);
    if (ec) return appIds;
    const std::filesystem::directory_iterator end;
    while (it != end) {
        const auto& entry = *it;
        std::error_code dirEc;
        if (entry.is_directory(dirEc)) {
            const std::string name = entry.path().filename().string();
            try {
                uint32_t parsed = static_cast<uint32_t>(std::stoul(name));
                // Skip the account-scope sentinel; not a real Steam app.
                if (parsed != CloudIntercept::kAccountScopeAppId) {
                    appIds.insert(parsed);
                }
            } catch (...) {
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
    std::string path = g_localRoot + "storage\\" + std::to_string(accountId) +
                       "\\" + std::to_string(appId) + "\\" + filename;
    for (auto& c : path) { if (c == '/') c = '\\'; }

    std::string storageRoot = g_localRoot + "storage\\";
    if (!FileUtil::IsPathWithin(storageRoot, path)) {
        LOG("[CloudStorage] BLOCKED path traversal: '%s' root='%s'",
            filename.c_str(), storageRoot.c_str());
        return {};
    }

    return path;
}


static void WorkerLoop(int threadId) {
    LOG("[CloudStorage] Background worker %d started", threadId);
    int consecutiveFailures = 0;
    while (g_workerRunning) {
        WorkItem item;
        {
            std::unique_lock<std::mutex> lock(g_queueMutex);
            g_queueCV.wait(lock, [] {
                if (!g_workerRunning) return true;
                for (const auto& queued : g_workQueue) {
                    if (!g_activePaths.count(queued.cloudPath)) return true;
                }
                return false;
            });
            if (!g_workerRunning && g_workQueue.empty()) break;

            auto workIt = std::find_if(g_workQueue.begin(), g_workQueue.end(),
                [](const WorkItem& queued) {
                    return !g_activePaths.count(queued.cloudPath);
                });
            if (workIt == g_workQueue.end()) continue;

            item = std::move(*workIt);
            // Remove from dedup index before popping (H8)
            if (item.type == WorkItem::Upload) {
                g_uploadIndex.erase(item.cloudPath);
            }
            g_workQueue.erase(workIt);
            ++g_activeWorkers;
            ++g_activePaths[item.cloudPath];
        }

        if (!g_provider) { --g_activeWorkers; g_drainCV.notify_all(); continue; }

        // Exponential backoff after consecutive failures (cap at 30s)
        if (consecutiveFailures > 0) {
            int delayMs = 1000 * (1 << (consecutiveFailures < 5 ? consecutiveFailures : 5));
            if (delayMs > 30000) delayMs = 30000;
            LOG("[CloudStorage] Worker %d backing off %d ms after %d consecutive failure(s)",
                threadId, delayMs, consecutiveFailures);
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }

        std::string activePath = item.cloudPath;
        bool success = false;
        bool requeued = false;
        bool droppedAsStale = false;
        bool faulted = false;
        // Catch all so the post-switch counter cleanup runs and an escaped
        // exception doesn't kill the host process.
        try {
            switch (item.type) {
            case WorkItem::Upload:
                if (item.skipIfExists) {
                    auto exists = g_provider->CheckExists(item.cloudPath);
                    if (exists == ICloudProvider::ExistsStatus::Exists) {
                        LOG("[CloudStorage] BG upload skipped existing [%d]: %s",
                            threadId, item.cloudPath.c_str());
                        OnCloudSuccess();
                        success = true;
                        break;
                    }
                    if (exists == ICloudProvider::ExistsStatus::Error && item.existsCheckRetries++ < 3) {
                        LOG("[CloudStorage] BG upload deferred after existence check failure [%d]: %s",
                            threadId, item.cloudPath.c_str());
                        OnCloudFailure("Exists", item.cloudPath);
                        requeued = RequeueFromWorker(std::move(item));
                        if (!requeued) droppedAsStale = true;
                        break;
                    }
                    if (exists == ICloudProvider::ExistsStatus::Error) {
                        LOG("[CloudStorage] BG upload abandoned after repeated existence check failures [%d]: %s",
                            threadId, item.cloudPath.c_str());
                        OnCloudFailure("Exists", item.cloudPath);
                        break;
                    }
                }
                if (g_provider->Upload(item.cloudPath, item.data.data(), item.data.size())) {
                    LOG("[CloudStorage] BG upload OK [%d]: %s (%zu bytes)",
                        threadId, item.cloudPath.c_str(), item.data.size());
                    OnCloudSuccess();
                    success = true;
                } else {
                    LOG("[CloudStorage] BG upload FAILED [%d]: %s", threadId, item.cloudPath.c_str());
                    OnCloudFailure("Upload", item.cloudPath);
                    if (item.transferRetries++ < 3) {
                        requeued = RequeueFromWorker(std::move(item));
                        if (!requeued) droppedAsStale = true;
                    }
                }
                break;
            case WorkItem::Delete:
                if (g_provider->Remove(item.cloudPath)) {
                    LOG("[CloudStorage] BG delete OK [%d]: %s", threadId, item.cloudPath.c_str());
                    OnCloudSuccess();
                    success = true;
                    // Drop the canonicalized tombstone; skipped for internal cleanups so concurrent user deletes survive.
                    if (!item.suppressTombstoneClear) {
                        uint32_t doneAcct = 0, doneApp = 0;
                        std::string doneFile;
                        if (ParseCloudBlobPath(item.cloudPath, doneAcct, doneApp, doneFile)) {
                            LocalStorage::ClearDeleted(doneAcct, doneApp,
                                                       CanonicalizeInternalMetadataName(doneFile));
                        }
                    }
                } else {
                    LOG("[CloudStorage] BG delete FAILED [%d]: %s", threadId, item.cloudPath.c_str());
                    OnCloudFailure("Delete", item.cloudPath);
                    if (item.transferRetries++ < 3) {
                        requeued = RequeueFromWorker(std::move(item));
                        if (!requeued) droppedAsStale = true;
                    }
                }
                break;
            }
        } catch (const std::exception& ex) {
            faulted = true;
            LOG("[CloudStorage] BG worker [%d] EXCEPTION on %s: %s",
                threadId, activePath.c_str(), ex.what());
        } catch (...) {
            faulted = true;
            LOG("[CloudStorage] BG worker [%d] UNKNOWN EXCEPTION on %s",
                threadId, activePath.c_str());
        }
        // Don't stash a possibly moved-from item; just let the path drop.
        if (faulted) {
            success = false;
            requeued = false;
            droppedAsStale = true;
        }

        if (success)
            consecutiveFailures = 0;
        else
            ++consecutiveFailures;

        {
            std::lock_guard<std::mutex> lock(g_queueMutex);
            auto it = g_activePaths.find(activePath);
            if (it != g_activePaths.end()) {
                if (--it->second <= 0) g_activePaths.erase(it);
            }
            if (success) {
                g_failedPaths.erase(activePath);
                g_failedWorkItems.erase(activePath);
            } else if (droppedAsStale) {
                // Fresher upload supersedes this retry; new queued item is authoritative.
            } else if (!requeued) {
                g_failedPaths.insert(activePath);
                g_failedWorkItems[activePath] = std::move(item);
            }
            --g_activeWorkers;
        }
        g_drainCV.notify_all();
        g_queueCV.notify_all();
    }
    LOG("[CloudStorage] Background worker %d stopped", threadId);
}

static void EnqueueWork(WorkItem item) {
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_failedPaths.erase(item.cloudPath);
        g_failedWorkItems.erase(item.cloudPath);

        // Dedup: replace any queued upload for the same path with newer data.
        if (item.type == WorkItem::Upload) {
            auto indexIt = g_uploadIndex.find(item.cloudPath);
            if (indexIt != g_uploadIndex.end()) {
                auto& existing = *indexIt->second;
                if (item.skipIfExists && !existing.skipIfExists) {
                    LOG("[CloudStorage] Dedup: keeping queued authoritative upload for %s",
                        item.cloudPath.c_str());
                    return;
                }
                LOG("[CloudStorage] Dedup: replacing queued upload for %s (%zu -> %zu bytes)",
                    item.cloudPath.c_str(), existing.data.size(), item.data.size());
                existing.data = std::move(item.data);
                existing.skipIfExists = item.skipIfExists;
                // Fresh data resets inline retries; drainRequeues preserved for the cap.
                existing.existsCheckRetries = item.existsCheckRetries;
                existing.transferRetries = item.transferRetries;
                return; // replaced in-place, no need to notify
            }
        }

        g_workQueue.push_back(std::move(item));
        auto it = std::prev(g_workQueue.end());
        if (it->type == WorkItem::Upload) {
            g_uploadIndex[it->cloudPath] = it;
        }
    }
    g_queueCV.notify_one();
}

static bool RequeueFromWorker(WorkItem item) {
    std::lock_guard<std::mutex> lock(g_queueMutex);
    // Drop the retry if a fresher caller-enqueued upload now supersedes it.
    if (item.type == WorkItem::Upload) {
        auto indexIt = g_uploadIndex.find(item.cloudPath);
        if (indexIt != g_uploadIndex.end()) {
            LOG("[CloudStorage] Retry dropped: newer upload already queued for %s",
                item.cloudPath.c_str());
            g_failedPaths.erase(item.cloudPath);
            g_failedWorkItems.erase(item.cloudPath);
            return false;
        }
    }
    // Drop a stale Delete if an Upload for the same path is queued.
    if (item.type == WorkItem::Delete) {
        auto indexIt = g_uploadIndex.find(item.cloudPath);
        if (indexIt != g_uploadIndex.end()) {
            LOG("[CloudStorage] Retry dropped: upload supersedes stale delete for %s",
                item.cloudPath.c_str());
            g_failedPaths.erase(item.cloudPath);
            g_failedWorkItems.erase(item.cloudPath);
            return false;
        }
    }
    // Clear prior failure state; this retry is now the pending attempt.
    g_failedPaths.erase(item.cloudPath);
    g_failedWorkItems.erase(item.cloudPath);
    g_workQueue.push_back(std::move(item));
    auto qit = std::prev(g_workQueue.end());
    if (qit->type == WorkItem::Upload) {
        g_uploadIndex[qit->cloudPath] = qit;
    }
    g_queueCV.notify_one();
    return true;
}

// Enqueue a cloud upload of the current CN value for this app.
// Dedup in EnqueueWork will coalesce multiple calls during a batch.
void PushCNToCloud(uint32_t accountId, uint32_t appId, uint64_t cn) {
    std::string cnStr = std::to_string(cn);
    WorkItem wi;
    wi.type = WorkItem::Upload;
    wi.cloudPath = CloudMetadataPath(accountId, appId, "cn.dat");
    wi.data.assign(cnStr.begin(), cnStr.end());
    EnqueueWork(std::move(wi));
}

bool PushCNToCloudSync(uint32_t accountId, uint32_t appId, uint64_t cn) {
    if (!g_provider) return true;
    std::string cnStr = std::to_string(cn);
    std::string cloudPath = CloudMetadataPath(accountId, appId, "cn.dat");
    return g_provider->Upload(cloudPath, reinterpret_cast<const uint8_t*>(cnStr.data()), cnStr.size());
}

bool CommitCNWithRetry(uint32_t accountId, uint32_t appId, uint64_t cn) {
    bool drained = DrainQueueForApp(accountId, appId);
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;
    bool cnPublished = drained && PushCNToCloudSync(accountId, appId, cn);
    if (cnPublished) return true;
    // Async retry so a failed cloud delete still gets a chance before the
    // batch returns; a leftover delete can resurrect on the next sync.
    LOG("[CloudStorage] CommitCNWithRetry app %u CN=%llu drained=%d: deferring to async retry",
        appId, (unsigned long long)cn, drained ? 1 : 0);
    PushCNToCloud(accountId, appId, cn);
    DrainQueueForApp(accountId, appId);
    return false;
}

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
    std::string conflictsRoot = localRoot + "conflicts\\";
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
    if (!g_localRoot.empty() && g_localRoot.back() != '\\')
        g_localRoot += '\\';

    // Re-arm in case Shutdown ran earlier (in-process restart path).
    g_shuttingDown.store(false, std::memory_order_seq_cst);
    // Do NOT zero g_foregroundSyncCount: a late ForegroundSyncScope dtor
    // would underflow it; the counter self-balances across restart.

    g_provider = std::move(provider);

    LOG("[CloudStorage] Initialized. localRoot=%s provider=%s",
        g_localRoot.c_str(), g_provider ? g_provider->Name() : "none (local-only)");

    // Prune stale conflict copies once per process launch (best-effort).
    PruneStaleConflictCopies(g_localRoot);

    // Drop legacy-named Playtime.bin/UserGameStats.bin in the local blob cache
    // whenever the canonical `.cloudredirect\` sibling already exists.
    LegacyMetadataCleanup::PruneLocalBlobCache(g_localRoot);

    // Start background workers if we have a cloud provider
    if (g_provider) {
        g_workerRunning = true;
        for (int i = 0; i < WORKER_THREAD_COUNT; ++i) {
            g_workerThreads.emplace_back(WorkerLoop, i);
        }
        LOG("[CloudStorage] Started %d background worker threads", WORKER_THREAD_COUNT);
    }
}

void Shutdown() {
    LOG("[CloudStorage] Shutting down...");

    // seq_cst handshake against the SyncFromCloud wrapper's increment+check.
    g_shuttingDown.store(true, std::memory_order_seq_cst);
    g_workerRunning = false;
    g_queueCV.notify_all();

    for (auto& t : g_workerThreads) {
        if (t.joinable()) t.join();
    }
    g_workerThreads.clear();

    // Clear queue and wake parked CommitCNAsync threads so they see g_shuttingDown before the inflight cap (avoids g_provider UAF on teardown).
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_workQueue.clear();
        g_uploadIndex.clear();
        g_failedPaths.clear();
        g_failedWorkItems.clear();
    }
    g_drainCV.notify_all();
    // Wake any thread parked on the foreground-sync gate so it observes
    // g_shuttingDown and exits before the inflight wait below.
    {
        std::lock_guard<std::mutex> g(g_foregroundSyncMutex);
        g_foregroundSyncCV.notify_all();
    }

    // Drain in-flight ops before g_provider teardown (no internal cancel). 15s cap so a wedged TLS handshake can't block DLL unload.
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while ((g_inflightSyncCount.load(std::memory_order_seq_cst) > 0
                || g_inflightCommitDrainCount.load(std::memory_order_seq_cst) > 0)
               && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        int residualSync   = g_inflightSyncCount.load(std::memory_order_seq_cst);
        int residualCommit = g_inflightCommitDrainCount.load(std::memory_order_seq_cst);
        if (residualSync > 0 || residualCommit > 0) {
            LOG("[CloudStorage] Shutdown: %d in-flight SyncFromCloud and %d CommitCNAsync "
                "call(s) did not drain within 15s; proceeding with provider teardown",
                residualSync, residualCommit);
        }
    }

    if (g_provider) {
        g_provider->Shutdown();
        g_provider.reset();
    }

    // Set the shutdown flag, move out the thread vector under the lock,
    // join unlocked (MessageBox dismissal can take arbitrarily long).
    g_dialogShuttingDown.store(true, std::memory_order_release);
    std::vector<std::thread> dialogs;
    {
        std::lock_guard<std::mutex> lock(g_dialogMutex);
        dialogs = std::move(g_dialogThreads);
    }
    for (auto& t : dialogs) {
        if (t.joinable()) t.join();
    }

    LOG("[CloudStorage] Shutdown complete");
}

const char* ProviderName() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_provider) return g_provider->Name();
    return "Local Only";
}

bool IsCloudActive() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_provider && g_provider->IsAuthenticated();
}


bool StoreBlob(uint32_t accountId, uint32_t appId,
               const std::string& filename,
               const uint8_t* data, size_t len) {
    // Synchronous local write via LocalStorage::WriteFileNoIncrement so it
    // serializes against SyncFromCloud staged-blob promotion under g_mutex.
    if (!LocalStorage::WriteFileNoIncrement(accountId, appId, filename, data, len)) {
        LOG("[CloudStorage] StoreBlob: local write failed: app=%u file=%s (%zu bytes)",
            appId, filename.c_str(), len);
        return false;
    }
    LOG("[CloudStorage] StoreBlob: cached locally: %s (%zu bytes)", filename.c_str(), len);

    // Drop any stale tombstone (canonicalized to match DeleteBlob's MarkDeleted key).
    LocalStorage::ClearDeleted(accountId, appId,
                               CanonicalizeInternalMetadataName(filename));

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

    if (g_provider) {
        WorkItem wi;
        wi.type = WorkItem::Upload;
        wi.cloudPath = CloudBlobPath(accountId, appId, filename);
        if (len != 0) {
            wi.data.assign(data, data + len);
        }
        EnqueueWork(std::move(wi));
    }

    return true;
}

std::vector<uint8_t> RetrieveBlob(uint32_t accountId, uint32_t appId,
                                  const std::string& filename) {
    // 1. Check local cache
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return {}; // path traversal blocked
    {
        std::ifstream f(FileUtil::Utf8ToPath(localPath), std::ios::binary | std::ios::ate);
        if (f) {
            // tellg may return -1 on stream failure; treat as cache miss
            // rather than truncating into SIZE_MAX -> bad_alloc.
            auto rawSize = f.tellg();
            bool cacheServed = false;
            std::vector<uint8_t> data;
            if (rawSize >= 0) {
                auto size = static_cast<std::streamoff>(rawSize);
                f.seekg(0, std::ios::beg);
                data.resize(static_cast<size_t>(size));
                if (size == 0) {
                    cacheServed = true;
                } else {
                    f.read(reinterpret_cast<char*>(data.data()), size);
                    // Check fail() too; an I/O error can set badbit while gcount matches.
                    if (!f.fail() && f.gcount() == size) {
                        cacheServed = true;
                    } else {
                        LOG("[CloudStorage] RetrieveBlob: cache read failed for %s (gcount=%lld of %lld, fail=%d); falling back",
                            filename.c_str(),
                            static_cast<long long>(f.gcount()),
                            static_cast<long long>(size),
                            f.fail() ? 1 : 0);
                    }
                }
            } else {
                LOG("[CloudStorage] RetrieveBlob: cache tellg failed for %s; falling back to cloud",
                    filename.c_str());
            }
            if (cacheServed) {
                LOG("[CloudStorage] RetrieveBlob: cache hit: %s (%zu bytes)",
                    filename.c_str(), data.size());
                return data;
            }
        }
    }

    // 2. Cache miss -- pull from cloud provider (blocking)
    if (g_provider) {
        std::string cloudPath = CloudBlobPath(accountId, appId, filename);
        std::vector<uint8_t> data;
        if (g_provider->Download(cloudPath, data)) {
            LOG("[CloudStorage] RetrieveBlob: downloaded from cloud: %s (%zu bytes)",
                filename.c_str(), data.size());
            // Populate cache via WriteFileNoIncrement (serialized under g_mutex).
            const uint8_t* writeData = data.empty() ? nullptr : data.data();
            LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                               writeData, data.size());
            return data;
        }
        LOG("[CloudStorage] RetrieveBlob: not found in cloud: %s", filename.c_str());
    }

    LOG("[CloudStorage] RetrieveBlob: not found anywhere: %s", filename.c_str());
    return {};
}

bool DeleteBlob(uint32_t accountId, uint32_t appId,
                const std::string& filename,
                bool keepTombstoneOnSuccess) {
    // 1. Delete from local cache
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
    LocalStorage::MarkDeleted(accountId, appId,
                              CanonicalizeInternalMetadataName(filename), cnAtDelete);

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

    if (g_provider) {
        WorkItem wi;
        wi.type = WorkItem::Delete;
        wi.cloudPath = CloudBlobPath(accountId, appId, filename);
        wi.suppressTombstoneClear = keepTombstoneOnSuccess;
        EnqueueWork(std::move(wi));
    }

    return true;
}

bool BlobExists(uint32_t accountId, uint32_t appId,
                const std::string& filename) {
    return CheckBlobExists(accountId, appId, filename) == ICloudProvider::ExistsStatus::Exists;
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
    if (g_provider) {
        std::string cloudPath = CloudBlobPath(accountId, appId, filename);
        return g_provider->CheckExists(cloudPath);
    }

    return ICloudProvider::ExistsStatus::Missing;
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

bool SaveRootTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_set<std::string>& tokens) {
    // Skip the cloud push if local persist failed; cloud must never hold
    // tokens that disk cannot reproduce on restart.
    bool localOk = LocalStorage::SaveRootTokens(accountId, appId, tokens);

    if (localOk && g_provider) {
        std::string content;
        for (auto& t : tokens) {
            content += t + "\n";
        }
        WorkItem wi;
        wi.type = WorkItem::Upload;
        wi.cloudPath = CloudMetadataPath(accountId, appId, "root_token.dat");
        wi.data.assign(content.begin(), content.end());
        EnqueueWork(std::move(wi));
    }
    return localOk;
}

std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId) {
    return LocalStorage::LoadRootTokens(accountId, appId);
}

bool SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens) {
    // Skip cloud push on local persist failure (mirrors SaveRootTokens).
    bool localOk = LocalStorage::SaveFileTokens(accountId, appId, fileTokens);

    if (localOk && g_provider) {
        std::string content;
        for (auto& [cleanName, token] : fileTokens) {
            content += cleanName + "\t" + token + "\n";
        }
        WorkItem wi;
        wi.type = WorkItem::Upload;
        wi.cloudPath = CloudMetadataPath(accountId, appId, "file_tokens.dat");
        wi.data.assign(content.begin(), content.end());
        EnqueueWork(std::move(wi));
    }
    return localOk;
}

std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId) {
    return LocalStorage::LoadFileTokens(accountId, appId);
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

    // 1. Sync CN: take max of local and cloud (CN read from LocalStorage's
    //    in-memory cache to match Steam's behavior).
    {
        localCN = LocalStorage::GetChangeNumber(accountId, appId);

        if (!SweepShouldYield(isSweep, "SyncFromCloud (pre-cn.dat)")) return false;

        std::string cloudCNPath = CloudMetadataPath(accountId, appId, "cn.dat");
        std::vector<uint8_t> cloudData;
        if (g_provider->Download(cloudCNPath, cloudData)) {
            cloudCNFound = true;
            std::string s(cloudData.begin(), cloudData.end());
            try { cloudCN = std::stoull(s); } catch (...) {}
        }

        if (cloudCN > localCN) {
            LOG("[CloudStorage] SyncFromCloud app %u: cloud CN=%llu > local CN=%llu, using cloud",
                appId, cloudCN, localCN);
            LocalStorage::SetChangeNumber(accountId, appId, cloudCN);
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
    originalRootTokens = LocalStorage::LoadRootTokens(accountId, appId);
    originalFileTokens = LocalStorage::LoadFileTokens(accountId, appId);
    haveOriginalTokenMetadata = true;

    auto rollbackNewerCloudState = [&](const char* reason) {
        uint64_t currentCN = LocalStorage::GetChangeNumber(accountId, appId);
        if (currentCN == cloudCN) {
            LocalStorage::SetChangeNumber(accountId, appId, localCN);
        } else {
            LOG("[CloudStorage] SyncFromCloud app %u: preserving local CN=%llu during rollback; expected cloud CN=%llu",
                appId, currentCN, cloudCN);
        }
        // Vacuously true when nothing was merged; otherwise must be set
        // explicitly by a successful Save below.
        bool rootRolledBack = !haveMergedCloudRootTokens;
        bool fileRolledBack = !haveMergedCloudFileTokens;
        if (haveOriginalTokenMetadata) {
            if (haveMergedCloudRootTokens) {
                if (LocalStorage::LoadRootTokens(accountId, appId) == mergedCloudRootTokens) {
                    if (LocalStorage::SaveRootTokens(accountId, appId, originalRootTokens)) {
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
                if (LocalStorage::LoadFileTokens(accountId, appId) == mergedCloudFileTokens) {
                    if (LocalStorage::SaveFileTokens(accountId, appId, originalFileTokens)) {
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

    // 2. Sync root_token.dat: merge cloud tokens into local set.
    {
        // Skip park if cloudHadNewerCN: local CN advertises newer state with blobs pending; bailing would strand stale blobs under CN-in-sync.
        if (!cloudHadNewerCN &&
            !SweepShouldYield(isSweep, "SyncFromCloud (pre-root_token)")) return false;

        std::string cloudTokenPath = CloudMetadataPath(accountId, appId, "root_token.dat");
        std::vector<uint8_t> cloudData;
        if (g_provider->Download(cloudTokenPath, cloudData)) {
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
                    LOG("[CloudStorage] SyncFromCloud app %u: cloud root_token.dat had %zu raw entries but only %zu clean tokens -- pushing cleaned version",
                        appId, rawCount, cloudTokens.size());
                }
            }

            auto localTokens = LocalStorage::LoadRootTokens(accountId, appId);
            size_t beforeSize = localTokens.size();
            localTokens.insert(cloudTokens.begin(), cloudTokens.end());

            if (localTokens.size() > beforeSize) {
                LOG("[CloudStorage] SyncFromCloud app %u: merged %zu new root tokens from cloud",
                    appId, localTokens.size() - beforeSize);
                // Only record for rollback-predicate matching if disk persist succeeded.
                if (LocalStorage::SaveRootTokens(accountId, appId, localTokens)) {
                    mergedCloudRootTokens = localTokens;
                    haveMergedCloudRootTokens = true;
                    hadNewer = true;
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: merged root-token persist failed -- skipping rollback predicate bookkeeping",
                        appId);
                }
            }

            // Push the cleaned *cloud* set, not the local-merged superset:
            // this is a serialization repair only, must not leak local tokens.
            if (cloudHadCorruption) {
                std::string cleaned;
                for (auto& t : cloudTokens) {
                    cleaned += t + "\n";
                }
                std::vector<uint8_t> cleanedData(cleaned.begin(), cleaned.end());
                if (g_provider->Upload(cloudTokenPath, cleanedData.data(), cleanedData.size())) {
                    LOG("[CloudStorage] SyncFromCloud app %u: pushed cleaned root_token.dat to cloud (%zu tokens)",
                        appId, cloudTokens.size());
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: FAILED to push cleaned root_token.dat to cloud",
                        appId);
                }
            }
        }
    }

    // 2b. Sync file_tokens.dat: merge cloud file-token mappings into local.
    {
        if (!cloudHadNewerCN &&
            !SweepShouldYield(isSweep, "SyncFromCloud (pre-file_tokens)")) return false;

        std::string cloudPath = CloudMetadataPath(accountId, appId, "file_tokens.dat");
        std::vector<uint8_t> cloudData;
        if (g_provider->Download(cloudPath, cloudData)) {
            cloudFileTokensFound = true;
            if (!cloudData.empty()) {
                // Parse cloud file_tokens.dat
                std::unordered_map<std::string, std::string> cloudFileTokens;
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
                    if (!cleanName.empty())
                        cloudFileTokens[cleanName] = token;
                }

                // Merge: cloud entries fill in any gaps in local
                auto localFileTokens = LocalStorage::LoadFileTokens(accountId, appId);
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
                    if (LocalStorage::SaveFileTokens(accountId, appId, localFileTokens)) {
                        mergedCloudFileTokens = localFileTokens;
                        haveMergedCloudFileTokens = true;
                        hadNewer = true;
                    } else {
                        LOG("[CloudStorage] SyncFromCloud app %u: merged file-token persist failed -- skipping rollback predicate bookkeeping",
                            appId);
                    }
                }
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
    // Highest-leverage park point; suppressed under cloudHadNewerCN so the
    // promote/rollback path always runs to completion.
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
    std::unordered_set<std::string> cloudBlobNames;
    for (auto& fi : cloudBlobs) {
        auto blobsPos = fi.path.find("/blobs/");
        if (blobsPos == std::string::npos) continue;
        cloudBlobNames.insert(CanonicalizeInternalMetadataName(fi.path.substr(blobsPos + 7)));
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
            WorkItem wi;
            wi.type = WorkItem::Delete;
            wi.cloudPath = std::move(legacyPath);
            wi.suppressTombstoneClear = true;
            EnqueueWork(std::move(wi));
        }
    }

    // Tombstones hold until cloud CN advances AND blob mtime is newer (skew grace). MigrateDeletedKeys canonicalizes legacy keys under g_mutex.
    std::unordered_map<std::string, LocalStorage::TombstoneInfo> deletedTombstones;
    {
        size_t migratedCount = 0;
        LocalStorage::MigrateDeletedKeys(
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
                    LocalStorage::ClearDeleted(accountId, appId, filename);
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
        LocalStorage::EvictTombstonesNotIn(accountId, appId, cloudBlobNames,
                                           listingCapturedAtUnix);
    }

    // Gap-repair from local cache; verified-complete listing only (an incomplete sub-tree looks identical to empty).
    bool providerLooksUninitialized = cloudListSucceeded && cloudListComplete &&
                                      !cloudCNFound && !cloudRootTokensFound &&
                                      !cloudFileTokensFound && cloudBlobNames.empty();
    bool canRepairProviderGaps = cloudListSucceeded && cloudListComplete &&
                                 localCN > 0 && providerLooksUninitialized;
    if (canRepairProviderGaps) {
        std::string localBlobDir = g_localRoot + "storage\\" +
                                   std::to_string(accountId) + "\\" +
                                   std::to_string(appId) + "\\";
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
                    if (rel == "cn.dat" || rel == "root_token.dat" ||
                        rel == "file_tokens.dat" || rel == "deleted.dat") continue;
                    // Canonicalize so a legacy-named local blob isn't re-uploaded when its canonical sibling is already in cloud.
                    if (cloudBlobNames.count(CanonicalizeInternalMetadataName(rel))) continue;

                    std::ifstream f(entry.path(), std::ios::binary);
                    if (!f) continue;
                    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                              std::istreambuf_iterator<char>());
                    WorkItem wi;
                    wi.type = WorkItem::Upload;
                    wi.cloudPath = CloudBlobPath(accountId, appId, rel);
                    wi.data = std::move(data);
                    wi.skipIfExists = true;
                    EnqueueWork(std::move(wi));
                    seeded++;
                }
                if (iterEc) {
                    LOG("[CloudStorage] SyncFromCloud app %u: gap-repair iteration aborted after %d seeded: %s",
                        appId, seeded, iterEc.message().c_str());
                }
            }
        }

        auto seedMeta = [&](const std::string& filename) {
            std::string localFile = storagePath + filename;
            std::error_code metaEc;
            auto localFilePath = FileUtil::Utf8ToPath(localFile);
            if (!std::filesystem::exists(localFilePath, metaEc) || metaEc) return;

            std::ifstream f(localFilePath, std::ios::binary);
            if (!f) return;
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());

            WorkItem wi;
            wi.type = WorkItem::Upload;
            wi.cloudPath = CloudMetadataPath(accountId, appId, filename);
            wi.data = std::move(data);
            wi.skipIfExists = true;
            EnqueueWork(std::move(wi));
            seeded++;
        };

        if (!cloudRootTokensFound) seedMeta("root_token.dat");
        if (!cloudFileTokensFound) seedMeta("file_tokens.dat");
        if (!cloudCNFound) seedMeta("cn.dat");

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
    auto waitStart = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> g(*m);
    auto waitedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - waitStart).count();
    if (waitedMs > 50) {
        LOG("[CloudStorage] SyncFromCloud app %u: waited %lld ms for in-flight sync on the same app",
            appId, (long long)waitedMs);
    }
    if (g_shuttingDown.load(std::memory_order_seq_cst)) return false;
    return SyncFromCloudInner(accountId, appId, isSweep);
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

    LOG("[CloudStorage] SyncAllFromCloud: scanning for apps belonging to account %u...", accountId);

    // List all items under the account prefix to discover apps
    std::string prefix = std::to_string(accountId) + "/";
    auto items = g_provider->List(prefix);

    // Extract unique app IDs from paths like "54303850/1229490/cn.dat"
    std::unordered_set<uint32_t> appIds;
    for (auto& fi : items) {
        // path: "{accountId}/{appId}/..."
        auto firstSlash = fi.path.find('/');
        if (firstSlash == std::string::npos) continue;
        auto secondSlash = fi.path.find('/', firstSlash + 1);
        if (secondSlash == std::string::npos) continue;
        std::string appStr = fi.path.substr(firstSlash + 1, secondSlash - firstSlash - 1);
        try {
            uint32_t parsed = static_cast<uint32_t>(std::stoul(appStr));
            if (parsed == CloudIntercept::kAccountScopeAppId) continue;
            appIds.insert(parsed);
        } catch (...) {}
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

void DrainQueue() {
    if (!g_provider) return;

    LOG("[CloudStorage] DrainQueue: waiting for background work to complete...");

    constexpr int TIMEOUT_MS = 30000;   // 30 seconds max wait
    auto start = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> lock(g_queueMutex);
    bool completed = g_drainCV.wait_for(lock,
        std::chrono::milliseconds(TIMEOUT_MS),
        [] { return g_workQueue.empty() && g_activeWorkers.load() == 0; });

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    if (completed) {
        LOG("[CloudStorage] DrainQueue: done (%lld ms)", (long long)elapsed);
    } else {
        LOG("[CloudStorage] DrainQueue: TIMEOUT after %lld ms, %zu queued, %d active",
            (long long)elapsed, g_workQueue.size(), g_activeWorkers.load());
    }
}

bool DrainQueueForApp(uint32_t accountId, uint32_t appId) {
    if (!g_provider) return true;

    std::string prefix = std::to_string(accountId) + "/" + std::to_string(appId) + "/";
    LOG("[CloudStorage] DrainQueueForApp: waiting for %s", prefix.c_str());

    constexpr int TIMEOUT_MS = 30000;
    auto start = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> lock(g_queueMutex);
    RequeueFailedWorkForPrefixLocked(prefix);
    g_queueCV.notify_all();
    bool completed = g_drainCV.wait_for(lock,
        std::chrono::milliseconds(TIMEOUT_MS),
        [&prefix] { return !HasPendingWorkForPrefix(prefix); });
    bool failed = HasFailedWorkForPrefix(prefix);

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    if (completed && !failed) {
        LOG("[CloudStorage] DrainQueueForApp: done for %s (%lld ms)",
            prefix.c_str(), (long long)elapsed);
    } else if (failed) {
        LOG("[CloudStorage] DrainQueueForApp: failed work for %s after %lld ms",
            prefix.c_str(), (long long)elapsed);
    } else {
        LOG("[CloudStorage] DrainQueueForApp: TIMEOUT for %s after %lld ms",
            prefix.c_str(), (long long)elapsed);
    }
    return completed && !failed;
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
