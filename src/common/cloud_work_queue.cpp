#include "cloud_work_queue.h"
#include "cloud_storage.h"
#include "local_storage.h"
#include "log.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <list>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#ifdef _WIN32
#include <Windows.h>
#endif

namespace CloudWorkQueue {

static ICloudProvider*                     g_provider = nullptr;
static std::atomic<bool>                  g_shuttingDown{false};

static std::list<WorkItem>               g_workQueue;
static std::mutex                        g_queueMutex;
static std::condition_variable           g_queueCV;
static std::unordered_map<std::string, std::list<WorkItem>::iterator> g_uploadIndex;
static std::vector<std::thread>          g_workerThreads;
static std::atomic<bool>                 g_workerRunning{false};
static std::atomic<int>                  g_activeWorkers{0};
static std::unordered_map<std::string, int> g_activePaths;
static std::unordered_map<std::string, int> g_activeBestEffortPaths;
static std::unordered_map<std::string, int> g_activeDeletes;
static std::unordered_map<std::string, std::pair<uint64_t, std::chrono::steady_clock::time_point>> g_recentUploadFingerprints;
static std::unordered_set<std::string>   g_failedPaths;
static std::unordered_map<std::string, WorkItem> g_failedWorkItems;
static std::condition_variable           g_drainCV;
static constexpr int                     WORKER_THREAD_COUNT = 8;

// Number of background worker threads. Defaults to WORKER_THREAD_COUNT.
// Tests set it to 1 for deterministic, single-worker repro runs.
static std::atomic<int>                  g_workerThreadCount{WORKER_THREAD_COUNT};

static constexpr int                     MAX_DRAIN_REQUEUES = 3;
static constexpr int                     FAIL_THRESHOLD     = 5;
static constexpr auto                    RECENT_UPLOAD_TTL = std::chrono::seconds(120);

// Base unit for exponential retry backoff (delay = unit << (retries - 1)).
// Defaults to 1000ms (1s/2s/4s). Tests set it to 0 for deterministic, fast runs.
static std::atomic<int>                  g_retryBackoffUnitMs{1000};

// Error reporter -- set once at Init. Tests inject a no-op or spy.
// Never changed after Init; no mutex needed.
static Reporter g_reporter;
static std::atomic<int> g_consecutiveFails{0};

// Default reporter: shows a synchronous MessageBox.
// Extracted into a named function so Init(provider) can reference it.
static Reporter MakeDefaultReporter() {
#ifdef _WIN32
    return [](const std::string& message) {
        std::wstring wmsg;
        int wlen = MultiByteToWideChar(CP_UTF8, 0, message.c_str(),
                                       static_cast<int>(message.size()), nullptr, 0);
        if (wlen > 0) {
            wmsg.resize(static_cast<size_t>(wlen));
            MultiByteToWideChar(CP_UTF8, 0, message.c_str(),
                                static_cast<int>(message.size()),
                                wmsg.data(), wlen);
        }
        MessageBoxW(nullptr, wmsg.c_str(),
                    L"CloudRedirect - Cloud Sync Error",
                    MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
    };
#else
    return [](const std::string& message) {
        (void)message;
    };
#endif
}

// Lazy-init default reporter for pre-Init error dialogs.
static void EnsureDefaultReporter() {
    static std::once_flag once;
    std::call_once(once, [] { g_reporter = MakeDefaultReporter(); });
}

// Forward declarations for interdependencies
static void OnCloudSuccess();
static void OnCloudFailure(const char* operation, const std::string& path);
static void WorkerLoop(int threadId);
static bool RequeueFromWorker(WorkItem item);
static void RequeueFailedWorkForPrefixLocked(const std::string& prefix);
static bool HasFailedWorkForPrefix(const std::string& prefix);

static uint64_t FingerprintUpload(const std::vector<uint8_t>& data) {
    uint64_t hash = 1469598103934665603ULL;
    for (uint8_t byte : data) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    hash ^= static_cast<uint64_t>(data.size());
    hash *= 1099511628211ULL;
    return hash;
}

static bool HasQueuedDeleteForPathLocked(const std::string& path) {
    for (const auto& queued : g_workQueue) {
        if (queued.type == WorkItem::Delete && queued.cloudPath == path) return true;
    }
    return false;
}

static bool HasDeleteBarrierForPathLocked(const std::string& path) {
    return HasQueuedDeleteForPathLocked(path) || g_activeDeletes.count(path) != 0;
}

static void ClearActiveDeleteLocked(const std::string& path) {
    auto it = g_activeDeletes.find(path);
    if (it != g_activeDeletes.end() && --it->second <= 0) g_activeDeletes.erase(it);
}

static void ClearActiveBestEffortLocked(const std::string& path) {
    auto it = g_activeBestEffortPaths.find(path);
    if (it != g_activeBestEffortPaths.end() && --it->second <= 0) g_activeBestEffortPaths.erase(it);
}

static void ClearRecentUploadForDeleteLocked(const std::string& path) {
    g_recentUploadFingerprints.erase(path);
}

static void PruneRecentUploadFingerprintsLocked(std::chrono::steady_clock::time_point now) {
    for (auto it = g_recentUploadFingerprints.begin(); it != g_recentUploadFingerprints.end(); ) {
        if (now - it->second.second > RECENT_UPLOAD_TTL) it = g_recentUploadFingerprints.erase(it);
        else ++it;
    }
}

void ShowErrorDialog(const std::string& message) {
    EnsureDefaultReporter();
    if (g_reporter) g_reporter(message);
}

static void OnCloudFailure(const char* operation, const std::string& path) {
    int fails = ++g_consecutiveFails;
    if (fails == FAIL_THRESHOLD) {
        std::string provName = g_provider ? g_provider->Name() : "Cloud";
        ShowErrorDialog(
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

static bool HasPendingWorkForPrefixLocked(const std::string& prefix) {
    for (const auto& item : g_workQueue) {
        if (item.cloudPath.rfind(prefix, 0) == 0) return true;
    }
    for (const auto& [path, count] : g_activePaths) {
        if (count > 0 && path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

// Like HasPendingWorkForPrefixLocked but ignores bestEffort items.
// Used by commit drains so gap-repair uploads don't block CN advance.
static bool HasPendingCommitWorkForPrefixLocked(const std::string& prefix) {
    for (const auto& item : g_workQueue) {
        if (!item.bestEffort && item.cloudPath.rfind(prefix, 0) == 0) return true;
    }
    for (const auto& [path, count] : g_activePaths) {
        if (count > 0 && path.rfind(prefix, 0) == 0) {
            auto beIt = g_activeBestEffortPaths.find(path);
            int beCount = (beIt != g_activeBestEffortPaths.end()) ? beIt->second : 0;
            if (count > beCount) return true;
        }
    }
    return false;
}

bool HasPendingWorkForPrefix(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(g_queueMutex);
    return HasPendingWorkForPrefixLocked(prefix);
}

static bool HasFailedWorkForPrefix(const std::string& prefix) {
    for (const auto& path : g_failedPaths) {
        if (path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

// Like HasFailedWorkForPrefix but ignores bestEffort items.
static bool HasFailedCommitWorkForPrefix(const std::string& prefix) {
    for (const auto& [path, item] : g_failedWorkItems) {
        if (!item.bestEffort && path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

void ClearFailedWorkForPrefix(const std::string& prefix) {
    std::lock_guard<std::mutex> lock(g_queueMutex);
    for (auto it = g_failedPaths.begin(); it != g_failedPaths.end(); ) {
        if (it->rfind(prefix, 0) == 0) it = g_failedPaths.erase(it);
        else ++it;
    }
}

static void RequeueFailedWorkForPrefixLocked(const std::string& prefix) {
    for (auto it = g_failedWorkItems.begin(); it != g_failedWorkItems.end(); ) {
        if (it->first.rfind(prefix, 0) != 0) {
            ++it;
            continue;
        }
        // Skip best-effort items during drain.
        if (it->second.bestEffort) {
            ++it;
            continue;
        }
        if (it->second.drainRequeues >= MAX_DRAIN_REQUEUES) {
            g_failedPaths.erase(it->first);
            it = g_failedWorkItems.erase(it);
            continue;
        }
        WorkItem item = std::move(it->second);
        item.existsCheckRetries = 0;
        item.transferRetries = 0;
        item.notBefore = std::chrono::steady_clock::time_point{};
        g_failedPaths.erase(it->first);
        if (!g_activePaths.count(item.cloudPath)) {
            ++item.drainRequeues;
            bool isUpload = item.type == WorkItem::Upload;
            g_workQueue.push_back(std::move(item));
            // Re-index requeued uploads: std::list iterators stay valid until the
            // node is erased, so the stored iterator tracks this entry.
            if (isUpload) {
                g_uploadIndex[g_workQueue.back().cloudPath] = std::prev(g_workQueue.end());
            }
        } else {
            // Path is actively being processed; preserve the failed item
            // so it can be retried on the next drain cycle.
            std::string path = item.cloudPath;
            g_failedWorkItems[path] = std::move(item);
            g_failedPaths.insert(path);
            it = g_failedWorkItems.find(path);
            ++it;
            continue;
        }
        it = g_failedWorkItems.erase(it);
    }
}

static void WorkerLoop(int threadId) {
    LOG("[CloudStorage] Background worker %d started", threadId);
    int consecutiveFailures = 0;
    while (g_workerRunning) {
        WorkItem item;
        {
            std::unique_lock<std::mutex> lock(g_queueMutex);
            auto eligibleNow = [](const WorkItem& q) {
                return !g_activePaths.count(q.cloudPath)
                    && std::chrono::steady_clock::now() >= q.notBefore;
            };
            auto havePending = [&]() {
                if (!g_workerRunning) return true;
                for (const auto& queued : g_workQueue) {
                    if (eligibleNow(queued)) return true;
                }
                return false;
            };
            while (!havePending()) {
                const auto kNoDeferred =
                    (std::chrono::steady_clock::time_point::max)();
                auto soonest = kNoDeferred;
                for (const auto& queued : g_workQueue) {
                    if (g_activePaths.count(queued.cloudPath)) continue;
                    if (queued.notBefore < soonest) soonest = queued.notBefore;
                }
                if (soonest == kNoDeferred) {
                    g_queueCV.wait(lock);
                } else {
                    g_queueCV.wait_until(lock, soonest);
                }
                if (!g_workerRunning && g_workQueue.empty()) break;
            }
            if (!g_workerRunning && g_workQueue.empty()) break;

            auto workIt = std::find_if(g_workQueue.begin(), g_workQueue.end(),
                [&](const WorkItem& queued) { return eligibleNow(queued); });
            if (workIt == g_workQueue.end()) continue;

            item = std::move(*workIt);
            if (item.type == WorkItem::Upload) {
                g_uploadIndex.erase(item.cloudPath);
            }
            g_workQueue.erase(workIt);
            ++g_activeWorkers;
            ++g_activePaths[item.cloudPath];
            if (item.bestEffort) ++g_activeBestEffortPaths[item.cloudPath];
            if (item.type == WorkItem::Delete) ++g_activeDeletes[item.cloudPath];
        }

        if (!g_provider) {
            std::lock_guard<std::mutex> lk(g_queueMutex);
            auto it = g_activePaths.find(item.cloudPath);
            if (it != g_activePaths.end() && --it->second <= 0) g_activePaths.erase(it);
            if (item.bestEffort) ClearActiveBestEffortLocked(item.cloudPath);
            if (item.type == WorkItem::Delete) ClearActiveDeleteLocked(item.cloudPath);
            --g_activeWorkers;
            g_drainCV.notify_all();
            continue;
        }

        if (consecutiveFailures > 0) {
            int delayMs = g_retryBackoffUnitMs.load() * (1 << (consecutiveFailures < 5 ? consecutiveFailures : 5));
            if (delayMs > 30000) delayMs = 30000;
            LOG("[CloudStorage] Worker %d backing off %d ms after %d consecutive failure(s)",
                threadId, delayMs, consecutiveFailures);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
            while (std::chrono::steady_clock::now() < deadline) {
                if (g_shuttingDown.load(std::memory_order_seq_cst)) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (g_shuttingDown.load(std::memory_order_seq_cst)) {
                std::lock_guard<std::mutex> lk(g_queueMutex);
                auto it = g_activePaths.find(item.cloudPath);
                if (it != g_activePaths.end() && --it->second <= 0) g_activePaths.erase(it);
                if (item.bestEffort) ClearActiveBestEffortLocked(item.cloudPath);
                if (item.type == WorkItem::Delete) ClearActiveDeleteLocked(item.cloudPath);
                --g_activeWorkers;
                g_drainCV.notify_all();
                break;
            }
        }

        std::string activePath = item.cloudPath;
        // Capture before potential move (UB after move).
        const bool itemBestEffort = item.bestEffort;
        const auto itemType = item.type;
        bool success = false;
        bool uploadedBytes = false;
        bool requeued = false;
        bool droppedAsStale = false;
        bool faulted = false;
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
                        int delayMs = g_retryBackoffUnitMs.load() << (item.existsCheckRetries - 1);
                        item.notBefore = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(delayMs);
                        LOG("[CloudStorage] Exists retry %d in %dms: %s",
                            item.existsCheckRetries, delayMs, item.cloudPath.c_str());
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
                    uploadedBytes = true;
                } else {
                    LOG("[CloudStorage] BG upload FAILED [%d]: %s", threadId, item.cloudPath.c_str());
                    OnCloudFailure("Upload", item.cloudPath);
                    if (item.transferRetries++ < 3) {
                        int delayMs = g_retryBackoffUnitMs.load() << (item.transferRetries - 1);
                        item.notBefore = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(delayMs);
                        LOG("[CloudStorage] Upload retry %d in %dms: %s",
                            item.transferRetries, delayMs, item.cloudPath.c_str());
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
                } else {
                    LOG("[CloudStorage] BG delete FAILED [%d]: %s", threadId, item.cloudPath.c_str());
                    OnCloudFailure("Delete", item.cloudPath);
                    if (item.transferRetries++ < 3) {
                        int delayMs = g_retryBackoffUnitMs.load() << (item.transferRetries - 1);
                        item.notBefore = std::chrono::steady_clock::now()
                            + std::chrono::milliseconds(delayMs);
                        LOG("[CloudStorage] Delete retry %d in %dms: %s",
                            item.transferRetries, delayMs, item.cloudPath.c_str());
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
            if (itemBestEffort) ClearActiveBestEffortLocked(activePath);
            if (itemType == WorkItem::Delete) ClearActiveDeleteLocked(activePath);
            if (success) {
                g_failedPaths.erase(activePath);
                g_failedWorkItems.erase(activePath);
                if (itemType == WorkItem::Upload && uploadedBytes) {
                    // item.data valid (upload succeeded, no move).
                    g_recentUploadFingerprints[activePath] = {
                        FingerprintUpload(item.data), std::chrono::steady_clock::now()
                    };
                } else if (itemType == WorkItem::Delete) {
                    g_recentUploadFingerprints.erase(activePath);
                }
            } else if (droppedAsStale) {
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

void EnqueueWork(WorkItem item) {
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_failedPaths.erase(item.cloudPath);
        g_failedWorkItems.erase(item.cloudPath);

        if (item.type == WorkItem::Delete) {
            ClearRecentUploadForDeleteLocked(item.cloudPath);
        } else if (item.type == WorkItem::Upload) {
            uint64_t fingerprint = FingerprintUpload(item.data);
            auto now = std::chrono::steady_clock::now();
            PruneRecentUploadFingerprintsLocked(now);

            auto recentIt = g_recentUploadFingerprints.find(item.cloudPath);
            if (!HasDeleteBarrierForPathLocked(item.cloudPath) &&
                recentIt != g_recentUploadFingerprints.end() &&
                recentIt->second.first == fingerprint) {
                LOG("[CloudStorage] Dedup: dropping recent identical upload for %s",
                    item.cloudPath.c_str());
                return;
            }

            auto indexIt = g_uploadIndex.find(item.cloudPath);
            if (indexIt != g_uploadIndex.end()) {
                WorkItem existingCopy = *indexIt->second;
                g_workQueue.erase(indexIt->second);
                g_uploadIndex.erase(indexIt);
                
                if (item.skipIfExists && !existingCopy.skipIfExists) {
                    LOG("[CloudStorage] Dedup: keeping queued authoritative upload for %s",
                        item.cloudPath.c_str());
                    g_workQueue.push_back(std::move(existingCopy));
                    g_uploadIndex[g_workQueue.back().cloudPath] = std::prev(g_workQueue.end());
                    return;
                }
                LOG("[CloudStorage] Dedup: replacing queued upload for %s (%zu -> %zu bytes)",
                    item.cloudPath.c_str(), existingCopy.data.size(), item.data.size());
                // Fall through to push new item
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
    if (item.type == WorkItem::Upload) {
        // A present index entry means a newer upload is already queued for this
        // path, so drop the retry instead of walking the list under the lock.
        if (g_uploadIndex.find(item.cloudPath) != g_uploadIndex.end()) {
            LOG("[CloudStorage] Retry dropped: newer upload already queued for %s",
                item.cloudPath.c_str());
            g_failedPaths.erase(item.cloudPath);
            g_failedWorkItems.erase(item.cloudPath);
            return false;
        }
    }
    if (item.type == WorkItem::Delete) {
        ClearRecentUploadForDeleteLocked(item.cloudPath);
        auto indexIt = g_uploadIndex.find(item.cloudPath);
        if (indexIt != g_uploadIndex.end()) {
            LOG("[CloudStorage] Retry dropped: upload supersedes stale delete for %s",
                item.cloudPath.c_str());
            g_failedPaths.erase(item.cloudPath);
            g_failedWorkItems.erase(item.cloudPath);
            return false;
        }
    }
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

void DrainQueue() {
    if (!g_provider) return;

    LOG("[CloudStorage] DrainQueue: waiting for background work to complete...");

    constexpr int TIMEOUT_MS = 30000;
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

    constexpr int POLL_MS = 100;
    constexpr int BASE_TIMEOUT_MS = 30000;
    constexpr int PER_ITEM_MS = 3000;
    constexpr int MAX_TIMEOUT_MS = 180000;

    // Scale timeout with pending work count.
    int pendingCount = 0;
    {
        std::lock_guard<std::mutex> countLock(g_queueMutex);
        for (const auto& item : g_workQueue)
            if (!item.bestEffort && item.cloudPath.rfind(prefix, 0) == 0)
                ++pendingCount;
    }
    int timeoutMs = (std::min)(MAX_TIMEOUT_MS, BASE_TIMEOUT_MS + pendingCount * PER_ITEM_MS);

    auto start = std::chrono::steady_clock::now();
    auto deadline = start + std::chrono::milliseconds(timeoutMs);

    std::unique_lock<std::mutex> lock(g_queueMutex);
    RequeueFailedWorkForPrefixLocked(prefix);
    g_queueCV.notify_all();

    // Best-effort items continue in background.
    bool completed = !HasPendingCommitWorkForPrefixLocked(prefix);
    bool failed = HasFailedCommitWorkForPrefix(prefix);
    if (completed && !failed) {
        LOG("[CloudStorage] DrainQueueForApp: no pending commit work for %s", prefix.c_str());
        return true;
    }

    LOG("[CloudStorage] DrainQueueForApp: waiting for %s", prefix.c_str());
    while (std::chrono::steady_clock::now() < deadline) {
        completed = !HasPendingCommitWorkForPrefixLocked(prefix);
        failed = HasFailedCommitWorkForPrefix(prefix);
        if (completed || failed) break;
        if (g_shuttingDown.load(std::memory_order_seq_cst)) break;
        g_drainCV.wait_for(lock, std::chrono::milliseconds(POLL_MS));
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    if (completed && !failed) {
        LOG("[CloudStorage] DrainQueueForApp: done for %s (%lld ms)",
            prefix.c_str(), (long long)elapsed);
    } else if (failed) {
        LOG("[CloudStorage] DrainQueueForApp: failed work for %s after %lld ms",
            prefix.c_str(), (long long)elapsed);
    } else if (g_shuttingDown.load(std::memory_order_seq_cst)) {
        LOG("[CloudStorage] DrainQueueForApp: shutdown for %s (%lld ms)",
            prefix.c_str(), (long long)elapsed);
    } else {
        LOG("[CloudStorage] DrainQueueForApp: TIMEOUT for %s after %lld ms",
            prefix.c_str(), (long long)elapsed);
    }
    return completed && !failed;
}

void Init(ICloudProvider* provider) {
    Init(provider, MakeDefaultReporter());
}

void Init(ICloudProvider* provider, Reporter reporter) {
    // Reuse existing workers if still running.
    if (g_workerRunning.load()) {
        g_workerRunning = false;
        g_queueCV.notify_all();
        for (auto& t : g_workerThreads) {
            if (t.joinable()) t.join();
        }
        g_workerThreads.clear();
    }

    g_provider = provider;
    g_reporter = reporter ? reporter : [](const std::string&) {};
    g_shuttingDown.store(false, std::memory_order_seq_cst);
    g_consecutiveFails.store(0, std::memory_order_seq_cst);
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_workQueue.clear();
        g_uploadIndex.clear();
        g_activePaths.clear();
        g_activeDeletes.clear();
        g_activeBestEffortPaths.clear();
        g_failedPaths.clear();
        g_failedWorkItems.clear();
        g_recentUploadFingerprints.clear();
    }

    if (g_provider) {
        g_workerRunning = true;
        int workerCount = g_workerThreadCount.load();
        if (workerCount < 1) workerCount = 1;
        for (int i = 0; i < workerCount; ++i) {
            g_workerThreads.emplace_back(WorkerLoop, i);
        }
        LOG("[CloudStorage] Started %d background worker threads", workerCount);
    }
}

void SetShuttingDown() {
    g_shuttingDown.store(true, std::memory_order_seq_cst);
    g_queueCV.notify_all();
}

void SetRetryBackoffUnitMs(int unitMs) {
    if (unitMs < 0) unitMs = 0;
    g_retryBackoffUnitMs.store(unitMs);
}

void SetWorkerThreadCount(int count) {
    if (count < 1) count = 1;
    g_workerThreadCount.store(count);
}

void Shutdown() {
    g_shuttingDown.store(true, std::memory_order_seq_cst);
    g_workerRunning = false;
    g_queueCV.notify_all();

    // 5s bounded wait for workers; detach stragglers blocked on cloud I/O.
    auto joinDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (auto& t : g_workerThreads) {
        if (!t.joinable()) continue;
        auto remaining = joinDeadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::milliseconds(0)) {
            LOG("[CloudStorage] WorkQueue shutdown: detaching worker (join deadline exceeded)");
            t.detach();
            continue;
        }
#ifdef _WIN32
        DWORD waitMs = (DWORD)std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
        HANDLE h = t.native_handle();
        if (WaitForSingleObject(h, waitMs) == WAIT_TIMEOUT) {
            LOG("[CloudStorage] WorkQueue shutdown: detaching worker (join timed out after %lu ms)", waitMs);
            t.detach();
        } else {
            t.join();
        }
#else
        // No timed join on POSIX; best-effort sleep then join.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (t.joinable()) {
            t.join();
        }
#endif
    }
    g_workerThreads.clear();

    int spinCount = 0;
    while (g_activeWorkers.load(std::memory_order_acquire) > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        if (++spinCount > 500) { // 5 seconds max
            LOG("[CloudStorage] WorkQueue shutdown: timed out waiting for %d active workers",
                g_activeWorkers.load());
            break;
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_workQueue.clear();
        g_uploadIndex.clear();
        g_activePaths.clear();
        g_activeDeletes.clear();
        g_activeBestEffortPaths.clear();
        g_recentUploadFingerprints.clear();
        g_failedPaths.clear();
        g_failedWorkItems.clear();
    }
    g_drainCV.notify_all();

    LOG("[CloudStorage] Background work queue shutdown complete");
}

} // namespace CloudWorkQueue
