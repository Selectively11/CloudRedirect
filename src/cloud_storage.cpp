#include "cloud_storage.h"
#include "local_storage.h"
#include "local_disk_provider.h"
#include "google_drive_provider.h"
#include "onedrive_provider.h"
#include "cloud_intercept.h"
#include "file_util.h"
#include "log.h"
#include <fstream>
#include <filesystem>
#include <sstream>
#include <chrono>
#include <list>
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

// Non-blocking dialog when cloud operations fail repeatedly.
// Shows once after FAIL_THRESHOLD consecutive failures, then
// suppresses for COOLDOWN_SECS to avoid spamming.

static constexpr int    FAIL_THRESHOLD   = 3;
static constexpr int    COOLDOWN_SECS    = 300; // 5 minutes

static std::atomic<int> g_consecutiveFails{0};
static std::atomic<int64_t> g_lastDialogTime{0};
static std::mutex g_dialogMutex;
static std::thread g_dialogThread;

static void ShowCloudError(const std::string& message) {
    // check cooldown
    int64_t now = (int64_t)time(nullptr);
    int64_t last = g_lastDialogTime.load();
    if (last > 0 && now - last < COOLDOWN_SECS) return;
    g_lastDialogTime.store(now);

    LOG("[CloudStorage] Showing error dialog: %s", message.c_str());

    // non-blocking: fire-and-forget thread for MessageBox
    // Tracked so Shutdown can join before DLL unload.
    std::string msg = message; // copy for thread
    std::lock_guard<std::mutex> lock(g_dialogMutex);
    if (g_dialogThread.joinable()) g_dialogThread.join();
    g_dialogThread = std::thread([msg]() {
        MessageBoxA(nullptr, msg.c_str(), "CloudRedirect - Cloud Sync Error",
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
};

static std::list<WorkItem>               g_workQueue;
static std::mutex                        g_queueMutex;
static std::condition_variable           g_queueCV;
// O(1) dedup index: maps cloudPath -> iterator into g_workQueue for Upload items.
// Replaces the O(n) linear scan that previously checked every queued item (H8).
static std::unordered_map<std::string, std::list<WorkItem>::iterator> g_uploadIndex;
static std::vector<std::thread>          g_workerThreads;
static std::atomic<bool>                 g_workerRunning{false};
static std::atomic<int>                  g_activeWorkers{0};
static std::unordered_map<std::string, int> g_activePaths;
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


// Cloud provider paths use forward slashes: "{accountId}/{appId}/blobs/{filename}"
static std::string CloudBlobPath(uint32_t accountId, uint32_t appId,
                                 const std::string& filename) {
    return std::to_string(accountId) + "/" + std::to_string(appId) +
           "/blobs/" + filename;
}

static std::string CloudMetadataPath(uint32_t accountId, uint32_t appId,
                                     const std::string& name) {
    return std::to_string(accountId) + "/" + std::to_string(appId) + "/" + name;
}

// Local cache paths use the existing LocalStorage layout:
//   {g_localRoot}\storage\{accountId}\{appId}\{filename}  — all file data + metadata
// Previously blobs were stored separately in a "blobs\" directory, but this caused
// desync between changelist metadata and HTTP-served file bytes. Now unified.
static std::string LocalStoragePath(uint32_t accountId, uint32_t appId) {
    return g_localRoot + "storage\\" + std::to_string(accountId) + "\\" +
           std::to_string(appId) + "\\";
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
                return !g_workQueue.empty() || !g_workerRunning;
            });
            if (!g_workerRunning && g_workQueue.empty()) break;
            if (g_workQueue.empty()) continue;
            item = std::move(g_workQueue.front());
            // Remove from dedup index before popping (H8)
            if (item.type == WorkItem::Upload) {
                g_uploadIndex.erase(item.cloudPath);
            }
            g_workQueue.pop_front();
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

        bool success = false;
        switch (item.type) {
        case WorkItem::Upload:
            if (g_provider->Upload(item.cloudPath, item.data.data(), item.data.size())) {
                LOG("[CloudStorage] BG upload OK [%d]: %s (%zu bytes)",
                    threadId, item.cloudPath.c_str(), item.data.size());
                OnCloudSuccess();
                success = true;
            } else {
                LOG("[CloudStorage] BG upload FAILED [%d]: %s", threadId, item.cloudPath.c_str());
                OnCloudFailure("Upload", item.cloudPath);
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
            }
            break;
        }

        if (success)
            consecutiveFailures = 0;
        else
            ++consecutiveFailures;

        {
            std::lock_guard<std::mutex> lock(g_queueMutex);
            auto it = g_activePaths.find(item.cloudPath);
            if (it != g_activePaths.end()) {
                if (--it->second <= 0) g_activePaths.erase(it);
            }
            --g_activeWorkers;
        }
        g_drainCV.notify_all();
    }
    LOG("[CloudStorage] Background worker %d stopped", threadId);
}

static void EnqueueWork(WorkItem item) {
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);

        // Deduplication: for Upload items, if the same cloudPath is already
        // queued for upload, replace it with the newer data. This eliminates
        // redundant uploads of metadata files (cn.dat, file_tokens.dat, etc.)
        // that get re-enqueued multiple times during a batch.
        // Uses O(1) index lookup instead of O(n) queue scan (H8).
        if (item.type == WorkItem::Upload) {
            auto indexIt = g_uploadIndex.find(item.cloudPath);
            if (indexIt != g_uploadIndex.end()) {
                auto& existing = *indexIt->second;
                LOG("[CloudStorage] Dedup: replacing queued upload for %s (%zu -> %zu bytes)",
                    item.cloudPath.c_str(), existing.data.size(), item.data.size());
                existing.data = std::move(item.data);
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


void Init(const std::string& localRoot, std::unique_ptr<ICloudProvider> provider) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_localRoot = localRoot;
    if (!g_localRoot.empty() && g_localRoot.back() != '\\')
        g_localRoot += '\\';

    g_provider = std::move(provider);

    LOG("[CloudStorage] Initialized. localRoot=%s provider=%s",
        g_localRoot.c_str(), g_provider ? g_provider->Name() : "none (local-only)");

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

    // Signal workers to stop
    g_workerRunning = false;
    g_queueCV.notify_all();

    for (auto& t : g_workerThreads) {
        if (t.joinable()) t.join();
    }
    g_workerThreads.clear();

    // Clear any remaining queued items and dedup index
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_workQueue.clear();
        g_uploadIndex.clear();
    }

    if (g_provider) {
        g_provider->Shutdown();
        g_provider.reset();
    }

    // Join any outstanding error dialog thread before DLL unload
    {
        std::lock_guard<std::mutex> lock(g_dialogMutex);
        if (g_dialogThread.joinable()) g_dialogThread.join();
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
    // 1. Write to local cache (synchronous — the HTTP server needs this immediately)
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return false; // path traversal blocked
    {
        auto parent = std::filesystem::path(localPath).parent_path();
        std::filesystem::create_directories(parent);

        // Atomic write: write to .tmp then rename to avoid partial reads
        if (!FileUtil::AtomicWriteBinary(localPath, data, len)) {
            LOG("[CloudStorage] StoreBlob: atomic write failed: %s (%zu bytes)", localPath.c_str(), len);
            return false;
        }
    }
    LOG("[CloudStorage] StoreBlob: cached locally: %s (%zu bytes)", filename.c_str(), len);

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

    // 2. Enqueue async upload to cloud provider
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
        std::ifstream f(localPath, std::ios::binary | std::ios::ate);
        if (f) {
            auto size = f.tellg();
            f.seekg(0, std::ios::beg);
            std::vector<uint8_t> data(static_cast<size_t>(size));
            f.read(reinterpret_cast<char*>(data.data()), size);
            LOG("[CloudStorage] RetrieveBlob: cache hit: %s (%zu bytes)",
                filename.c_str(), data.size());
            return data;
        }
    }

    // 2. Cache miss — pull from cloud provider (blocking)
    if (g_provider) {
        std::string cloudPath = CloudBlobPath(accountId, appId, filename);
        std::vector<uint8_t> data;
        if (g_provider->Download(cloudPath, data)) {
            LOG("[CloudStorage] RetrieveBlob: downloaded from cloud: %s (%zu bytes)",
                filename.c_str(), data.size());
            // Populate local cache for next time (best-effort atomic write)
            auto parent = std::filesystem::path(localPath).parent_path();
            std::filesystem::create_directories(parent);
            FileUtil::AtomicWriteBinary(localPath, data.data(), data.size());
            return data;
        }
        LOG("[CloudStorage] RetrieveBlob: not found in cloud: %s", filename.c_str());
    }

    LOG("[CloudStorage] RetrieveBlob: not found anywhere: %s", filename.c_str());
    return {};
}

bool DeleteBlob(uint32_t accountId, uint32_t appId,
                const std::string& filename) {
    // 1. Delete from local cache
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return false; // path traversal blocked
    std::error_code ec;
    std::filesystem::remove(localPath, ec);

    LOG("[CloudStorage] DeleteBlob: removed local cache: %s", filename.c_str());

    // CN is incremented once per batch in HandleCompleteBatch, not per file.

    // 2. Enqueue cloud delete
    if (g_provider) {
        WorkItem wi;
        wi.type = WorkItem::Delete;
        wi.cloudPath = CloudBlobPath(accountId, appId, filename);
        EnqueueWork(std::move(wi));
    }

    return true;
}

bool BlobExists(uint32_t accountId, uint32_t appId,
                const std::string& filename) {
    // Check local cache first
    std::string localPath = LocalBlobPath(accountId, appId, filename);
    if (localPath.empty()) return false;  // path traversal rejected
    if (std::filesystem::exists(localPath) && std::filesystem::is_regular_file(localPath))
        return true;

    // Check cloud
    if (g_provider) {
        std::string cloudPath = CloudBlobPath(accountId, appId, filename);
        return g_provider->Exists(cloudPath);
    }

    return false;
}


// Helper: read a small file from local storage path
static std::string ReadLocalText(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

// Helper: write a small text file to local storage path (atomic via .tmp+rename)
static bool WriteLocalText(const std::string& path, const std::string& content) {
    auto parent = std::filesystem::path(path).parent_path();
    std::filesystem::create_directories(parent);
    return FileUtil::AtomicWriteText(path, content);
}

// SaveMetadata: removed — metadata.json was never created locally by any code path.
// With the blob→storage copy in SyncFromCloud, GetFileList() works on restore
// without a separate metadata file.

uint64_t GetChangeNumber(uint32_t accountId, uint32_t appId) {
    // Read from LocalStorage's cn.dat (the authoritative local CN)
    // CloudStorage::SyncFromCloud will have already reconciled with cloud CN
    std::string cnPath = LocalStoragePath(accountId, appId) + "cn.dat";
    std::string content = ReadLocalText(cnPath);
    if (!content.empty()) {
        try {
            return std::stoull(content);
        } catch (...) {}
    }
    return 1; // default
}


void SaveRootTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_set<std::string>& tokens) {
    // Delegate to LocalStorage for the actual disk write
    LocalStorage::SaveRootTokens(accountId, appId, tokens);

    // Push to cloud
    if (g_provider) {
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
}

std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId) {
    // Just read from local — SyncFromCloud will have pulled the cloud version already
    return LocalStorage::LoadRootTokens(accountId, appId);
}

void SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens) {
    // Delegate to LocalStorage for the actual disk write
    LocalStorage::SaveFileTokens(accountId, appId, fileTokens);

    // Push to cloud
    if (g_provider) {
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
}

std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId) {
    return LocalStorage::LoadFileTokens(accountId, appId);
}


bool SyncFromCloud(uint32_t accountId, uint32_t appId) {
    if (!g_provider || !g_provider->IsAuthenticated()) return false;

    auto syncStart = std::chrono::steady_clock::now();
    bool hadNewer = false;
    std::string storagePath = LocalStoragePath(accountId, appId);
    std::filesystem::create_directories(storagePath);

    // 1. Sync CN: take max of local and cloud
    //    Read from LocalStorage's in-memory cache (matches Steam behavior where
    //    CN is read from an in-memory structure, not from disk).
    {
        uint64_t localCN = LocalStorage::GetChangeNumber(accountId, appId);

        std::string cloudCNPath = CloudMetadataPath(accountId, appId, "cn.dat");
        std::vector<uint8_t> cloudData;
        uint64_t cloudCN = 0;
        if (g_provider->Download(cloudCNPath, cloudData)) {
            std::string s(cloudData.begin(), cloudData.end());
            try { cloudCN = std::stoull(s); } catch (...) {}
        }

        if (cloudCN > localCN) {
            LOG("[CloudStorage] SyncFromCloud app %u: cloud CN=%llu > local CN=%llu, using cloud",
                appId, cloudCN, localCN);
            LocalStorage::SetChangeNumber(accountId, appId, cloudCN);
            hadNewer = true;
        } else if (localCN > cloudCN && cloudCN > 0) {
            LOG("[CloudStorage] SyncFromCloud app %u: local CN=%llu > cloud CN=%llu, pushing local to cloud",
                appId, localCN, cloudCN);
            PushCNToCloud(accountId, appId, localCN);
        } else {
            LOG("[CloudStorage] SyncFromCloud app %u: CN in sync (local=%llu, cloud=%llu)",
                appId, localCN, cloudCN);
        }
    }

    // 2. Sync root_token.dat: merge cloud tokens into local set
    {
        std::string cloudTokenPath = CloudMetadataPath(accountId, appId, "root_token.dat");
        std::vector<uint8_t> cloudData;
        if (g_provider->Download(cloudTokenPath, cloudData)) {
            std::unordered_set<std::string> cloudTokens;
            bool cloudHadCorruption = false;
            std::istringstream iss(std::string(cloudData.begin(), cloudData.end()));
            std::string line;
            while (std::getline(iss, line)) {
                // Strip trailing \r / \n (CRLF corruption from Windows line endings)
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (!line.empty()) cloudTokens.insert(line);
            }

            // Detect if cloud copy had more raw lines than cleaned tokens
            // (i.e., corrupted duplicates like "%Token%" and "%Token%\r")
            {
                size_t rawCount = 0;
                std::istringstream iss2(std::string(cloudData.begin(), cloudData.end()));
                std::string rawLine;
                while (std::getline(iss2, rawLine)) {
                    if (!rawLine.empty()) rawCount++;
                }
                if (rawCount > cloudTokens.size()) {
                    cloudHadCorruption = true;
                    LOG("[CloudStorage] SyncFromCloud app %u: cloud root_token.dat had %zu raw entries but only %zu clean tokens — pushing cleaned version",
                        appId, rawCount, cloudTokens.size());
                }
            }

            auto localTokens = LocalStorage::LoadRootTokens(accountId, appId);
            size_t beforeSize = localTokens.size();
            localTokens.insert(cloudTokens.begin(), cloudTokens.end());

            if (localTokens.size() > beforeSize) {
                LOG("[CloudStorage] SyncFromCloud app %u: merged %zu new root tokens from cloud",
                    appId, localTokens.size() - beforeSize);
                LocalStorage::SaveRootTokens(accountId, appId, localTokens);
                hadNewer = true;
            }

            // If cloud had corrupted tokens, push cleaned version back
            if (cloudHadCorruption) {
                std::string cleaned;
                for (auto& t : localTokens) {
                    cleaned += t + "\n";
                }
                std::vector<uint8_t> cleanedData(cleaned.begin(), cleaned.end());
                if (g_provider->Upload(cloudTokenPath, cleanedData.data(), cleanedData.size())) {
                    LOG("[CloudStorage] SyncFromCloud app %u: pushed cleaned root_token.dat to cloud (%zu tokens)",
                        appId, localTokens.size());
                } else {
                    LOG("[CloudStorage] SyncFromCloud app %u: FAILED to push cleaned root_token.dat to cloud",
                        appId);
                }
            }
        }
    }

    // 2b. Sync file_tokens.dat: merge cloud file-token mappings into local
    {
        std::string cloudPath = CloudMetadataPath(accountId, appId, "file_tokens.dat");
        std::vector<uint8_t> cloudData;
        if (g_provider->Download(cloudPath, cloudData) && !cloudData.empty()) {
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
                if (!cleanName.empty() && !token.empty())
                    cloudFileTokens[cleanName] = token;
            }

            // Merge: cloud entries fill in any gaps in local
            auto localFileTokens = LocalStorage::LoadFileTokens(accountId, appId);
            size_t beforeSize = localFileTokens.size();
            for (auto& [name, token] : cloudFileTokens) {
                if (localFileTokens.find(name) == localFileTokens.end()) {
                    localFileTokens[name] = token;
                }
            }
            if (localFileTokens.size() > beforeSize) {
                LOG("[CloudStorage] SyncFromCloud app %u: merged %zu new file-token mappings from cloud",
                    appId, localFileTokens.size() - beforeSize);
                LocalStorage::SaveFileTokens(accountId, appId, localFileTokens);
                hadNewer = true;
            }
        }
    }

    // 3. (removed) metadata.json sync — no longer needed.
    //    Downloaded blobs are now written directly to LocalStorage,
    //    so GetFileList() works without a separate metadata file.

    // 4. Pre-populate blob cache: list cloud blobs, download any we don't have locally.
    //    Bounded by BLOB_SYNC_TIMEOUT_SEC to prevent blocking game launch indefinitely.
    //    Also reused in step 5 (seed upload) to avoid a redundant List() call.
    constexpr int BLOB_SYNC_TIMEOUT_SEC = 120; // 2 minutes max for blob downloads
    std::string blobPrefix = std::to_string(accountId) + "/" +
                             std::to_string(appId) + "/blobs/";
    auto cloudBlobs = g_provider->List(blobPrefix);

    {
        int downloaded = 0, skipped = 0;
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
                break;
            }

            // fi.path is relative to provider root, e.g. "54303850/1229490/blobs/save.dat"
            // Extract filename from after "blobs/"
            auto blobsPos = fi.path.find("/blobs/");
            if (blobsPos == std::string::npos) continue;
            std::string filename = CanonicalizeInternalMetadataName(fi.path.substr(blobsPos + 7));

            std::string localBlobFile = LocalBlobPath(accountId, appId, filename);
            if (std::filesystem::exists(localBlobFile)) {
                skipped++;
                continue; // already cached
            }

            // Download to local cache (atomic write)
            LOG("[CloudStorage] SyncFromCloud app %u: downloading blob %s...", appId, filename.c_str());
            std::vector<uint8_t> data;
            if (g_provider->Download(fi.path, data)) {
                auto parent = std::filesystem::path(localBlobFile).parent_path();
                std::filesystem::create_directories(parent);
                if (FileUtil::AtomicWriteBinary(localBlobFile, data.data(), data.size())) {
                    downloaded++;
                    LOG("[CloudStorage] SyncFromCloud app %u: blob %s downloaded (%zu bytes)",
                        appId, filename.c_str(), data.size());
                }

                // Also write to LocalStorage so GetFileList() can find the file.
                // Without this, the changelist would report zero files on a fresh machine.
                // Use WriteFileNoIncrement: CN was already set from the cloud response
                // in step 1 (matching real Steam behavior where CN is set once, not per-file).
                const uint8_t* localData = data.empty() ? nullptr : data.data();
                LocalStorage::WriteFileNoIncrement(accountId, appId, filename,
                                                  localData, data.size());
            } else {
                LOG("[CloudStorage] SyncFromCloud app %u: FAILED to download blob %s",
                    appId, filename.c_str());
            }
        }
        if (downloaded > 0) {
            LOG("[CloudStorage] SyncFromCloud app %u: downloaded %d blobs from cloud (skipped %d cached)",
                appId, downloaded, skipped);
            hadNewer = true;
        }
    }

    // 5. Seed upload: push local blobs to cloud if cloud is empty/missing them.
    //    This handles the case where files exist locally (from previous sessions)
    //    but have never been uploaded to the cloud provider.
    {
        // Build set of cloud blob filenames for quick lookup (reuses cloudBlobs from step 4)
        std::unordered_set<std::string> cloudBlobNames;
        for (auto& fi : cloudBlobs) {
            auto blobsPos = fi.path.find("/blobs/");
            if (blobsPos == std::string::npos) continue;
            cloudBlobNames.insert(CanonicalizeInternalMetadataName(fi.path.substr(blobsPos + 7)));
        }

        // Scan local storage directory for files to seed to cloud.
        // Skip internal metadata files (cn.dat, root_token.dat, file_tokens.dat).
        std::string localBlobDir = g_localRoot + "storage\\" +
                                   std::to_string(accountId) + "\\" +
                                   std::to_string(appId) + "\\";
        int seeded = 0;
        if (std::filesystem::exists(localBlobDir)) {
            for (auto& entry : std::filesystem::recursive_directory_iterator(localBlobDir)) {
                if (!entry.is_regular_file()) continue;

                // Get relative path with forward slashes
                std::string rel = std::filesystem::relative(entry.path(), localBlobDir).string();
                for (auto& c : rel) { if (c == '\\') c = '/'; }

                // Skip internal metadata files
                if (rel == "cn.dat" || rel == "root_token.dat" || rel == "file_tokens.dat") continue;

                if (cloudBlobNames.count(rel)) continue; // already on cloud

                // Read local file and enqueue upload
                std::ifstream f(entry.path(), std::ios::binary);
                if (!f) continue;
                std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                          std::istreambuf_iterator<char>());
                WorkItem wi;
                wi.type = WorkItem::Upload;
                wi.cloudPath = CloudBlobPath(accountId, appId, rel);
                wi.data = std::move(data);
                EnqueueWork(std::move(wi));
                seeded++;
            }
        }

        // Also seed metadata files if cloud didn't have them
        auto seedMeta = [&](const std::string& filename) {
            std::string localFile = storagePath + filename;
            if (!std::filesystem::exists(localFile)) return;

            // Check if cloud already has it (we already tried downloading above,
            // so just check via the provider)
            std::string cloudPath = CloudMetadataPath(accountId, appId, filename);
            std::vector<uint8_t> probe;
            if (g_provider->Download(cloudPath, probe) && !probe.empty()) return;

            // Read local and push (empty files are valid — e.g. file_tokens.dat
            // for ISteamRemoteStorage games with no root tokens)
            std::ifstream f(localFile, std::ios::binary);
            if (!f) return;
            std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                      std::istreambuf_iterator<char>());

            WorkItem wi;
            wi.type = WorkItem::Upload;
            wi.cloudPath = cloudPath;
            wi.data = std::move(data);
            EnqueueWork(std::move(wi));
            seeded++;
        };

        seedMeta("cn.dat");
        seedMeta("root_token.dat");
        seedMeta("file_tokens.dat");

        if (seeded > 0) {
            LOG("[CloudStorage] SyncFromCloud app %u: seeding %d local files to cloud (%s)",
                appId, seeded, g_provider->Name());
        }
    }

    auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - syncStart).count();
    LOG("[CloudStorage] SyncFromCloud app %u: completed in %lld ms (hadNewer=%d)",
        appId, (long long)totalMs, hadNewer);

    return hadNewer;
}

void SyncAllFromCloud(uint32_t accountId) {
    if (!g_provider || !g_provider->IsAuthenticated()) return;

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
            appIds.insert(std::stoul(appStr));
        } catch (...) {}
    }

    LOG("[CloudStorage] SyncAllFromCloud: found %zu apps in cloud", appIds.size());
    for (uint32_t appId : appIds) {
        SyncFromCloud(accountId, appId);
    }
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

void DrainQueueForApp(uint32_t accountId, uint32_t appId) {
    if (!g_provider) return;

    std::string prefix = std::to_string(accountId) + "/" + std::to_string(appId) + "/";
    LOG("[CloudStorage] DrainQueueForApp: waiting for %s", prefix.c_str());

    constexpr int TIMEOUT_MS = 30000;
    auto start = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> lock(g_queueMutex);
    bool completed = g_drainCV.wait_for(lock,
        std::chrono::milliseconds(TIMEOUT_MS),
        [&prefix] { return !HasPendingWorkForPrefix(prefix); });

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();

    if (completed) {
        LOG("[CloudStorage] DrainQueueForApp: done for %s (%lld ms)",
            prefix.c_str(), (long long)elapsed);
    } else {
        LOG("[CloudStorage] DrainQueueForApp: TIMEOUT for %s after %lld ms",
            prefix.c_str(), (long long)elapsed);
    }
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
    if (lower == "gdrive") {
        return std::make_unique<GoogleDriveProvider>();
    }
    if (lower == "onedrive") {
        return std::make_unique<OneDriveProvider>();
    }
    LOG("[CloudStorage] CreateCloudProvider: unknown provider '%s'", name.c_str());
    return nullptr;
}
