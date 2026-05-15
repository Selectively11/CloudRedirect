#include "batch_tracker.h"
#include "cloud_metadata_paths.h"
#include "log.h"

namespace CloudIntercept {
namespace {

static std::atomic<uint64_t> g_nextBatchId{1};
static std::mutex g_uploadBatchMutex;
static std::unordered_map<uint64_t, UploadBatchState> g_activeUploadBatches;

} // namespace

uint64_t BatchTracker_NextId() {
    return g_nextBatchId.fetch_add(1);
}

uint64_t BatchTracker_ActiveId(uint32_t accountId, uint32_t appId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> lock(g_uploadBatchMutex);
    auto it = g_activeUploadBatches.find(key);
    return it == g_activeUploadBatches.end() ? 0 : it->second.batchId;
}

void BatchTracker_Begin(uint32_t accountId, uint32_t appId, uint64_t batchId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> lock(g_uploadBatchMutex);
    if (g_activeUploadBatches.find(key) != g_activeUploadBatches.end()) {
        LOG("[BatchTracker] BeginBatch: replacing stale batch %llu with %llu for account %u app %u",
            (unsigned long long)g_activeUploadBatches[key].batchId, (unsigned long long)batchId,
            accountId, appId);
        g_activeUploadBatches.erase(key);
    }
    UploadBatchState state;
    state.batchId = batchId;
    g_activeUploadBatches[key] = std::move(state);
}

void BatchTracker_RecordUpload(uint32_t accountId, uint32_t appId,
                               const std::string& filename) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> lock(g_uploadBatchMutex);
    auto it = g_activeUploadBatches.find(key);
    if (it == g_activeUploadBatches.end()) return;
    it->second.deletes.erase(filename);
    it->second.uploads.insert(filename);
}

void BatchTracker_RecordDelete(uint32_t accountId, uint32_t appId,
                               const std::string& filename) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> lock(g_uploadBatchMutex);
    auto it = g_activeUploadBatches.find(key);
    if (it == g_activeUploadBatches.end()) return;
    it->second.uploads.erase(filename);
    it->second.deletes.insert(filename);
}

UploadBatchState BatchTracker_Get(uint32_t accountId, uint32_t appId,
                                  uint64_t requestedBatchId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> lock(g_uploadBatchMutex);
    auto it = g_activeUploadBatches.find(key);
    if (it == g_activeUploadBatches.end()) return {};
    if (requestedBatchId != 0 && it->second.batchId != requestedBatchId) {
        LOG("[NS] CompleteBatch app=%u requested batch %llu but active batch is %llu; rejecting mismatch",
            appId, (unsigned long long)requestedBatchId,
            (unsigned long long)it->second.batchId);
        return {};
    }
    return it->second;
}

void BatchTracker_Clear(uint32_t accountId, uint32_t appId,
                        uint64_t batchId) {
    uint64_t key = MakeAppAccountKey(accountId, appId);
    std::lock_guard<std::mutex> lock(g_uploadBatchMutex);
    auto it = g_activeUploadBatches.find(key);
    if (it != g_activeUploadBatches.end() && it->second.batchId == batchId) {
        g_activeUploadBatches.erase(it);
    }
}

} // namespace CloudIntercept
