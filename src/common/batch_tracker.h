#pragma once
#include <cstdint>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace CloudIntercept {

uint64_t MakeAppAccountKey(uint32_t accountId, uint32_t appId);

// SHA/size/timestamp captured from the exact bytes received at CommitFileUpload,
// so CompleteBatch publishes what was uploaded rather than re-stat'ing disk.
struct UploadFileMeta {
    std::vector<uint8_t> sha;   // SHA-1 over the uploaded bytes
    uint64_t size = 0;
    uint64_t timestamp = 0;
};

struct UploadBatchState {
    uint64_t batchId = 0;
    uint64_t assignedCN = 0;   // CN assigned by BeginAppUploadBatch (= currentCN + 1)
    uint64_t appBuildId = 0;
    int declaredUploads = 0;   // count Steam declared in BeginBatch
    int declaredDeletes = 0;   // count Steam declared in BeginBatch
    std::unordered_set<std::string> uploads;
    std::unordered_set<std::string> deletes;
    std::unordered_map<std::string, uint32_t> filePlatforms; // filename -> platforms_to_sync
    std::unordered_map<std::string, UploadFileMeta> uploadMeta; // filename -> uploaded sha/size/ts
};

// Allocate the next unique batch ID (monotonic per process).
uint64_t BatchTracker_NextId();

// Return the active batch ID for this (account, app), or 0 if none.
uint64_t BatchTracker_ActiveId(uint32_t accountId, uint32_t appId);

// Create a new batch for this (account, app) with the given batch ID.
void BatchTracker_Begin(uint32_t accountId, uint32_t appId, uint64_t batchId, uint64_t assignedCN, uint64_t appBuildId,
                        int declaredUploads = 0, int declaredDeletes = 0);

// Record a file upload in the active batch with the uploaded bytes' SHA/size/ts.
// No-op if no active batch.
void BatchTracker_RecordUpload(uint32_t accountId, uint32_t appId,
                               const std::string& filename,
                               const std::vector<uint8_t>& sha,
                               uint64_t size, uint64_t timestamp);
// Record a file delete in the active batch.  No-op if no active batch.
void BatchTracker_RecordDelete(uint32_t accountId, uint32_t appId,
                               const std::string& filename);

// Record platforms_to_sync for a file in the active batch.  No-op if no active batch.
void BatchTracker_RecordFilePlatforms(uint32_t accountId, uint32_t appId,
                                      const std::string& filename, uint32_t platformsToSync);

// Return the active batch state (caller owns the copy).
UploadBatchState BatchTracker_Get(uint32_t accountId, uint32_t appId,
                                  uint64_t requestedBatchId);

// Remove the active batch, only if batchId matches.
void BatchTracker_Clear(uint32_t accountId, uint32_t appId, uint64_t batchId);

} // namespace CloudIntercept
