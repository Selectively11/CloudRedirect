#pragma once
#include <cstdint>
#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace CloudIntercept {

uint64_t MakeAppAccountKey(uint32_t accountId, uint32_t appId);

struct UploadBatchState {
    uint64_t batchId = 0;
    std::unordered_set<std::string> uploads;
    std::unordered_set<std::string> deletes;
};

// Allocate the next unique batch ID (monotonic per process).
uint64_t BatchTracker_NextId();

// Return the active batch ID for this (account, app), or 0 if none.
uint64_t BatchTracker_ActiveId(uint32_t accountId, uint32_t appId);

// Create a new batch for this (account, app) with the given batch ID.
void BatchTracker_Begin(uint32_t accountId, uint32_t appId, uint64_t batchId);

// Record a file upload or delete in the active batch.  No-op if no active batch.
void BatchTracker_RecordUpload(uint32_t accountId, uint32_t appId,
                               const std::string& filename);
void BatchTracker_RecordDelete(uint32_t accountId, uint32_t appId,
                               const std::string& filename);

// Return the active batch state (caller owns the copy).
UploadBatchState BatchTracker_Get(uint32_t accountId, uint32_t appId,
                                  uint64_t requestedBatchId);

// Remove the active batch, only if batchId matches.
void BatchTracker_Clear(uint32_t accountId, uint32_t appId, uint64_t batchId);

} // namespace CloudIntercept
