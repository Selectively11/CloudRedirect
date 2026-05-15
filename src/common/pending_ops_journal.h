#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace PendingOpsJournal {

enum class Operation : uint32_t {
    None = 0,
    AppSessionActive = 1,
    UploadInProgress = 2,
    UploadPending = 3,
    AppSessionSuspended = 4,
};

struct Entry {
    Operation operation = Operation::None;
    std::string machineName;
    uint64_t clientId = 0;
    uint32_t timeLastUpdated = 0;
    uint32_t osType = 0;
    uint32_t deviceType = 0;
};

void Init(const std::string& root);
void RecordPending(uint32_t accountId, uint32_t appId,
                   const std::vector<Entry>& entries);
std::vector<Entry> RecordLaunchIntent(uint32_t accountId, uint32_t appId,
                                      const Entry& currentSession,
                                      bool ignorePendingOperations);
void RecordUploadBatchStart(uint32_t accountId, uint32_t appId);
void RecordUploadBatchInterrupted(uint32_t accountId, uint32_t appId);
void RecordUploadBatchEnd(uint32_t accountId, uint32_t appId);
void RecordSuspendState(uint32_t accountId, uint32_t appId,
                        const Entry& session, bool uploadsCompleted);
void RecordResumeState(uint32_t accountId, uint32_t appId,
                       uint64_t clientId);
void RecordExitSyncState(uint32_t accountId, uint32_t appId,
                         bool uploadsCompleted, bool uploadsRequired,
                         uint64_t clientId);
std::vector<Entry> LoadPending(uint32_t accountId, uint32_t appId);
std::optional<Entry> LoadCurrentSession(uint32_t accountId, uint32_t appId);
void ClearPending(uint32_t accountId, uint32_t appId);

} // namespace PendingOpsJournal
