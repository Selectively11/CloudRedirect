#pragma once
#include "protobuf.h"
#include <vector>

namespace CloudIntercept {

// Cloud RPC method names
inline constexpr const char* RPC_GET_CHANGELIST     = "Cloud.GetAppFileChangelist#1";
inline constexpr const char* RPC_BEGIN_UPLOAD        = "Cloud.ClientBeginFileUpload#1";
inline constexpr const char* RPC_COMMIT_UPLOAD       = "Cloud.ClientCommitFileUpload#1";
inline constexpr const char* RPC_FILE_DOWNLOAD       = "Cloud.ClientFileDownload#1";
inline constexpr const char* RPC_DELETE_FILE         = "Cloud.ClientDeleteFile#1";
inline constexpr const char* RPC_BEGIN_BATCH         = "Cloud.BeginAppUploadBatch#1";
inline constexpr const char* RPC_COMPLETE_BATCH      = "Cloud.CompleteAppUploadBatchBlocking#1";
inline constexpr const char* RPC_QUOTA_USAGE         = "Cloud.ClientGetAppQuotaUsage#1";
inline constexpr const char* RPC_LAUNCH_INTENT       = "Cloud.SignalAppLaunchIntent#1";
inline constexpr const char* RPC_EXIT_SYNC           = "Cloud.SignalAppExitSyncDone#1";
inline constexpr const char* RPC_CONFLICT            = "Cloud.ClientConflictResolution#1";
inline constexpr const char* RPC_SYNC_STATS          = "ClientMetrics.ClientCloudAppSyncStats#1";
inline constexpr const char* RPC_TRANSFER_REPORT     = "Cloud.ExternalStorageTransferReport#1";

// Extract appId from Cloud RPC body (field varies by method)
uint32_t ExtractAppId(const char* method, const std::vector<PB::Field>& body);

// RPC handler functions -- each takes (appId, parsed request body) and returns
// a PB::Writer containing the response body.
PB::Writer HandleGetChangelist(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleLaunchIntent(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleQuotaUsage(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleBeginBatch(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleBeginFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleCommitFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleCompleteBatch(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleFileDownload(uint32_t appId, const std::vector<PB::Field>& reqBody);
PB::Writer HandleDeleteFile(uint32_t appId, const std::vector<PB::Field>& reqBody);

void RestoreAppMetadata(uint32_t accountId, uint32_t appId);
void ShutdownRpcHandlers();

} // namespace CloudIntercept
