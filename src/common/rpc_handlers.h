#pragma once
#include "cloud_rpc_utils.h"
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
inline constexpr const char* RPC_SUSPEND_SESSION     = "Cloud.SuspendAppSession#1";
inline constexpr const char* RPC_RESUME_SESSION      = "Cloud.ResumeAppSession#1";
inline constexpr const char* RPC_EXIT_SYNC           = "Cloud.SignalAppExitSyncDone#1";
inline constexpr const char* RPC_CONFLICT            = "Cloud.ClientConflictResolution#1";
inline constexpr const char* RPC_SYNC_STATS          = "ClientMetrics.ClientCloudAppSyncStats#1";
inline constexpr const char* RPC_TRANSFER_REPORT     = "Cloud.ExternalStorageTransferReport#1";

// Steam EResult values used by the cloud RPC layer.
inline constexpr int32_t kEResultOK       = 1;
inline constexpr int32_t kEResultFail     = 2;
inline constexpr int32_t kEResultDisabled = 108;

// RPC response: body bytes + optional EResult override.
struct RpcResult {
    PB::Writer body;
    int32_t    eresult = kEResultOK;

    RpcResult() = default;
    RpcResult(PB::Writer b) : body(std::move(b)) {}
    RpcResult(PB::Writer b, int32_t er) : body(std::move(b)), eresult(er) {}
};

// ExtractAppId, BuildBeginBatchResponseBody, ParseCompleteBatchRequest,
// and CompleteBatchRequestInfo have moved to cloud_rpc_utils.h (namespace CloudRpcUtils).
// Use CloudRpcUtils::ExtractAppId(...) etc.

RpcResult HandleGetChangelist(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleLaunchIntent(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleSuspendSession(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleResumeSession(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleQuotaUsage(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleBeginBatch(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleBeginFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleCommitFileUpload(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleCompleteBatch(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleFileDownload(uint32_t appId, const std::vector<PB::Field>& reqBody);
RpcResult HandleDeleteFile(uint32_t appId, const std::vector<PB::Field>& reqBody);

void RestoreAppMetadata(uint32_t accountId, uint32_t appId);
void ShutdownRpcHandlers();

void RecordConflictResolution(uint32_t appId, bool choseLocal);
bool ConsumeConflictLocalChoice(uint32_t appId);

// Flush pending sync icon states to registry.vdf (Linux, called from OnUnload).
void FlushPendingSyncStates();

// True if the UserGameStats blob has any non-zero stat/achievement data.
// Empty stubs and unparseable input return false.
bool StatsBlobHasUnlocks(const uint8_t* data, size_t len);

} // namespace CloudIntercept
