#pragma once
#include "protobuf.h"
#include <cstring>
#include <vector>

namespace CloudRpcUtils {

// RPC method name constants used by ExtractAppId.
inline constexpr const char* RPC_COMMIT_UPLOAD  = "Cloud.ClientCommitFileUpload#1";
inline constexpr const char* RPC_COMPLETE_BATCH = "Cloud.CompleteAppUploadBatchBlocking#1";
inline constexpr const char* RPC_LAUNCH_INTENT  = "Cloud.SignalAppLaunchIntent#1";
inline constexpr const char* RPC_SUSPEND_SESSION = "Cloud.SuspendAppSession#1";
inline constexpr const char* RPC_RESUME_SESSION  = "Cloud.ResumeAppSession#1";

inline uint32_t ExtractAppId(const char* method, const std::vector<PB::Field>& body) {
    if (!method) return 0;

    uint32_t fieldNum = 1;
    if (std::strcmp(method, RPC_COMMIT_UPLOAD) == 0) fieldNum = 2;
    else if (std::strcmp(method, RPC_COMPLETE_BATCH) == 0) fieldNum = 1;
    else if (std::strcmp(method, RPC_LAUNCH_INTENT) == 0) fieldNum = 1;
    else if (std::strcmp(method, RPC_SUSPEND_SESSION) == 0) fieldNum = 1;
    else if (std::strcmp(method, RPC_RESUME_SESSION) == 0) fieldNum = 1;

    auto* f = PB::FindField(body, fieldNum);
    return f ? static_cast<uint32_t>(f->varintVal) : 0;
}

inline PB::Writer BuildBeginBatchResponseBody(uint64_t batchId, uint64_t changeNumber) {
    PB::Writer body;
    body.WriteVarint(1, batchId);
    body.WriteVarint(4, changeNumber);
    return body;
}

struct CompleteBatchRequestInfo {
    uint64_t batchId = 0;
    uint32_t result = 1;
    bool hasResult = false;
};

inline CompleteBatchRequestInfo ParseCompleteBatchRequest(const std::vector<PB::Field>& fields) {
    CompleteBatchRequestInfo info;
    for (const auto& field : fields) {
        if (field.fieldNum == 2 && field.wireType == PB::Varint) {
            info.batchId = field.varintVal;
        } else if (field.fieldNum == 3 && field.wireType == PB::Varint) {
            info.result = static_cast<uint32_t>(field.varintVal);
            info.hasResult = true;
        }
    }
    return info;
}

} // namespace CloudRpcUtils
