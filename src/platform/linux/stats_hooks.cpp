#include "stats_hooks.h"
#include "stats_handlers.h"
#include "metadata_sync.h"
#include "cloud_intercept.h"
#include "protobuf.h"
#include "log.h"

#include <cstring>

namespace StatsHooks {

static SerializeFn g_serialize;
static ParseFn     g_parse;

void SetProtobufHelpers(SerializeFn serialize, ParseFn parse) {
    g_serialize = std::move(serialize);
    g_parse = std::move(parse);
}

bool TryHandleGetUserStats(const char* methodName, void* request, void* response, int* flags) {
    if (!methodName || !g_serialize || !g_parse) return false;
    if (strcmp(methodName, StatsHandlers::RPC_GET_USER_STATS) != 0) return false;
    if (!MetadataSync::syncAchievements.load(std::memory_order_relaxed)) return false;
    if (!request || !response) return false;

    auto reqBytes = g_serialize(request);
    if (reqBytes.empty()) return false;
    auto reqFields = PB::Parse(reqBytes.data(), reqBytes.size());

    // appid is field 2 in CPlayer_GetUserStats_Request.
    uint32_t appId = 0;
    if (auto* f = PB::FindField(reqFields, 2)) appId = (uint32_t)f->varintVal;
    if (appId == 0 || !CloudIntercept::IsNamespaceApp(appId)) return false;

    auto res = StatsHandlers::HandleGetUserStats(appId, reqFields);
    if (res.body.Size() == 0) {
        LOG("[Stats] GetUserStats app=%u: store returned empty -> passthrough", appId);
        return false;
    }
    if (!g_parse(response, res.body.Data().data(), res.body.Size())) {
        LOG("[Stats] GetUserStats app=%u: ParseFromArray failed -> passthrough", appId);
        return false;
    }
    if (flags) {
        flags[2] = 1;            // transport success
        flags[3] = res.eresult;  // eresult
    }
    LOG("[Stats] GetUserStats app=%u handled locally (%zu bytes)", appId, res.body.Size());
    return true;
}

void MergeLastPlayedTimes(const char* methodName, void* request, void* response) {
    if (!methodName || !g_serialize || !g_parse) return;
    if (strcmp(methodName, StatsHandlers::RPC_GET_LAST_PLAYED) != 0) return;
    if (!MetadataSync::syncPlaytime.load(std::memory_order_relaxed)) return;
    if (!response) return;

    std::vector<PB::Field> reqFields;
    if (request) {
        auto reqBytes = g_serialize(request);
        if (!reqBytes.empty())
            reqFields = PB::Parse(reqBytes.data(), reqBytes.size());
    }

    auto ours = StatsHandlers::HandleGetLastPlayedTimes(reqFields);
    if (ours.body.Size() == 0) return;

    // Keep the server's response verbatim and append our games[] (field 1, each
    // a length-delimited CPlayer_LastPlayedTimes_Game). The client merges by
    // appid, so real owned games keep their server playtime.
    auto respBytes = g_serialize(response);
    PB::Writer merged;
    auto existing = PB::Parse(respBytes.data(), respBytes.size());
    for (const auto& f : existing) {
        if (f.wireType == PB::Varint)              merged.WriteVarint(f.fieldNum, f.varintVal);
        else if (f.wireType == PB::Fixed64)        merged.WriteFixed64(f.fieldNum, f.varintVal);
        else if (f.wireType == PB::Fixed32)        merged.WriteFixed32(f.fieldNum, (uint32_t)f.varintVal);
        else if (f.wireType == PB::LengthDelimited) merged.WriteBytes(f.fieldNum, f.data, f.dataLen);
    }

    auto ourFields = PB::Parse(ours.body.Data().data(), ours.body.Size());
    size_t added = 0;
    for (const auto& f : ourFields) {
        if (f.fieldNum == 1 && f.wireType == PB::LengthDelimited) {
            merged.WriteBytes(1, f.data, f.dataLen);
            ++added;
        }
    }

    if (added > 0 && g_parse(response, merged.Data().data(), merged.Size()))
        LOG("[Stats] GetLastPlayedTimes: appended %zu local game(s) to server response", added);
}

} // namespace StatsHooks
