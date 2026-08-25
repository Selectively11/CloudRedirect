#pragma once
#include <cstdint>
#include <vector>
#include <functional>

// Native achievement / playtime sync for namespace (lua) apps on Linux.
//
// Steam's modern stats path is the Player.* unified service method, carried on
// the same CClientUnifiedServiceTransport vtable the cloud hooks already wrap
// (cloud_hooks.cpp slots 5/7/8). These entry points let the cloud hooks hand
// off Player.GetUserStats#1 / Player.ClientGetLastPlayedTimes#1 without knowing
// the stats internals.

namespace StatsHooks {

// Serialize a live protobuf message object to raw bytes (msg vtable ByteSizeLong
// + SerializeToArray). Provided by cloud_hooks.cpp.
using SerializeFn = std::function<std::vector<uint8_t>(void* msg)>;
// Parse raw bytes into a live protobuf message object (ParseFromArray).
using ParseFn = std::function<bool(void* msg, const uint8_t* data, size_t len)>;

void SetProtobufHelpers(SerializeFn serialize, ParseFn parse);

// Attempt to answer a Player.* stats service method from the local store.
//
// Returns true if the method was handled locally (the caller must then return
// success and must NOT forward to the real server). Returns false to pass the
// call through unchanged.
//
//   GetUserStats#1            -> answered entirely from the store (gated on
//                                MetadataSync::syncAchievements)
//   ClientGetLastPlayedTimes#1-> the caller forwards to the server FIRST, then
//                                passes the real response here to append our
//                                namespace apps' playtime (gated on syncPlaytime)
//
// `request` / `response` are the live protobuf message objects from the hook.
// `flags` is the transport flag array (flags[2]=transport ok, flags[3]=eresult).
bool TryHandleGetUserStats(const char* methodName, void* request, void* response, int* flags);

// Merge our namespace apps' playtime into an already-populated server response.
// Call AFTER the real server reply succeeds. No-op if syncPlaytime is off or we
// have nothing to add.
void MergeLastPlayedTimes(const char* methodName, void* request, void* response);

} // namespace StatsHooks
