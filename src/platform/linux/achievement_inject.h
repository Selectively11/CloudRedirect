#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

// Serves the legacy CMsgClientGetUserStats (EMsg 818) achievement request on
// Linux by injecting a CMsgClientGetUserStatsResponse (819) routed to the waiting
// CAPIJobRequestUserStats. The Linux Steam client fetches achievements for many
// apps via this legacy CM message (CAPIJobRequestUserStats picks it over the
// Player.GetUserStats#1 service method when appid < a runtime threshold), so the
// achievements our store holds only reach the library UI through this path.
//
// Flow: observe the outbound 818 (its jobid + appid) -> build the 819 body from
// the store -> wrap it as a CProtoBufNetPacket with a header whose jobid_target
// is the 818's jobid -> route it via CJobMgr::BRouteMsgToJob, which resumes the
// suspended job exactly as a real server reply would.
namespace AchievementInject {

// Serializes a protobuf message body to raw bytes (installed by the platform
// layer; same helper the GamesPlayed observer uses).
using SerializeBodyFn = const uint8_t* (*)(void* bodyObj, size_t* outLen);

// Resolve the steamclient.so functions by signature (WrapPacket, BRouteMsgToJob).
// Returns true if both were found. With them absent the legacy path is left to
// the real server (achievements just won't show for apps Steam has no data for).
bool Resolve(uintptr_t steamclientBase, size_t steamclientSize, SerializeBodyFn serialize);
bool Ready();

// Called from the CCMInterface::Send observer for every outbound message. Detects
// EMsg 818, reads its appid + jobid from the message header, and (for a namespace
// app) queues a 819 response. Returns immediately; the response is routed on the
// next network-thread drain. msgObj = the CProtoBufMsg being sent.
void ObserveOutbound(uint32_t emsg, void* msgObj, void* cmInterface);

// Route any queued 819 responses. MUST run on Steam's network thread (valid
// coroutine TLS), same constraint as the live playtime drain.
void DrainOnNetThread();

} // namespace AchievementInject
