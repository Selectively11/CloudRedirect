#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

// Pushes another device's playtime into the running client's tracking map +
// library UI. Parses a CPlayer_GetLastPlayedTimes_Response and drives the writer
// (steamclient.so sub_182F530), which updates m_mapAppMinutesPlayed, the
// localconfig keys, and posts the 1020046 AppMinutesPlayedDataNotice callback --
// the same write sub_182F8A0 performs after its GetLastPlayedTimes RPC.
//
// PlayerClient.NotifyLastPlayedTimes#1 is a service-method listener, not a
// job-name route, so a synthesized packet cannot be routed to it; the direct
// write is the only path to a live update.
namespace LivePlaytime {

using ParseFromArrayFn = int(*)(void* msg, const void* data, int len);

// Resolve the steamclient.so functions by signature. Returns true if all the
// required entry points were found (otherwise live updates are unavailable and
// the poller's on-disk merge still applies on Steam's next natural refresh).
bool Resolve(uintptr_t steamclientBase, size_t steamclientSize, ParseFromArrayFn parseFromArray);

// Install the CUser-capture detour on the writer's entry. The first natural
// playtime write (post-logon refresh) records the active CUser pointer, which we
// reuse to drive our own updates. Safe no-op if Resolve failed.
bool InstallUserCapture();
void RemoveUserCapture();

// Apply a serialized CPlayer_GetLastPlayedTimes_Response (repeated Game games)
// to the running client. No-op until the CUser has been captured. Must run on
// Steam's network thread.
void Apply(const std::vector<uint8_t>& respBody);

// Queue a serialized response body from any thread; the net-thread drain applies
// it. The background cloud poller uses this so the writer (which touches Steam's
// minutes-played map and posts callbacks) only runs on the network thread.
void Queue(const std::vector<uint8_t>& respBody);

// Apply all queued bodies. Caller MUST be on Steam's network thread (invoked
// from the GamesPlayed send observer and the GetLastPlayedTimes transport hook).
void DrainOnNetThread();

// True once the CUser pointer has been captured and updates can be applied.
bool Ready();

} // namespace LivePlaytime
