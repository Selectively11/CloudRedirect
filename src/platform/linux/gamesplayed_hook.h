#pragma once
#include <cstddef>
#include <cstdint>

// Playtime session tracking for namespace (lua) apps on Linux.
//
// Steam broadcasts CMsgClientGamesPlayed (EMsg 5410/742/715) through the CM
// send primitive CCMInterface::Send when a game starts or stops. We tap that
// send to observe the broadcast and start/stop StatsStore sessions by appid.
// This is read-only: we never modify or block the message.

namespace GamesPlayedHook {

// Serialize a protobuf message body object to raw bytes. Returns a pointer to a
// thread-local buffer valid until the next call on the same thread; sets *outLen.
// Installed by the platform layer so this module stays free of protobuf plumbing.
using SerializeBodyFn = const uint8_t* (*)(void* bodyObj, size_t* outLen);
void SetSerializer(SerializeBodyFn fn);

// Resolve CCMInterface::Send in the loaded steamclient.so and install an inline
// detour that observes outbound GamesPlayed broadcasts. Safe to call once after
// steamclient is mapped and relocated. Returns true if the detour was installed.
bool Install(uintptr_t steamclientBase, size_t steamclientSize);

// Remove the detour and wait for in-flight observers to drain.
void Remove();

} // namespace GamesPlayedHook
