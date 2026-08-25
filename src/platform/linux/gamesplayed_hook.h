#pragma once
#include <cstddef>
#include <cstdint>

// Observes CCMInterface::Send for playtime tracking and achievement capture.

namespace GamesPlayedHook {

using SerializeBodyFn = const uint8_t* (*)(void* bodyObj, size_t* outLen);
void SetSerializer(SerializeBodyFn fn);

bool Install(uintptr_t steamclientBase, size_t steamclientSize);
void Remove();

} // namespace GamesPlayedHook
