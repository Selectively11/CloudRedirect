#pragma once

#include <cstdint>
#include <cstddef>

namespace CloudHooks
{
    // Called after hooks are installed to store the original function pointers
    void SetOriginals(void* origSlot5, void* origSlot7, void* origSlot8);

    // Called after IsCloudEnabledForApp hook is installed
    void SetOriginalIsCloudEnabled(void* orig);

    // Resolve protobuf helper functions from the loaded steamclient.so.
    // Must be called after steamclient is loaded. Returns true on success.
    bool ResolveProtobufHelpers(void* steamclientBase, size_t steamclientSize);

    // Install the GamesPlayed observer (playtime tracking) using the resolved
    // protobuf serializer. Call after ResolveProtobufHelpers succeeds.
    void InstallGamesPlayedObserver(uintptr_t steamclientBase, size_t steamclientSize);

    // Signal hooks to stop and wait for in-flight calls to drain.
    void BeginShutdown();
}
