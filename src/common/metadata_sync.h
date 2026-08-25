#pragma once
#include <cstdint>
#include <atomic>

namespace MetadataSync {

extern std::atomic<bool> steamToolsPresent;
extern std::atomic<bool> syncLuas;

// Native stats/playtime sync gates (config: sync_achievements / sync_playtime).
extern std::atomic<bool> syncAchievements;
extern std::atomic<bool> syncPlaytime;

// Retired schema-fetch flag. SchemaFetchEnabled() always returns false now.
extern std::atomic<bool> schemaFetch;

inline bool IsEnabled() {
    return steamToolsPresent.load(std::memory_order_relaxed) &&
           syncLuas.load(std::memory_order_relaxed);
}

// SteamTools-client gate. Win: needs DLL entry. Linux: always open.
inline bool StGateOpen() {
#if defined(__linux__)
    return true;
#else
    return steamToolsPresent.load(std::memory_order_relaxed);
#endif
}

// Per-feature flag AND'd with the ST-gate (for hook-based paths only).
inline bool AchievementsEnabled() {
    return syncAchievements.load(std::memory_order_relaxed) && StGateOpen();
}
inline bool PlaytimeEnabled() {
    return syncPlaytime.load(std::memory_order_relaxed) && StGateOpen();
}
inline bool SchemaFetchEnabled() {
    return false;
}

}
