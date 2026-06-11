#pragma once
#include <cstdint>
#include <atomic>

namespace MetadataSync {

extern std::atomic<bool> steamToolsPresent;
extern std::atomic<bool> syncLuas;

// Native stats/playtime sync gates (config: sync_achievements / sync_playtime).
// When false, the corresponding native path does NOT interfere at all: stats
// pass straight through to Steam's real server (no import/synthesize), and
// playtime is neither tracked nor merged. Default true (sync enabled).
extern std::atomic<bool> syncAchievements;
extern std::atomic<bool> syncPlaytime;

// Experimental: proactively fetch missing achievement/stats schemas from the CM
// (config: experimental_schema_fetch). When false, no schema requests are sent.
// Default false (opt-in experimental feature).
extern std::atomic<bool> schemaFetch;

// UNSUPPORTED WIP OVERRIDE NON-ST CLIENT GATE.
// Metadata features (achievements, playtime, schema fetch, non-Steam-game spoof)
// are hard-gated to SteamTools clients. config override_non_st_client_gate lifts
// the gate so a non-ST client honors the per-feature flags. Default false.
extern std::atomic<bool> overrideNonStGate;

inline bool IsEnabled() {
    return steamToolsPresent.load(std::memory_order_relaxed) &&
           syncLuas.load(std::memory_order_relaxed);
}

// True when the ST-gate is open: either a SteamTools client, or the unsupported
// override is set. Metadata features must AND their per-feature flag with this.
inline bool StGateOpen() {
    return steamToolsPresent.load(std::memory_order_relaxed) ||
           overrideNonStGate.load(std::memory_order_relaxed);
}

// Per-feature flag AND'd with the ST-gate. Use these everywhere instead of the raw
// flags so a missed call site can't bypass the gate.
inline bool AchievementsEnabled() {
    return syncAchievements.load(std::memory_order_relaxed) && StGateOpen();
}
inline bool PlaytimeEnabled() {
    return syncPlaytime.load(std::memory_order_relaxed) && StGateOpen();
}
inline bool SchemaFetchEnabled() {
    return schemaFetch.load(std::memory_order_relaxed) && StGateOpen();
}

}
