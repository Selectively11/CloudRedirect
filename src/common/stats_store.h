#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace StatsStore {

// Cloud-backing provider callbacks. The store stays decoupled from the
// platform CloudStorage / account-id plumbing: the platform layer installs
// these so per-app stats blobs are pulled on first access and pushed on save.
// pull: return true and fill outJson if a cloud blob exists for appId.
// push: persist the JSON blob for appId to the cloud (fire-and-forget).
using CloudPullFn = std::function<bool(uint32_t appId, std::string& outJson)>;
using CloudPushFn = std::function<void(uint32_t appId, const std::string& json)>;
void SetCloudProvider(CloudPullFn pull, CloudPushFn push);

struct StatEntry {
    uint32_t statId;
    uint32_t value;
};

struct AchievementUnlock {
    uint32_t bit;       // 0-31 within the achievement stat
    uint32_t unlockTime; // unix timestamp, 0 = locked
};

struct AchievementBlock {
    uint32_t statId;    // the achievement stat ID (type 4)
    uint32_t bits;      // bitmask of unlocked achievements
    uint32_t unlockTimes[32]; // per-bit unlock timestamps
    std::string names[32];    // per-bit human-readable display name (from schema)
};

struct PlaytimeData {
    uint32_t minutesForever;
    uint32_t minutesLastTwoWeeks;
    uint32_t lastPlayedTime;       // unix timestamp
    uint32_t playtimeWindows;
    uint32_t playtimeMac;
    uint32_t playtimeLinux;
};

struct AppStats {
    uint32_t crcStats;  // CRC of the stats data, must match client
    std::vector<StatEntry> stats;
    std::vector<AchievementBlock> achievements;
    PlaytimeData playtime;
    std::vector<uint8_t> schema; // raw KV binary blob
};

// Initialize the store with a root directory for JSON files.
// steamPath: e.g. "C:\Games\Steam\" -- used to read localconfig.vdf for playtime reconciliation
//            and to import Steam's native UserGameStats / schema blobs from appcache\stats.
void Init(const std::string& storageRoot, const std::string& steamPath);

// Install a provider that resolves the current Steam accountId (32-bit). Used
// to locate native appcache\stats\UserGameStats_<accountId>_<appId>.bin blobs.
// Returns 0 if not yet known (e.g. not logged in). Resolved lazily on access.
using AccountIdProvider = std::function<uint32_t()>;
void SetAccountIdProvider(AccountIdProvider provider);

// Install a callback invoked when a native import finds NO achievement schema
// for an app (UserGameStatsSchema_<appId>.bin missing). The platform layer uses
// this to request the schema from Steam's server. Fire-and-forget.
using SchemaMissingCallback = std::function<void(uint32_t appId)>;
void SetSchemaMissingCallback(SchemaMissingCallback cb);

// Namespace-app predicate; reconcile uses it to seed playtime from localconfig.vdf
// for managed apps before any stats JSON exists.
using NamespacePredicate = std::function<bool(uint32_t appId)>;
void SetNamespacePredicate(NamespacePredicate pred);

// Seed apps at startup (cloud blob + native UserGameStats + local JSON) so
// GetLastPlayedTimes has data before launch. Requires a logged-in accountId.
void SeedApps(const std::vector<uint32_t>& appIds);

// Re-pull + merge each app's cloud blob; returns apps whose playtime advanced
// (another device played) for a live notification. Runs in the background.
std::vector<uint32_t> RefreshFromCloud(const std::vector<uint32_t>& appIds);

// Load stats for an app. Returns true if data exists on disk.
bool LoadAppStats(uint32_t appId, AppStats& out);

// Save stats for an app to disk.
void SaveAppStats(uint32_t appId, const AppStats& stats);

// Get or create stats entry for an app (thread-safe, cached in memory).
AppStats& GetOrCreate(uint32_t appId);

// Update a single stat value. Returns the new CRC.
uint32_t SetStat(uint32_t appId, uint32_t statId, uint32_t value);

// Update multiple stat values at once. Returns the new CRC.
uint32_t SetStats(uint32_t appId, const std::vector<StatEntry>& entries);

// Set an achievement bit and record unlock time. Returns the new CRC.
uint32_t SetAchievement(uint32_t appId, uint32_t statId, uint32_t bit, uint32_t unlockTime);

// Store/retrieve the schema blob for an app.
void SetSchema(uint32_t appId, const uint8_t* data, size_t len);
const std::vector<uint8_t>& GetSchema(uint32_t appId);

// Compute CRC32 over current stat values for an app.
uint32_t ComputeCrc(uint32_t appId);

// Re-read Steam's native blob for an app and merge any newly unlocked
// achievements / updated stat values into the store, then push to the cloud if
// anything changed. Called when an achievement-store message is observed on the
// wire (the genuine unlock event). Safe to call from the network thread.
void CaptureNativeUnlocks(uint32_t appId);

// Playtime tracking
void StartSession(uint32_t appId);
void EndSession(uint32_t appId);
PlaytimeData GetPlaytime(uint32_t appId);

// Enumerate appIds that have any tracked playtime (for GetLastPlayedTimes).
std::vector<uint32_t> GetTrackedApps();

// Flush all dirty apps to disk.
void FlushAll();

} // namespace StatsStore
