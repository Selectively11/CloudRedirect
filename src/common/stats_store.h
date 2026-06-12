#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace StatsStore {

// Cloud-backing provider callbacks; the platform layer installs these.
//
// Stats sync as a single account-wide blob keyed by appId, not one blob per app
// (which cost a Drive round-trip per app at every startup/poll, stalling launch).
//   pullAll: fill `out` (appId -> stats JSON) from the account blob. One read.
//   pushAll: persist the snapshot; the platform layer RMW-merges against the live
//            blob (so another device isn't clobbered) and skips unchanged uploads.
using CloudPullAllFn =
    std::function<bool(std::unordered_map<uint32_t, std::string>& out)>;
using CloudPushAllFn =
    std::function<void(const std::unordered_map<uint32_t, std::string>& all)>;
// Read one app's LEGACY per-app stats blob (<accountId>/<appId>/stats.json) from
// the older layout that predates the consolidated account blob. Returns the JSON,
// or empty if absent. Used once to migrate stranded playtime into the account blob.
using CloudPullLegacyFn = std::function<std::string(uint32_t appId)>;
// Read one app's first-format playtime blob (account-scope Playtime/<appId>.bin,
// {"LastPlayed","Playtime","Playtime2wks"}). Returns the JSON or empty. Lets the
// playtime migration recover from the cloud when the .bin isn't in the local cache.
using CloudPullLegacyPlaytimeFn = std::function<std::string(uint32_t appId)>;
void SetCloudProvider(CloudPullAllFn pullAll, CloudPushAllFn pushAll,
                      CloudPullLegacyFn pullLegacy = nullptr,
                      CloudPullLegacyPlaytimeFn pullLegacyPlaytime = nullptr);

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

// One device's own contribution to an app's playtime. A device only ever writes
// the field matching the platform it runs on; the other two stay whatever that
// device last observed (normally 0). Counters are monotonic per device.
struct DevicePlaytime {
    uint32_t windows = 0;
    uint32_t mac = 0;
    uint32_t lin = 0;   // NOTE: not 'linux' -- that's a predefined macro on Linux/GCC
};

struct PlaytimeData {
    // Derived aggregates (sum across all devices). Recomputed from perDevice on
    // load/merge/accrue; serialized for readers (UI) that want the totals.
    uint32_t minutesForever = 0;
    uint32_t minutesLastTwoWeeks = 0;
    uint32_t lastPlayedTime = 0;       // unix timestamp (max across devices)
    uint32_t playtimeWindows = 0;
    uint32_t playtimeMac = 0;
    uint32_t playtimeLinux = 0;

    // Authoritative per-device sub-totals, keyed by stable device id (hostname).
    // Cloud stats.json is last-writer-wins; keying by device makes each writer own
    // its key so merge (union + max-per-device) never clobbers or double-counts.
    std::map<std::string, DevicePlaytime> perDevice;
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
// Returns a live cache reference; caller must hold the store lock (background
// poller/unlock-capture mutate the same vectors). Read handlers should use
// Snapshot() instead. Kept for lock-holding/single-threaded-init callers.
AppStats& GetOrCreate(uint32_t appId);

// Thread-safe by-value snapshot for read handlers: seeds the app (cloud pull +
// native import) like GetOrCreate, then returns a COPY taken under the store
// lock, so the caller can build a response without racing background mutations.
AppStats Snapshot(uint32_t appId);

// Thread-safe explicit reset (CMsgClientStoreUserStats2 explicit_reset): clears
// stats/achievements and zeroes the crc under the store lock.
void ResetStats(uint32_t appId);

// Update a single stat value. Returns the new CRC.
uint32_t SetStat(uint32_t appId, uint32_t statId, uint32_t value);

// Update multiple stat values at once. Returns the new CRC.
uint32_t SetStats(uint32_t appId, const std::vector<StatEntry>& entries);

// Set an achievement bit and record unlock time. Returns the new CRC.
uint32_t SetAchievement(uint32_t appId, uint32_t statId, uint32_t bit, uint32_t unlockTime);

// Store/retrieve the schema blob for an app.
void SetSchema(uint32_t appId, const uint8_t* data, size_t len);
const std::vector<uint8_t>& GetSchema(uint32_t appId);

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
