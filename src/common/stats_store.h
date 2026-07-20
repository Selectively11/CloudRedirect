#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <functional>

namespace StatsStore {

// Account-wide blob callbacks (one read/write for all apps, not per-app).
using CloudPullAllFn =
    std::function<bool(std::unordered_map<uint32_t, std::string>& out)>;
using CloudPushAllFn =
    std::function<void(const std::unordered_map<uint32_t, std::string>& all)>;
// Read one legacy per-app blob for migration into the account blob.
using CloudPullLegacyFn = std::function<std::string(uint32_t appId)>;
// Read one legacy Playtime/<appId>.bin for migration recovery.
using CloudPullLegacyPlaytimeFn = std::function<std::string(uint32_t appId)>;
void SetCloudProvider(CloudPullAllFn pullAll, CloudPushAllFn pushAll,
                      CloudPullLegacyFn pullLegacy = nullptr,
                      CloudPullLegacyPlaytimeFn pullLegacyPlaytime = nullptr);

// Merge strategies for stat values (mirrors Steam's resolution_method + type_int).
enum class StatMerge : uint8_t {
    Overwrite  = 0,  // last-writer-wins (resolution_method=3 or unknown)
    BitwiseOr  = 1,  // type_int=4 (achievements) or resolution_method=1
    MaxInt     = 2,  // resolution_method=2, type_int=1 (signed int max)
    MaxFloat   = 3,  // resolution_method=2, type_int=2/3 (float max)
};

struct StatEntry {
    uint32_t statId;
    uint32_t value;
    StatMerge merge = StatMerge::Overwrite;
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

// Per-device playtime contribution; only the current platform's field is written.
struct DevicePlaytime {
    uint32_t windows = 0;
    uint32_t mac = 0;
    uint32_t lin = 0;   // NOTE: not 'linux' -- that's a predefined macro on Linux/GCC
};

struct PlaytimeData {
    // Derived totals (recomputed from perDevice).
    uint32_t minutesForever = 0;
    uint32_t minutesLastTwoWeeks = 0;
    uint32_t lastPlayedTime = 0;       // unix timestamp (max across devices)
    uint32_t playtimeWindows = 0;
    uint32_t playtimeMac = 0;
    uint32_t playtimeLinux = 0;

    // Per-device sub-totals keyed by hostname (merge source of truth).
    std::map<std::string, DevicePlaytime> perDevice;
};

struct AppStats {
    uint32_t crcStats;  // CRC of the stats data, must match client
    std::vector<StatEntry> stats;
    std::vector<AchievementBlock> achievements;
    PlaytimeData playtime;
    std::vector<uint8_t> schema; // raw KV binary blob
};

// steamPath: used for localconfig.vdf reconciliation and native blob import.
void Init(const std::string& storageRoot, const std::string& steamPath);

// Resolves current Steam accountId (32-bit). Returns 0 if not yet known.
using AccountIdProvider = std::function<uint32_t()>;
void SetAccountIdProvider(AccountIdProvider provider);

// Called when no schema blob exists for an app; platform requests it from Steam.
using SchemaMissingCallback = std::function<void(uint32_t appId)>;
void SetSchemaMissingCallback(SchemaMissingCallback cb);

// Namespace-app predicate; reconcile uses it to seed playtime from localconfig.vdf
// for managed apps before any stats JSON exists.
using NamespacePredicate = std::function<bool(uint32_t appId)>;
void SetNamespacePredicate(NamespacePredicate pred);

// Seed apps at startup (cloud blob + native UserGameStats + local JSON) so
// GetLastPlayedTimes has data before launch. Requires a logged-in accountId.
void SeedApps(const std::vector<uint32_t>& appIds);

// Block until SeedApps completes (or timeout expires). Returns true if seed
// finished, false on timeout. Safe to call from any thread.
bool WaitForSeed(uint32_t timeoutMs);

// Retry native imports for namespace apps with an on-disk schema that the
// boot-time sweep skipped (accountId not yet known). Flags dirty, no push.
void RetryNativeImportsAfterLogin();

// Clear per-account in-memory caches on a Steam account switch so one account's
// stats don't leak into the next. No push. Returns true if state was cleared.
bool ResetForAccountSwitch(uint32_t newAccountId);

// Test-only: reset all per-account state plus the last-seen account id so tests
// start clean regardless of order. Never call from production.
void ResetForTesting();

// Re-pull + merge each app's cloud blob; returns apps whose playtime advanced
// (another device played) for a live notification. Runs in the background.
std::vector<uint32_t> RefreshFromCloud(const std::vector<uint32_t>& appIds);

// Returns true if data exists on disk.
bool LoadAppStats(uint32_t appId, AppStats& out);

void SaveAppStats(uint32_t appId, const AppStats& stats);

// Live cache reference; caller holds the store lock. Prefer Snapshot() for reads.
AppStats& GetOrCreate(uint32_t appId);

// Thread-safe copy for read handlers (no lock needed by caller).
AppStats Snapshot(uint32_t appId);

// Thread-safe explicit reset (CMsgClientStoreUserStats2 explicit_reset): clears
// stats/achievements and zeroes the crc under the store lock.
void ResetStats(uint32_t appId);

// Returns the new CRC.
uint32_t SetStat(uint32_t appId, uint32_t statId, uint32_t value);

// Returns the new CRC.
uint32_t SetStats(uint32_t appId, const std::vector<StatEntry>& entries);

// Returns the new CRC.
uint32_t SetAchievement(uint32_t appId, uint32_t statId, uint32_t bit, uint32_t unlockTime);

// Store/retrieve the schema blob for an app.
void SetSchema(uint32_t appId, const uint8_t* data, size_t len);
std::vector<uint8_t> GetSchema(uint32_t appId);

void CaptureNativeUnlocks(uint32_t appId);

// Merge stats stored by Steam under nativeAppId into appId's cloud namespace.
// FakeAppID hosts use this when Steam's local blob key differs from the game.
void CaptureNativeUnlocksFrom(uint32_t appId, uint32_t nativeAppId);

// Playtime tracking
void StartSession(uint32_t appId);
void EndSession(uint32_t appId);
PlaytimeData GetPlaytime(uint32_t appId);
uint32_t GetDiskAccountId();

// Enumerate appIds that have any tracked playtime (for GetLastPlayedTimes).
std::vector<uint32_t> GetTrackedApps();

void FlushAll();

// Merge two app-stats JSONs (monotonic playtime, union achievements).
std::string MergeAppStatsJson(const std::string& base, const std::string& incoming);

// Consume the set of apps whose stats were intentionally reset this session.
// The push path should replace (not merge) these entries in the cloud blob.
// Returns the set and clears it atomically under the store lock.
std::unordered_set<uint32_t> ConsumeResetApps();

} // namespace StatsStore
