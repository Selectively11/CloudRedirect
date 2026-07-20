#pragma once
// Third-party client API for CloudRedirect cloud save + stats sync.
// Host hooks CClientUnifiedServiceTransport, extracts method/appId/body,
// calls CR_HandleCloudRpc, writes the response back into Steam's objects.
// Non-cloud-save features (manifest pinning, parental) are disabled.

#include <cstdint>

#ifdef _WIN32
#  ifdef CR_API_EXPORTS
#    define CR_API extern "C" __declspec(dllexport)
#  else
#    define CR_API extern "C" __declspec(dllimport)
#  endif
#else
#  define CR_API extern "C" __attribute__((visibility("default")))
#endif

#define CR_NOTIFY_INFO  0
#define CR_NOTIFY_WARN  1
#define CR_NOTIFY_ERROR 2

// Host-provided notification callback. Called instead of MessageBoxA.
// Must be thread-safe. Pass NULL for default (MessageBoxA).
typedef void (*CR_NotifyFn)(int level, const char* title, const char* message);

// steamPath: Steam install dir with trailing separator.
CR_API bool CR_InitCloudSave(const char* steamPath, CR_NotifyFn notify);

// Dispatch a Cloud.* or Player.* RPC. Returns false if appId is not a
// namespace app or method is unrecognized -- caller should chain to the
// original. respBuf is caller-allocated; respLen receives actual size written.
//
// Cloud.* RPCs are always handled. Player.* RPCs are handled only when the
// corresponding stats sync feature is enabled (see below):
//   Player.GetUserStats#1          -> requires CR_EnableStatsSync(achievements)
//   Player.ClientGetLastPlayedTimes#1 -> requires CR_EnableStatsSync(playtime)
CR_API bool CR_HandleCloudRpc(const char* method, uint32_t appId,
                              uint32_t accountId,
                              const uint8_t* reqBody, uint32_t reqLen,
                              uint8_t* respBuf, uint32_t respMaxLen,
                              uint32_t* respLen, int32_t* eresult);

CR_API void CR_AddApp(uint32_t appId);
CR_API void CR_RemoveApp(uint32_t appId);
CR_API bool CR_IsApp(uint32_t appId);

CR_API void CR_SetAccountId(uint32_t accountId);

// Replace the namespace-app set with the given list. NULL/0 clears it.
CR_API void CR_SetApps(const uint32_t* appIds, uint32_t count);

CR_API void CR_DrainPlaytimeUpdates(void);

CR_API void CR_Shutdown(void);

// Install CR's own vtable hooks on CClientUnifiedServiceTransport.
// Consumers that don't install their own vtable hooks (i.e. they intercept
// Cloud RPCs at the network-packet layer and call CR_HandleCloudRpc) MUST
// call this after CR_InitCloudSave + CR_SetApps. Without it, slot4 RPCs
// (BeginFileUpload, CommitFileUpload, etc.) will timeout because the
// consumer's async packet-injection path can't satisfy slot4's synchronous
// response semantics.
// Returns true if hooks were installed, false if prerequisites are missing.
CR_API bool CR_InstallVtableHooks(void);

// ═══════════════════════════════════════════════════════════════════════════
// Achievement / Playtime Sync API
//
// Opt-in cloud-backed achievement and playtime sync for third-party clients.
// Data syncs across devices via the same GDrive infrastructure as cloud saves.
//
// Typical integration:
//
//   // After init (actual sync controlled by user config):
//   CR_EnableStatsSync(true, true);
//
//   // When your hook sees a game start/stop:
//   CR_NotifyAppRunning(appId, true);   // game launched
//   CR_NotifyAppRunning(appId, false);  // game exited
//
//   // When your BAsyncSend hook sees EMsg 820 (StoreUserStats2):
//   CR_NotifyStatsStored(appId);        // CR re-reads the native blob
//
//   // When serving responses in your RecvPkt/vtable hooks:
//   CR_GetPlaytime(appId, &info);
//   CR_GetAchievements(appId, blocks, maxBlocks);
//
// Notes:
// - All functions are thread-safe.
// - Cloud push is automatic on session end and stats capture.
// - CR does NOT inject into Steam's UI in cloudSaveOnly mode; the host's
//   own hooks serve the data using the query functions below.
// - Schemas: Steam writes UserGameStatsSchema_<appId>.bin to disk when it
//   processes EMsg 819 responses. CR reads from there automatically. If
//   the host strips the schema from 819 responses, it should write the
//   schema file itself (or another device will have it in the cloud blob).
// ═══════════════════════════════════════════════════════════════════════════

// ─── Feature enable ──────────────────────────────────────────────────────
// Signal that the host has stats hooks installed. Actual sync behavior is
// controlled by the user's config (sync_achievements / sync_playtime).
CR_API void CR_EnableStatsSync(bool achievements, bool playtime);

// ─── Data input ──────────────────────────────────────────────────────────
// Notify CR that a namespace app is running (true) or has stopped (false).
// Start: begins accruing playtime minutes.
// Stop: flushes accumulated minutes to disk and pushes to cloud.
// Idempotent: re-calling with true restarts the timer (no minutes lost).
CR_API void CR_NotifyAppRunning(uint32_t appId, bool running);

// Notify CR that stats were stored for an app (the host observed EMsg 820).
// CR re-reads Steam's native UserGameStats blob from disk, merges any new
// achievement unlocks or stat values, and pushes changes to cloud.
CR_API void CR_NotifyStatsStored(uint32_t appId);

// FakeAppID variant: appId remains the cloud/schema namespace while
// nativeAppId selects Steam's UserGameStats_<account>_<nativeAppId>.bin.
CR_API void CR_NotifyStatsStoredFrom(uint32_t appId, uint32_t nativeAppId);

// ─── Query ───────────────────────────────────────────────────────────────
// Query playtime data. Returns false if no data exists for this app.
struct CR_PlaytimeInfo {
    uint32_t minutesForever;
    uint32_t minutesLastTwoWeeks;
    uint32_t lastPlayedTime;       // unix timestamp
    uint32_t playtimeWindows;      // minutes on Windows
    uint32_t playtimeMac;          // minutes on macOS
    uint32_t playtimeLinux;        // minutes on Linux
};
CR_API bool CR_GetPlaytime(uint32_t appId, CR_PlaytimeInfo* out);

// Query achievement blocks. Returns number of blocks written to `out`.
// Each block covers one achievement stat (up to 32 achievements per stat).
struct CR_AchievementBlock {
    uint32_t statId;
    uint32_t bits;              // bitmask of unlocked achievements
    uint32_t unlockTimes[32];   // per-bit unix timestamps (0 = locked)
};
CR_API uint32_t CR_GetAchievements(uint32_t appId, CR_AchievementBlock* out,
                                   uint32_t maxBlocks);
