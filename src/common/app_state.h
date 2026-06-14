#pragma once
// Per-app cloud state: CN + manifest + session in one atomic JSON file (state.cloudredirect).

#include "cloud_provider.h"
#include <cstdint>
#include <future>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace CloudStorage {

// Mirrors CCloud_AppFileInfo proto fields.
struct FileEntry {
    std::vector<uint8_t> sha;       // SHA-1 (20 bytes) -- proto field 2: sha_file
    uint64_t timestamp = 0;         // Canonical timestamp -- proto field 3: time_stamp
    uint64_t size = 0;              // Raw file size -- proto field 4: raw_file_size
    uint32_t persistState = 0;      // 0=Persisted, 1=Forgotten, 2=Deleted -- proto field 5
    uint32_t platformsToSync = 0xFFFFFFFFu; // Platform bitmask -- proto field 6
    uint32_t rootIndex = 0;         // Path prefix index -- proto field 7
    uint32_t machineIndex = 0;      // Machine name index -- proto field 8
};

struct SessionLock {
    uint64_t clientId = 0;
    std::string machineName;
    uint64_t timeLastUpdated = 0;   // Unix timestamp
    std::string operation;          // "active", "uploading", "suspended", or empty
};

// PICS ufs quota cached for KV injection. Zero = not yet fetched or PICS returned 0.
struct AppQuotaConfig {
    uint64_t quotaBytes = 0;        // ufs.quota (bytes)
    uint32_t maxNumFiles = 0;       // ufs.maxnumfiles (file count)
    uint64_t fetchedAtUnix = 0;     // Unix timestamp of last successful fetch
    uint64_t lastSeenBuildId = 0;   // appBuildId at time of fetch; mismatch = stale
};

// Both > 0 means usable; zero = PICS failure marker, use fallback.
inline bool QuotaConfigIsUsable(const AppQuotaConfig& q) {
    return q.quotaBytes > 0 && q.maxNumFiles > 0;
}

// Complete cloud-side state for one app+account pair.
struct CloudAppState {
    uint32_t version = 2;           // Format version (1 = pre-quota, 2 = with quota)
    uint64_t cn = 0;                // Change number
    uint64_t appBuildId = 0;        // Last uploaded app build ID (app_buildid_hwm)
    AppQuotaConfig quota;           // Developer's cloud quota config from PICS
    SessionLock session;
    std::vector<std::string> machines; // Machine name array (indexed by FileEntry.machineIndex)
    std::unordered_map<std::string, FileEntry> files;

    bool hasActiveSession() const;
};

// Result of fetching state from cloud provider.
enum class StateFetchStatus {
    Ok,
    NotFound,       // State file does not exist on provider (new app or pre-migration)
    FetchFailed,
    ParseFailed,
    Timeout,        // Bounded fetch exceeded its deadline (provider slow); caller should
                    // serve local/last-known state and let the background fetch finish.
};

struct StateFetchResult {
    StateFetchStatus status = StateFetchStatus::FetchFailed;
    CloudAppState state;
};

void AppState_Init(ICloudProvider* provider);
void AppState_Shutdown();

// Handles migration from old cn.cloudredirect + manifest.cloudredirect.
// Always performs a live provider fetch. Read-modify-write callers (any fetch
// that precedes a PublishCloudState) must use this, not the cached serve
// accessor, to avoid clobbering a concurrent cross-machine update with a stale base.
StateFetchResult FetchCloudState(uint32_t accountId, uint32_t appId);

// Time-bounded live fetch for the serve path (runs on Steam's main-loop thread,
// where a slow download stalls BMainLoop). Runs the fetch on a worker, waits up to
// deadlineMs, and on timeout returns Timeout -- the still-running fetch warms the
// serve cache for next time, matching native's non-blocking yielding job.
StateFetchResult FetchCloudStateBounded(uint32_t accountId, uint32_t appId,
                                        int deadlineMs);

// Cache-aware accessor for the serve path only. Returns a recently-fetched state
// without re-hitting the provider, only when provably safe:
//   - cached entry younger than the hard max-age, AND
//   - no active foreign session in that snapshot.
// Otherwise delegates to FetchCloudState (live). Invalidated by every local
// mutation. Not for read-modify-write callers.
StateFetchResult FetchCloudStateForServe(uint32_t accountId, uint32_t appId);

// Report this client's own Steam id so the serve cache treats only foreign-client
// sessions as contention. See g_ownClientId in app_state.cpp.
void NoteOwnClientId(uint64_t clientId);

// Publishes the app's cloud state. Refuses to regress the changenumber (re-fetches
// and rejects if the provider already holds a newer CN) -- the only guard against
// a stale RMW on providers with no conditional-write primitive.
// lockOnly skips the blob verify/heal pass; use it only on the session-release
// publish, where the manifest and CN were just committed by the upload batch.
// `confirmedDurable` (optional) forwards to VerifyAndHealManifestForPublish: filenames
// uploaded+provider-confirmed in this batch, so their durability needn't be re-listed.
bool PublishCloudState(uint32_t accountId, uint32_t appId,
                       const CloudAppState& state, bool lockOnly = false,
                       const std::unordered_set<std::string>* confirmedDurable = nullptr);

std::string SerializeState(const CloudAppState& state);
bool DeserializeState(const std::string& json, CloudAppState& outState);

// Release the session lock in the cloud state (called on ExitSyncDone).
// Blocks until any pending async publish completes before releasing.
void ReleaseCloudSession(uint32_t accountId, uint32_t appId, uint64_t clientId);

// Pending publish barrier: CompleteBatch defers cloud publish to a background
// thread and registers a future here. ReleaseCloudSession and BeginBatch's
// FetchCloudStateForServe wait on it to ensure cross-machine consistency.
void SetPendingPublish(uint32_t accountId, uint32_t appId,
                       std::shared_future<void> fut);
void WaitForPendingPublish(uint32_t accountId, uint32_t appId);

CloudAppState MigrateFromLegacy(uint64_t cn,
                                 const std::unordered_map<std::string, FileEntry>& legacyFiles);

} // namespace CloudStorage
