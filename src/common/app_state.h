#pragma once
// Per-app cloud state: CN + manifest + session in one atomic JSON file (state.cloudredirect).

#include "cloud_provider.h"
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
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
};

struct StateFetchResult {
    StateFetchStatus status = StateFetchStatus::FetchFailed;
    CloudAppState state;
    std::string etag; // For conditional writes (OneDrive)
};

void AppState_Init(ICloudProvider* provider);
void AppState_Shutdown();

// Handles migration from old cn.cloudredirect + manifest.cloudredirect.
// Always performs a live provider fetch. Read-modify-write callers (any fetch
// that precedes a PublishCloudState) must use this, not the cached serve
// accessor, to avoid clobbering a concurrent cross-machine update with a stale base.
StateFetchResult FetchCloudState(uint32_t accountId, uint32_t appId);

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

// If etag is non-empty, uses conditional write (OneDrive).
bool PublishCloudState(uint32_t accountId, uint32_t appId,
                       const CloudAppState& state,
                       const std::string& etag = "");

std::string SerializeState(const CloudAppState& state);
bool DeserializeState(const std::string& json, CloudAppState& outState);

// Release the session lock in the cloud state (called on ExitSyncDone).
void ReleaseCloudSession(uint32_t accountId, uint32_t appId, uint64_t clientId);

CloudAppState MigrateFromLegacy(uint64_t cn,
                                 const std::unordered_map<std::string, FileEntry>& legacyFiles);

} // namespace CloudStorage
