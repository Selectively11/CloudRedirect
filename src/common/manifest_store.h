#pragma once
#include "cloud_provider.h"
#include "local_storage.h"
#include <mutex>
#include <unordered_map>
#include <unordered_set>

// Manifest lifecycle: cloud fetch/save, local load/build, repair, per-entry updates.
// All public methods are thread-safe.

namespace CloudStorage {

// Per-file metadata stored in manifest.cloudredirect
struct ManifestEntry {
    std::vector<uint8_t> sha;  // 20-byte SHA1
    uint64_t timestamp = 0;
    uint64_t size = 0;
};

// Full manifest: filename -> metadata
using Manifest = std::unordered_map<std::string, ManifestEntry>;

enum class ManifestRepairStatus {
    Complete,
    Repaired,
    Incomplete,
};

// Initialize the manifest store with the active provider and local root.
void ManifestStore_Init(const std::string& localRoot,
                        ICloudProvider* provider);

// Fetch manifest from cloud. Returns empty map if not found or error.
Manifest FetchCloudManifest(uint32_t accountId, uint32_t appId);

// Save manifest to local cache and upload to cloud (async).
bool SaveManifest(uint32_t accountId, uint32_t appId, const Manifest& manifest);

// Save manifest to local cache only; do not upload to cloud.
bool SaveManifestLocal(uint32_t accountId, uint32_t appId, const Manifest& manifest);

// Commit barrier: drain work, rebuild manifest, publish before CN advance.
bool PublishFullManifestForCommit(uint32_t accountId, uint32_t appId);

// Commit barrier fast-path: applies the tracked batch delta onto the current
// manifest and publishes the result before CN advances.
bool PublishManifestDeltaForCommit(uint32_t accountId, uint32_t appId,
                                   const std::vector<std::string>& uploads,
                                   const std::vector<std::string>& deletes);

// Load manifest from local cache (no cloud fetch).
Manifest LoadLocalManifest(uint32_t accountId, uint32_t appId);
bool TryLoadLocalManifest(uint32_t accountId, uint32_t appId, Manifest& outManifest);

// Build manifest from current local blob cache.
Manifest BuildManifestFromLocalBlobs(uint32_t accountId, uint32_t appId);

// Repair a cloud manifest against a complete provider blob listing.
ManifestRepairStatus RepairCloudManifest(uint32_t accountId, uint32_t appId,
                                          Manifest& manifest,
                                          bool pruneAbsentRemote = false,
                                          bool persistRepair = true);

// Update a single entry in the manifest (after blob upload).
bool UpdateManifestEntry(uint32_t accountId, uint32_t appId,
                         const std::string& filename,
                         const std::vector<uint8_t>& sha,
                         uint64_t timestamp, uint64_t size);

// Remove an entry from the manifest (after blob delete).
bool RemoveManifestEntry(uint32_t accountId, uint32_t appId,
                         const std::string& filename);

// --- manifest snapshots for Steam-faithful delta changelist ---

struct ManifestDelta {
    struct FileChange {
        std::string filename;
        std::vector<uint8_t> sha;
        uint64_t timestamp = 0;
        uint64_t size = 0;
        bool deleted = false;
    };
    std::vector<FileChange> files;
    uint64_t serverCN = 0;
};

// Save a point-in-time snapshot of the current manifest at the given CN.
// Prunes snapshots older than the most recent 100.
void SaveManifestSnapshot(uint32_t accountId, uint32_t appId, uint64_t cn);

// Check whether a manifest snapshot exists for the given CN.
bool ManifestSnapshotExists(uint32_t accountId, uint32_t appId, uint64_t cn);

// Compute file delta between clientCN and serverCN manifest snapshots.
ManifestDelta ComputeManifestDelta(uint32_t accountId, uint32_t appId,
                                    uint64_t clientCN, uint64_t serverCN,
                                    const Manifest& serverManifest = {});

} // namespace CloudStorage
