#pragma once
#include "cloud_provider.h"
#include "cloud_work_queue.h"
#include "local_storage.h"
#include "local_metadata_store.h"
#include "manifest_store.h"
#include "token_store.h"
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

namespace CloudStorage {

struct CloudAppState; // defined in app_state.h

void Init(const std::string& localRoot, std::unique_ptr<ICloudProvider> provider);
void Shutdown();
bool IsCloudActive();

bool StoreBlob(uint32_t accountId, uint32_t appId,
               const std::string& filename,
               const uint8_t* data, size_t len);

bool StoreBlobStaged(uint32_t accountId, uint32_t appId, uint64_t batchId,
                     const std::string& filename,
                     const uint8_t* data, size_t len);

// Cloud-first when active; returns empty if not found.
// Sets *found=true if the blob exists (even if 0 bytes).
// expectedShaHex: cloud SHA; skip network if local cache matches.
std::vector<uint8_t> RetrieveBlob(uint32_t accountId, uint32_t appId,
                                   const std::string& filename,
                                   bool* found = nullptr,
                                   const std::string& expectedShaHex = {});

bool DeleteBlob(uint32_t accountId, uint32_t appId,
                const std::string& filename);
bool DeleteBlobStaged(uint32_t accountId, uint32_t appId,
                      const std::string& filename);

// CN must not advance unless this succeeds.
bool PromoteStagedBatchForCommit(uint32_t accountId, uint32_t appId,
                                 uint64_t batchId,
                                 const std::vector<std::string>& uploads,
                                 const std::vector<std::string>& deletes);

// Verifies every file in `state` has its CAS blob durably on the provider before
// its manifest is published; heals from the local cache or drops phantom entries.
// Returns false only when the cloud blob listing is unavailable (don't publish).
//
// `confirmedDurable`, when non-null, lists filenames whose blobs were just uploaded
// (and provider-confirmed with a 2xx) in this batch. These are durable by definition
// -- exactly the signal native trusts (the upload EResult; see YldUploadFiles) -- so
// they need no re-listing. If every file in `state` is confirmed, the (slow, ~20s for
// GDrive) blob listing is skipped entirely; otherwise it lists only to verify the
// carried-forward remainder (files from a prior CN that this batch did not re-upload).
bool VerifyAndHealManifestForPublish(uint32_t accountId, uint32_t appId,
                                     CloudAppState& state,
                                     const std::unordered_set<std::string>* confirmedDurable = nullptr);

std::vector<uint64_t> ListStagedBatchIds(uint32_t accountId, uint32_t appId);
bool RemoveStagedBatch(uint32_t accountId, uint32_t appId, uint64_t batchId);

ICloudProvider::ExistsStatus CheckBlobExists(uint32_t accountId, uint32_t appId,
                                             const std::string& filename);

// Local-only mode returns true with an empty set.
bool ListRemoteBlobNames(uint32_t accountId, uint32_t appId,
                         std::unordered_set<std::string>& outNames);

bool HasLocalBlob(uint32_t accountId, uint32_t appId,
                   const std::string& filename);

// GC: delete unreferenced blobs. Returns count deleted, or -1 on error.
int GarbageCollectBlobs(uint32_t accountId, uint32_t appId);

bool SyncFromCloud(uint32_t accountId, uint32_t appId);
std::vector<uint32_t> SyncAllFromCloud(uint32_t accountId);

// Pauses background uploads so foreground SyncFromCloud doesn't queue behind sweeps.
struct ForegroundSyncScope {
    ForegroundSyncScope();
    ~ForegroundSyncScope();
    ForegroundSyncScope(const ForegroundSyncScope&)            = delete;
    ForegroundSyncScope& operator=(const ForegroundSyncScope&) = delete;
};

void NotifyAuthFailure(const std::string& providerName);

// --- internal: shared with manifest_store.cpp and token_store.cpp ---
struct InflightSyncScope {
    bool entered = false;
    InflightSyncScope();
    ~InflightSyncScope();
    explicit operator bool() const { return entered; }
    InflightSyncScope(const InflightSyncScope&) = delete;
    InflightSyncScope& operator=(const InflightSyncScope&) = delete;
};
std::string CloudMetadataPath(uint32_t accountId, uint32_t appId, const std::string& name);
bool DownloadCloudMetadataWithLegacyFallback(uint32_t accountId, uint32_t appId,
    const char* canonicalName, const char* legacyName,
    std::vector<uint8_t>& outData, bool* outUsedLegacy = nullptr);
// Download the first-format per-app playtime blob (account-scope
// <acct>/0/blobs/Playtime/<appId>.bin). False if absent/unavailable. Migration-only.
bool DownloadLegacyPlaytimeBlob(uint32_t accountId, uint32_t appId,
    std::vector<uint8_t>& outData);
bool UploadCloudMetadataText(uint32_t accountId, uint32_t appId,
    const char* name, const std::string& content);
// Queued (thread-safe) variant: serializes on the cloud work queue.
void UploadCloudMetadataTextAsync(uint32_t accountId, uint32_t appId,
    const char* name, const std::string& content);
void RemoveCloudMetadataIfPresent(uint32_t accountId, uint32_t appId, const char* name);
void RemoveLegacyCloudMetadataIfCanonicalExists(uint32_t accountId, uint32_t appId,
    const char* canonicalName, const char* legacyName);
std::string CanonicalizeInternalMetadataName(std::string_view filename);
bool ParseCloudBlobPath(const std::string& cloudPath,
    uint32_t& accountId, uint32_t& appId, std::string& filename);
std::shared_ptr<std::mutex> AcquireAppSyncMutex(uint32_t accountId, uint32_t appId);

} // namespace CloudStorage
