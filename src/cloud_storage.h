#pragma once
#include "cloud_provider.h"
#include "local_storage.h"
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <unordered_set>

// CloudStorage — central layer between cloud_intercept and ICloudProvider.
// Manages local blob cache, metadata sync, change number coordination,
// and a background worker for async cloud uploads/deletes.
// All public methods are thread-safe.

namespace CloudStorage {

// Initialize the storage system.
//   localRoot: path to local cache directory (e.g., "C:\Games\Steam\cloud_redirect\")
//   provider:  cloud provider instance (takes ownership), or nullptr for local-only mode
void Init(const std::string& localRoot, std::unique_ptr<ICloudProvider> provider);

// Shut down: drain background queue, shut down provider.
void Shutdown();

// Human-readable name of the active provider ("Google Drive", "Local Disk", etc.)
const char* ProviderName();

// True if a cloud provider is active and authenticated.
bool IsCloudActive();

// Store a blob. Writes to local cache immediately, enqueues cloud upload.
// Returns true if the local write succeeded.
bool StoreBlob(uint32_t accountId, uint32_t appId,
               const std::string& filename,
               const uint8_t* data, size_t len);

// Retrieve a blob. Checks local cache first, pulls from cloud on cache miss.
// Returns empty vector if not found anywhere.
std::vector<uint8_t> RetrieveBlob(uint32_t accountId, uint32_t appId,
                                  const std::string& filename);

// Delete a blob from local cache and cloud.
bool DeleteBlob(uint32_t accountId, uint32_t appId,
                const std::string& filename);

// Check if a blob exists (local cache or cloud).
bool BlobExists(uint32_t accountId, uint32_t appId,
                const std::string& filename);

// Get the authoritative change number (max of local and cloud).
uint64_t GetChangeNumber(uint32_t accountId, uint32_t appId);

// Root token persistence — same as before but also syncs to cloud.
void SaveRootTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_set<std::string>& tokens);
std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId);

// Per-file token tracking: which root token each file was uploaded under.
// Synced to cloud alongside root_token.dat and cn.dat.
void SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens);
std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId);

// Pull metadata + CN from cloud for a specific app.
// Called on startup or when we suspect another machine uploaded.
// Returns true if cloud had newer data.
bool SyncFromCloud(uint32_t accountId, uint32_t appId);

// Pull metadata for ALL known apps from cloud.
// Called once during Init after provider is authenticated.
void SyncAllFromCloud(uint32_t accountId);

// Block until all pending background operations complete.
void DrainQueue();

// Block until pending background operations for one app complete.
void DrainQueueForApp(uint32_t accountId, uint32_t appId);

// Push the change number to the cloud provider (uploads cn.dat).
void PushCNToCloud(uint32_t accountId, uint32_t appId, uint64_t cn);

// Show an immediate error dialog for critical auth failures (e.g. token refresh broken).
// Called by provider implementations (GDrive, OneDrive) when refresh fails.
void NotifyAuthFailure(const std::string& providerName);

} // namespace CloudStorage
