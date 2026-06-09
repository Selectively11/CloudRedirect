#pragma once
// Linux cloud_intercept.h - matches Windows API surface for common/ code

#include "cloud_metadata_paths.h"
#include "common.h"

namespace CloudIntercept {

// Initialize the Linux intercept layer (reads SLSsteam config, loginusers.vdf)
void InitLinux();

// Check if an appId is a managed namespace app (from SLSsteam AdditionalApps)
bool IsNamespaceApp(uint32_t appId);
bool HasNamespaceApps();

// Snapshot of all managed namespace app IDs.
std::vector<uint32_t> GetNamespaceApps();

// Dynamically register an app as a namespace app
void RegisterNamespaceApp(uint32_t appId);

// Get the Steam installation path (with trailing slash)
std::string GetSteamPath();

// Get the 32-bit account ID from the captured SteamID
uint32_t GetAccountId();

// Set the account ID (called by Linux hook layer when first RPC is intercepted)
void SetAccountId(uint32_t id);

// Set the Steam path (called by Linux hook layer during init)
void SetSteamPath(const std::string& path);

// Signal shutdown
void Shutdown();

} // namespace CloudIntercept
