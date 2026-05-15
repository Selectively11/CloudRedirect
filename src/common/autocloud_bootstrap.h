#pragma once
// AutoCloud bootstrap - imports pre-existing save files into cloud storage
// on first launch per app.

#include <string>
#include <cstdint>
#include <unordered_map>

namespace AutoCloudBootstrap {

void Bootstrap(uint32_t accountId, uint32_t appId, bool wait = false);

void WaitFor(uint32_t accountId, uint32_t appId);

bool IsActive(uint32_t accountId, uint32_t appId);

std::string CanonicalizeToken(uint32_t accountId, uint32_t appId,
                              const std::string& cleanName,
                              const std::string& fallbackToken);

uint64_t GetCacheGeneration(uint32_t accountId, uint32_t appId);

std::unordered_map<std::string, std::string> GetCachedTokens(uint32_t accountId, uint32_t appId);

void InvalidateCache(uint32_t accountId, uint32_t appId);

void ResetAttempted(uint32_t accountId, uint32_t appId);

int RestoreBlobsToGameFolder(uint32_t accountId, uint32_t appId,
                              const std::string& steamPath);

void Shutdown();

} // namespace AutoCloudBootstrap
