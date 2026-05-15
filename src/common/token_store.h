#pragma once
#include "cloud_provider.h"
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace CloudStorage {

void TokenStore_Init(const std::string& localRoot, ICloudProvider* provider);

bool SaveRootTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_set<std::string>& tokens);
std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId);

bool SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens);
std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId);

} // namespace CloudStorage
