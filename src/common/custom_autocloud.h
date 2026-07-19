#pragma once

#include "autocloud_util.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

namespace CustomAutoCloud {

// Loads a validated app entry from config.json. The file is checked on every call;
// parsed content is reused until its size or modification time changes.
std::vector<AutoCloudUtil::AutoCloudRuleNative> GetRules(uint32_t appId);

// GamesPlayed lifecycle for apps with custom rules. A real Steam cloud RPC wins
// for the entire session and suppresses managed capture.
void ObserveGamesPlayed(const std::unordered_set<uint32_t>& appIds);
void ObserveSteamRpc(uint32_t appId);

#ifdef CLOUDREDIRECT_TESTING
std::vector<AutoCloudUtil::AutoCloudRuleNative> ParseConfig(
    const std::string& json, uint32_t appId, std::string* error = nullptr);
#endif

} // namespace CustomAutoCloud
