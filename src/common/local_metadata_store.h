#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace LocalMetadataStore {

struct TombstoneInfo {
    uint64_t cn = 0;
    uint64_t createTimeUnix = 0;
};

void Init(const std::string& baseRoot);
void InitApp(uint32_t accountId, uint32_t appId);

// Root tokens
bool SaveRootTokens(uint32_t accountId, uint32_t appId,
    const std::unordered_set<std::string>& tokens);
std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId);

// File tokens
bool SaveFileTokens(uint32_t accountId, uint32_t appId,
    const std::unordered_map<std::string, std::string>& fileTokens,
    const std::unordered_set<std::string>& validRootTokens = {});
std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId,
    const std::unordered_set<std::string>& validRootTokens = {});

// Tombstones
void MarkDeleted(uint32_t accountId, uint32_t appId, const std::string& filename, uint64_t cnAtDelete);
void ClearDeleted(uint32_t accountId, uint32_t appId, const std::string& filename);
bool IsDeleted(uint32_t accountId, uint32_t appId, const std::string& filename);
std::unordered_map<std::string, TombstoneInfo> LoadDeleted(uint32_t accountId, uint32_t appId);
void EvictTombstonesNotIn(uint32_t accountId, uint32_t appId,
    const std::unordered_set<std::string>& keepSet, uint64_t listingCapturedAtUnix);
bool MigrateDeletedKeys(uint32_t accountId, uint32_t appId,
    const std::function<std::string(const std::string&)>& keyRewrite,
    std::unordered_map<std::string, TombstoneInfo>& outFinalState,
    size_t& outMigratedCount);

} // namespace LocalMetadataStore
