#include "token_store.h"
#include "cloud_storage.h"     // WorkItem helpers and cloud metadata fallback helpers
#include "cloud_metadata_paths.h"
#include "local_storage.h"
#include "log.h"

#include <sstream>

using CloudIntercept::kRootTokenFilename;
using CloudIntercept::kLegacyRootTokenFilename;
using CloudIntercept::kFileTokensFilename;
using CloudIntercept::kLegacyFileTokensFilename;

namespace CloudStorage {
namespace {

static ICloudProvider* g_tokenProvider = nullptr;
static std::string     g_tokenLocalRoot;
static std::mutex      g_tokenPersistMutex;

} // namespace

void TokenStore_Init(const std::string& localRoot, ICloudProvider* provider) {
    g_tokenLocalRoot = localRoot;
    g_tokenProvider  = provider;
    LOG("[TokenStore] Initialized at %s", localRoot.c_str());
}

bool SaveRootTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_set<std::string>& tokens) {
    std::lock_guard<std::mutex> persistLock(g_tokenPersistMutex);
    if (LocalMetadataStore::LoadRootTokens(accountId, appId) == tokens) {
        LOG("[TokenStore] SaveRootTokens app %u: unchanged, skipping persist/upload", appId);
        return true;
    }
    bool localOk = LocalMetadataStore::SaveRootTokens(accountId, appId, tokens);

    if (localOk && g_tokenProvider) {
        std::string content;
        for (auto& t : tokens) content += t + "\n";
        CloudWorkQueue::WorkItem wi;
        wi.type = CloudWorkQueue::WorkItem::Upload;
        wi.cloudPath = CloudMetadataPath(accountId, appId, kRootTokenFilename);
        wi.data.assign(content.begin(), content.end());
        CloudWorkQueue::EnqueueWork(std::move(wi));
    }
    return localOk;
}

std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId) {
    auto localTokens = LocalMetadataStore::LoadRootTokens(accountId, appId);
    if (!localTokens.empty() || !g_tokenProvider || !g_tokenProvider->IsAuthenticated())
        return localTokens;

    InflightSyncScope guard;
    if (!guard) return localTokens;

    std::vector<uint8_t> cloudData;
    bool usedLegacyRootTokens = false;
    if (!DownloadCloudMetadataWithLegacyFallback(accountId, appId,
            kRootTokenFilename, kLegacyRootTokenFilename,
            cloudData, &usedLegacyRootTokens))
        return localTokens;

    std::unordered_set<std::string> cloudTokens;
    std::istringstream iss(std::string(cloudData.begin(), cloudData.end()));
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (!line.empty()) cloudTokens.insert(line);
    }

    if (cloudTokens.empty()) return localTokens;

    if (!LocalMetadataStore::SaveRootTokens(accountId, appId, cloudTokens)) {
        LOG("[TokenStore] LoadRootTokens app %u: failed to persist cloud token fallback locally", appId);
        return localTokens;
    }

    if (usedLegacyRootTokens) {
        std::string cleaned;
        for (const auto& token : cloudTokens) cleaned += token + "\n";
        if (UploadCloudMetadataText(accountId, appId, kRootTokenFilename, cleaned))
            RemoveCloudMetadataIfPresent(accountId, appId, kLegacyRootTokenFilename);
        else
            LOG("[TokenStore] LoadRootTokens app %u: failed to migrate legacy cloud root tokens", appId);
    } else {
        RemoveCloudMetadataIfPresent(accountId, appId, kLegacyRootTokenFilename);
    }

    return cloudTokens;
}

bool SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens) {
    std::lock_guard<std::mutex> persistLock(g_tokenPersistMutex);

    auto validRootTokens = LocalMetadataStore::LoadRootTokens(accountId, appId);

    // Filter: only entries whose root token is valid, or internal metadata files.
    std::unordered_map<std::string, std::string> filteredTokens;
    size_t rejectedCount = 0;
    for (const auto& [cleanName, token] : fileTokens) {
        if (validRootTokens.empty() || validRootTokens.count(token) ||
            CloudIntercept::IsInternalMetadataFile(cleanName)) {
            filteredTokens[cleanName] = token;
        } else {
            LOG("[TokenStore] SaveFileTokens app %u: rejecting '%s' -> '%s' (root token not in valid set)",
                appId, cleanName.c_str(), token.c_str());
            ++rejectedCount;
        }
    }
    if (rejectedCount > 0)
        LOG("[TokenStore] SaveFileTokens app %u: rejected %zu entries with invalid root tokens",
            appId, rejectedCount);

    if (LocalMetadataStore::LoadFileTokens(accountId, appId, validRootTokens) == filteredTokens) {
        LOG("[TokenStore] SaveFileTokens app %u: unchanged, skipping persist/upload", appId);
        return true;
    }

    bool localOk = LocalMetadataStore::SaveFileTokens(accountId, appId, filteredTokens, validRootTokens);

    if (localOk && g_tokenProvider) {
        std::string content;
        for (auto& [cleanName, token] : filteredTokens)
            content += cleanName + "\t" + token + "\n";
        CloudWorkQueue::WorkItem wi;
        wi.type = CloudWorkQueue::WorkItem::Upload;
        wi.cloudPath = CloudMetadataPath(accountId, appId, kFileTokensFilename);
        wi.data.assign(content.begin(), content.end());
        CloudWorkQueue::EnqueueWork(std::move(wi));
    }
    return localOk;
}

std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId) {
    auto localFileTokens = LocalMetadataStore::LoadFileTokens(accountId, appId);
    if (!localFileTokens.empty() || !g_tokenProvider || !g_tokenProvider->IsAuthenticated())
        return localFileTokens;

    InflightSyncScope guard;
    if (!guard) return localFileTokens;

    auto validRootTokens = LoadRootTokens(accountId, appId);

    std::vector<uint8_t> cloudData;
    bool usedLegacyFileTokens = false;
    if (!DownloadCloudMetadataWithLegacyFallback(accountId, appId,
            kFileTokensFilename, kLegacyFileTokensFilename,
            cloudData, &usedLegacyFileTokens))
        return localFileTokens;

    std::unordered_map<std::string, std::string> cloudFileTokens;
    std::istringstream iss(std::string(cloudData.begin(), cloudData.end()));
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty()) continue;
        auto tab = line.find('\t');
        if (tab == std::string::npos) continue;
        std::string cleanName = line.substr(0, tab);
        std::string token = line.substr(tab + 1);
        if (cleanName.empty()) continue;
        if (!validRootTokens.empty() && !validRootTokens.count(token)) continue;
        cloudFileTokens[cleanName] = token;
    }

    if (cloudFileTokens.empty()) return localFileTokens;

    if (!LocalMetadataStore::SaveFileTokens(accountId, appId, cloudFileTokens)) {
        LOG("[TokenStore] LoadFileTokens app %u: failed to persist cloud token fallback locally", appId);
        return localFileTokens;
    }

    if (usedLegacyFileTokens) {
        std::string cleaned;
        for (const auto& [cleanName, token] : cloudFileTokens)
            cleaned += cleanName + "\t" + token + "\n";
        if (UploadCloudMetadataText(accountId, appId, kFileTokensFilename, cleaned))
            RemoveCloudMetadataIfPresent(accountId, appId, kLegacyFileTokensFilename);
        else
            LOG("[TokenStore] LoadFileTokens app %u: failed to migrate legacy cloud file tokens", appId);
    } else {
        RemoveCloudMetadataIfPresent(accountId, appId, kLegacyFileTokensFilename);
    }

    return cloudFileTokens;
}

} // namespace CloudStorage
