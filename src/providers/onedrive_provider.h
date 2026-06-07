#pragma once
#include "cloud_provider_base.h"
#include <optional>
#include <unordered_map>

// OneDrive provider.
// Inherits shared OAuth2/WinHTTP infrastructure from CloudProviderBase.
//
// Paths are flat: "{accountId}/{appId}/blobs/{filename}", etc.
// Mapped to OneDrive path: CloudRedirect/{accountId}/{appId}/...

class OneDriveProvider : public CloudProviderBase {
public:
    const char* Name() const override { return "OneDrive"; }

    bool Upload(const std::string& path, const uint8_t* data, size_t len) override;
    bool UploadBatch(const std::vector<UploadItem>& items) override;
    bool Download(const std::string& path, std::vector<uint8_t>& outData) override;
    bool Remove(const std::string& path) override;
    ExistsStatus CheckExists(const std::string& path) override;
    std::vector<FileInfo> List(const std::string& prefix) override;
    std::vector<std::string> ListSubfolders(const std::string& prefix) override;
    bool ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles,
                     bool* outComplete = nullptr) override;
    std::vector<SearchHit> SearchByName(const std::string& filename,
                                        bool* outSupported = nullptr) override;

protected:
    // CloudProviderBase hooks
    const char* LogTag() const override { return "[OneDrive]"; }
    const char* ProviderTag() const override { return "[OneDriveProvider]"; }
    const char* ApiHost() const override { return "graph.microsoft.com"; }
    const char* TokenEndpointHost() const override { return "login.microsoftonline.com"; }
    const char* TokenEndpointPath() const override { return "/consumers/oauth2/v2.0/token"; }
    const char* AuthFailureName() const override { return "OneDrive"; }
    std::string BuildRefreshBody(const std::string& refreshToken) const override;
    bool IsRateLimited(int status, const std::string& body) const override;

private:
    // OneDrive path helpers
    static std::string EncodePath(const std::string& path);
    static std::string BuildItemPath(uint32_t accountId, uint32_t appId,
                                     const std::string& filename);
    static std::string BuildFolderPath(uint32_t accountId, uint32_t appId);
    static std::string BuildAccountFolderPath(uint32_t accountId);

    // File operations
    struct RemoteFile {
        std::string id;
        std::string relativePath;
        int64_t modifiedTime = 0;
        int64_t size = 0;
    };

    static constexpr int MAX_RECURSION_DEPTH = 32;

    bool ListChildrenById(const std::string& itemId, const std::string& prefix,
                           std::vector<RemoteFile>& out,
                           bool* outComplete = nullptr, int depth = 0);
    std::vector<RemoteFile> ListAppFiles(uint32_t accountId, uint32_t appId,
                                         bool* ok = nullptr, bool* outComplete = nullptr);

    std::optional<std::vector<uint8_t>> DownloadFileById(const std::string& itemId);

    bool SimpleUpload(uint32_t accountId, uint32_t appId, const std::string& filename,
                      const uint8_t* data, size_t len, int64_t timestamp);
    bool SessionUpload(uint32_t accountId, uint32_t appId, const std::string& filename,
                       const uint8_t* data, size_t len, int64_t timestamp);

    bool DoOneDriveDelete(uint32_t accountId, uint32_t appId, const std::string& filename);

    // Item path → OneDrive item ID cache. Populated on first lookup, invalidated on delete.
    std::unordered_map<std::string, std::string> m_itemIdCache;
    mutable std::mutex m_itemIdCacheMtx;

    // Returns cached item ID, or fetches and caches. Empty on failure.
    std::string GetOrFetchItemId(const std::string& itemPath);

    // Remove itemPath from the item ID cache (call after successful delete).
    void InvalidateItemId(const std::string& itemPath);
};
