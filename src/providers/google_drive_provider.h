#pragma once
#include "cloud_provider_base.h"
#include <unordered_map>
#include <chrono>
#include <optional>

// Google Drive provider.
// Inherits shared OAuth2/WinHTTP infrastructure from CloudProviderBase.
//
// Paths are flat: "{accountId}/{appId}/blobs/{filename}", etc.
// Mapped to Drive folder hierarchy: CloudRedirect/{accountId}/{appId}/...

class GoogleDriveProvider : public CloudProviderBase {
public:
    const char* Name() const override { return "Google Drive"; }

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
    const char* LogTag() const override { return "[GDrive]"; }
    const char* ProviderTag() const override { return "[GDriveProvider]"; }
    const char* ApiHost() const override { return "www.googleapis.com"; }
    const char* TokenEndpointHost() const override { return "oauth2.googleapis.com"; }
    const char* TokenEndpointPath() const override { return "/token"; }
    const char* AuthFailureName() const override { return "Google Drive"; }
    std::string BuildRefreshBody(const std::string& refreshToken) const override;
    bool IsRateLimited(int status, const std::string& body) const override;

private:
    // Google Drive folder/file ID cache
    std::unordered_map<std::string, std::string> m_folders;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_missingFolders; // negative cache with TTL
    std::unordered_map<std::string, std::string> m_files;
    std::recursive_mutex m_folderMtx;
    std::recursive_mutex m_folderCreateMtx;  // serializes find-or-create to prevent duplicate folders

    enum class LookupStatus { Missing, Exists, Error };
    enum class UploadStatus { Success, MissingTarget, Error };

    // Folder management (Drive is ID-based, not path-based)
    std::string EscapeQuery(const std::string& s) const;
    std::string BuildChildCacheKey(const std::string& parentId, const std::string& name) const;
    void CacheFolderChild(const std::string& parentId, const std::string& name,
                          const std::string& id);
    void CacheFileChild(const std::string& parentId, const std::string& name,
                        const std::string& id);
    void InvalidateFolderChild(const std::string& parentId, const std::string& name);
    void InvalidateFileChild(const std::string& parentId, const std::string& name);
    void InvalidateFilesInFolder(const std::string& folderId);
    std::string GetCachedFileId(const std::string& name, const std::string& folderId);
    void InvalidateFolderById(const std::string& folderId);
    LookupStatus FindDriveFolderStatus(const std::string& name, const std::string& parentId,
                                       std::string* outId = nullptr);
    LookupStatus LookupRootFolder(std::string* outId = nullptr);
    LookupStatus LookupAccountFolder(uint32_t accountId, std::string* outId = nullptr);
    LookupStatus LookupAppFolder(uint32_t accountId, uint32_t appId,
                                 std::string* outId = nullptr);
    std::string FindDriveFolder(const std::string& name, const std::string& parentId);
    std::string CreateDriveFolder(const std::string& name, const std::string& parentId);
    std::string GetRootFolder();
    std::string GetAccountFolder(uint32_t accountId);
    std::string GetAppFolder(uint32_t accountId, uint32_t appId);
    LookupStatus ResolveSubfolders(const std::string& parentId, const std::string& relDir,
                                   std::string* outId, bool create);

    // File operations
    struct DriveFileInfo {
        std::string id;
        std::string name;
        int64_t modifiedTime = 0;
        int64_t size = 0;
        bool isFolder = false;
    };

    struct RemoteFile {
        std::string id;
        std::string relativePath;
        int64_t modifiedTime = 0;
        int64_t size = 0;
    };

    struct DuplicateFileIdsResult {
        std::vector<std::string> ids;
        bool ok = false;
    };

    std::vector<DriveFileInfo> ListFolder(const std::string& folderId, bool* ok = nullptr);
    bool ListRecursive(const std::string& folderId, const std::string& prefix,
                       std::vector<RemoteFile>& out,
                       bool* outComplete = nullptr, int depth = 0);
    std::optional<std::vector<uint8_t>> DownloadFileById(const std::string& fileId);
    LookupStatus FindFileInFolderStatus(const std::string& name, const std::string& folderId,
                                        std::string* outId = nullptr);
    DuplicateFileIdsResult FindDuplicateFileIdsInFolder(const std::string& name,
                                                        const std::string& folderId);
    std::string FindFileInFolder(const std::string& name, const std::string& folderId);
    UploadStatus UploadOrUpdate(const std::string& name, const std::string& folderId,
                                const uint8_t* data, size_t len, int64_t timestamp,
                                const std::string& existingId = {});
    bool DeleteById(const std::string& fileId);
    LookupStatus ResolvePath(uint32_t accountId, uint32_t appId, const std::string& filename,
                             std::string& outParentId, std::string& outLeafName,
                             bool create);
    bool DoDriveDelete(uint32_t accountId, uint32_t appId, const std::string& filename);
};
