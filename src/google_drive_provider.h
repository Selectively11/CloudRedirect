#pragma once
#include "cloud_provider_base.h"
#include <unordered_map>
#include <optional>

// GoogleDriveProvider -- ICloudProvider implementation using Google Drive.
// Inherits shared OAuth2/WinHTTP infrastructure from CloudProviderBase.
//
// Paths are flat: "{accountId}/{appId}/blobs/{filename}", etc.
// Mapped to Drive folder hierarchy: CloudRedirect/{accountId}/{appId}/...

class GoogleDriveProvider : public CloudProviderBase {
public:
    const char* Name() const override { return "Google Drive"; }

    bool Upload(const std::string& path, const uint8_t* data, size_t len) override;
    bool Download(const std::string& path, std::vector<uint8_t>& outData) override;
    bool Remove(const std::string& path) override;
    bool Exists(const std::string& path) override;
    ExistsStatus CheckExists(const std::string& path) override;
    std::vector<FileInfo> List(const std::string& prefix) override;
    bool ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles,
                     bool* outComplete = nullptr) override;

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
    // Google Drive folder ID cache
    std::unordered_map<std::string, std::string> m_folders;
    std::recursive_mutex m_folderMtx;
    std::recursive_mutex m_folderCreateMtx;  // serializes find-or-create to prevent duplicate folders

    enum class LookupStatus { Missing, Exists, Error };

    // Folder management (Drive is ID-based, not path-based)
    std::string EscapeQuery(const std::string& s) const;
    void InvalidateFolderById(const std::string& folderId);
    LookupStatus FindDriveFolderStatus(const std::string& name, const std::string& parentId,
                                       std::string* outId = nullptr);
    std::string FindDriveFolder(const std::string& name, const std::string& parentId);
    std::string CreateDriveFolder(const std::string& name, const std::string& parentId);
    std::string GetRootFolder();
    std::string GetAccountFolder(uint32_t accountId);
    std::string GetAppFolder(uint32_t accountId, uint32_t appId);
    bool HasAppFolder(uint32_t accountId, uint32_t appId);
    std::string EnsureSubfolders(const std::string& parentId, const std::string& relDir,
                                 bool create = true);

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

    std::vector<DriveFileInfo> ListFolder(const std::string& folderId, bool* ok = nullptr);
    bool ListRecursive(const std::string& folderId, const std::string& prefix,
                       std::vector<RemoteFile>& out,
                       bool* outComplete = nullptr, int depth = 0);
    std::optional<std::vector<uint8_t>> DownloadFileById(const std::string& fileId);
    LookupStatus FindFileInFolderStatus(const std::string& name, const std::string& folderId,
                                        std::string* outId = nullptr);
    std::string FindFileInFolder(const std::string& name, const std::string& folderId);
    bool UploadOrUpdate(const std::string& name, const std::string& folderId,
                        const uint8_t* data, size_t len, int64_t timestamp,
                        const std::string& existingId = {});
    bool DeleteById(const std::string& fileId);
    bool ResolvePath(uint32_t accountId, uint32_t appId, const std::string& filename,
                     std::string& outParentId, std::string& outLeafName);
    bool DoDriveDelete(uint32_t accountId, uint32_t appId, const std::string& filename);
};
