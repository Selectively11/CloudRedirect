#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <memory>

// Cloud storage provider interface.
// Paths are relative with forward slashes: "{accountId}/{appId}/blobs/{filename}"

class ICloudProvider {
public:
    enum class ExistsStatus { Missing, Exists, Error };

    virtual ~ICloudProvider() = default;

    virtual const char* Name() const = 0;

    virtual bool Init(const std::string& configPath) = 0;

    virtual void Shutdown() = 0;

    virtual bool IsAuthenticated() const = 0;

    virtual bool Upload(const std::string& path,
                        const uint8_t* data, size_t len) = 0;

    struct UploadItem {
        std::string path;
        std::vector<uint8_t> data;
    };

    // Contract: implementations MUST CAS-skip existing blobs (per-file dedup).
    // Skip only on definite Exists; on Missing/Error, upload (CAS is idempotent).
    virtual bool UploadBatch(const std::vector<UploadItem>& items) {
        for (const auto& item : items) {
            if (CheckExists(item.path) == ExistsStatus::Exists) continue;
            if (!Upload(item.path, item.data.data(), item.data.size()))
                return false;
        }
        return true;
    }

    virtual bool Download(const std::string& path,
                          std::vector<uint8_t>& outData) = 0;

    virtual bool Remove(const std::string& path) = 0;

    virtual ExistsStatus CheckExists(const std::string& path) = 0;

    struct FileInfo {
        std::string path;         // relative path (same format as other calls)
        uint64_t    size = 0;     // file size in bytes
        uint64_t    modifiedTime = 0; // Unix timestamp (seconds)
        std::string versionId;        // opaque provider version id ("" if none)
        bool        isLatest = true;  // this is the current version of the key
        bool        isDeleteMarker = false; // a versioning tombstone, not data
    };

    virtual std::vector<FileInfo> List(const std::string& prefix) = 0;

    virtual std::vector<std::string> ListSubfolders(const std::string& prefix) {
        auto files = List(prefix);
        std::vector<std::string> folders;
        for (const auto& f : files) {
            if (f.path.size() <= prefix.size()) continue;
            std::string rest = f.path.substr(prefix.size());
            size_t slash = rest.find('/');
            if (slash == std::string::npos) continue;
            std::string folder = rest.substr(0, slash);
            if (std::find(folders.begin(), folders.end(), folder) == folders.end())
                folders.push_back(folder);
        }
        return folders;
    }

    virtual bool ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles,
                             bool* outComplete = nullptr) {
        if (outComplete) *outComplete = false;
        outFiles = List(prefix);
        if (outComplete) *outComplete = true;
        return true;
    }

    // A blob found by a global filename search: its full relative path
    // ("{accountId}/{appId}/{filename}") and content.
    struct SearchHit {
        std::string path;
        std::vector<uint8_t> content;
    };

    // Search account for exact filename matches. Default: unsupported (callers fall back to listing).
    virtual std::vector<SearchHit> SearchByName(const std::string& /*filename*/,
                                                bool* outSupported = nullptr) {
        if (outSupported) *outSupported = false;
        return {};
    }

    virtual bool SupportsVersioning() const { return false; }

    virtual bool ListVersions(const std::string& /*path*/,
                              std::vector<FileInfo>& outVersions) {
        outVersions.clear();
        return false;
    }

    virtual bool DownloadVersion(const std::string& path,
                                 const std::string& versionId,
                                 std::vector<uint8_t>& outData) {
        if (versionId.empty()) return Download(path, outData);
        return false;
    }

    // Permanently remove one specific version (by id) of a key, leaving other
    // versions intact. Default: unsupported.
    virtual bool RemoveVersion(const std::string& /*path*/,
                               const std::string& /*versionId*/) {
        return false;
    }
};

std::unique_ptr<ICloudProvider> CreateCloudProvider(const std::string& name);

std::string ResolveProviderTokenPath(const std::string& configDir,
                                     const std::string& configJson,
                                     const std::string& provider);
