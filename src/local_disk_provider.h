#pragma once
#include "cloud_provider.h"

// LocalDiskProvider -- ICloudProvider that stores files on a separate local/network path.

class LocalDiskProvider : public ICloudProvider {
public:
    const char* Name() const override { return "Local Disk"; }
    bool Init(const std::string& rootPath) override;
    void Shutdown() override {}
    bool IsAuthenticated() const override { return true; }

    bool Upload(const std::string& path, const uint8_t* data, size_t len) override;
    bool Download(const std::string& path, std::vector<uint8_t>& outData) override;
    bool Remove(const std::string& path) override;
    bool Exists(const std::string& path) override;
    ExistsStatus CheckExists(const std::string& path) override;
    std::vector<FileInfo> List(const std::string& prefix) override;
    bool ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles,
                     bool* outComplete = nullptr) override;

private:
    std::string m_root; // absolute path, ends with separator
    std::string ToFullPath(const std::string& relPath) const;
};
