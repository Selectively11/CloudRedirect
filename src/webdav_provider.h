#pragma once
#include "cloud_provider.h"
#include "http_util.h"
#include <Windows.h>
#include <winhttp.h>
#include <mutex>
#include <string>
#include <vector>

class WebDavProvider : public ICloudProvider {
public:
    WebDavProvider() = default;
    virtual ~WebDavProvider();

    // ICloudProvider
    const char* Name() const override { return "WebDAV"; }
    bool Init(const std::string& configPath) override;
    void Shutdown() override;
    bool IsAuthenticated() const override { return m_authenticated; }

    bool Upload(const std::string& path, const uint8_t* data, size_t len) override;
    bool Download(const std::string& path, std::vector<uint8_t>& outData) override;
    bool Remove(const std::string& path) override;
    bool Exists(const std::string& path) override;
    ExistsStatus CheckExists(const std::string& path) override;
    std::vector<FileInfo> List(const std::string& prefix) override;
    bool ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles, bool* outComplete = nullptr) override;

private:
    struct WebDavConfig {
        std::string url;
        std::string user;
        std::string pass;
    };

    bool LoadConfig(const std::string& configPath);
    bool EnsureSubfolders(const std::string& relDir);
    
    HttpUtil::HttpResp Request(const char* method, const std::string& path,
                               const std::string& body = {},
                               const std::vector<std::string>& hdrs = {});

    std::string BuildAuthHeader() const;
    std::string GetFullUrl(const std::string& relPath) const;
    bool ParseUrl(const std::string& url, std::string& host, int& port, std::string& basePath, bool& isHttps);

    WebDavConfig m_cfg;
    HINTERNET m_session = nullptr;
    std::string m_host;
    int m_port = 443;
    std::string m_basePath;
    bool m_isHttps = true;
    bool m_authenticated = false;
    mutable std::mutex m_mtx;
};
