#pragma once
// CloudProviderBase -- shared infrastructure for OAuth2 cloud providers.
// Provides token management (DPAPI-encrypted, refresh with condvar),
// WinHTTP session lifecycle, throttled API requests with retry on rate limit.
//
// Subclasses implement provider-specific operations (upload, download, etc.)
// and supply virtual hooks for OAuth endpoints, rate-limit detection, and log tags.

#include "cloud_provider.h"
#include "http_util.h"

#include <Windows.h>
#include <winhttp.h>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <string>
#include <vector>

class CloudProviderBase : public ICloudProvider {
public:
    virtual ~CloudProviderBase() = default;

    // Callback invoked when token refresh fails permanently (refresh-token
    // rejected). Wired by the factory so this layer does not reverse-depend
    // on cloud_storage. Pass the provider's display name, e.g. "Google Drive".
    using AuthFailureCallback = std::function<void(const std::string&)>;
    void SetAuthFailureCallback(AuthFailureCallback cb) {
        m_authFailureCb = std::move(cb);
    }

    // ICloudProvider shared implementations
    bool Init(const std::string& configPath) override;
    void Shutdown() override;
    bool IsAuthenticated() const override;

    // Utility

    // Parse "{accountId}/{appId}/rest/of/path" into components.
    // Minimum valid: "accountId/appId" (relFilename may be empty for prefix queries).
    static bool ParsePath(const std::string& path,
                          uint32_t& accountId, uint32_t& appId,
                          std::string& relFilename);

protected:
    // Subclass must implement these

    // Log tag for the namespace layer, e.g. "[GDrive]"
    virtual const char* LogTag() const = 0;
    // Log tag for the provider adapter layer, e.g. "[GDriveProvider]"
    virtual const char* ProviderTag() const = 0;

    // OAuth2 token endpoint host, e.g. "oauth2.googleapis.com"
    virtual const char* TokenEndpointHost() const = 0;
    // OAuth2 token endpoint path, e.g. "/token"
    virtual const char* TokenEndpointPath() const = 0;
    // Build the POST body for token refresh. refreshToken is the current refresh token.
    virtual std::string BuildRefreshBody(const std::string& refreshToken) const = 0;
    // Provider name for auth failure notification, e.g. "Google Drive"
    virtual const char* AuthFailureName() const = 0;

    // API host for authenticated requests, e.g. "www.googleapis.com"
    virtual const char* ApiHost() const = 0;
    // Returns true if the response indicates rate limiting worth retrying.
    virtual bool IsRateLimited(int status, const std::string& body) const = 0;

    // Extra WinHTTP flags for requests (e.g. WINHTTP_FLAG_ESCAPE_DISABLE).
    // Default: none (0).
    virtual DWORD ExtraRequestFlags() const { return 0; }

    // Shared state

    struct Tokens {
        std::string access;
        std::string refresh;
        int64_t expiresAt = 0;
    };

    Tokens m_tok;
    std::string m_tokenPath;
    HINTERNET m_session = nullptr;
    mutable std::mutex m_mtx;
    std::condition_variable m_refreshCv;
    bool m_refreshing = false;
    int64_t m_lastRefreshFailTime = 0;
    static constexpr int64_t REFRESH_BACKOFF_SECS = 30;
    std::atomic<ULONGLONG> m_lastApiCallTick{0};
    bool m_initialized = false;
    AuthFailureCallback m_authFailureCb;

    // Shared methods

    // Rate-limit API calls: ensures minimum 150ms between calls.
    void ThrottleApiCall();

    // Token persistence (DPAPI-encrypted JSON).
    bool LoadTokens();
    bool SaveTokens();
    bool TokenValid() const;
    std::string GetAccessToken();

    // Raw WinHTTP request. Applies ExtraRequestFlags().
    HttpUtil::HttpResp Request(const char* method, const char* host,
                               const std::string& path,
                               const std::string& body = {},
                               const std::vector<std::string>& hdrs = {});

    // Raw WinHTTP request to an arbitrary full URL (e.g. CDN redirect targets,
    // upload session URLs). Parses host/port/path from the URL. HTTPS-only.
    HttpUtil::HttpResp RequestUrl(const char* method, const std::string& fullUrl,
                                  const std::string& body = {},
                                  const std::vector<std::string>& hdrs = {});

    // Authenticated API GET with retry on rate limit (3 attempts + final).
    HttpUtil::HttpResp ApiGet(const std::string& path);
    // Authenticated API request with retry on rate limit.
    HttpUtil::HttpResp ApiRequest(const char* method, const std::string& path,
                                  const std::string& body = {},
                                  const std::string& contentType = "application/json");

private:
    bool InitSession(const std::string& tokenPath);
    bool RefreshAccessToken();
};
