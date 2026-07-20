#pragma once
// Base class for OAuth2 cloud providers (Google Drive, OneDrive).
// Handles token refresh, API throttling, and authenticated redirects.

#include "cloud_provider.h"
#include "http_util.h"

#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include <limits>
#include <string>
#include <vector>
#include <cstdint>

// Global counter of HTTP 429/403 rate-limit hits, incremented in ApiRequest.
// Read/reset per batch in UploadBatch for throughput telemetry.
extern std::atomic<uint64_t> g_rateLimitHits;

// Max bytes in flight in UploadBatch (config.json "upload_inflight_mb", default
// 24 MB). Lower keeps each large blob above the request receive timeout.
extern std::atomic<uint64_t> g_uploadInFlightCapBytes;

struct TransportOptions {
    bool allowInsecureHttp = false;   // permit plaintext http:// (LAN MinIO/Garage)
    bool allowInsecureTls  = false;   // skip TLS cert verification (self-signed)
    std::string caCertPath;           // custom CA bundle for internal CAs
};

class IHttpTransport {
public:
    virtual ~IHttpTransport() = default;

    // Initialize the transport (e.g., open WinHTTP session, call curl_global_init).
    // Called once during CloudProviderBase::Init.
    virtual bool Init() = 0;

    // Tear down the transport (e.g., close WinHTTP session).
    virtual void Shutdown() = 0;

    // Returns true if the transport is ready to make requests.
    virtual bool IsReady() const = 0;

    // Apply insecure-mode options. Default no-op keeps HTTPS-only, verified TLS.
    virtual void SetOptions(const TransportOptions&) {}

    // Execute an HTTPS request to host+path. Returns status code + body.
    // method: "GET", "POST", "PUT", "DELETE", "PATCH"
    virtual HttpUtil::HttpResp Request(const char* method, const char* host,
                                       const std::string& path,
                                       const std::string& body,
                                       const std::vector<std::string>& headers) = 0;

    // Execute an HTTPS request to an arbitrary full URL.
    // Used for CDN redirect targets and upload session URLs.
    virtual HttpUtil::HttpResp RequestUrl(const char* method, const std::string& fullUrl,
                                          const std::string& body,
                                          const std::vector<std::string>& headers) = 0;

    // Authenticated GET that handles 302 redirects by stripping the auth header
    // before following (required by OneDrive /content downloads where the CDN
    // rejects Bearer tokens). On 200: returns body directly. On 302: follows
    // Location without auth header.
    virtual HttpUtil::HttpResp AuthenticatedGetWithRedirect(const std::string& host,
                                                            const std::string& path,
                                                            const std::string& authHeader) = 0;
};

class ITokenStore {
public:
    virtual ~ITokenStore() = default;

    // Read token JSON from the given path. Returns empty string on failure.
    // Implementation handles decryption/keyring lookup internally.
    virtual std::string Read(const std::string& path) = 0;

    // Write token JSON to the given path. Returns true on success.
    // Implementation handles encryption/keyring storage internally.
    virtual bool Write(const std::string& path, const std::string& json) = 0;

    // Returns true if the token store uses encryption (DPAPI, keyring).
    // If false, tokens are stored as plaintext files (0600 perms on Linux).
    virtual bool IsEncryptionAvailable() const = 0;
};

std::unique_ptr<IHttpTransport> CreateHttpTransport(const char* logTag);
std::unique_ptr<ITokenStore> CreateTokenStore();

class CloudProviderBase : public ICloudProvider {
public:
    virtual ~CloudProviderBase() = default;

    // Callback invoked when token refresh fails permanently (refresh-token
    // rejected). Wired by the factory so this layer does not reverse-depend
    // on cloud_storage.
    using AuthFailureCallback = std::function<void(const std::string&)>;
    void SetAuthFailureCallback(AuthFailureCallback cb) {
        m_authFailureCb = std::move(cb);
    }

    // ICloudProvider shared implementations
    bool Init(const std::string& configPath) override;
    void Shutdown() override;
    bool IsAuthenticated() const override;

    // Utility

    // Sentinel returned in appId for account-only prefix paths like "{accountId}/".
    static constexpr uint32_t kNoAppId = (std::numeric_limits<uint32_t>::max)();

    // Parse "{accountId}/{appId}/rest/of/path" into components.
    static bool ParsePath(const std::string& path,
                          uint32_t& accountId, uint32_t& appId,
                          std::string& relFilename);

protected:
    // Subclass must implement these

    virtual const char* LogTag() const = 0;
    virtual const char* ProviderTag() const = 0;
    virtual const char* TokenEndpointHost() const = 0;
    virtual const char* TokenEndpointPath() const = 0;
    virtual std::string BuildRefreshBody(const std::string& refreshToken) const = 0;
    virtual const char* AuthFailureName() const = 0;
    virtual const char* ApiHost() const = 0;
    virtual bool IsRateLimited(int status, const std::string& body) const = 0;

    // Shared state

    struct Tokens {
        std::string access;
        std::string refresh;
        int64_t expiresAt = 0;
    };

    Tokens m_tok;
    std::string m_tokenPath;
    mutable std::mutex m_mtx;
    std::condition_variable m_refreshCv;
    bool m_refreshing = false;
    int64_t m_lastRefreshFailTime = 0;
    static constexpr int64_t REFRESH_BACKOFF_SECS = 30;
    std::atomic<uint64_t> m_lastApiCallTick{0};
    bool m_initialized = false;
    AuthFailureCallback m_authFailureCb;

    std::unique_ptr<IHttpTransport> m_transport;
    std::unique_ptr<ITokenStore> m_tokenStore;

    // Shared methods

    void ThrottleApiCall();
    bool LoadTokens();
    bool SaveTokens();
    bool TokenValid() const;
    std::string GetAccessToken();

    // Authenticated API GET with retry on rate limit (3 attempts + final).
    HttpUtil::HttpResp ApiGet(const std::string& path);
    // Authenticated API request with retry on rate limit.
    HttpUtil::HttpResp ApiRequest(const char* method, const std::string& path,
                                  const std::string& body = {},
                                  const std::string& contentType = "application/json");

    // Convenience wrappers that delegate to transport
    HttpUtil::HttpResp Request(const char* method, const char* host,
                               const std::string& path,
                               const std::string& body = {},
                               const std::vector<std::string>& hdrs = {});

    HttpUtil::HttpResp RequestUrl(const char* method, const std::string& fullUrl,
                                  const std::string& body = {},
                                  const std::vector<std::string>& hdrs = {});

    HttpUtil::HttpResp AuthenticatedGetWithRedirect(const std::string& path);

private:
    bool InitSession(const std::string& tokenPath);
    bool RefreshAccessToken();
};
