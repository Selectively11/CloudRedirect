// Shared OAuth2 provider logic.

#include "cloud_provider_base.h"
#include "json.h"
#include "log.h"

#include <charconv>
#include <ctime>
#include <thread>
#include <chrono>

using HttpUtil::HttpResp;

// ── ParsePath ──────────────────────────────────────────────────────────────

bool CloudProviderBase::ParsePath(const std::string& path,
                                   uint32_t& accountId, uint32_t& appId,
                                   std::string& relFilename) {
    size_t s1 = path.find('/');
    size_t accountEnd = (s1 != std::string::npos) ? s1 : path.size();
    auto r1 = std::from_chars(path.data(), path.data() + accountEnd, accountId);
    if (r1.ec != std::errc{}) return false;
    if (r1.ptr != path.data() + accountEnd) return false;

    if (s1 == std::string::npos || s1 + 1 >= path.size()) {
        appId = kNoAppId;
        relFilename.clear();
        return true;
    }

    size_t s2 = path.find('/', s1 + 1);
    size_t appEnd = (s2 != std::string::npos) ? s2 : path.size();
    auto r2 = std::from_chars(path.data() + s1 + 1, path.data() + appEnd, appId);
    if (r2.ec != std::errc{}) return false;
    if (r2.ptr != path.data() + appEnd) return false;
    if (appId == kNoAppId) return false;  // reserved sentinel must not collide

    relFilename = (s2 != std::string::npos && s2 + 1 < path.size())
                  ? path.substr(s2 + 1) : std::string();
    return true;
}

// ── ThrottleApiCall ────────────────────────────────────────────────────────

void CloudProviderBase::ThrottleApiCall() {
    using namespace std::chrono;
    uint64_t desired, last;
    do {
        last = m_lastApiCallTick.load(std::memory_order_acquire);
        uint64_t now = (uint64_t)duration_cast<milliseconds>(
            steady_clock::now().time_since_epoch()).count();
        desired = (last != 0 && now < last + 150) ? last + 150 : now;
    } while (!m_lastApiCallTick.compare_exchange_weak(last, desired,
                std::memory_order_acq_rel, std::memory_order_acquire));
    uint64_t now = (uint64_t)duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count();
    if (now < desired)
        std::this_thread::sleep_for(milliseconds(desired - now));
}

// ── Token lifecycle ────────────────────────────────────────────────────────

bool CloudProviderBase::LoadTokens() {
    if (!m_tokenStore) {
        LOG("%s LoadTokens: no token store configured", LogTag());
        return false;
    }
    auto content = m_tokenStore->Read(m_tokenPath);
    if (content.empty()) {
        // Token store already logged the specific error
        return false;
    }
    auto j = Json::Parse(content);
    m_tok.access = j["access_token"].str();
    m_tok.refresh = j["refresh_token"].str();
    m_tok.expiresAt = j["expires_at"].integer();
    if (m_tok.refresh.empty()) {
        LOG("%s LoadTokens: token file exists but refresh_token is empty/missing", LogTag());
        return false;
    }
    return true;
}

bool CloudProviderBase::SaveTokens() {
    if (!m_tokenStore) return false;
    auto obj = Json::Object();
    obj.objVal["access_token"] = Json::String(m_tok.access);
    obj.objVal["refresh_token"] = Json::String(m_tok.refresh);
    obj.objVal["expires_at"] = Json::Number((double)m_tok.expiresAt);

    std::string json = Json::Stringify(obj);
    if (!m_tokenStore->Write(m_tokenPath, json)) {
        LOG("%s WARNING: SaveTokens failed (write error)", LogTag());
        return false;
    }
    return true;
}

bool CloudProviderBase::TokenValid() const {
    return !m_tok.access.empty() && (int64_t)time(nullptr) < m_tok.expiresAt - 60;
}

std::string CloudProviderBase::ParseRefreshAccessToken(const std::string& body) const {
    return Json::Parse(body)["access_token"].str();
}
std::string CloudProviderBase::ParseRefreshRefreshToken(const std::string& body) const {
    return Json::Parse(body)["refresh_token"].str();
}
int64_t CloudProviderBase::ParseRefreshExpiresIn(const std::string& body) const {
    return Json::Parse(body)["expires_in"].integer();
}

bool CloudProviderBase::RefreshAccessToken() {
    std::string refreshTok;
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        refreshTok = m_tok.refresh;
    }

    std::string body = BuildRefreshBody(refreshTok);
    std::vector<std::string> hdrs;
    hdrs.push_back(std::string("Content-Type: ") + RefreshContentType());
    for (const auto& h : ExtraRefreshHeaders()) hdrs.push_back(h);
    auto r = Request("POST", TokenEndpointHost(), TokenEndpointPath(), body, hdrs);
    if (r.status != 200) {
        LOG("%s Token refresh failed: HTTP %d", LogTag(), r.status);
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_lastRefreshFailTime = (int64_t)time(nullptr);
        }
        if (m_authFailureCb) m_authFailureCb(AuthFailureName());
        return false;
    }
    std::string newAccess = ParseRefreshAccessToken(r.body);
    if (newAccess.empty()) {
        LOG("%s Token refresh response missing access token", LogTag());
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_lastRefreshFailTime = (int64_t)time(nullptr);
        }
        if (m_authFailureCb) m_authFailureCb(AuthFailureName());
        return false;
    }
    int64_t expiresIn = ParseRefreshExpiresIn(r.body);
    auto newRefresh = ParseRefreshRefreshToken(r.body);

    std::lock_guard<std::mutex> lock(m_mtx);
    m_tok.access = std::move(newAccess);
    m_tok.expiresAt = (int64_t)time(nullptr) + expiresIn;
    if (!newRefresh.empty()) m_tok.refresh = std::move(newRefresh);
    if (!SaveTokens()) {
        LOG("%s WARNING: rotated refresh token may be lost if process crashes!", LogTag());
    }
    m_lastRefreshFailTime = 0;
    LOG("%s Token refreshed, valid for %lld s", LogTag(), (long long)expiresIn);
    return true;
}

std::string CloudProviderBase::GetAccessToken() {
    std::unique_lock<std::mutex> lock(m_mtx);

    if (TokenValid()) return m_tok.access;
    if (m_tok.refresh.empty()) {
        LOG("%s GetAccessToken: no refresh token", LogTag());
        if (m_authFailureCb) m_authFailureCb(AuthFailureName());
        return {};
    }

    if (m_refreshing) {
        if (!m_refreshCv.wait_for(lock, std::chrono::seconds(30),
                                   [this] { return !m_refreshing; })) {
            LOG("%s GetAccessToken: timed out waiting for in-flight refresh", LogTag());
            return {};
        }
        if (TokenValid()) return m_tok.access;
        LOG("%s GetAccessToken: other thread refresh failed", LogTag());
        return {};
    }

    if (m_lastRefreshFailTime > 0 &&
        (int64_t)time(nullptr) - m_lastRefreshFailTime < REFRESH_BACKOFF_SECS) {
        LOG("%s GetAccessToken: in backoff period", LogTag());
        return {};
    }

    m_refreshing = true;
    lock.unlock();

    bool ok = RefreshAccessToken();

    lock.lock();
    m_refreshing = false;
    m_refreshCv.notify_all();

    if (!ok) return {};
    return m_tok.access;
}

// ── Transport delegation ───────────────────────────────────────────────────

HttpResp CloudProviderBase::Request(const char* method, const char* host,
                                     const std::string& path,
                                     const std::string& body,
                                     const std::vector<std::string>& hdrs) {
    if (!m_transport || !m_transport->IsReady()) return {};
    return m_transport->Request(method, host, path, body, hdrs);
}

HttpResp CloudProviderBase::RequestUrl(const char* method, const std::string& fullUrl,
                                        const std::string& body,
                                        const std::vector<std::string>& hdrs) {
    if (!m_transport || !m_transport->IsReady()) return {};
    return m_transport->RequestUrl(method, fullUrl, body, hdrs);
}

HttpResp CloudProviderBase::AuthenticatedGetWithRedirect(const std::string& path) {
    auto token = GetAccessToken();
    if (token.empty()) return {};
    if (!m_transport || !m_transport->IsReady()) return {};

    ThrottleApiCall();
    std::string authHeader = "Authorization: Bearer " + token;
    return m_transport->AuthenticatedGetWithRedirect(ApiHost(), path, authHeader);
}

// ── API request with retry ─────────────────────────────────────────────────

HttpResp CloudProviderBase::ApiGet(const std::string& path) {
    return ApiRequest("GET", path, {}, {});
}

HttpResp CloudProviderBase::ApiRequest(const char* method, const std::string& path,
                                        const std::string& body,
                                        const std::string& contentType) {
    HttpResp lastResp;
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (attempt > 0)
            std::this_thread::sleep_for(std::chrono::seconds(attempt));
        auto token = GetAccessToken();
        if (token.empty()) {
            LOG("%s ApiRequest: no access token for %s %s", LogTag(), method, path.c_str());
            return {};
        }
        ThrottleApiCall();
        std::vector<std::string> hdrs = {"Authorization: Bearer " + token};
        if (!contentType.empty())
            hdrs.push_back("Content-Type: " + contentType);
        for (const auto& h : ExtraApiHeaders()) hdrs.push_back(h);
        lastResp = Request(method, ApiHost(), path, body, hdrs);
        if (!IsRateLimited(lastResp.status, lastResp.body)) return lastResp;
        LOG("%s Rate limited (%s attempt %d, HTTP %d), retrying",
            LogTag(), method, attempt + 1, lastResp.status);
    }
    LOG("%s Rate limit retries exhausted for %s %s", LogTag(), method, path.c_str());
    return lastResp;
}

// ── Init / Shutdown / IsAuthenticated ──────────────────────────────────────

bool CloudProviderBase::InitSession(const std::string& tokenPath) {
    m_tokenPath = tokenPath;

    m_tokenStore = CreateTokenStore();
    m_transport = CreateHttpTransport(LogTag());

    if (!m_transport->Init()) {
        LOG("%s Transport init failed", LogTag());
        return false;
    }

    if (LoadTokens()) {
        LOG("%s Tokens loaded from %s", LogTag(), tokenPath.c_str());
    } else {
        LOG("%s No tokens at %s -- authenticate via the CloudRedirect UI",
            LogTag(), tokenPath.c_str());
    }
    return true;
}

bool CloudProviderBase::Init(const std::string& configPath) {
    if (m_initialized) return true;
    m_initialized = InitSession(configPath);
    if (m_initialized)
        LOG("%s Initialized (tokens: %s)", ProviderTag(), configPath.c_str());
    else
        LOG("%s Init failed", ProviderTag());
    return m_initialized;
}

void CloudProviderBase::Shutdown() {
    m_initialized = false;
    // Transport stays alive until unique_ptr destructor (after inflight drain).
    LOG("%s Shutdown", ProviderTag());
}

bool CloudProviderBase::IsAuthenticated() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_initialized && !m_tok.refresh.empty();
}
