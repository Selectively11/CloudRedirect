#include "cloud_provider_base.h"
#include "dpapi_util.h"
#include "json.h"
#include "log.h"

#include <charconv>
#include <ctime>

using HttpUtil::Widen;
using HttpUtil::UrlEncode;
using HttpUtil::HttpResp;

bool CloudProviderBase::ParsePath(const std::string& path,
                                   uint32_t& accountId, uint32_t& appId,
                                   std::string& relFilename) {
    // find first slash: accountId
    size_t s1 = path.find('/');
    if (s1 == std::string::npos) return false;

    auto r1 = std::from_chars(path.data(), path.data() + s1, accountId);
    if (r1.ec != std::errc{}) return false;

    // find second slash: appId
    size_t s2 = path.find('/', s1 + 1);
    size_t appEnd = (s2 != std::string::npos) ? s2 : path.size();
    auto r2 = std::from_chars(path.data() + s1 + 1, path.data() + appEnd, appId);
    if (r2.ec != std::errc{}) return false;

    // everything after "accountId/appId/" is the relative filename
    relFilename = (s2 != std::string::npos && s2 + 1 < path.size())
                  ? path.substr(s2 + 1) : std::string();
    return true;
}

void CloudProviderBase::ThrottleApiCall() {
    ULONGLONG desired, last;
    do {
        last = m_lastApiCallTick.load(std::memory_order_acquire);
        ULONGLONG now = GetTickCount64();
        desired = (last != 0 && now < last + 150) ? last + 150 : now;
    } while (!m_lastApiCallTick.compare_exchange_weak(last, desired,
                std::memory_order_acq_rel, std::memory_order_acquire));
    ULONGLONG now = GetTickCount64();
    if (now < desired) Sleep((DWORD)(desired - now));
}

bool CloudProviderBase::LoadTokens() {
    auto content = DpapiUtil::ReadTokenFile(m_tokenPath);
    if (content.empty()) return false;
    auto j = Json::Parse(content);
    m_tok.access = j["access_token"].str();
    m_tok.refresh = j["refresh_token"].str();
    m_tok.expiresAt = j["expires_at"].integer();
    return !m_tok.refresh.empty();
}

bool CloudProviderBase::SaveTokens() {
    auto obj = Json::Object();
    obj.objVal["access_token"] = Json::String(m_tok.access);
    obj.objVal["refresh_token"] = Json::String(m_tok.refresh);
    obj.objVal["expires_at"] = Json::Number((double)m_tok.expiresAt);

    std::string json = Json::Stringify(obj);
    if (!DpapiUtil::WriteTokenFile(m_tokenPath, json)) {
        LOG("%s WARNING: SaveTokens failed (DPAPI encrypt or write error)", LogTag());
        return false;
    }
    return true;
}

bool CloudProviderBase::TokenValid() const {
    return !m_tok.access.empty() && (int64_t)time(nullptr) < m_tok.expiresAt - 60;
}

bool CloudProviderBase::RefreshAccessToken() {
    // copy refresh token under lock -- the HTTPS call is made without holding m_mtx
    std::string refreshTok;
    {
        std::lock_guard<std::mutex> lock(m_mtx);
        refreshTok = m_tok.refresh;
    }

    std::string body = BuildRefreshBody(refreshTok);
    auto r = Request("POST", TokenEndpointHost(), TokenEndpointPath(), body,
                     {"Content-Type: application/x-www-form-urlencoded"});
    if (r.status != 200) {
        std::string truncBody = r.body.size() > 200 ? r.body.substr(0, 200) + "..." : r.body;
        LOG("%s Token refresh failed: HTTP %d: %s", LogTag(), r.status, truncBody.c_str());
        {
            std::lock_guard<std::mutex> lock(m_mtx);
            m_lastRefreshFailTime = (int64_t)time(nullptr);
        }
        // Fire the callback outside the lock to keep the notification path
        // (which may show a dialog) off the token mutex.
        if (m_authFailureCb) m_authFailureCb(AuthFailureName());
        return false;
    }
    auto j = Json::Parse(r.body);
    std::string newAccess = j["access_token"].str();
    int64_t expiresIn = j["expires_in"].integer();
    auto newRefresh = j["refresh_token"].str();

    std::lock_guard<std::mutex> lock(m_mtx);
    m_tok.access = std::move(newAccess);
    m_tok.expiresAt = (int64_t)time(nullptr) + expiresIn;
    if (!newRefresh.empty()) m_tok.refresh = std::move(newRefresh);
    if (!SaveTokens()) {
        LOG("%s WARNING: rotated refresh token may be lost if process crashes!", LogTag());
    }
    m_lastRefreshFailTime = 0;
    LOG("%s Token refreshed, valid for %lld s", LogTag(), expiresIn);
    return true;
}

// Get a snapshot of the current access token (thread-safe).
// If a refresh is needed, exactly one thread performs it while others wait.
std::string CloudProviderBase::GetAccessToken() {
    std::unique_lock<std::mutex> lock(m_mtx);

    if (TokenValid()) return m_tok.access;
    if (m_tok.refresh.empty()) {
        LOG("%s GetAccessToken: no refresh token", LogTag());
        return {};
    }

    // if another thread is already refreshing, wait for it to finish
    if (m_refreshing) {
        m_refreshCv.wait(lock, [this] { return !m_refreshing; });
        if (TokenValid()) return m_tok.access;
        LOG("%s GetAccessToken: other thread refresh failed", LogTag());
        return {};
    }

    // backoff after recent failure
    if (m_lastRefreshFailTime > 0 &&
        (int64_t)time(nullptr) - m_lastRefreshFailTime < REFRESH_BACKOFF_SECS) {
        LOG("%s GetAccessToken: in backoff period (%lld s ago)",
            LogTag(), (int64_t)time(nullptr) - m_lastRefreshFailTime);
        return {};
    }

    // we are the refresher -- set flag and release lock for the network call
    m_refreshing = true;
    lock.unlock();

    bool ok = RefreshAccessToken();

    lock.lock();
    m_refreshing = false;
    m_refreshCv.notify_all();

    if (!ok) return {};
    return m_tok.access;
}

HttpResp CloudProviderBase::Request(const char* method, const char* host,
                                     const std::string& path,
                                     const std::string& body,
                                     const std::vector<std::string>& hdrs) {
    HttpResp resp;
    if (!m_session) return resp;

    auto wHost = Widen(host);
    HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(),
                                      INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) return resp;

    auto wMethod = Widen(method);
    auto wPath = Widen(path);
    HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE | ExtraRequestFlags());
    if (!hReq) { WinHttpCloseHandle(hConn); return resp; }

    for (auto& h : hdrs) {
        auto wh = Widen(h);
        WinHttpAddRequestHeaders(hReq, wh.c_str(), (DWORD)wh.size(),
                                  WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.empty() ? nullptr : (void*)body.data(), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    if (!ok) {
        DWORD err = GetLastError();
        LOG("%s WinHttpSendRequest failed: error %lu", LogTag(), err);
    }
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        LOG("%s WinHttpReceiveResponse failed: error %lu", LogTag(), err);
    }

    if (ok) {
        DWORD code = 0, codeLen = sizeof(code);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen, WINHTTP_NO_HEADER_INDEX);
        resp.status = (int)code;

        DWORD avail, got;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            if (resp.body.size() + avail > 1024ULL * 1024 * 1024) {
                LOG("%s Response body exceeded 1GB cap, aborting read", LogTag());
                break;
            }
            size_t off = resp.body.size();
            resp.body.resize(off + avail);
            got = 0;
            if (!WinHttpReadData(hReq, &resp.body[off], avail, &got))
                got = 0;
            resp.body.resize(off + got);
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return resp;
}

HttpResp CloudProviderBase::RequestUrl(const char* method, const std::string& fullUrl,
                                        const std::string& body,
                                        const std::vector<std::string>& hdrs) {
    size_t schemeEnd = fullUrl.find("://");
    if (schemeEnd == std::string::npos) return {};
    size_t hostStart = schemeEnd + 3;
    size_t pathStart = fullUrl.find('/', hostStart);
    std::string host = (pathStart != std::string::npos)
        ? fullUrl.substr(hostStart, pathStart - hostStart)
        : fullUrl.substr(hostStart);
    std::string path = (pathStart != std::string::npos)
        ? fullUrl.substr(pathStart)
        : "/";

    bool isHttps = fullUrl.substr(0, schemeEnd) == "https";
    if (!isHttps) {
        LOG("%s BLOCKED non-HTTPS request to %s", LogTag(), fullUrl.c_str());
        return {};
    }
    if (!m_session) return {};

    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    size_t colonPos = host.find(':');
    if (colonPos != std::string::npos) {
        port = (INTERNET_PORT)atoi(host.substr(colonPos + 1).c_str());
        host = host.substr(0, colonPos);
    }

    auto wHost = Widen(host);
    HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(), port, 0);
    if (!hConn) return {};

    auto wMethod = Widen(method);
    auto wPath = Widen(path);
    HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE | ExtraRequestFlags());
    if (!hReq) { WinHttpCloseHandle(hConn); return {}; }

    for (auto& h : hdrs) {
        auto wh = Widen(h);
        WinHttpAddRequestHeaders(hReq, wh.c_str(), (DWORD)wh.size(),
                                  WINHTTP_ADDREQ_FLAG_ADD);
    }

    HttpResp resp;
    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.empty() ? nullptr : (void*)body.data(), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    if (!ok) {
        LOG("%s WinHttpSendRequest failed for URL: error %lu", LogTag(), GetLastError());
    }
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) {
        LOG("%s WinHttpReceiveResponse failed for URL: error %lu", LogTag(), GetLastError());
    }

    if (ok) {
        DWORD code = 0, codeLen = sizeof(code);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen, WINHTTP_NO_HEADER_INDEX);
        resp.status = (int)code;

        DWORD avail, got;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            if (resp.body.size() + avail > 1024ULL * 1024 * 1024) {
                LOG("%s Response body exceeded 1GB cap (URL request), aborting read", LogTag());
                break;
            }
            size_t off = resp.body.size();
            resp.body.resize(off + avail);
            got = 0;
            if (!WinHttpReadData(hReq, &resp.body[off], avail, &got))
                got = 0;
            resp.body.resize(off + got);
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return resp;
}

HttpResp CloudProviderBase::ApiGet(const std::string& path) {
    return ApiRequest("GET", path, {}, {});
}

HttpResp CloudProviderBase::ApiRequest(const char* method, const std::string& path,
                                        const std::string& body,
                                        const std::string& contentType) {
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (attempt > 0) Sleep(attempt * 1000);
        auto token = GetAccessToken();
        if (token.empty()) {
            LOG("%s ApiRequest: no access token for %s %s", LogTag(), method, path.c_str());
            return {};
        }
        ThrottleApiCall();
        std::vector<std::string> hdrs = {"Authorization: Bearer " + token};
        if (!contentType.empty())
            hdrs.push_back("Content-Type: " + contentType);
        auto r = Request(method, ApiHost(), path, body, hdrs);
        if (!IsRateLimited(r.status, r.body)) return r;
        LOG("%s Rate limited (%s attempt %d, HTTP %d), retrying in %ds",
            LogTag(), method, attempt + 1, r.status, attempt + 1);
    }
    // final attempt
    auto token = GetAccessToken();
    if (token.empty()) {
        LOG("%s ApiRequest: no access token (final) for %s %s", LogTag(), method, path.c_str());
        return {};
    }
    ThrottleApiCall();
    std::vector<std::string> hdrs = {"Authorization: Bearer " + token};
    if (!contentType.empty())
        hdrs.push_back("Content-Type: " + contentType);
    return Request(method, ApiHost(), path, body, hdrs);
}

bool CloudProviderBase::InitSession(const std::string& tokenPath) {
    if (m_session) return true; // already initialized

    m_tokenPath = tokenPath;
    m_session = WinHttpOpen(L"CloudRedirect/1.0",
                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!m_session) {
        LOG("%s WinHttpOpen failed: %u", LogTag(), GetLastError());
        return false;
    }

    // 5s connect, 10s send/receive
    WinHttpSetTimeouts(m_session, 5000, 5000, 10000, 10000);

    if (LoadTokens()) {
        LOG("%s Tokens loaded from %s", LogTag(), tokenPath.c_str());
    } else {
        LOG("%s No tokens at %s -- run CloudRedirect EXE to authenticate",
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
    if (m_session) {
        WinHttpCloseHandle(m_session);
        m_session = nullptr;
    }
    LOG("%s Shutdown", ProviderTag());
}

bool CloudProviderBase::IsAuthenticated() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_initialized && !m_tok.refresh.empty();
}
