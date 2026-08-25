// WinHTTP transport adapter for CloudProviderBase.
// Implements IHttpTransport using WinHTTP session/connection/request handles.

#include "cloud_provider_base.h"
#include "http_util.h"
#include "log.h"

#include <Windows.h>
#include <winhttp.h>
#include <cctype>
#include <map>
#include <memory>
#include <string>

using HttpUtil::Widen;
using HttpUtil::HttpResp;

class WinHttpTransport : public IHttpTransport {
public:
    explicit WinHttpTransport(const char* logTag) : m_logTag(logTag) {}
    ~WinHttpTransport() override { Shutdown(); }

    bool Init() override {
        if (m_session) return true;
        m_session = WinHttpOpen(L"CloudRedirect/1.0",
                                 WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!m_session) {
            LOG("%s WinHttpOpen failed: %u", m_logTag, GetLastError());
            return false;
        }
        WinHttpSetTimeouts(m_session, 5000, 5000, 10000, 10000);
        return true;
    }

    // Scale send/receive timeouts with body size so multi-MB PUTs survive a slow link
    // without making small requests wait on the 10s session default.
    static void TuneTimeoutsForBody(HINTERNET hReq, size_t bodyBytes) {
        if (bodyBytes <= 256 * 1024) return; // small requests keep the fast default
        int sendMs = 60000;    // allow a multi-MB body to finish uploading
        int receiveMs = 30000; // allow Drive to commit and reply
        WinHttpSetTimeouts(hReq, 5000, 5000, sendMs, receiveMs);
    }

    void Shutdown() override {
        if (m_session) {
            WinHttpCloseHandle(m_session);
            m_session = nullptr;
        }
    }

    bool IsReady() const override { return m_session != nullptr; }
    void SetOptions(const TransportOptions& opts) override { m_opts = opts; }

    HttpResp Request(const char* method, const char* host,
                     const std::string& path,
                     const std::string& body,
                     const std::vector<std::string>& hdrs) override {
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
            WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE);
        if (!hReq) { WinHttpCloseHandle(hConn); return resp; }

        for (auto& h : hdrs) {
            auto wh = Widen(h);
            WinHttpAddRequestHeaders(hReq, wh.c_str(), (DWORD)wh.size(),
                                      WINHTTP_ADDREQ_FLAG_ADD);
        }

        TuneTimeoutsForBody(hReq, body.size());
        BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            body.empty() ? nullptr : (void*)body.data(), (DWORD)body.size(),
            (DWORD)body.size(), 0);
        if (!ok) LOG("%s WinHttpSendRequest failed: error %lu", m_logTag, GetLastError());
        if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
        if (!ok) LOG("%s WinHttpReceiveResponse failed: error %lu", m_logTag, GetLastError());

        if (ok) {
            DWORD code = 0, codeLen = sizeof(code);
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen, WINHTTP_NO_HEADER_INDEX);
            resp.status = (int)code;
            ReadBody(hReq, resp.body);
            ReadLocationHeader(hReq, resp.location);
            ReadAllHeaders(hReq, resp.headers);
        }

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        return resp;
    }

    HttpResp RequestUrl(const char* method, const std::string& fullUrl,
                        const std::string& body,
                        const std::vector<std::string>& hdrs) override {
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
        if (!isHttps && !(m_opts.allowInsecureHttp && fullUrl.substr(0, schemeEnd) == "http")) {
            LOG("%s BLOCKED non-HTTPS request to %s", m_logTag, fullUrl.c_str());
            return {};
        }
        if (!m_session) return {};

        INTERNET_PORT port = isHttps ? INTERNET_DEFAULT_HTTPS_PORT
                                     : INTERNET_DEFAULT_HTTP_PORT;
        size_t colonPos = host.find(':');
        if (colonPos != std::string::npos) {
            port = (INTERNET_PORT)atoi(host.substr(colonPos + 1).c_str());
            host = host.substr(0, colonPos);
        }

        auto wHost = Widen(host);
        HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(), port, 0);
        if (!hConn) return {};

        DWORD openFlags = WINHTTP_FLAG_ESCAPE_DISABLE;
        if (isHttps) openFlags |= WINHTTP_FLAG_SECURE;
        auto wMethod = Widen(method);
        auto wPath = Widen(path);
        HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), wPath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags);
        if (!hReq) { WinHttpCloseHandle(hConn); return {}; }

        if (isHttps && m_opts.allowInsecureTls) {
            DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
                           | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                           | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                           | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                             &secFlags, sizeof(secFlags));
        }

        for (auto& h : hdrs) {
            auto wh = Widen(h);
            WinHttpAddRequestHeaders(hReq, wh.c_str(), (DWORD)wh.size(),
                                      WINHTTP_ADDREQ_FLAG_ADD);
        }

        HttpResp resp;
        TuneTimeoutsForBody(hReq, body.size());
        BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            body.empty() ? nullptr : (void*)body.data(), (DWORD)body.size(),
            (DWORD)body.size(), 0);
        if (!ok) LOG("%s WinHttpSendRequest failed for URL: error %lu", m_logTag, GetLastError());
        if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
        if (!ok) LOG("%s WinHttpReceiveResponse failed for URL: error %lu", m_logTag, GetLastError());

        if (ok) {
            DWORD code = 0, codeLen = sizeof(code);
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen, WINHTTP_NO_HEADER_INDEX);
            resp.status = (int)code;
            ReadBody(hReq, resp.body);
            ReadLocationHeader(hReq, resp.location);
            ReadAllHeaders(hReq, resp.headers);
        }

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        return resp;
    }

    HttpResp AuthenticatedGetWithRedirect(const std::string& host,
                                           const std::string& path,
                                           const std::string& authHeader) override {
        if (!m_session) return {};

        auto wHost = Widen(host);
        HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(),
                                          INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConn) return {};

        auto wPath = Widen(path);
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", wPath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE | WINHTTP_FLAG_ESCAPE_DISABLE);
        if (!hReq) { WinHttpCloseHandle(hConn); return {}; }

        // Disable auto-redirect so we can strip auth before following
        DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY,
                         &redirectPolicy, sizeof(redirectPolicy));

        auto wAuth = Widen(authHeader);
        WinHttpAddRequestHeaders(hReq, wAuth.c_str(), (DWORD)wAuth.size(),
                                  WINHTTP_ADDREQ_FLAG_ADD);

        BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
        if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);

        HttpResp resp;
        if (!ok) {
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            return resp;
        }

        DWORD statusCode = 0, codeLen = sizeof(statusCode);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &codeLen, WINHTTP_NO_HEADER_INDEX);
        resp.status = (int)statusCode;

        if (statusCode == 200) {
            ReadBody(hReq, resp.body);
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            return resp;
        }

        if (statusCode == 302) {
            DWORD locLen = 0;
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                WINHTTP_NO_OUTPUT_BUFFER, &locLen, WINHTTP_NO_HEADER_INDEX);
            std::wstring wLoc(locLen / sizeof(wchar_t), 0);
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                wLoc.data(), &locLen, WINHTTP_NO_HEADER_INDEX);
            while (!wLoc.empty() && wLoc.back() == 0) wLoc.pop_back();

            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);

            if (wLoc.empty()) { resp.status = 0; return resp; }

            int n = WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                                         nullptr, 0, nullptr, nullptr);
            std::string location(n, 0);
            WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                                 location.data(), n, nullptr, nullptr);

            return RequestUrl("GET", location, {}, {});
        }

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        return resp;
    }

private:
    void ReadLocationHeader(HINTERNET hReq, std::string& location) {
        DWORD size = 0;
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
        std::wstring wLoc(size / sizeof(wchar_t), 0);
        if (!WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                wLoc.data(), &size, WINHTTP_NO_HEADER_INDEX)) return;
        while (!wLoc.empty() && wLoc.back() == 0) wLoc.pop_back();
        if (wLoc.empty()) return;
        int n = WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                                     nullptr, 0, nullptr, nullptr);
        if (n <= 0) return;
        location.resize(n);
        WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                             location.data(), n, nullptr, nullptr);
    }

    // Query the full raw header block and fold it into a lower-cased map so
    // callers can read S3 response headers (x-amz-version-id, etag, ...).
    void ReadAllHeaders(HINTERNET hReq, std::map<std::string, std::string>& out) {
        DWORD size = 0;
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX, WINHTTP_NO_OUTPUT_BUFFER, &size,
            WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
        std::wstring wRaw(size / sizeof(wchar_t), 0);
        if (!WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX, wRaw.data(), &size,
                WINHTTP_NO_HEADER_INDEX)) return;
        int n = WideCharToMultiByte(CP_UTF8, 0, wRaw.c_str(), (int)wRaw.size(),
                                     nullptr, 0, nullptr, nullptr);
        if (n <= 0) return;
        std::string raw(n, 0);
        WideCharToMultiByte(CP_UTF8, 0, wRaw.c_str(), (int)wRaw.size(),
                             raw.data(), n, nullptr, nullptr);

        size_t pos = 0;
        while (pos < raw.size()) {
            size_t eol = raw.find("\r\n", pos);
            std::string line = raw.substr(pos, (eol == std::string::npos ? raw.size() : eol) - pos);
            pos = (eol == std::string::npos) ? raw.size() : eol + 2;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;  // status line or blank
            std::string name = line.substr(0, colon);
            for (char& c : name) c = (char)tolower((unsigned char)c);
            size_t vs = colon + 1;
            while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) vs++;
            out[name] = line.substr(vs);
        }
    }

    void ReadBody(HINTERNET hReq, std::string& body) {
        DWORD avail, got;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            if (body.size() + avail > 1024ULL * 1024 * 1024) {
                LOG("%s Response body exceeded 1GB cap, aborting read", m_logTag);
                break;
            }
            size_t off = body.size();
            body.resize(off + avail);
            got = 0;
            if (!WinHttpReadData(hReq, &body[off], avail, &got))
                got = 0;
            body.resize(off + got);
        }
    }

    const char* m_logTag;
    HINTERNET m_session = nullptr;
    TransportOptions m_opts;
};

// Factory function
std::unique_ptr<IHttpTransport> CreateHttpTransport(const char* logTag) {
    return std::make_unique<WinHttpTransport>(logTag);
}
