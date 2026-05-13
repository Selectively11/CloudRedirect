#include "webdav_provider.h"
#include "json.h"
#include "log.h"
#include "dpapi_util.h"
#include <wincrypt.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

using HttpUtil::Widen;
using HttpUtil::UrlEncode;
using HttpUtil::HttpResp;

WebDavProvider::~WebDavProvider() {
    Shutdown();
}

static std::string Base64Encode(const std::string& in) {
    DWORD outLen = 0;
    CryptBinaryToStringA((const BYTE*)in.data(), (DWORD)in.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &outLen);
    std::string out(outLen, '\0');
    CryptBinaryToStringA((const BYTE*)in.data(), (DWORD)in.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &outLen);
    while (!out.empty() && (out.back() == '\0' || out.back() == '\r' || out.back() == '\n')) out.pop_back();
    return out;
}

bool WebDavProvider::Init(const std::string& configPath) {
    if (m_authenticated) return true;
    if (!LoadConfig(configPath)) return false;

    m_session = WinHttpOpen(L"CloudRedirect/1.0",
                             WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!m_session) {
        LOG("[WebDAV] WinHttpOpen failed: %u", GetLastError());
        return false;
    }

    WinHttpSetTimeouts(m_session, 5000, 5000, 10000, 10000);
    m_authenticated = true;
    LOG("[WebDAV] Initialized with URL: %s", m_cfg.url.c_str());
    return true;
}

void WebDavProvider::Shutdown() {
    m_authenticated = false;
    if (m_session) {
        WinHttpCloseHandle(m_session);
        m_session = nullptr;
    }
    LOG("[WebDAV] Shutdown");
}

bool WebDavProvider::LoadConfig(const std::string& configPath) {
    auto content = DpapiUtil::ReadTokenFile(configPath);
    if (content.empty()) return false;
    
    auto j = Json::Parse(content);
    m_cfg.url = j["webdav_url"].str();
    m_cfg.user = j["webdav_user"].str();
    m_cfg.pass = j["webdav_pass"].str();

    if (m_cfg.url.empty()) return false;
    if (!ParseUrl(m_cfg.url, m_host, m_port, m_basePath, m_isHttps)) {
        LOG("[WebDAV] Failed to parse URL: %s", m_cfg.url.c_str());
        return false;
    }
    return true;
}

bool WebDavProvider::ParseUrl(const std::string& url, std::string& host, int& port, std::string& basePath, bool& isHttps) {
    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) return false;
    
    std::string scheme = url.substr(0, schemeEnd);
    isHttps = (scheme == "https");
    
    size_t hostStart = schemeEnd + 3;
    size_t pathStart = url.find('/', hostStart);
    std::string hostPort = (pathStart == std::string::npos) ? url.substr(hostStart) : url.substr(hostStart, pathStart - hostStart);
    
    size_t colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        host = hostPort.substr(0, colonPos);
        port = std::stoi(hostPort.substr(colonPos + 1));
    } else {
        host = hostPort;
        port = isHttps ? 443 : 80;
    }
    
    basePath = (pathStart == std::string::npos) ? "/" : url.substr(pathStart);
    if (!basePath.empty() && basePath.back() != '/') basePath += '/';
    
    return !host.empty();
}

std::string WebDavProvider::BuildAuthHeader() const {
    if (m_cfg.user.empty()) return "";
    return "Authorization: Basic " + Base64Encode(m_cfg.user + ":" + m_cfg.pass);
}

std::string WebDavProvider::GetFullUrl(const std::string& relPath) const {
    std::string path = m_basePath;
    if (!relPath.empty()) {
        if (relPath[0] == '/') path += relPath.substr(1);
        else path += relPath;
    }
    return path;
}

HttpResp WebDavProvider::Request(const char* method, const std::string& path,
                                  const std::string& body,
                                  const std::vector<std::string>& hdrs) {
    HttpResp resp;
    if (!m_session) return resp;

    auto wHost = Widen(m_host);
    HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(), (INTERNET_PORT)m_port, 0);
    if (!hConn) return resp;

    auto wMethod = Widen(method);
    auto wPath = Widen(path);
    DWORD flags = m_isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, wMethod.c_str(), wPath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    if (!hReq) { WinHttpCloseHandle(hConn); return resp; }

    std::string auth = BuildAuthHeader();
    if (!auth.empty()) {
        auto wAuth = Widen(auth);
        WinHttpAddRequestHeaders(hReq, wAuth.c_str(), (DWORD)wAuth.size(), WINHTTP_ADDREQ_FLAG_ADD);
    }

    for (auto& h : hdrs) {
        auto wh = Widen(h);
        WinHttpAddRequestHeaders(hReq, wh.c_str(), (DWORD)wh.size(), WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.empty() ? nullptr : (void*)body.data(), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);

    if (ok) {
        DWORD code = 0, codeLen = sizeof(code);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &code, &codeLen, WINHTTP_NO_HEADER_INDEX);
        resp.status = (int)code;

        DWORD avail, got;
        while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
            size_t off = resp.body.size();
            resp.body.resize(off + avail);
            got = 0;
            if (!WinHttpReadData(hReq, &resp.body[off], avail, &got)) got = 0;
            resp.body.resize(off + got);
        }
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    return resp;
}

bool WebDavProvider::Upload(const std::string& path, const uint8_t* data, size_t len) {
    size_t lastSlash = path.rfind('/');
    if (lastSlash != std::string::npos) {
        if (!EnsureSubfolders(path.substr(0, lastSlash))) return false;
    }

    auto r = Request("PUT", GetFullUrl(path), std::string((const char*)data, len), {"Content-Type: application/octet-stream"});
    return r.status >= 200 && r.status < 300;
}

bool WebDavProvider::Download(const std::string& path, std::vector<uint8_t>& outData) {
    auto r = Request("GET", GetFullUrl(path));
    if (r.status != 200) return false;
    outData.assign(r.body.begin(), r.body.end());
    return true;
}

bool WebDavProvider::Remove(const std::string& path) {
    auto r = Request("DELETE", GetFullUrl(path));
    return r.status >= 200 && r.status < 300 || r.status == 404;
}

bool WebDavProvider::Exists(const std::string& path) {
    return CheckExists(path) == ExistsStatus::Exists;
}

ICloudProvider::ExistsStatus WebDavProvider::CheckExists(const std::string& path) {
    // PROPFIND with Depth: 0 is used to check existence
    auto r = Request("PROPFIND", GetFullUrl(path), "", {"Depth: 0"});
    if (r.status == 207 || r.status == 200) return ExistsStatus::Exists;
    if (r.status == 404) return ExistsStatus::Missing;
    return ExistsStatus::Error;
}

static std::string ExtractTag(const std::string& xml, const std::string& tag) {
    size_t start = xml.find("<" + tag);
    if (start == std::string::npos) return "";
    start = xml.find(">", start);
    if (start == std::string::npos) return "";
    start++;
    size_t end = xml.find("</" + tag, start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

static int64_t ParseHttpDate(const std::string& date) {
    // Format: Mon, 21 Oct 2013 20:13:22 GMT
    struct tm tm = {};
    const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char monthStr[4];
    if (sscanf(date.c_str(), "%*s %d %3s %d %d:%d:%d", &tm.tm_mday, monthStr, &tm.tm_year, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) return 0;
    for (int i = 0; i < 12; i++) {
        if (strcmp(monthStr, months[i]) == 0) {
            tm.tm_mon = i;
            break;
        }
    }
    tm.tm_year -= 1900;
    return (int64_t)_mkgmtime(&tm);
}

std::vector<ICloudProvider::FileInfo> WebDavProvider::List(const std::string& prefix) {
    std::vector<FileInfo> res;
    ListChecked(prefix, res);
    return res;
}

bool WebDavProvider::ListChecked(const std::string& prefix, std::vector<FileInfo>& outFiles, bool* outComplete) {
    outFiles.clear();
    if (outComplete) *outComplete = false;

    std::string path = GetFullUrl(prefix);
    if (!path.empty() && path.back() != '/') path += '/';

    auto r = Request("PROPFIND", path, "", {"Depth: 1"});
    if (r.status != 207) {
        if (r.status == 404) {
            if (outComplete) *outComplete = true;
            return true;
        }
        return false;
    }

    // Very basic XML response parsing for <d:response>
    size_t pos = 0;
    while ((pos = r.body.find("<d:response", pos)) != std::string::npos || (pos = r.body.find("<D:response", pos)) != std::string::npos) {
        size_t endPos = r.body.find("</", pos + 1); // find next closing tag
        size_t respEnd = r.body.find("response>", pos);
        if (respEnd == std::string::npos) break;
        respEnd += 9;
        std::string response = r.body.substr(pos, respEnd - pos);
        pos = respEnd;

        std::string href = ExtractTag(response, "d:href");
        if (href.empty()) href = ExtractTag(response, "D:href");
        if (href.empty()) continue;

        // Skip the directory itself
        std::string decodedHref = HttpUtil::UrlDecode(href);
        // Normalize: sometimes href is full URL, sometimes relative
        size_t hostPos = decodedHref.find(m_host);
        if (hostPos != std::string::npos) {
            decodedHref = decodedHref.substr(decodedHref.find('/', hostPos + m_host.length()));
        }
        
        std::string normPath = path;
        if (normPath.length() > 0 && normPath[0] != '/') normPath = "/" + normPath;
        if (decodedHref == normPath || decodedHref == normPath.substr(0, normPath.length() - 1)) continue;

        std::string resType = ExtractTag(response, "d:resourcetype");
        if (resType.empty()) resType = ExtractTag(response, "D:resourcetype");
        bool isFolder = resType.find("collection") != std::string::npos;

        if (isFolder) {
            // WebDAV List is Depth 1, but ICloudProvider expects recursive List if needed?
            // Actually ICloudProvider::List usually just lists the prefix.
            // GoogleDriveProvider does recursion.
            // For now, let's just do non-recursive list and see.
            // Wait, the interface says "List all files under a prefix".
            // If prefix is "54303850/1229490/blobs/", it should return all blobs.
            
            // If I see a folder, I should probably recurse if I want to match other providers.
            // But WebDAV PROPFIND with Depth: infinity is often disabled.
            // Let's implement recursion manually if needed.
            
            std::string subPrefix = prefix;
            if (!subPrefix.empty() && subPrefix.back() != '/') subPrefix += '/';
            
            // Extract filename from href
            size_t lastSlash = decodedHref.rfind('/', decodedHref.length() - 2);
            std::string folderName = decodedHref.substr(lastSlash + 1);
            if (folderName.back() == '/') folderName.pop_back();
            
            std::vector<FileInfo> subFiles;
            if (ListChecked(subPrefix + folderName, subFiles)) {
                outFiles.insert(outFiles.end(), subFiles.begin(), subFiles.end());
            }
        } else {
            FileInfo fi;
            // Path should be relative to the "root" of CloudRedirect storage
            // Our paths are {accountId}/{appId}/blobs/{filename}
            // decodedHref is e.g. /remote.php/dav/files/user/CloudRedirect/123/456/blobs/file.txt
            // m_basePath is e.g. /remote.php/dav/files/user/CloudRedirect/
            
            std::string relPath = decodedHref;
            if (relPath.substr(0, m_basePath.length()) == m_basePath) {
                relPath = relPath.substr(m_basePath.length());
            } else if (relPath.length() > 0 && relPath[0] == '/' && m_basePath.length() > 0 && m_basePath[0] != '/') {
                 // handle mismatched leading slash
            }

            fi.path = relPath;
            
            std::string sizeStr = ExtractTag(response, "d:getcontentlength");
            if (sizeStr.empty()) sizeStr = ExtractTag(response, "D:getcontentlength");
            fi.size = sizeStr.empty() ? 0 : std::stoull(sizeStr);
            
            std::string dateStr = ExtractTag(response, "d:getlastmodified");
            if (dateStr.empty()) dateStr = ExtractTag(response, "D:getlastmodified");
            fi.modifiedTime = ParseHttpDate(dateStr);
            
            outFiles.push_back(std::move(fi));
        }
    }

    if (outComplete) *outComplete = true;
    return true;
}

bool WebDavProvider::EnsureSubfolders(const std::string& relDir) {
    if (relDir.empty()) return true;
    
    std::stringstream ss(relDir);
    std::string part;
    std::string current;
    while (std::getline(ss, part, '/')) {
        if (part.empty()) continue;
        current += part + "/";
        auto r = Request("PROPFIND", GetFullUrl(current), "", {"Depth: 0"});
        if (r.status == 404) {
            auto mk = Request("MKCOL", GetFullUrl(current));
            if (mk.status < 200 || mk.status >= 300) return false;
        } else if (r.status >= 300) {
            return false;
        }
    }
    return true;
}
