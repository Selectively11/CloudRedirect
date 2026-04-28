#include "onedrive_provider.h"
#include "http_util.h"
#include "json.h"
#include "log.h"

#include <winhttp.h>
#include <ctime>

#pragma comment(lib, "winhttp.lib")

using HttpUtil::Widen;
using HttpUtil::UrlEncode;
using HttpUtil::UrlDecode;
using HttpUtil::Iso8601ToUnix;
using HttpUtil::UnixToIso8601;
using HttpUtil::HttpResp;

// Azure AD Application (client) ID.
static constexpr const char* CLIENT_ID = "c582f799-5dc5-48a7-a4cd-cd0d8af354a2";

std::string OneDriveProvider::BuildRefreshBody(const std::string& refreshToken) const {
    return "client_id=" + UrlEncode(CLIENT_ID) +
        "&refresh_token=" + UrlEncode(refreshToken) +
        "&grant_type=refresh_token" +
        "&scope=" + UrlEncode("Files.ReadWrite offline_access");
}

bool OneDriveProvider::IsRateLimited(int status, const std::string& /*body*/) const {
    return status == 429 || status == 503;
}

DWORD OneDriveProvider::ExtraRequestFlags() const {
    // We encode paths via EncodePath; disable WinHTTP's built-in escaping.
    return WINHTTP_FLAG_ESCAPE_DISABLE;
}

// URL-encode each path segment but preserve '/' separators
std::string OneDriveProvider::EncodePath(const std::string& path) {
    std::string out;
    size_t start = 0;
    while (start < path.size()) {
        size_t slash = path.find('/', start);
        std::string seg = (slash != std::string::npos)
            ? path.substr(start, slash - start)
            : path.substr(start);
        if (!seg.empty())
            out += UrlEncode(seg);
        if (slash != std::string::npos) {
            out += '/';
            start = slash + 1;
        } else {
            break;
        }
    }
    return out;
}

// /me/drive/root:/CloudRedirect/{acct}/{app}/{filename}:
std::string OneDriveProvider::BuildItemPath(uint32_t accountId, uint32_t appId,
                                             const std::string& filename) {
    std::string raw = "CloudRedirect/" + std::to_string(accountId) + "/"
        + std::to_string(appId) + "/" + filename;
    return "/v1.0/me/drive/root:/" + EncodePath(raw) + ":";
}

// /me/drive/root:/CloudRedirect/{acct}/{app}:
std::string OneDriveProvider::BuildFolderPath(uint32_t accountId, uint32_t appId) {
    std::string raw = "CloudRedirect/" + std::to_string(accountId) + "/"
        + std::to_string(appId);
    return "/v1.0/me/drive/root:/" + EncodePath(raw) + ":";
}

// /me/drive/root:/CloudRedirect/{acct}:
std::string OneDriveProvider::BuildAccountFolderPath(uint32_t accountId) {
    std::string raw = "CloudRedirect/" + std::to_string(accountId);
    return "/v1.0/me/drive/root:/" + EncodePath(raw) + ":";
}

// Recursive children listing by item ID.
bool OneDriveProvider::ListChildrenById(const std::string& itemId, const std::string& prefix,
                                          std::vector<RemoteFile>& out,
                                          bool* outComplete, int depth) {
    if (depth >= MAX_RECURSION_DEPTH) {
        LOG("[OneDrive] ListChildrenById: max depth %d reached at %s, stopping",
            MAX_RECURSION_DEPTH, prefix.c_str());
        // Cap reached: not an error, but mark incomplete.
        if (outComplete) *outComplete = false;
        return true;
    }
    std::string url = "/v1.0/me/drive/items/" + itemId +
        "/children?$select=id,name,size,fileSystemInfo,folder";

    while (!url.empty()) {
        LOG("[OneDrive] ListChildrenById: GET %s", url.c_str());
        auto r = ApiGet(url);
        if (r.status != 200) {
            LOG("[OneDrive] ListChildren failed: HTTP %d: %s", r.status, r.body.c_str());
            return false;
        }
        auto j = Json::Parse(r.body);
        auto& items = j["value"];
        for (size_t i = 0; i < items.size(); ++i) {
            auto& item = items[i];
            // Existing files may have double-encoded names.
            std::string name = UrlDecode(item["name"].str());
            std::string path = prefix.empty() ? name : prefix + "/" + name;

        if (!item["folder"].isNull()) {
                if (!ListChildrenById(item["id"].str(), path, out, outComplete, depth + 1)) return false;
            } else {
                RemoteFile rf;
                rf.id = item["id"].str();
                rf.relativePath = path;
                rf.modifiedTime = Iso8601ToUnix(
                    item["fileSystemInfo"]["lastModifiedDateTime"].str());
                rf.size = item["size"].integer();
                out.push_back(std::move(rf));
            }
        }

        // Pagination: @odata.nextLink is a full URL; extract path+query.
        auto nextLink = j["@odata.nextLink"].str();
        if (nextLink.empty()) break;

        // Graph docs don't guarantee "/v1.0/" (beta endpoints, regional hosts).
        // Unparseable nextLink: stop, but mark listing incomplete.
        size_t pathStart = nextLink.find("/v1.0/");
        if (pathStart != std::string::npos) {
            url = nextLink.substr(pathStart);
        } else {
            LOG("[OneDrive] ListChildrenById: unparseable @odata.nextLink, "
                "marking listing incomplete: %s", nextLink.c_str());
            if (outComplete) *outComplete = false;
            url.clear();
        }
    }
    return true;
}

// All files under an app folder, via path-based addressing.
std::vector<OneDriveProvider::RemoteFile>
OneDriveProvider::ListAppFiles(uint32_t accountId, uint32_t appId, bool* ok, bool* outComplete) {
    std::vector<RemoteFile> result;
    if (ok) *ok = false;
    // Pessimistic default; only the verified-success tail sets true.
    if (outComplete) *outComplete = false;

    auto folderPath = BuildFolderPath(accountId, appId);
    LOG("[OneDrive] ListAppFiles: looking up folder: %s", folderPath.c_str());
    auto r = ApiGet(folderPath + "?$select=id");
    if (r.status == 404) {
        // Folder absent: empty-complete listing.
        LOG("[OneDrive] ListAppFiles: folder not found (404)");
        if (ok) *ok = true;
        if (outComplete) *outComplete = true;
        return result;
    }
    if (r.status != 200) {
        LOG("[OneDrive] ListAppFiles: folder lookup failed: HTTP %d: %s",
            r.status, r.body.c_str());
        return result;
    }

    auto fj = Json::Parse(r.body);
    std::string folderId = fj["id"].str();
    if (folderId.empty()) {
        LOG("[OneDrive] ListAppFiles: folder ID empty from response");
        return result;
    }

    LOG("[OneDrive] ListAppFiles: folder ID=%s, listing children", folderId.c_str());
    bool childrenComplete = true;
    if (!ListChildrenById(folderId, "", result, &childrenComplete)) {
        return result;
    }
    if (ok) *ok = true;
    if (outComplete) *outComplete = childrenComplete;
    return result;
}

bool OneDriveProvider::HasAppFolder(uint32_t accountId, uint32_t appId) {
    auto folderPath = BuildFolderPath(accountId, appId);
    auto r = ApiGet(folderPath + "?$select=id");
    return r.status == 200;
}

// /content returns a 302 to a pre-authenticated CDN URL; Bearer token must
// be stripped before following or the CDN returns 401. Retries 429/503.
std::optional<std::vector<uint8_t>>
OneDriveProvider::DownloadFileById(const std::string& itemId) {
    for (int attempt = 0; attempt <= 3; ++attempt) {
        if (attempt > 0) Sleep(attempt * 1000);

        auto token = GetAccessToken();
        if (token.empty()) {
            LOG("[OneDrive] DownloadFileById: no access token");
            return std::nullopt;
        }

        // Step 1: GET /content with redirects disabled to capture the 302 Location.
        if (!m_session) return std::nullopt;
        auto wHost = Widen("graph.microsoft.com");
        HINTERNET hConn = WinHttpConnect(m_session, wHost.c_str(),
                                          INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConn) return std::nullopt;

        std::string path = "/v1.0/me/drive/items/" + itemId + "/content";
        auto wPath = Widen(path);
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", wPath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hReq) {
            WinHttpCloseHandle(hConn);
            return std::nullopt;
        }

        // disable auto-redirect so we can intercept the 302
        DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(hReq, WINHTTP_OPTION_REDIRECT_POLICY,
                         &redirectPolicy, sizeof(redirectPolicy));

        std::string authHdr = "Authorization: Bearer " + token;
        auto wAuth = Widen(authHdr);
        WinHttpAddRequestHeaders(hReq, wAuth.c_str(), (DWORD)wAuth.size(),
                                  WINHTTP_ADDREQ_FLAG_ADD);

        ThrottleApiCall();
        BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                      nullptr, 0, 0, 0);
        if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);

        if (!ok) {
            LOG("[OneDrive] DownloadFileById: initial request failed, error %lu",
                GetLastError());
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            return std::nullopt;
        }

        DWORD statusCode = 0, codeLen = sizeof(statusCode);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &codeLen, WINHTTP_NO_HEADER_INDEX);

        // Retry on 429/503 throttling
        if ((statusCode == 429 || statusCode == 503) && attempt < 3) {
            LOG("[OneDrive] DownloadFileById: throttled (HTTP %lu, attempt %d), retrying in %ds",
                statusCode, attempt + 1, attempt + 1);
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            continue;
        }

        if (statusCode == 200) {
            // some small files may return 200 directly with the content
            std::string body;
            DWORD avail, got;
            while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                if (body.size() + avail > 1024ULL * 1024 * 1024) {
                    LOG("[OneDrive] DownloadFileById: response exceeded 1GB cap, aborting");
                    break;
                }
                size_t off = body.size();
                body.resize(off + avail);
                got = 0;
                WinHttpReadData(hReq, &body[off], avail, &got);
                body.resize(off + got);
            }
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            return std::vector<uint8_t>(body.begin(), body.end());
        }

        if (statusCode != 302) {
            LOG("[OneDrive] DownloadFileById: expected 302 but got %lu", statusCode);
            WinHttpCloseHandle(hReq);
            WinHttpCloseHandle(hConn);
            return std::nullopt;
        }

        // extract Location header
        DWORD locLen = 0;
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER, &locLen, WINHTTP_NO_HEADER_INDEX);
        std::wstring wLoc(locLen / sizeof(wchar_t), 0);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
            wLoc.data(), &locLen, WINHTTP_NO_HEADER_INDEX);
        // trim null terminator if present
        while (!wLoc.empty() && wLoc.back() == 0) wLoc.pop_back();

        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);

        if (wLoc.empty()) {
            LOG("[OneDrive] DownloadFileById: 302 but no Location header");
            return std::nullopt;
        }

        // convert Location to narrow string
        int n = WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                                     nullptr, 0, nullptr, nullptr);
        std::string location(n, 0);
        WideCharToMultiByte(CP_UTF8, 0, wLoc.c_str(), (int)wLoc.size(),
                             location.data(), n, nullptr, nullptr);

        // step 2: fetch the CDN URL WITHOUT the auth header
        auto r = RequestUrl("GET", location);
        if (r.status != 200) {
            LOG("[OneDrive] DownloadFileById: CDN fetch failed: HTTP %d", r.status);
            return std::nullopt;
        }
        return std::vector<uint8_t>(r.body.begin(), r.body.end());
    }
    // Should not reach here, but just in case
    return std::nullopt;
}

// simple upload (<=4MB): PUT content to path-based address
bool OneDriveProvider::SimpleUpload(uint32_t accountId, uint32_t appId,
                                     const std::string& filename,
                                     const uint8_t* data, size_t len, int64_t timestamp) {
    auto itemPath = BuildItemPath(accountId, appId, filename);
    auto r = ApiRequest("PUT", itemPath + "/content",
                         std::string((const char*)data, len),
                         "application/octet-stream");
    if (r.status < 200 || r.status >= 300) {
        LOG("[OneDrive] SimpleUpload '%s' failed: HTTP %d: %s",
            filename.c_str(), r.status, r.body.c_str());
        return false;
    }

    // set lastModifiedDateTime via PATCH if we have a timestamp
    if (timestamp > 0) {
        auto j = Json::Parse(r.body);
        std::string itemId = j["id"].str();
        if (!itemId.empty()) {
            auto meta = Json::Object();
            auto fsi = Json::Object();
            fsi.objVal["lastModifiedDateTime"] = Json::String(UnixToIso8601(timestamp));
            meta.objVal["fileSystemInfo"] = std::move(fsi);
            ApiRequest("PATCH", "/v1.0/me/drive/items/" + itemId,
                       Json::Stringify(meta));
        }
    }

    return true;
}

// Upload session for files >4MB. Abandoned sessions auto-expire server-side.
bool OneDriveProvider::SessionUpload(uint32_t accountId, uint32_t appId,
                                      const std::string& filename,
                                      const uint8_t* data, size_t len, int64_t timestamp) {
    auto itemPath = BuildItemPath(accountId, appId, filename);

    // create upload session
    auto sessionBody = Json::Object();
    auto item = Json::Object();
    item.objVal["@microsoft.graph.conflictBehavior"] = Json::String("replace");
    sessionBody.objVal["item"] = std::move(item);

    auto r = ApiRequest("POST", itemPath + "/createUploadSession",
                         Json::Stringify(sessionBody));
    if (r.status < 200 || r.status >= 300) {
        LOG("[OneDrive] CreateUploadSession failed: HTTP %d: %s", r.status, r.body.c_str());
        return false;
    }

    auto sj = Json::Parse(r.body);
    std::string uploadUrl = sj["uploadUrl"].str();
    if (uploadUrl.empty()) {
        LOG("[OneDrive] No uploadUrl in session response");
        return false;
    }

    // upload in chunks (10MB chunks, Graph supports up to 60MB)
    static constexpr size_t CHUNK_SIZE = 10 * 1024 * 1024;
    size_t offset = 0;
    std::string lastBody;

    while (offset < len) {
        size_t chunkEnd = (offset + CHUNK_SIZE < len) ? offset + CHUNK_SIZE : len;
        size_t chunkLen = chunkEnd - offset;

        char rangeBuf[128];
        snprintf(rangeBuf, sizeof(rangeBuf), "bytes %zu-%zu/%zu", offset, chunkEnd - 1, len);

        auto cr = RequestUrl("PUT", uploadUrl,
                              std::string((const char*)data + offset, chunkLen),
                              {"Content-Range: " + std::string(rangeBuf)});

        if (cr.status == 200 || cr.status == 201) {
            // upload complete
            lastBody = cr.body;
            break;
        } else if (cr.status == 202) {
            // accepted, continue uploading
            offset = chunkEnd;
        } else {
            LOG("[OneDrive] Session upload chunk failed: HTTP %d: %s",
                cr.status, cr.body.c_str());
            // cancel the session
            RequestUrl("DELETE", uploadUrl);
            return false;
        }
    }

    // If lastBody is empty (final chunk was 202), look up item ID by path
    // so we can still PATCH the timestamp.
    if (timestamp > 0) {
        std::string itemId;
        if (!lastBody.empty()) {
            auto j = Json::Parse(lastBody);
            itemId = j["id"].str();
        }
        if (itemId.empty()) {
            auto lookup = ApiGet(itemPath + "?$select=id");
            if (lookup.status == 200) {
                auto lj = Json::Parse(lookup.body);
                itemId = lj["id"].str();
            }
        }
        if (!itemId.empty()) {
            auto meta = Json::Object();
            auto fsi = Json::Object();
            fsi.objVal["lastModifiedDateTime"] = Json::String(UnixToIso8601(timestamp));
            meta.objVal["fileSystemInfo"] = std::move(fsi);
            ApiRequest("PATCH", "/v1.0/me/drive/items/" + itemId,
                       Json::Stringify(meta));
        }
    }

    return true;
}

// wrapper to avoid Windows DeleteFile macro collision
bool OneDriveProvider::DoOneDriveDelete(uint32_t accountId, uint32_t appId,
                                         const std::string& filename) {
    if (GetAccessToken().empty()) return false;

    auto itemPath = BuildItemPath(accountId, appId, filename);
    auto r = ApiRequest("DELETE", itemPath, "", "");
    if (r.status == 404) {
        LOG("[OneDrive] %s not on OneDrive, nothing to delete", filename.c_str());
        return true;
    }
    if (r.status >= 200 && r.status < 300) {
        LOG("[OneDrive] Deleted %s for acct %u app %u", filename.c_str(), accountId, appId);
        return true;
    }
    LOG("[OneDrive] Delete '%s' failed: HTTP %d: %s",
        filename.c_str(), r.status, r.body.c_str());
    return false;
}

bool OneDriveProvider::Upload(const std::string& path,
                               const uint8_t* data, size_t len) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("[OneDriveProvider] Upload: bad path '%s'", path.c_str());
        return false;
    }

    if (GetAccessToken().empty()) return false;

    static constexpr size_t SIMPLE_UPLOAD_LIMIT = 4 * 1024 * 1024; // 4MB
    bool ok;
    if (len <= SIMPLE_UPLOAD_LIMIT) {
        ok = SimpleUpload(accountId, appId, relFilename, data, len, 0);
    } else {
        ok = SessionUpload(accountId, appId, relFilename, data, len, 0);
    }

    if (ok)
        LOG("[OneDriveProvider] Uploaded %s (%zu bytes)", path.c_str(), len);
    else
        LOG("[OneDriveProvider] Upload FAILED %s", path.c_str());
    return ok;
}

bool OneDriveProvider::Download(const std::string& path,
                                 std::vector<uint8_t>& outData) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("[OneDriveProvider] Download: bad path '%s'", path.c_str());
        return false;
    }

    // Path-based addressing: resolve the item by path to get its ID.
    auto itemPath = BuildItemPath(accountId, appId, relFilename);
    auto r = ApiGet(itemPath + "?$select=id");
    if (r.status == 404) {
        LOG("[OneDriveProvider] Download: '%s' not found on OneDrive", path.c_str());
        return false;
    }
    if (r.status != 200) {
        LOG("[OneDriveProvider] Download: lookup failed HTTP %d for %s",
            r.status, path.c_str());
        return false;
    }

    auto j = Json::Parse(r.body);
    std::string itemId = j["id"].str();
    if (itemId.empty()) {
        LOG("[OneDriveProvider] Download: empty item ID for %s", path.c_str());
        return false;
    }

    auto data = DownloadFileById(itemId);
    if (!data.has_value()) {
        LOG("[OneDriveProvider] Download FAILED %s", path.c_str());
        return false;
    }

    outData = std::move(data.value());
    LOG("[OneDriveProvider] Downloaded %s (%zu bytes)", path.c_str(), outData.size());
    return true;
}

bool OneDriveProvider::Remove(const std::string& path) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("[OneDriveProvider] Remove: bad path '%s'", path.c_str());
        return false;
    }

    bool ok = DoOneDriveDelete(accountId, appId, relFilename);
    if (ok)
        LOG("[OneDriveProvider] Removed %s", path.c_str());
    return ok;
}

bool OneDriveProvider::Exists(const std::string& path) {
    return CheckExists(path) == ExistsStatus::Exists;
}

ICloudProvider::ExistsStatus OneDriveProvider::CheckExists(const std::string& path) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty())
        return ExistsStatus::Error;

    auto itemPath = BuildItemPath(accountId, appId, relFilename);
    auto r = ApiGet(itemPath + "?$select=id");
    if (r.status == 200) return ExistsStatus::Exists;
    if (r.status == 404) return ExistsStatus::Missing;
    return ExistsStatus::Error;
}

std::vector<ICloudProvider::FileInfo>
OneDriveProvider::List(const std::string& prefix) {
    std::vector<FileInfo> result;
    ListChecked(prefix, result);
    return result;
}

bool OneDriveProvider::ListChecked(const std::string& prefix, std::vector<FileInfo>& result,
                                    bool* outComplete) {
    result.clear();
    // Pessimistic default; only the verified-success tail sets true.
    if (outComplete) *outComplete = false;

    uint32_t accountId, appId;
    std::string relPrefix;
    if (!ParsePath(prefix, accountId, appId, relPrefix)) {
        return false;
    }

    // Account-wide enumeration: walk the account folder so callers can
    // discover every app under {accountId}/. Emitted paths are
    // {accountId}/<appId>/<rest> where <appId>/<rest> comes from the
    // recursive listing of the account folder.
    if (appId == kNoAppId) {
        auto folderPath = BuildAccountFolderPath(accountId);
        LOG("[OneDrive] ListChecked (account-wide): looking up folder: %s", folderPath.c_str());
        auto r = ApiGet(folderPath + "?$select=id");
        if (r.status == 404) {
            LOG("[OneDrive] ListChecked: account folder not found (404)");
            if (outComplete) *outComplete = true;
            return true;
        }
        if (r.status != 200) {
            LOG("[OneDrive] ListChecked: account folder lookup failed: HTTP %d: %s",
                r.status, r.body.c_str());
            return false;
        }
        auto fj = Json::Parse(r.body);
        std::string folderId = fj["id"].str();
        if (folderId.empty()) {
            LOG("[OneDrive] ListChecked: account folder ID empty from response");
            return false;
        }

        std::vector<RemoteFile> remoteFiles;
        bool childrenComplete = true;
        if (!ListChildrenById(folderId, "", remoteFiles, &childrenComplete)) {
            return false;
        }

        std::string basePrefix = std::to_string(accountId) + "/";
        result.reserve(remoteFiles.size());
        for (auto& rf : remoteFiles) {
            FileInfo fi;
            fi.path = basePrefix + rf.relativePath;
            fi.size = (uint64_t)rf.size;
            fi.modifiedTime = (uint64_t)rf.modifiedTime;
            result.push_back(std::move(fi));
        }

        LOG("[OneDriveProvider] List '%s': %zu files (complete=%d)",
            prefix.c_str(), result.size(), (int)childrenComplete);
        if (outComplete) *outComplete = childrenComplete;
        return true;
    }

    // Local completeness flag so only the success tail flips outComplete.
    bool ok = false;
    bool listComplete = true;
    auto remoteFiles = ListAppFiles(accountId, appId, &ok, &listComplete);
    if (!ok) {
        return false;
    }

    std::string basePrefix = std::to_string(accountId) + "/" + std::to_string(appId) + "/";

    // Filter by relPrefix if provided
    for (auto& rf : remoteFiles) {
        if (!relPrefix.empty()) {
            std::string normPrefix = relPrefix;
            if (!normPrefix.empty() && normPrefix.back() != '/') normPrefix += '/';
            if (rf.relativePath.substr(0, normPrefix.size()) != normPrefix)
                continue;
        }

        FileInfo fi;
        fi.path = basePrefix + rf.relativePath;
        fi.size = (uint64_t)rf.size;
        fi.modifiedTime = (uint64_t)rf.modifiedTime;
        result.push_back(std::move(fi));
    }

    LOG("[OneDriveProvider] List '%s': %zu files (complete=%d)",
        prefix.c_str(), result.size(), (int)listComplete);
    if (outComplete) *outComplete = listComplete;
    return true;
}
