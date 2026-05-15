#include "onedrive_provider.h"
#include "http_util.h"
#include "json.h"
#include "log.h"

#include <thread>
#include <chrono>
#include <ctime>

using HttpUtil::UrlEncode;
using HttpUtil::UrlDecode;
using HttpUtil::Iso8601ToUnix;
using HttpUtil::UnixToIso8601;
using HttpUtil::HttpResp;

// Azure AD Application (client) ID.
static constexpr const char* CLIENT_ID = "b15665d9-eda6-4092-8539-0eec376afd59";
static constexpr const char* CLIENT_SECRET = "qtyfaBBYA403=unZUP40~_#";

std::string OneDriveProvider::BuildRefreshBody(const std::string& refreshToken) const {
    return "client_id=" + UrlEncode(CLIENT_ID) +
        "&client_secret=" + UrlEncode(CLIENT_SECRET) +
        "&refresh_token=" + UrlEncode(refreshToken) +
        "&grant_type=refresh_token" +
        "&scope=" + UrlEncode("Files.ReadWrite offline_access");
}

bool OneDriveProvider::IsRateLimited(int status, const std::string& /*body*/) const {
    return status == 429 || status == 503;
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
            LOG("[OneDrive] ListChildren failed: HTTP %d", r.status);
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
        LOG("[OneDrive] ListAppFiles: folder lookup failed: HTTP %d", r.status);
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

// /content returns a 302 to a pre-authenticated CDN URL; Bearer token must
// be stripped before following or the CDN returns 401. Retries 429/503.
std::optional<std::vector<uint8_t>>
OneDriveProvider::DownloadFileById(const std::string& itemId) {
    for (int attempt = 0; attempt <= 3; ++attempt) {
        if (attempt > 0)
            std::this_thread::sleep_for(std::chrono::seconds(attempt));

        std::string path = "/v1.0/me/drive/items/" + itemId + "/content";
        auto r = AuthenticatedGetWithRedirect(path);

        // Retry on 429/503 throttling
        if ((r.status == 429 || r.status == 503) && attempt < 3) {
            LOG("[OneDrive] DownloadFileById: throttled (HTTP %d, attempt %d), retrying",
                r.status, attempt + 1);
            continue;
        }

        if (r.status == 200) {
            return std::vector<uint8_t>(r.body.begin(), r.body.end());
        }

        LOG("[OneDrive] DownloadFileById: failed HTTP %d for item %s", r.status, itemId.c_str());
        return std::nullopt;
    }
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
        LOG("[OneDrive] SimpleUpload '%s' failed: HTTP %d", filename.c_str(), r.status);
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
        LOG("[OneDrive] CreateUploadSession failed: HTTP %d (body length=%zu)", r.status, r.body.size());
        return false;
    }

    auto sj = Json::Parse(r.body);
    std::string uploadUrl = sj["uploadUrl"].str();
    if (uploadUrl.empty()) {
        LOG("[OneDrive] No uploadUrl in session response (body length=%zu)", r.body.size());
        return false;
    }

    if (uploadUrl.find("https://") != 0) {
        LOG("[OneDrive] SessionUpload: non-HTTPS upload URL rejected: %s", uploadUrl.c_str());
        return false;
    }

    // upload in chunks (10MB chunks, Graph supports up to 60MB)
    static constexpr size_t CHUNK_SIZE = 10 * 1024 * 1024;
    LOG("[OneDrive] SessionUpload: %s (%zu bytes, %zu chunks)",
        filename.c_str(), len, (len + CHUNK_SIZE - 1) / CHUNK_SIZE);

    size_t offset = 0;
    std::string lastBody;

    // Zero-length uploads: send a single empty PUT to complete the session.
    if (len == 0) {
        auto cr = RequestUrl("PUT", uploadUrl, "",
                              {"Content-Length: 0",
                               "Content-Range: bytes */0"});
        if (cr.status == 200 || cr.status == 201) {
            lastBody = cr.body;
        } else {
            LOG("[OneDrive] SessionUpload: zero-length upload failed: HTTP %d body=%s",
                cr.status, cr.body.c_str());
            RequestUrl("DELETE", uploadUrl);
            return false;
        }
    }

    while (offset < len) {
        size_t chunkEnd = (offset + CHUNK_SIZE < len) ? offset + CHUNK_SIZE : len;
        size_t chunkLen = chunkEnd - offset;

        char rangeBuf[128];
        snprintf(rangeBuf, sizeof(rangeBuf), "bytes %zu-%zu/%zu", offset, chunkEnd - 1, len);

        auto cr = RequestUrl("PUT", uploadUrl,
                              std::string((const char*)data + offset, chunkLen),
                              {"Content-Range: " + std::string(rangeBuf),
                               "Content-Length: " + std::to_string(chunkLen)});

        if (cr.status == 200 || cr.status == 201) {
            lastBody = cr.body;
            if (chunkEnd == len) {
                break;
            } else {
                LOG("[OneDrive] SessionUpload: non-final chunk returned 200/201, protocol error");
                RequestUrl("DELETE", uploadUrl);
                return false;
            }
        } else if (cr.status == 202) {
            if (chunkEnd == len) {
                auto statusResp = RequestUrl("GET", uploadUrl);
                if (statusResp.status == 200 || statusResp.status == 201) {
                    lastBody = statusResp.body;
                    break;
                } else {
                    LOG("[OneDrive] SessionUpload: final chunk 202, status query failed HTTP %d",
                        statusResp.status);
                    RequestUrl("DELETE", uploadUrl);
                    return false;
                }
            }
            offset = chunkEnd;
        } else {
            LOG("[OneDrive] Session upload chunk failed: HTTP %d (body length=%zu)", cr.status, cr.body.size());
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
    LOG("[OneDrive] Delete '%s' failed: HTTP %d", filename.c_str(), r.status);
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

bool OneDriveProvider::UploadBatch(const std::vector<UploadItem>& items) {
    if (items.empty()) return true;
    if (items.size() == 1) {
        return Upload(items[0].path, items[0].data.data(), items[0].data.size());
    }

    // OneDrive $batch API: max 20 requests per batch, max 4 MB per request
    constexpr size_t MAX_BATCH_SIZE = 20;
    constexpr size_t MAX_ITEM_SIZE = 4 * 1024 * 1024;

    std::vector<std::string> allUploadedPaths;

    for (size_t batchStart = 0; batchStart < items.size(); batchStart += MAX_BATCH_SIZE) {
        size_t batchEnd = (std::min)(batchStart + MAX_BATCH_SIZE, items.size());
        size_t batchCount = batchEnd - batchStart;

        auto token = GetAccessToken();
        if (token.empty()) {
            for (const auto& path : allUploadedPaths) { Remove(path); }
            return false;
        }

        auto batchObj = Json::Object();
        auto requestsArr = Json::Array();
        std::vector<std::string> individuallyUploaded;

        for (size_t i = batchStart; i < batchEnd; ++i) {
            const auto& item = items[i];

            // Skip items larger than 4MB (would need session upload)
            if (item.data.size() > MAX_ITEM_SIZE) {
                LOG("[OneDriveProvider] UploadBatch: item %zu exceeds 4MB, falling back to individual upload",
                    i - batchStart);
                if (!Upload(item.path, item.data.data(), item.data.size())) {
                    for (const auto& path : individuallyUploaded) { Remove(path); }
                    for (const auto& path : allUploadedPaths) { Remove(path); }
                    return false;
                }
                individuallyUploaded.push_back(item.path);
                continue;
            }

            uint32_t accountId, appId;
            std::string relFilename;
            if (!ParsePath(item.path, accountId, appId, relFilename) || relFilename.empty()) {
                LOG("[OneDriveProvider] UploadBatch: bad path '%s'", item.path.c_str());
                for (const auto& path : individuallyUploaded) { Remove(path); }
                for (const auto& path : allUploadedPaths) { Remove(path); }
                return false;
            }

            auto itemPath = BuildItemPath(accountId, appId, relFilename);

            auto reqObj = Json::Object();
            reqObj.objVal["id"] = Json::String(std::to_string(i - batchStart));
            reqObj.objVal["method"] = Json::String("PUT");
            reqObj.objVal["url"] = Json::String(itemPath + "/content");

            auto headersObj = Json::Object();
            headersObj.objVal["Content-Type"] = Json::String("application/octet-stream");
            reqObj.objVal["headers"] = std::move(headersObj);

            std::string base64Body;
            static const char* base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            const uint8_t* bytes = item.data.data();
            size_t len = item.data.size();
            
            base64Body.reserve((len + 2) / 3 * 4);
            
            for (size_t j = 0; j < len; ) {
                uint32_t val = (bytes[j] << 16);
                if (j + 1 < len) val |= (bytes[j + 1] << 8);
                if (j + 2 < len) val |= bytes[j + 2];
                base64Body += base64_chars[(val >> 18) & 0x3F];
                base64Body += base64_chars[(val >> 12) & 0x3F];
                base64Body += (j + 1 < len) ? base64_chars[(val >> 6) & 0x3F] : '=';
                base64Body += (j + 2 < len) ? base64_chars[val & 0x3F] : '=';
                
                j += 3;
                if (j >= len) break;
            }
            reqObj.objVal["body"] = Json::String(base64Body);

            requestsArr.arrVal.push_back(std::move(reqObj));
        }

        if (requestsArr.arrVal.empty()) {
            LOG("[OneDriveProvider] UploadBatch: all items in chunk exceeded 4MB, handled individually");
            continue;  // Move to next batch chunk
        }

        batchObj.objVal["requests"] = std::move(requestsArr);
        std::string batchJson = Json::Stringify(batchObj);

        HttpResp r;
        for (int attempt = 0; attempt < 3; ++attempt) {
            if (attempt > 0) {
                std::this_thread::sleep_for(std::chrono::seconds(attempt));
                token = GetAccessToken();
                if (token.empty()) {
                    for (const auto& path : individuallyUploaded) { Remove(path); }
                    for (const auto& path : allUploadedPaths) { Remove(path); }
                    return false;
                }
            }
            ThrottleApiCall();
            r = ApiRequest("POST", "/v1.0/$batch", batchJson);
            if (!IsRateLimited(r.status, r.body)) break;
            LOG("[OneDrive] Batch rate limited (attempt %d), backing off %ds",
                attempt + 1, attempt + 1);
        }

        if (r.status < 200 || r.status >= 300) {
            LOG("[OneDriveProvider] UploadBatch failed: HTTP %d", r.status);
            for (const auto& path : individuallyUploaded) { Remove(path); }
            for (const auto& path : allUploadedPaths) { Remove(path); }
            return false;
        }

        auto respJson = Json::Parse(r.body);
        auto responses = respJson["responses"];
        if (responses.type != Json::Type::Array) {
            LOG("[OneDriveProvider] UploadBatch: invalid response format");
            for (const auto& path : individuallyUploaded) { Remove(path); }
            for (const auto& path : allUploadedPaths) { Remove(path); }
            return false;
        }

        for (const auto& resp : responses.arrVal) {
            int status = (int)resp["status"].number();
            if (status < 200 || status >= 300) {
                LOG("[OneDriveProvider] UploadBatch: request %s failed with status %d",
                    resp["id"].str().c_str(), status);
                for (const auto& path : individuallyUploaded) { Remove(path); }
                for (const auto& path : allUploadedPaths) { Remove(path); }
                return false;
            }
        }

        for (const auto& path : individuallyUploaded) {
            allUploadedPaths.push_back(path);
        }
        for (size_t i = batchStart; i < batchEnd; ++i) {
            if (items[i].data.size() <= MAX_ITEM_SIZE) {
                allUploadedPaths.push_back(items[i].path);
            }
        }

        LOG("[OneDriveProvider] UploadBatch: uploaded %zu files", batchCount);
    }

    return true;
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

std::vector<std::string>
OneDriveProvider::ListSubfolders(const std::string& prefix) {
    uint32_t accountId, appId;
    std::string relPrefix;
    if (!ParsePath(prefix, accountId, appId, relPrefix)) {
        return {};
    }

    // Only account-wide listing makes sense for subfolder enumeration
    if (appId != kNoAppId) {
        return ICloudProvider::ListSubfolders(prefix);
    }

    // GET /v1.0/me/drive/root:/CloudRedirect/{accountId}:/children?$select=name,folder
    std::string folderPath = BuildAccountFolderPath(accountId);
    std::string url = folderPath + "/children?$select=name,folder&$top=1000";

    std::string paginatedUrl = url;
    std::vector<std::string> folders;
    while (!paginatedUrl.empty()) {
        auto r = ApiGet(paginatedUrl);
        if (r.status != 200) break;

        auto j = Json::Parse(r.body);
        auto& items = j["value"];

        for (size_t i = 0; i < items.size(); ++i) {
            if (!items[i]["folder"].isNull()) {
                std::string name = items[i]["name"].str();
                if (!name.empty()) {
                    folders.push_back(name);
                }
            }
        }

        std::string nextLink = j["@odata.nextLink"].str();
        if (nextLink.empty()) break;
        size_t pathStart = nextLink.find("/v1.0/");
        paginatedUrl = (pathStart != std::string::npos) ? nextLink.substr(pathStart) : std::string();
    }

    LOG("[OneDriveProvider] ListSubfolders '%s': %zu folders", prefix.c_str(), folders.size());
    return folders;
}

bool OneDriveProvider::ListChecked(const std::string& prefix, std::vector<FileInfo>& result,
                                    bool* outComplete) {
    result.clear();
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
            LOG("[OneDrive] ListChecked: account folder lookup failed: HTTP %d", r.status);
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
