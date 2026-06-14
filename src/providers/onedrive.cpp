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

std::string OneDriveProvider::GetOrFetchItemId(const std::string& itemPath) {
    {
        std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
        auto it = m_itemIdCache.find(itemPath);
        if (it != m_itemIdCache.end())
            return it->second;
    }
    auto r = ApiGet(itemPath + "?$select=id");
    if (r.status != 200)
        return {};
    std::string id = Json::Parse(r.body)["id"].str();
    if (id.empty())
        return {};
    std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
    m_itemIdCache[itemPath] = id;
    return id;
}

void OneDriveProvider::InvalidateItemId(const std::string& itemPath) {
    std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
    m_itemIdCache.erase(itemPath);
}

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
    // Check cache first; fall back to a single fetch that distinguishes 404 from error.
    std::string folderId;
    {
        std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
        auto it = m_itemIdCache.find(folderPath);
        if (it != m_itemIdCache.end()) folderId = it->second;
    }
    if (folderId.empty()) {
        auto r = ApiGet(folderPath + "?$select=id");
        if (r.status == 404) {
            LOG("[OneDrive] ListAppFiles: folder not found (404)");
            if (ok) *ok = true;
            if (outComplete) *outComplete = true;
            return result;
        }
        if (r.status != 200) {
            LOG("[OneDrive] ListAppFiles: folder lookup failed: HTTP %d", r.status);
            return result;
        }
        folderId = Json::Parse(r.body)["id"].str();
        if (folderId.empty()) {
            LOG("[OneDrive] ListAppFiles: folder ID empty from response");
            return result;
        }
        std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
        m_itemIdCache[folderPath] = folderId;
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

std::vector<ICloudProvider::SearchHit>
OneDriveProvider::SearchByName(const std::string& filename, bool* outSupported) {
    if (outSupported) *outSupported = true;
    std::vector<SearchHit> hits;

    // Graph search. Each hit's parentReference.path is like
    //   "/drive/root:/CloudRedirect/{accountId}/{appId}"
    // so account/app come straight from the path -- no extra lookups.
    std::string url = "/v1.0/me/drive/root/search(q='" + EncodePath(filename) + "')"
                      "?$select=id,name,parentReference&$top=200";

    while (!url.empty()) {
        auto r = ApiGet(url);
        if (r.status != 200) {
            LOG("[OneDrive] SearchByName('%s'): HTTP %d", filename.c_str(), r.status);
            if (hits.empty() && outSupported) *outSupported = (r.status == 404);
            return hits;
        }

        auto j = Json::Parse(r.body);
        auto& items = j["value"];
        for (size_t i = 0; i < items.size(); ++i) {
            auto& item = items[i];
            std::string name = UrlDecode(item["name"].str());
            if (name != filename) continue; // search is fuzzy; require exact name

            std::string parentPath = item["parentReference"]["path"].str();
            // Find the segment after "CloudRedirect/".
            const std::string marker = "CloudRedirect/";
            size_t pos = parentPath.find(marker);
            if (pos == std::string::npos) continue;
            std::string rest = parentPath.substr(pos + marker.size()); // "{acct}/{app}" (maybe more)
            size_t slash = rest.find('/');
            if (slash == std::string::npos) continue;
            std::string accountId = rest.substr(0, slash);
            std::string appId = rest.substr(slash + 1);
            // appId may have a trailing "/sub" -- keep only the first segment.
            size_t slash2 = appId.find('/');
            if (slash2 != std::string::npos) appId = appId.substr(0, slash2);

            // Our layout uses numeric account/app folder names.
            bool ok = !accountId.empty() && !appId.empty();
            for (char c : accountId) if (c < '0' || c > '9') { ok = false; break; }
            for (char c : appId)     if (c < '0' || c > '9') { ok = false; break; }
            if (!ok) continue;

            auto content = DownloadFileById(item["id"].str());
            if (!content || content->empty()) continue;

            SearchHit hit;
            hit.path = accountId + "/" + appId + "/" + filename;
            hit.content = std::move(*content);
            hits.push_back(std::move(hit));
        }

        // Pagination.
        auto nextLink = j["@odata.nextLink"].str();
        url.clear();
        if (!nextLink.empty()) {
            size_t pathStart = nextLink.find("/v1.0/");
            if (pathStart != std::string::npos) url = nextLink.substr(pathStart);
        }
    }

    LOG("[OneDrive] SearchByName('%s'): %zu match(es)", filename.c_str(), hits.size());
    return hits;
}

// simple upload (<=4MB): PUT content to path-based address
bool OneDriveProvider::SimpleUpload(uint32_t accountId, uint32_t appId,
                                     const std::string& filename,
                                     const uint8_t* data, size_t len, int64_t timestamp) {
    auto itemPath = BuildItemPath(accountId, appId, filename);
    auto r = ApiRequest("PUT", itemPath + "/content",
                         std::string((const char*)data, len),
                         "application/octet-stream");
    if (r.status == 404) {
        // Legacy flat blob blocking CAS directory creation — remove and retry.
        auto lastSlash = filename.rfind('/');
        if (lastSlash != std::string::npos) {
            std::string parentFile = filename.substr(0, lastSlash);
            if (parentFile.find("blobs/") == 0) {
                LOG("[OneDrive] SimpleUpload '%s': 404, removing legacy blob '%s' and retrying",
                    filename.c_str(), parentFile.c_str());
                DoOneDriveDelete(accountId, appId, parentFile);
                InvalidateItemId(BuildItemPath(accountId, appId, parentFile));
                r = ApiRequest("PUT", itemPath + "/content",
                               std::string((const char*)data, len),
                               "application/octet-stream");
            }
        }
    }
    if (r.status < 200 || r.status >= 300) {
        LOG("[OneDrive] SimpleUpload '%s' failed: HTTP %d", filename.c_str(), r.status);
        return false;
    }

    // Upload response contains the item ID -- populate cache and optionally set timestamp.
    auto j = Json::Parse(r.body);
    std::string itemId = j["id"].str();
    if (!itemId.empty()) {
        std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
        m_itemIdCache[itemPath] = itemId;
    }
    if (timestamp > 0 && !itemId.empty()) {
        auto meta = Json::Object();
        auto fsi = Json::Object();
        fsi.objVal["lastModifiedDateTime"] = Json::String(UnixToIso8601(timestamp));
        meta.objVal["fileSystemInfo"] = std::move(fsi);
        ApiRequest("PATCH", "/v1.0/me/drive/items/" + itemId,
                   Json::Stringify(meta));
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

    // Extract item ID from final response (or fall back to path lookup) for
    // timestamp PATCH and cache population.
    {
        std::string itemId;
        if (!lastBody.empty())
            itemId = Json::Parse(lastBody)["id"].str();
        if (itemId.empty()) {
            auto lookup = ApiGet(itemPath + "?$select=id");
            if (lookup.status == 200)
                itemId = Json::Parse(lookup.body)["id"].str();
        }
        if (!itemId.empty()) {
            std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
            m_itemIdCache[itemPath] = itemId;
        }
        if (timestamp > 0 && !itemId.empty()) {
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
        InvalidateItemId(itemPath);
        return true;
    }
    if (r.status >= 200 && r.status < 300) {
        LOG("[OneDrive] Deleted %s for acct %u app %u", filename.c_str(), accountId, appId);
        InvalidateItemId(itemPath);
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
        if (CheckExists(items[0].path) == ExistsStatus::Exists) return true;
        return Upload(items[0].path, items[0].data.data(), items[0].data.size());
    }

    auto rollbackUploaded = [&](const std::vector<std::string>& paths) {
        for (auto it = paths.rbegin(); it != paths.rend(); ++it) {
            Remove(*it);
        }
    };

    // Upload sequentially with rollback on failure.
    std::vector<std::string> uploaded;
    size_t dedupSkips = 0;
    for (const auto& item : items) {
        // Per-file CAS dedup (PromoteStagedBatchForCommit no longer pre-filters).
        // Skip only on a definite Exists; on Missing OR Error, upload -- the CAS path
        // is idempotent, so an errored check never strands a blob.
        if (CheckExists(item.path) == ExistsStatus::Exists) {
            ++dedupSkips;
            continue;
        }
        if (!Upload(item.path, item.data.data(), item.data.size())) {
            LOG("[OneDriveProvider] UploadBatch: failed on '%s', rolling back %zu uploads",
                item.path.c_str(), uploaded.size());
            rollbackUploaded(uploaded);
            return false;
        }
        uploaded.push_back(item.path);
    }
    LOG("[OneDriveProvider] UploadBatch: %zu file(s) (%zu uploaded, %zu CAS-skipped)",
        items.size(), uploaded.size(), dedupSkips);
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

    // Resolve path to item ID (cached after first lookup).
    auto itemPath = BuildItemPath(accountId, appId, relFilename);
    std::string itemId = GetOrFetchItemId(itemPath);
    if (itemId.empty()) {
        LOG("[OneDriveProvider] Download: lookup failed for %s", path.c_str());
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
    {
        std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
        if (m_itemIdCache.count(itemPath)) return ExistsStatus::Exists;
    }
    auto r = ApiGet(itemPath + "?$select=id");
    if (r.status == 200) {
        std::string id = Json::Parse(r.body)["id"].str();
        if (!id.empty()) {
            std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
            m_itemIdCache[itemPath] = id;
        }
        return ExistsStatus::Exists;
    }
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
        std::string folderId;
        {
            std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
            auto it = m_itemIdCache.find(folderPath);
            if (it != m_itemIdCache.end()) folderId = it->second;
        }
        if (folderId.empty()) {
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
            folderId = Json::Parse(r.body)["id"].str();
            if (folderId.empty()) {
                LOG("[OneDrive] ListChecked: account folder ID empty from response");
                return false;
            }
            std::lock_guard<std::mutex> lock(m_itemIdCacheMtx);
            m_itemIdCache[folderPath] = folderId;
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
