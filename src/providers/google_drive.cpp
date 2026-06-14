#include "google_drive_provider.h"
#include "http_util.h"
#include "json.h"
#include "log.h"

#include <thread>
#include <chrono>
#include <random>
#include <fstream>
#include <atomic>
#include <mutex>
#include <vector>

#ifdef _WIN32
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

using HttpUtil::UrlEncode;
using HttpUtil::Iso8601ToUnix;
using HttpUtil::UnixToIso8601;
using HttpUtil::HttpResp;

// clasp (Google's Apps Script CLI) OAuth credentials
static constexpr const char* CLIENT_ID =
    "1072944905499-vm2v2i5dvn0a0d2o4ca36i1vge8cvbn0.apps.googleusercontent.com";
static constexpr const char* CLIENT_SECRET = "v6V3fKV_zWU7iw1DrpO1rknX";

std::string GoogleDriveProvider::BuildRefreshBody(const std::string& refreshToken) const {
    return "client_id=" + UrlEncode(CLIENT_ID) +
        "&client_secret=" + UrlEncode(CLIENT_SECRET) +
        "&refresh_token=" + UrlEncode(refreshToken) +
        "&grant_type=refresh_token";
}

bool GoogleDriveProvider::IsRateLimited(int status, const std::string& body) const {
    return status == 429 || (status == 403 && body.find("rateLimitExceeded") != std::string::npos);
}

std::string GoogleDriveProvider::EscapeQuery(const std::string& s) const {
    std::string out;
    for (char c : s) {
        if (c == '\'') out += "\\'";
        else if (c == '\\') out += "\\\\";
        else if (c == '\"') out += "\\\"";
        else out += c;
    }
    return out;
}

std::string GoogleDriveProvider::BuildChildCacheKey(const std::string& parentId,
                                                     const std::string& name) const {
    if (parentId.empty() || name.empty()) return {};
    return parentId + "/" + name;
}

void GoogleDriveProvider::CacheFolderChild(const std::string& parentId,
                                            const std::string& name,
                                            const std::string& id) {
    auto key = BuildChildCacheKey(parentId, name);
    if (key.empty() || id.empty()) return;
    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
    m_folders[key] = id;
}

void GoogleDriveProvider::CacheFileChild(const std::string& parentId,
                                          const std::string& name,
                                          const std::string& id) {
    auto key = BuildChildCacheKey(parentId, name);
    if (key.empty() || id.empty()) return;
    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
    m_files[key] = id;
}

void GoogleDriveProvider::InvalidateFolderChild(const std::string& parentId,
                                                 const std::string& name) {
    auto key = BuildChildCacheKey(parentId, name);
    if (key.empty()) return;
    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
    m_folders.erase(key);
}

void GoogleDriveProvider::InvalidateFileChild(const std::string& parentId,
                                               const std::string& name) {
    auto key = BuildChildCacheKey(parentId, name);
    if (key.empty()) return;
    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
    m_files.erase(key);
}

void GoogleDriveProvider::InvalidateFilesInFolder(const std::string& folderId) {
    if (folderId.empty()) return;
    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
    std::string prefix = folderId + "/";
    for (auto it = m_files.begin(); it != m_files.end(); ) {
        if (it->first.rfind(prefix, 0) == 0) {
            it = m_files.erase(it);
        } else {
            ++it;
        }
    }
}

std::string GoogleDriveProvider::GetCachedFileId(const std::string& name,
                                                  const std::string& folderId) {
    auto key = BuildChildCacheKey(folderId, name);
    if (key.empty()) return {};
    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
    auto it = m_files.find(key);
    return it == m_files.end() ? std::string() : it->second;
}

void GoogleDriveProvider::InvalidateFolderById(const std::string& folderId) {
    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
    for (auto it = m_folders.begin(); it != m_folders.end(); ) {
        if (it->second == folderId) {
            LOG("[GDrive] Cache invalidate: %s -> %s", it->first.c_str(), it->second.c_str());
            it = m_folders.erase(it);
        } else {
            ++it;
        }
    }

    std::string prefix = folderId + "/";
    for (auto it = m_folders.begin(); it != m_folders.end(); ) {
        if (it->first.rfind(prefix, 0) == 0) {
            it = m_folders.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = m_files.begin(); it != m_files.end(); ) {
        if (it->first.rfind(prefix, 0) == 0) {
            it = m_files.erase(it);
        } else {
            ++it;
        }
    }
}

GoogleDriveProvider::LookupStatus GoogleDriveProvider::FindDriveFolderStatus(
    const std::string& name, const std::string& parentId, std::string* outId) {
    std::string q = "name='" + EscapeQuery(name) + "'"
                    " and mimeType='application/vnd.google-apps.folder'"
                    " and trashed=false";
    if (parentId.empty()) q += " and 'root' in parents";
    else q += " and '" + EscapeQuery(parentId) + "' in parents";

    auto r = ApiGet("/drive/v3/files?q=" + UrlEncode(q) +
                    "&fields=files(id,createdTime)&orderBy=createdTime&pageSize=10");
    if (r.status == 404 && !parentId.empty()) {
        InvalidateFolderById(parentId);
        return LookupStatus::Missing;
    }
    if (r.status != 200) return LookupStatus::Error;
    auto j = Json::Parse(r.body);
    auto& files = j["files"];
    if (files.size() == 0) {
        InvalidateFolderChild(parentId, name);
        return LookupStatus::Missing;
    }
    // Keep the oldest folder (first by createdTime ascending)
    std::string keepId = files[(size_t)0]["id"].str();
    // clean up duplicate folders (can happen from eventual consistency)
    for (size_t i = 1; i < files.size(); ++i) {
        std::string dupId = files[i]["id"].str();
        LOG("[GDrive] Deleting duplicate folder '%s' (id=%s, keeping %s)",
            name.c_str(), dupId.c_str(), keepId.c_str());
        if (!DeleteById(dupId)) {
            LOG("[GDrive] WARNING: Failed to delete duplicate folder %s; manual cleanup required",
                dupId.c_str());
        }
    }
    CacheFolderChild(parentId, name, keepId);
    if (outId) *outId = keepId;
    return LookupStatus::Exists;
}

std::string GoogleDriveProvider::FindDriveFolder(const std::string& name,
                                                  const std::string& parentId) {
    std::string id;
    return FindDriveFolderStatus(name, parentId, &id) == LookupStatus::Exists ? id : std::string();
}

GoogleDriveProvider::LookupStatus GoogleDriveProvider::LookupRootFolder(std::string* outId) {
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find("root");
        if (it != m_folders.end()) {
            if (outId) *outId = it->second;
            return LookupStatus::Exists;
        }
    }

    std::string id;
    auto status = FindDriveFolderStatus("CloudRedirect", "", &id);
    if (status == LookupStatus::Exists) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders["root"] = id;
        if (outId) *outId = id;
    }
    return status;
}

GoogleDriveProvider::LookupStatus GoogleDriveProvider::LookupAccountFolder(uint32_t accountId,
                                                                            std::string* outId) {
    static constexpr auto kNegativeCacheTTL = std::chrono::minutes(5);
    std::string key = "acct_" + std::to_string(accountId);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find(key);
        if (it != m_folders.end()) {
            if (outId) *outId = it->second;
            return LookupStatus::Exists;
        }
        auto neg = m_missingFolders.find(key);
        if (neg != m_missingFolders.end()) {
            if (std::chrono::steady_clock::now() - neg->second < kNegativeCacheTTL)
                return LookupStatus::Missing;
            m_missingFolders.erase(neg);
        }
    }

    std::string rootId;
    auto rootStatus = LookupRootFolder(&rootId);
    if (rootStatus != LookupStatus::Exists) return rootStatus;

    std::string id;
    auto status = FindDriveFolderStatus(std::to_string(accountId), rootId, &id);
    if (status == LookupStatus::Exists) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders[key] = id;
        if (outId) *outId = id;
    } else if (status == LookupStatus::Missing) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_missingFolders[key] = std::chrono::steady_clock::now();
    }
    return status;
}

GoogleDriveProvider::LookupStatus GoogleDriveProvider::LookupAppFolder(uint32_t accountId,
                                                                        uint32_t appId,
                                                                        std::string* outId) {
    static constexpr auto kNegativeCacheTTL = std::chrono::minutes(5);
    std::string key = "app_" + std::to_string(accountId) + "_" + std::to_string(appId);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find(key);
        if (it != m_folders.end()) {
            if (outId) *outId = it->second;
            return LookupStatus::Exists;
        }
        auto neg = m_missingFolders.find(key);
        if (neg != m_missingFolders.end()) {
            if (std::chrono::steady_clock::now() - neg->second < kNegativeCacheTTL)
                return LookupStatus::Missing;
            m_missingFolders.erase(neg); // expired
        }
    }

    std::string accountFolder;
    auto accountStatus = LookupAccountFolder(accountId, &accountFolder);
    if (accountStatus != LookupStatus::Exists) return accountStatus;

    std::string id;
    auto status = FindDriveFolderStatus(std::to_string(appId), accountFolder, &id);
    if (status == LookupStatus::Exists) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders[key] = id;
        if (outId) *outId = id;
    } else if (status == LookupStatus::Missing) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_missingFolders[key] = std::chrono::steady_clock::now();
    }
    return status;
}

std::string GoogleDriveProvider::CreateDriveFolder(const std::string& name,
                                                    const std::string& parentId) {
    auto meta = Json::Object();
    meta.objVal["name"] = Json::String(name);
    meta.objVal["mimeType"] = Json::String("application/vnd.google-apps.folder");
    if (!parentId.empty()) {
        auto arr = Json::Array();
        arr.arrVal.push_back(Json::String(parentId));
        meta.objVal["parents"] = std::move(arr);
    }
    auto r = ApiRequest("POST", "/drive/v3/files?fields=id", Json::Stringify(meta));
    if (r.status < 200 || r.status >= 300) {
        LOG("[GDrive] CreateFolder '%s' failed: HTTP %d", name.c_str(), r.status);
        return {};
    }
    return Json::Parse(r.body)["id"].str();
}

std::string GoogleDriveProvider::GetRootFolder() {
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find("root");
        if (it != m_folders.end()) return it->second;
    }
    std::string id;
    if (LookupRootFolder(&id) == LookupStatus::Exists) {
        if (!id.empty()) {
            std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
            m_folders["root"] = id;
        }
        return id;
    }
    // Serialize folder creation to prevent duplicate folders from concurrent workers
    std::lock_guard<std::recursive_mutex> createLock(m_folderCreateMtx);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find("root");
        if (it != m_folders.end()) return it->second;
    }
    id = CreateDriveFolder("CloudRedirect", "");
    if (!id.empty()) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders["root"] = id;
    }
    return id;
}

std::string GoogleDriveProvider::GetAccountFolder(uint32_t accountId) {
    std::string key = "acct_" + std::to_string(accountId);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find(key);
        if (it != m_folders.end()) return it->second;
    }
    std::string id;
    if (LookupAccountFolder(accountId, &id) == LookupStatus::Exists) {
        if (!id.empty()) {
            std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
            m_folders[key] = id;
        }
        return id;
    }
    // Serialize folder creation to prevent duplicate folders from concurrent workers
    std::lock_guard<std::recursive_mutex> createLock(m_folderCreateMtx);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find(key);
        if (it != m_folders.end()) return it->second;
    }
    auto root = GetRootFolder();
    if (root.empty()) return {};
    std::string name = std::to_string(accountId);
    id = CreateDriveFolder(name, root);
    if (!id.empty()) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders[key] = id;
        m_missingFolders.erase(key);
    }
    return id;
}

std::string GoogleDriveProvider::GetAppFolder(uint32_t accountId, uint32_t appId) {
    std::string key = "app_" + std::to_string(accountId) + "_" + std::to_string(appId);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find(key);
        if (it != m_folders.end()) return it->second;
    }
    std::string id;
    if (LookupAppFolder(accountId, appId, &id) == LookupStatus::Exists) {
        if (!id.empty()) {
            std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
            m_folders[key] = id;
        }
        return id;
    }
    // Serialize folder creation to prevent duplicate folders from concurrent workers
    std::lock_guard<std::recursive_mutex> createLock(m_folderCreateMtx);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find(key);
        if (it != m_folders.end()) return it->second;
    }
    auto acctFolder = GetAccountFolder(accountId);
    if (acctFolder.empty()) return {};
    std::string name = std::to_string(appId);
    id = CreateDriveFolder(name, acctFolder);
    if (!id.empty()) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders[key] = id;
        m_missingFolders.erase(key);
    }
    return id;
}

GoogleDriveProvider::LookupStatus GoogleDriveProvider::ResolveSubfolders(
    const std::string& parentId, const std::string& relDir, std::string* outId, bool create) {
    if (relDir.empty()) {
        if (outId) *outId = parentId;
        return LookupStatus::Exists;
    }

    // Only hold the creation mutex during CreateDriveFolder calls.
    // FindDriveFolder (network I/O) runs unlocked so other threads
    // can look up already-existing folders concurrently.
    std::unique_lock<std::recursive_mutex> createLock(m_folderCreateMtx, std::defer_lock);

    std::string current = parentId;
    size_t start = 0;
    while (start < relDir.size()) {
        size_t slash = relDir.find('/', start);
        std::string seg = (slash != std::string::npos) ?
            relDir.substr(start, slash - start) : relDir.substr(start);
        if (!seg.empty()) {
            std::string cacheKey = BuildChildCacheKey(current, seg);

            {
                std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
                auto it = m_folders.find(cacheKey);
                if (it != m_folders.end()) {
                    current = it->second;
                    start = (slash != std::string::npos) ? slash + 1 : relDir.size();
                    continue;
                }
            }

            std::string id = FindDriveFolder(seg, current);
            if (id.empty()) {
                if (!create) return LookupStatus::Missing;
                // Only hold creation mutex for the actual folder creation
                if (!createLock.owns_lock()) createLock.lock();
                // Double-check cache after acquiring the creation lock
                {
                    std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
                    auto it = m_folders.find(cacheKey);
                    if (it != m_folders.end()) {
                        current = it->second;
                        start = (slash != std::string::npos) ? slash + 1 : relDir.size();
                        continue;
                    }
                }
                id = CreateDriveFolder(seg, current);
            }
            if (id.empty()) return LookupStatus::Error;

            {
                std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
                m_folders[cacheKey] = id;
                current = id;
            }
        }
        start = (slash != std::string::npos) ? slash + 1 : relDir.size();
    }
    if (outId) *outId = current;
    return LookupStatus::Exists;
}

std::vector<GoogleDriveProvider::DriveFileInfo>
GoogleDriveProvider::ListFolder(const std::string& folderId, bool* ok) {
    std::vector<DriveFileInfo> result;
    if (ok) *ok = false;

    std::string q = "'" + EscapeQuery(folderId) + "' in parents and trashed=false";
    std::string baseUrl = "/drive/v3/files?q=" + UrlEncode(q) +
        "&fields=nextPageToken,files(id,name,mimeType,modifiedTime,size)&pageSize=1000";
    std::string pageToken;
    bool firstPage = true;

    do {
        std::string url = baseUrl;
        if (!pageToken.empty())
            url += "&pageToken=" + UrlEncode(pageToken);

        auto r = ApiGet(url);
        if (r.status == 404) {
            InvalidateFolderById(folderId);
            // First-page 404 = empty listing. Mid-pagination 404 means the
            // folder vanished between pages; partial result is unsafe to
            // mark complete, so report failure.
            if (firstPage) {
                if (ok) *ok = true;
            } else {
                LOG("[GDrive] ListFolder %s: mid-pagination 404; folder removed "
                    "between pages, reporting listing failure", folderId.c_str());
                // *ok remains false
            }
            return result;
        }
        if (r.status != 200) return result;
        firstPage = false;

        auto j = Json::Parse(r.body);
        auto& files = j["files"];
        for (size_t i = 0; i < files.size(); ++i) {
            DriveFileInfo df;
            df.id = files[i]["id"].str();
            df.name = files[i]["name"].str();
            df.modifiedTime = Iso8601ToUnix(files[i]["modifiedTime"].str());
            auto sizeStr = files[i]["size"].str();
            df.size = sizeStr.empty() ? 0 : strtoll(sizeStr.c_str(), nullptr, 10);
            df.isFolder = files[i]["mimeType"].str() == "application/vnd.google-apps.folder";
            result.push_back(std::move(df));
        }

        pageToken = j["nextPageToken"].str();
    } while (!pageToken.empty());

    std::unordered_map<std::string, size_t> fileCounts;
    fileCounts.reserve(result.size());
    for (const auto& item : result) {
        if (item.isFolder) continue;
        ++fileCounts[item.name];
    }
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        InvalidateFilesInFolder(folderId);
        for (const auto& item : result) {
            if (item.isFolder) continue;
            if (fileCounts[item.name] != 1) continue;
            auto key = BuildChildCacheKey(folderId, item.name);
            if (!key.empty()) m_files[key] = item.id;
        }
    }

    if (ok) *ok = true;
    return result;
}

static constexpr int MAX_RECURSION_DEPTH = 32;

bool GoogleDriveProvider::ListRecursive(const std::string& folderId, const std::string& prefix,
                                          std::vector<RemoteFile>& out,
                                          bool* outComplete, int depth) {
    if (depth >= MAX_RECURSION_DEPTH) {
        LOG("[GDrive] ListRecursive: max depth %d reached at %s, stopping",
            MAX_RECURSION_DEPTH, prefix.c_str());
        // Cap reached: not an error, but mark incomplete so destructive
        // prunes are suppressed.
        if (outComplete) *outComplete = false;
        return true;
    }
    bool ok = false;
    auto items = ListFolder(folderId, &ok);
    if (!ok) return false;
    for (auto& item : items) {
        std::string path = prefix.empty() ? item.name : prefix + "/" + item.name;
        if (item.isFolder) {
            if (!ListRecursive(item.id, path, out, outComplete, depth + 1)) return false;
        } else {
            out.push_back({item.id, path, item.modifiedTime, item.size});
        }
    }
    return true;
}

std::optional<std::vector<uint8_t>>
GoogleDriveProvider::DownloadFileById(const std::string& fileId) {
    auto r = ApiGet("/drive/v3/files/" + fileId + "?alt=media");
    if (r.status != 200) {
        LOG("[GDrive] DownloadFileById: HTTP %d", r.status);
        return std::nullopt;
    }
    return std::vector<uint8_t>(r.body.begin(), r.body.end());
}

std::vector<ICloudProvider::SearchHit>
GoogleDriveProvider::SearchByName(const std::string& filename, bool* outSupported) {
    if (outSupported) *outSupported = true;
    std::vector<SearchHit> hits;

    // Per-folder-id name resolution with a tiny local cache (account/app
    // folders repeat across hits). Returns "" on failure.
    std::unordered_map<std::string, std::pair<std::string, std::string>> folderInfo; // id -> {name, parentId}
    auto getFolder = [&](const std::string& id) -> std::pair<std::string, std::string> {
        auto it = folderInfo.find(id);
        if (it != folderInfo.end()) return it->second;
        auto r = ApiGet("/drive/v3/files/" + id + "?fields=name,parents");
        std::pair<std::string, std::string> info;
        if (r.status == 200) {
            auto j = Json::Parse(r.body);
            info.first = j["name"].str();
            auto& parents = j["parents"];
            if (parents.size() > 0) info.second = parents[(size_t)0].str();
        }
        folderInfo[id] = info;
        return info;
    };

    // Global search for the exact filename.
    std::string q = "name='" + EscapeQuery(filename) + "'"
                    " and mimeType!='application/vnd.google-apps.folder'"
                    " and trashed=false";
    std::string baseUrl = "/drive/v3/files?q=" + UrlEncode(q) +
        "&fields=nextPageToken,files(id,name,parents)&pageSize=1000";
    std::string pageToken;

    do {
        std::string url = baseUrl;
        if (!pageToken.empty()) url += "&pageToken=" + UrlEncode(pageToken);

        auto r = ApiGet(url);
        if (r.status != 200) {
            LOG("[GDrive] SearchByName('%s'): HTTP %d", filename.c_str(), r.status);
            if (hits.empty() && outSupported) *outSupported = (r.status == 404);
            return hits;
        }

        auto j = Json::Parse(r.body);
        auto& files = j["files"];
        for (size_t i = 0; i < files.size(); ++i) {
            std::string fileId = files[i]["id"].str();
            auto& parents = files[i]["parents"];
            if (parents.size() == 0) continue;

            // parent = appId folder, grandparent = accountId folder.
            std::string appFolderId = parents[(size_t)0].str();
            auto appInfo = getFolder(appFolderId);          // {appId, accountFolderId}
            if (appInfo.first.empty() || appInfo.second.empty()) continue;
            auto acctInfo = getFolder(appInfo.second);      // {accountId, rootFolderId}
            if (acctInfo.first.empty()) continue;

            // Only accept numeric account/app folder names (our layout).
            bool ok = !appInfo.first.empty() && !acctInfo.first.empty();
            for (char c : appInfo.first)  if (c < '0' || c > '9') { ok = false; break; }
            for (char c : acctInfo.first) if (c < '0' || c > '9') { ok = false; break; }
            if (!ok) continue;

            auto content = DownloadFileById(fileId);
            if (!content || content->empty()) continue;

            SearchHit hit;
            hit.path = acctInfo.first + "/" + appInfo.first + "/" + filename;
            hit.content = std::move(*content);
            hits.push_back(std::move(hit));
        }

        pageToken = j["nextPageToken"].str();
    } while (!pageToken.empty());

    LOG("[GDrive] SearchByName('%s'): %zu match(es)", filename.c_str(), hits.size());
    return hits;
}

GoogleDriveProvider::LookupStatus GoogleDriveProvider::FindFileInFolderStatus(
    const std::string& name, const std::string& folderId, std::string* outId) {
    std::string q = "name='" + EscapeQuery(name) + "'"
                    " and '" + EscapeQuery(folderId) + "' in parents"
                    " and mimeType!='application/vnd.google-apps.folder'"
                    " and trashed=false";
    auto r = ApiGet("/drive/v3/files?q=" + UrlEncode(q) +
                    "&fields=files(id,createdTime,size,modifiedTime)&orderBy=modifiedTime desc&pageSize=10");
    if (r.status == 404) {
        InvalidateFolderById(folderId);
        return LookupStatus::Missing;
    }
    if (r.status != 200) return LookupStatus::Error;
    auto j = Json::Parse(r.body);
    auto& files = j["files"];
    if (files.size() == 0) {
        InvalidateFileChild(folderId, name);
        return LookupStatus::Missing;
    }
    // Keep the most recently modified file (newest data wins in cross-PC races)
    std::string keepId = files[(size_t)0]["id"].str();
    if (files.size() > 1) {
        LOG("[GDrive] Duplicate file '%s' in folder %s (%zu copies); keeping newest id=%s, deleting rest",
            name.c_str(), folderId.c_str(), files.size(), keepId.c_str());
        for (size_t i = 1; i < files.size(); ++i) {
            std::string dupId = files[i]["id"].str();
            if (!DeleteById(dupId)) {
                LOG("[GDrive] WARNING: failed to delete duplicate file %s", dupId.c_str());
            }
        }
    }
    CacheFileChild(folderId, name, keepId);
    if (outId) *outId = keepId;
    return LookupStatus::Exists;
}

GoogleDriveProvider::DuplicateFileIdsResult GoogleDriveProvider::FindDuplicateFileIdsInFolder(
    const std::string& name, const std::string& folderId) {
    DuplicateFileIdsResult result;

    std::string q = "name='" + EscapeQuery(name) + "'"
                    " and '" + EscapeQuery(folderId) + "' in parents"
                    " and mimeType!='application/vnd.google-apps.folder'"
                    " and trashed=false";
    auto r = ApiGet("/drive/v3/files?q=" + UrlEncode(q) +
                    "&fields=files(id,modifiedTime)&orderBy=modifiedTime desc&pageSize=100");
    if (r.status == 404) {
        InvalidateFolderById(folderId);
        result.ok = true;
        return result;
    }
    if (r.status != 200) return result;

    auto j = Json::Parse(r.body);
    auto& files = j["files"];
    result.ids.reserve(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        result.ids.push_back(files[i]["id"].str());
    }
    result.ok = true;
    return result;
}

std::string GoogleDriveProvider::FindFileInFolder(const std::string& name,
                                                   const std::string& folderId) {
    std::string id;
    return FindFileInFolderStatus(name, folderId, &id) == LookupStatus::Exists ? id : std::string();
}

GoogleDriveProvider::UploadStatus GoogleDriveProvider::UploadOrUpdate(
    const std::string& name, const std::string& folderId,
    const uint8_t* data, size_t len, int64_t timestamp,
    const std::string& existingId) {
    auto token = GetAccessToken();
    if (token.empty()) return UploadStatus::Error;

    // metadata JSON
    auto meta = Json::Object();
    meta.objVal["name"] = Json::String(name);
    if (timestamp > 0)
        meta.objVal["modifiedTime"] = Json::String(UnixToIso8601(timestamp));
    if (existingId.empty()) {
        auto arr = Json::Array();
        arr.arrVal.push_back(Json::String(folderId));
        meta.objVal["parents"] = std::move(arr);
    }
    std::string metaJson = Json::Stringify(meta);

    // multipart body with random boundary
    char randHex[33];
    {
        uint8_t randBytes[16];
#ifdef _WIN32
        BCryptGenRandom(NULL, randBytes, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
        std::ifstream urandom("/dev/urandom", std::ios::binary);
        if (urandom) {
            urandom.read(reinterpret_cast<char*>(randBytes), 16);
        } else {
            auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
            std::mt19937 rng(static_cast<unsigned>(seed ^ reinterpret_cast<uintptr_t>(&meta)));
            for (int i = 0; i < 16; i++)
                randBytes[i] = (uint8_t)(rng() & 0xFF);
        }
#endif
        for (int i = 0; i < 16; i++)
            snprintf(randHex + i * 2, 3, "%02x", randBytes[i]);
    }
    std::string boundary = std::string("cr_") + randHex;
    std::string body;
    body.reserve(metaJson.size() + len + 256);
    body += "--"; body += boundary; body += "\r\n";
    body += "Content-Type: application/json; charset=UTF-8\r\n\r\n";
    body += metaJson;
    body += "\r\n--"; body += boundary; body += "\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append((const char*)data, len);
    body += "\r\n--"; body += boundary; body += "--\r\n";

    std::string path;
    const char* method;
    if (existingId.empty()) {
        path = "/upload/drive/v3/files?uploadType=multipart&fields=id";
        method = "POST";
    } else {
        path = "/upload/drive/v3/files/" + existingId + "?uploadType=multipart&fields=id";
        method = "PATCH";
    }

    std::vector<std::string> uploadHdrs = {
        "Authorization: Bearer " + token,
        std::string("Content-Type: multipart/related; boundary=") + boundary};

    HttpResp r;
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (attempt > 0) {
            std::this_thread::sleep_for(std::chrono::seconds(attempt));
            token = GetAccessToken();
            if (token.empty()) return UploadStatus::Error;
            uploadHdrs[0] = "Authorization: Bearer " + token;
        }
        ThrottleApiCall();
        r = Request(method, "www.googleapis.com", path, body, uploadHdrs);
        if (!IsRateLimited(r.status, r.body)) break;
        LOG("[GDrive] Rate limited (upload attempt %d), backing off %ds",
            attempt + 1, attempt + 1);
    }

    if (r.status == 404 && !existingId.empty()) {
        InvalidateFileChild(folderId, name);
        return UploadStatus::MissingTarget;
    }
    if (r.status < 200 || r.status >= 300) {
        LOG("[GDrive] Upload '%s' failed: HTTP %d", name.c_str(), r.status);
        return UploadStatus::Error;
    }
    auto uploadedId = Json::Parse(r.body)["id"].str();
    if (!uploadedId.empty()) {
        CacheFileChild(folderId, name, uploadedId);
    } else if (!existingId.empty()) {
        CacheFileChild(folderId, name, existingId);
    }
    return UploadStatus::Success;
}

bool GoogleDriveProvider::DeleteById(const std::string& fileId) {
    auto r = ApiRequest("DELETE", "/drive/v3/files/" + fileId, "", "");
    return r.status >= 200 && r.status < 300;
}

GoogleDriveProvider::LookupStatus GoogleDriveProvider::ResolvePath(uint32_t accountId, uint32_t appId,
                                                                    const std::string& filename,
                                                                    std::string& outParentId,
                                                                    std::string& outLeafName,
                                                                    bool create) {
    std::string appFolder;
    LookupStatus appStatus = create
        ? (GetAppFolder(accountId, appId).empty() ? LookupStatus::Error : LookupStatus::Exists)
        : LookupAppFolder(accountId, appId, &appFolder);
    if (create && appStatus == LookupStatus::Exists) {
        appFolder = GetAppFolder(accountId, appId);
        if (appFolder.empty()) return LookupStatus::Error;
    }
    if (appStatus != LookupStatus::Exists) return appStatus;

    size_t lastSlash = filename.rfind('/');
    std::string dirPart = (lastSlash != std::string::npos) ? filename.substr(0, lastSlash) : "";
    outLeafName = (lastSlash != std::string::npos) ? filename.substr(lastSlash + 1) : filename;
    if (dirPart.empty()) {
        outParentId = appFolder;
        return LookupStatus::Exists;
    }
    return ResolveSubfolders(appFolder, dirPart, &outParentId, create);
}

bool GoogleDriveProvider::DoDriveDelete(uint32_t accountId, uint32_t appId,
                                          const std::string& filename) {
    if (GetAccessToken().empty()) return false;

    std::string parentId, leafName;
    auto status = ResolvePath(accountId, appId, filename, parentId, leafName, /*create=*/false);
    if (status == LookupStatus::Missing) {
        LOG("[GDrive] %s not on Drive, nothing to delete", filename.c_str());
        return true;
    }
    if (status != LookupStatus::Exists) return false;

    auto duplicateLookup = FindDuplicateFileIdsInFolder(leafName, parentId);
    if (!duplicateLookup.ok) return false;
    if (duplicateLookup.ids.empty()) {
        LOG("[GDrive] %s not on Drive, nothing to delete", filename.c_str());
        return true;
    }
    bool ok = true;
    for (const auto& fileId : duplicateLookup.ids) {
        if (!DeleteById(fileId)) ok = false;
    }
    if (ok) {
        InvalidateFileChild(parentId, leafName);
        LOG("[GDrive] Deleted %s for acct %u app %u", filename.c_str(), accountId, appId);
    }
    return ok;
}

bool GoogleDriveProvider::Upload(const std::string& path,
                                  const uint8_t* data, size_t len) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("[GDriveProvider] Upload: bad path '%s'", path.c_str());
        return false;
    }

    std::string parentId, leafName;
    if (ResolvePath(accountId, appId, relFilename, parentId, leafName, /*create=*/true) != LookupStatus::Exists)
        return false;

    auto existingId = GetCachedFileId(leafName, parentId);
    UploadStatus uploadStatus = UploadStatus::Error;
    if (!existingId.empty()) {
        std::string verifiedId;
        auto verifyStatus = FindFileInFolderStatus(leafName, parentId, &verifiedId);
        if (verifyStatus == LookupStatus::Error) return false;
        if (verifyStatus == LookupStatus::Missing) {
            InvalidateFileChild(parentId, leafName);
            existingId.clear();
        } else if (verifiedId != existingId) {
            existingId = verifiedId;
        }
    }

    if (!existingId.empty()) {
        uploadStatus = UploadOrUpdate(leafName, parentId, data, len, 0, existingId);
        if (uploadStatus == UploadStatus::MissingTarget) {
            if (ResolvePath(accountId, appId, relFilename, parentId, leafName, /*create=*/true)
                != LookupStatus::Exists) {
                return false;
            }
            existingId = FindFileInFolder(leafName, parentId);
            uploadStatus = UploadOrUpdate(leafName, parentId, data, len, 0, existingId);
        }
    } else {
        existingId = FindFileInFolder(leafName, parentId);
        uploadStatus = UploadOrUpdate(leafName, parentId, data, len, 0, existingId);
        // Dedup check: delete stale copies if cross-PC race created duplicates.
        if (uploadStatus == UploadStatus::Success && existingId.empty()) {
            std::string verifiedId;
            FindFileInFolderStatus(leafName, parentId, &verifiedId);
        }
    }

    bool ok = uploadStatus == UploadStatus::Success;
    if (ok)
        LOG("[GDriveProvider] Uploaded %s (%zu bytes)", path.c_str(), len);
    else
        LOG("[GDriveProvider] Upload FAILED %s", path.c_str());
    return ok;
}

bool GoogleDriveProvider::UploadBatch(const std::vector<UploadItem>& items) {
    // Drive's batch API doesn't cover uploads, so each blob is an individual Upload().
    // Native uploads in parallel (convars @nClientCloudMaxNumParallelUploads=10,
    // @nClientCloudMaxMBParallelUploads=64MB); mirror that. Concurrent uploads are
    // safe: per-call request handles, distinct CAS paths, m_folderMtx-guarded folders.
    if (items.empty()) return true;

    // Per-batch throughput telemetry: wall time + rate-limit hit delta.
    auto batchStart = std::chrono::steady_clock::now();
    uint64_t rlBefore = g_rateLimitHits.load(std::memory_order_relaxed);

    static constexpr size_t kMaxParallel = 10;                 // native @nClientCloudMaxNumParallelUploads
    static constexpr uint64_t kMaxBytesInFlight = 64ull << 20; // native @nClientCloudMaxMBParallelUploads (64 MB)

    std::atomic<size_t> next{0};
    std::atomic<bool> failed{false};
    std::atomic<size_t> dedupSkips{0};        // CAS-existing blobs skipped in-worker
    std::mutex doneMtx;
    std::vector<std::string> uploadedPaths;   // for rollback, guarded by doneMtx

    // Worker: claim items by index until exhausted or a failure is seen.
    auto worker = [&]() {
        for (;;) {
            if (failed.load(std::memory_order_relaxed)) return;
            size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= items.size()) return;
            const UploadItem& item = items[i];
            // An exception escaping a std::thread entry calls std::terminate, so catch
            // here (bad_alloc is likelier with up to 10 buffers in flight).
            bool ok = false;
            try {
                // CAS dedup IN the parallel worker (native-faithful: mirrors
                // ClientBeginFileUpload's per-file EResult-29 server short-circuit,
                // IDA EYieldingUploadFile sub_1389119A0). Skip only on a definite
                // Exists; on Missing OR Error, upload (idempotent CAS path, so
                // treating an errored check as "must upload" never strands a blob).
                if (CheckExists(item.path) == ExistsStatus::Exists) {
                    dedupSkips.fetch_add(1, std::memory_order_relaxed);
                    ok = true;  // already durable; nothing to roll back
                } else {
                    ok = Upload(item.path, item.data.data(), item.data.size());
                    if (ok) {
                        std::lock_guard<std::mutex> lk(doneMtx);
                        uploadedPaths.push_back(item.path);
                    }
                }
            } catch (const std::exception& e) {
                LOG("[GDriveProvider] UploadBatch: worker threw on '%s': %s",
                    item.path.c_str(), e.what());
            } catch (...) {
                LOG("[GDriveProvider] UploadBatch: worker threw (unknown) on '%s'",
                    item.path.c_str());
            }
            if (!ok) {
                failed.store(true, std::memory_order_relaxed);
                LOG("[GDriveProvider] UploadBatch: failed to upload '%s'", item.path.c_str());
                return;
            }
        }
    };

    // Worker count = min(kMaxParallel, items), capped further by avg size so total
    // bytes in flight stay roughly under kMaxBytesInFlight.
    uint64_t totalBytes = 0;
    for (const auto& it : items) totalBytes += it.data.size();
    size_t byCount = (std::min)(kMaxParallel, items.size());
    size_t byBytes = byCount;
    if (totalBytes > kMaxBytesInFlight && items.size() > 1) {
        // Keep concurrent bytes roughly under the cap (avg item size based).
        uint64_t avg = totalBytes / items.size();
        if (avg > 0) {
            size_t cap = (size_t)(kMaxBytesInFlight / avg);
            byBytes = (cap < 1) ? 1 : cap;
        }
    }
    size_t workerCount = (std::min)(byCount, byBytes);
    if (workerCount < 1) workerCount = 1;

    std::vector<std::thread> pool;
    pool.reserve(workerCount);

    // Plain spawn-then-join worker pool. BMainLoop responsiveness is handled by the
    // CompleteBatch handler (PumpUntil at the active-coroutine level), not here -- the
    // coroutine is inactive this deep, so a yield would corrupt it.
    for (size_t t = 0; t < workerCount; ++t) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    if (failed.load(std::memory_order_relaxed)) {
        LOG("[GDriveProvider] UploadBatch: a parallel upload failed; rolling back %zu uploaded blob(s)",
            uploadedPaths.size());
        for (const auto& path : uploadedPaths) Remove(path);
        return false;
    }
    double elapsedSec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - batchStart).count();
    uint64_t rlHits = g_rateLimitHits.load(std::memory_order_relaxed) - rlBefore;
    double filesPerSec = elapsedSec > 0 ? items.size() / elapsedSec : 0.0;
    double mbPerSec = elapsedSec > 0 ? (totalBytes / (1024.0 * 1024.0)) / elapsedSec : 0.0;
    LOG("[GDriveProvider] UploadBatch: %zu file(s) (%zu uploaded, %zu CAS-skipped) "
        "with %zu parallel worker(s) in %.1fs (%.2f files/s, %.2f MB/s, %llu rate-limit hits)",
        items.size(), items.size() - dedupSkips.load(), dedupSkips.load(),
        workerCount, elapsedSec, filesPerSec, mbPerSec,
        (unsigned long long)rlHits);
    return true;
}

bool GoogleDriveProvider::Download(const std::string& path,
                                    std::vector<uint8_t>& outData) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("[GDriveProvider] Download: bad path '%s'", path.c_str());
        return false;
    }

    std::string parentId, leafName;
    auto status = ResolvePath(accountId, appId, relFilename, parentId, leafName, /*create=*/false);
    if (status == LookupStatus::Missing) {
        LOG("[GDriveProvider] Download: '%s' not found on Drive", path.c_str());
        return false;
    }
    if (status != LookupStatus::Exists)
        return false;

    auto fileId = FindFileInFolder(leafName, parentId);
    if (fileId.empty()) {
        LOG("[GDriveProvider] Download: '%s' not found on Drive", path.c_str());
        return false;
    }

    auto data = DownloadFileById(fileId);
    if (!data.has_value()) {
        LOG("[GDriveProvider] Download FAILED %s", path.c_str());
        return false;
    }

    outData = std::move(data.value());
    LOG("[GDriveProvider] Downloaded %s (%zu bytes)", path.c_str(), outData.size());
    return true;
}

bool GoogleDriveProvider::Remove(const std::string& path) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty()) {
        LOG("[GDriveProvider] Remove: bad path '%s'", path.c_str());
        return false;
    }

    bool ok = DoDriveDelete(accountId, appId, relFilename);
    if (ok)
        LOG("[GDriveProvider] Removed %s", path.c_str());
    return ok;
}

ICloudProvider::ExistsStatus GoogleDriveProvider::CheckExists(const std::string& path) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty())
        return ExistsStatus::Error;

    std::string parentId, leafName;
    auto status = ResolvePath(accountId, appId, relFilename, parentId, leafName, /*create=*/false);
    if (status == LookupStatus::Missing) return ExistsStatus::Missing;
    if (status != LookupStatus::Exists) return ExistsStatus::Error;

    auto fileStatus = FindFileInFolderStatus(leafName, parentId);
    if (fileStatus == LookupStatus::Exists) return ExistsStatus::Exists;
    if (fileStatus == LookupStatus::Missing) return ExistsStatus::Missing;
    return ExistsStatus::Error;
}

std::vector<ICloudProvider::FileInfo>
GoogleDriveProvider::List(const std::string& prefix) {
    std::vector<FileInfo> result;
    ListChecked(prefix, result);
    return result;
}

std::vector<std::string>
GoogleDriveProvider::ListSubfolders(const std::string& prefix) {
    // Used by CLI list-remote-app-ids to avoid full recursive enumeration.
    uint32_t accountId, appId;
    std::string relPrefix;
    if (!ParsePath(prefix, accountId, appId, relPrefix)) {
        return {};
    }

    // Only account-wide listing makes sense for subfolder enumeration
    if (appId != kNoAppId) {
        // For app-level prefix, fall back to default implementation
        return ICloudProvider::ListSubfolders(prefix);
    }

    std::string rootId;
    auto rootStatus = LookupRootFolder(&rootId);
    if (rootStatus != LookupStatus::Exists) return {};

    std::string accountFolder;
    auto accountStatus = LookupAccountFolder(accountId, &accountFolder);
    if (accountStatus != LookupStatus::Exists) return {};

    // List immediate children of account folder (folders only)
    bool ok = false;
    auto items = ListFolder(accountFolder, &ok);
    if (!ok) return {};

    std::vector<std::string> folders;
    for (auto& item : items) {
        if (item.isFolder) {
            folders.push_back(item.name);
        }
    }

    LOG("[GDriveProvider] ListSubfolders '%s': %zu folders", prefix.c_str(), folders.size());
    return folders;
}

bool GoogleDriveProvider::ListChecked(const std::string& prefix, std::vector<FileInfo>& result,
                                       bool* outComplete) {
    result.clear();
    if (outComplete) *outComplete = false;

    // Absent folder = complete-empty listing.
    auto returnComplete = [&]() {
        if (outComplete) *outComplete = true;
        return true;
    };

    uint32_t accountId, appId;
    std::string relPrefix;
    if (!ParsePath(prefix, accountId, appId, relPrefix)) {
        return false;
    }

    // Account-wide enumeration: walk the account folder and emit
    // {accountId}/<appId>/<rest> for every file under every app subfolder.
    if (appId == kNoAppId) {
        std::string rootId;
        auto rootStatus = LookupRootFolder(&rootId);
        if (rootStatus == LookupStatus::Error) return false;
        if (rootStatus == LookupStatus::Missing) return returnComplete();

        std::string accountFolder;
        auto accountStatus = LookupAccountFolder(accountId, &accountFolder);
        if (accountStatus == LookupStatus::Error) return false;
        if (accountStatus == LookupStatus::Missing) return returnComplete();

        std::vector<RemoteFile> remoteFiles;
        bool recursiveComplete = true;
        if (!ListRecursive(accountFolder, "", remoteFiles, &recursiveComplete)) {
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

        LOG("[GDriveProvider] List '%s': %zu files (complete=%d)",
            prefix.c_str(), result.size(), (int)recursiveComplete);
        if (outComplete) *outComplete = recursiveComplete;
        return true;
    }

    std::string appFolder;
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find("app_" + std::to_string(accountId) + "_" + std::to_string(appId));
        if (it != m_folders.end()) appFolder = it->second;
    }
    if (appFolder.empty()) {
        auto appStatus = LookupAppFolder(accountId, appId, &appFolder);
        if (appStatus == LookupStatus::Error) return false;
        if (appStatus == LookupStatus::Missing) return returnComplete();

        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders["app_" + std::to_string(accountId) + "_" + std::to_string(appId)] = appFolder;
    }

    // Resolve any sub-prefix (e.g. "blobs/") to its subfolder.
    std::string listRoot = appFolder;
    std::string pathPrefix;
    if (!relPrefix.empty()) {
        std::string dir = relPrefix;
        if (!dir.empty() && dir.back() == '/') dir.pop_back();
        std::stringstream ss(dir);
        std::string part;
        while (std::getline(ss, part, '/')) {
            if (part.empty()) continue;
            std::string nextId;
            auto status = FindDriveFolderStatus(part, listRoot, &nextId);
            if (status == LookupStatus::Error) return false;
            if (status == LookupStatus::Missing) return returnComplete();
            listRoot = std::move(nextId);
        }
        pathPrefix = relPrefix;
        if (!pathPrefix.empty() && pathPrefix.back() != '/') pathPrefix += '/';
    }

    // Local flag so the recursion can downgrade completeness independently.
    std::vector<RemoteFile> remoteFiles;
    bool recursiveComplete = true;
    if (!ListRecursive(listRoot, "", remoteFiles, &recursiveComplete)) {
        return false;
    }

    std::string basePrefix = std::to_string(accountId) + "/" + std::to_string(appId) + "/";
    if (!pathPrefix.empty()) basePrefix += pathPrefix;

    result.reserve(remoteFiles.size());
    for (auto& rf : remoteFiles) {
        FileInfo fi;
        fi.path = basePrefix + rf.relativePath;
        fi.size = (uint64_t)rf.size;
        fi.modifiedTime = (uint64_t)rf.modifiedTime;
        result.push_back(std::move(fi));
    }

    LOG("[GDriveProvider] List '%s': %zu files (complete=%d)",
        prefix.c_str(), result.size(), (int)recursiveComplete);
    if (outComplete) *outComplete = recursiveComplete;
    return true;
}
