#include "google_drive_provider.h"
#include "http_util.h"
#include "json.h"
#include "log.h"

#include <wincrypt.h>
#include <ctime>
#include <sstream>

#pragma comment(lib, "Advapi32.lib")

using HttpUtil::Widen;
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
    return status == 403 && body.find("rateLimitExceeded") != std::string::npos;
}

std::string GoogleDriveProvider::EscapeQuery(const std::string& s) const {
    std::string out;
    for (char c : s) {
        if (c == '\'') out += "\\'";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
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
    if (files.size() == 0) return LookupStatus::Missing;
    // Keep the oldest folder (first by createdTime ascending)
    std::string keepId = files[(size_t)0]["id"].str();
    // clean up duplicate folders (can happen from eventual consistency)
    for (size_t i = 1; i < files.size(); ++i) {
        std::string dupId = files[i]["id"].str();
        LOG("[GDrive] Deleting duplicate folder '%s' (id=%s, keeping %s)",
            name.c_str(), dupId.c_str(), keepId.c_str());
        DeleteById(dupId);
    }
    if (outId) *outId = keepId;
    return LookupStatus::Exists;
}

std::string GoogleDriveProvider::FindDriveFolder(const std::string& name,
                                                  const std::string& parentId) {
    std::string id;
    return FindDriveFolderStatus(name, parentId, &id) == LookupStatus::Exists ? id : std::string();
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
        LOG("[GDrive] CreateFolder '%s' failed: HTTP %d: %s",
            name.c_str(), r.status, r.body.c_str());
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
    // Serialize folder creation to prevent duplicate folders from concurrent workers
    std::lock_guard<std::recursive_mutex> createLock(m_folderCreateMtx);
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        auto it = m_folders.find("root");
        if (it != m_folders.end()) return it->second;
    }
    std::string id = FindDriveFolder("CloudRedirect", "");
    if (id.empty()) id = CreateDriveFolder("CloudRedirect", "");
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
    std::string id = FindDriveFolder(name, root);
    if (id.empty()) id = CreateDriveFolder(name, root);
    if (!id.empty()) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders[key] = id;
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
    std::string id = FindDriveFolder(name, acctFolder);
    if (id.empty()) id = CreateDriveFolder(name, acctFolder);
    if (!id.empty()) {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        m_folders[key] = id;
    }
    return id;
}

bool GoogleDriveProvider::HasAppFolder(uint32_t accountId, uint32_t appId) {
    std::string rootId;
    {
        std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
        std::string key = "app_" + std::to_string(accountId) + "_" + std::to_string(appId);
        if (m_folders.find(key) != m_folders.end()) return true;
        auto rootIt = m_folders.find("root");
        if (rootIt != m_folders.end()) rootId = rootIt->second;
    }
    if (rootId.empty()) rootId = FindDriveFolder("CloudRedirect", "");
    if (rootId.empty()) return false;
    std::string acctId = FindDriveFolder(std::to_string(accountId), rootId);
    if (acctId.empty()) return false;
    std::string appFolderId = FindDriveFolder(std::to_string(appId), acctId);
    return !appFolderId.empty();
}

std::string GoogleDriveProvider::EnsureSubfolders(const std::string& parentId,
                                                   const std::string& relDir,
                                                   bool create) {
    if (relDir.empty()) return parentId;
    // Serialize folder creation to prevent duplicate folders from concurrent workers
    std::lock_guard<std::recursive_mutex> createLock(m_folderCreateMtx);
    std::string current = parentId;
    size_t start = 0;
    while (start < relDir.size()) {
        size_t slash = relDir.find('/', start);
        std::string seg = (slash != std::string::npos) ?
            relDir.substr(start, slash - start) : relDir.substr(start);
        if (!seg.empty()) {
            std::string cacheKey = current + "/" + seg;

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
                if (!create) return {};
                id = CreateDriveFolder(seg, current);
            }
            if (id.empty()) return {};

            {
                std::lock_guard<std::recursive_mutex> lock(m_folderMtx);
                m_folders[cacheKey] = id;
                current = id;
            }
        }
        start = (slash != std::string::npos) ? slash + 1 : relDir.size();
    }
    return current;
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

GoogleDriveProvider::LookupStatus GoogleDriveProvider::FindFileInFolderStatus(
    const std::string& name, const std::string& folderId, std::string* outId) {
    std::string q = "name='" + EscapeQuery(name) + "'"
                    " and '" + EscapeQuery(folderId) + "' in parents"
                    " and mimeType!='application/vnd.google-apps.folder'"
                    " and trashed=false";
    auto r = ApiGet("/drive/v3/files?q=" + UrlEncode(q) + "&fields=files(id)&pageSize=1");
    if (r.status == 404) {
        InvalidateFolderById(folderId);
        return LookupStatus::Missing;
    }
    if (r.status != 200) return LookupStatus::Error;
    auto j = Json::Parse(r.body);
    auto& files = j["files"];
    if (files.size() == 0) return LookupStatus::Missing;
    if (outId) *outId = files[(size_t)0]["id"].str();
    return LookupStatus::Exists;
}

std::string GoogleDriveProvider::FindFileInFolder(const std::string& name,
                                                   const std::string& folderId) {
    std::string id;
    return FindFileInFolderStatus(name, folderId, &id) == LookupStatus::Exists ? id : std::string();
}

bool GoogleDriveProvider::UploadOrUpdate(const std::string& name, const std::string& folderId,
                                          const uint8_t* data, size_t len, int64_t timestamp,
                                          const std::string& existingId) {
    auto token = GetAccessToken();
    if (token.empty()) return false;

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
        HCRYPTPROV hProv = 0;
        BYTE randBytes[16];
        if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hProv, sizeof(randBytes), randBytes);
            CryptReleaseContext(hProv, 0);
        } else {
            auto t = GetTickCount64();
            memcpy(randBytes, &t, 8);
            auto p = (uintptr_t)&meta;
            memcpy(randBytes + 8, &p, 8);
        }
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
            Sleep(attempt * 1000);
            token = GetAccessToken();
            if (token.empty()) return false;
            uploadHdrs[0] = "Authorization: Bearer " + token;
        }
        ThrottleApiCall();
        r = Request(method, "www.googleapis.com", path, body, uploadHdrs);
        if (!IsRateLimited(r.status, r.body)) break;
        LOG("[GDrive] Rate limited (upload attempt %d), backing off %ds",
            attempt + 1, attempt + 1);
    }

    if (r.status < 200 || r.status >= 300) {
        LOG("[GDrive] Upload '%s' failed: HTTP %d: %s", name.c_str(), r.status, r.body.c_str());
        return false;
    }
    return true;
}

bool GoogleDriveProvider::DeleteById(const std::string& fileId) {
    auto r = ApiRequest("DELETE", "/drive/v3/files/" + fileId, "", "");
    return r.status >= 200 && r.status < 300;
}

bool GoogleDriveProvider::ResolvePath(uint32_t accountId, uint32_t appId,
                                       const std::string& filename,
                                       std::string& outParentId, std::string& outLeafName) {
    auto appFolder = GetAppFolder(accountId, appId);
    if (appFolder.empty()) return false;

    size_t lastSlash = filename.rfind('/');
    std::string dirPart = (lastSlash != std::string::npos) ? filename.substr(0, lastSlash) : "";
    outLeafName = (lastSlash != std::string::npos) ? filename.substr(lastSlash + 1) : filename;
    outParentId = dirPart.empty() ? appFolder : EnsureSubfolders(appFolder, dirPart);
    return !outParentId.empty();
}

bool GoogleDriveProvider::DoDriveDelete(uint32_t accountId, uint32_t appId,
                                         const std::string& filename) {
    if (GetAccessToken().empty()) return false;

    std::string parentId, leafName;
    if (!ResolvePath(accountId, appId, filename, parentId, leafName)) return false;

    auto fileId = FindFileInFolder(leafName, parentId);
    if (fileId.empty()) {
        LOG("[GDrive] %s not on Drive, nothing to delete", filename.c_str());
        return true;
    }
    bool ok = DeleteById(fileId);
    if (ok)
        LOG("[GDrive] Deleted %s for acct %u app %u", filename.c_str(), accountId, appId);
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
    if (!ResolvePath(accountId, appId, relFilename, parentId, leafName))
        return false;

    auto existingId = FindFileInFolder(leafName, parentId);
    bool ok = UploadOrUpdate(leafName, parentId, data, len, 0, existingId);
    if (ok)
        LOG("[GDriveProvider] Uploaded %s (%zu bytes)", path.c_str(), len);
    else
        LOG("[GDriveProvider] Upload FAILED %s", path.c_str());
    return ok;
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
    if (!ResolvePath(accountId, appId, relFilename, parentId, leafName))
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

bool GoogleDriveProvider::Exists(const std::string& path) {
    return CheckExists(path) == ExistsStatus::Exists;
}

ICloudProvider::ExistsStatus GoogleDriveProvider::CheckExists(const std::string& path) {
    uint32_t accountId, appId;
    std::string relFilename;
    if (!ParsePath(path, accountId, appId, relFilename) || relFilename.empty())
        return ExistsStatus::Error;

    std::string rootId;
    auto rootStatus = FindDriveFolderStatus("CloudRedirect", "", &rootId);
    if (rootStatus == LookupStatus::Error) return ExistsStatus::Error;
    if (rootStatus == LookupStatus::Missing) return ExistsStatus::Missing;

    std::string accountFolder;
    auto accountStatus = FindDriveFolderStatus(std::to_string(accountId), rootId, &accountFolder);
    if (accountStatus == LookupStatus::Error) return ExistsStatus::Error;
    if (accountStatus == LookupStatus::Missing) return ExistsStatus::Missing;

    std::string appFolder;
    auto appStatus = FindDriveFolderStatus(std::to_string(appId), accountFolder, &appFolder);
    if (appStatus == LookupStatus::Error) return ExistsStatus::Error;
    if (appStatus == LookupStatus::Missing) return ExistsStatus::Missing;

    size_t lastSlash = relFilename.rfind('/');
    std::string dirPart = (lastSlash != std::string::npos) ? relFilename.substr(0, lastSlash) : "";
    std::string leafName = (lastSlash != std::string::npos) ? relFilename.substr(lastSlash + 1) : relFilename;
    std::string parentId = appFolder;
    if (!dirPart.empty()) {
        std::stringstream ss(dirPart);
        std::string part;
        while (std::getline(ss, part, '/')) {
            if (part.empty()) continue;
            std::string nextId;
            auto partStatus = FindDriveFolderStatus(part, parentId, &nextId);
            if (partStatus == LookupStatus::Error) return ExistsStatus::Error;
            if (partStatus == LookupStatus::Missing) return ExistsStatus::Missing;
            parentId = std::move(nextId);
        }
    }

    auto status = FindFileInFolderStatus(leafName, parentId);
    if (status == LookupStatus::Exists) return ExistsStatus::Exists;
    if (status == LookupStatus::Missing) return ExistsStatus::Missing;
    return ExistsStatus::Error;
}

std::vector<ICloudProvider::FileInfo>
GoogleDriveProvider::List(const std::string& prefix) {
    std::vector<FileInfo> result;
    ListChecked(prefix, result);
    return result;
}

bool GoogleDriveProvider::ListChecked(const std::string& prefix, std::vector<FileInfo>& result,
                                       bool* outComplete) {
    result.clear();
    // Pessimistic default; only the verified-complete success path sets true.
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
        auto rootStatus = FindDriveFolderStatus("CloudRedirect", "", &rootId);
        if (rootStatus == LookupStatus::Error) return false;
        if (rootStatus == LookupStatus::Missing) return returnComplete();

        std::string accountFolder;
        auto accountStatus = FindDriveFolderStatus(std::to_string(accountId), rootId, &accountFolder);
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
        std::string rootId;
        auto rootStatus = FindDriveFolderStatus("CloudRedirect", "", &rootId);
        if (rootStatus == LookupStatus::Error) return false;
        if (rootStatus == LookupStatus::Missing) return returnComplete();

        std::string accountFolder;
        auto accountStatus = FindDriveFolderStatus(std::to_string(accountId), rootId, &accountFolder);
        if (accountStatus == LookupStatus::Error) return false;
        if (accountStatus == LookupStatus::Missing) return returnComplete();

        auto appStatus = FindDriveFolderStatus(std::to_string(appId), accountFolder, &appFolder);
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
