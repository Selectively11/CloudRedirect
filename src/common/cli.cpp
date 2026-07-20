// CLI mode implementation for cloud_redirect
// Enables the DLL/so to be invoked directly for provider management

#include "cli.h"
#include "legacy_metadata_cleanup.h"
#include "cloud_storage.h"
#include "app_state.h"
#include "local_storage.h"
#include "pending_ops_journal.h"
#include "cloud_provider.h"
#include "file_util.h"
#include "json.h"
#include "log.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <sstream>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <unordered_set>

#ifdef _WIN32
#include <Windows.h>
#include <Shlobj.h>
#else
#include <unistd.h>
#include <pwd.h>
#include "xdg.h"
#endif

namespace CloudRedirectCli {

static std::string GetConfigDir() {
#ifdef _WIN32
    wchar_t* appDataPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appDataPath))) {
        int len = WideCharToMultiByte(CP_UTF8, 0, appDataPath, -1, nullptr, 0, nullptr, nullptr);
        std::string result(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, appDataPath, -1, result.data(), len, nullptr, nullptr);
        CoTaskMemFree(appDataPath);
        return result + "\\CloudRedirect\\";
    }
    return "";
#else
    return XdgConfigHome() + "/CloudRedirect/";
#endif
}

static std::string GetTokenPath(const std::string& provider) {
    std::string configDir = GetConfigDir();
    if (configDir.empty()) return "";

    std::string configJson;
    std::string configPath = configDir + "config.json";
    FILE* f = fopen(configPath.c_str(), "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        if (len >= 0) {
            rewind(f);
            configJson.resize((size_t)len);
            size_t read = fread(configJson.data(), 1, (size_t)len, f);
            configJson.resize(read);
        }
        fclose(f);
    }

    return ResolveProviderTokenPath(configDir, configJson, provider);
}

static std::string NormalizeCloudRoot(std::string cloudRoot) {
    if (cloudRoot.empty()) return cloudRoot;
#ifdef _WIN32
    if (cloudRoot.back() != '\\' && cloudRoot.back() != '/') cloudRoot += '\\';
#else
    if (cloudRoot.back() != '/') cloudRoot += '/';
#endif
    return cloudRoot;
}

static std::string JsonEscape(const std::string& s) {
    std::ostringstream out;
    for (char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << c;
        }
    }
    return out.str();
}

static std::string JsonObject(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::ostringstream out;
    out << "{";
    bool first = true;
    for (const auto& [key, value] : fields) {
        if (!first) out << ",";
        out << "\"" << key << "\":" << value;
        first = false;
    }
    out << "}";
    return out.str();
}

// initializer_list overload so existing call sites using brace lists keep
// working; forwards to the vector implementation.
static std::string JsonObject(std::initializer_list<std::pair<std::string, std::string>> fields) {
    return JsonObject(std::vector<std::pair<std::string, std::string>>(fields));
}

static std::string JsonString(const std::string& s) {
    return "\"" + JsonEscape(s) + "\"";
}

static std::string JsonBool(bool b) {
    return b ? "true" : "false";
}

static std::string JsonInt(int64_t n) {
    return std::to_string(n);
}

static std::string JsonError(const std::string& message) {
    return JsonObject({{"success", JsonBool(false)}, {"error", JsonString(message)}});
}

static std::string JsonSuccess() {
    return JsonObject({{"success", JsonBool(true)}});
}

std::string CmdAuthStatus(const std::string& provider) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }
    
    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    
    if (!prov->Init(tokenPath)) {
        return JsonObject({
            {"authenticated", JsonBool(false)},
            {"error", JsonString("Failed to initialize provider")}
        });
    }
    
    bool authenticated = prov->IsAuthenticated();
    prov->Shutdown();
    
    return JsonObject({
        {"authenticated", JsonBool(authenticated)},
        {"token_path", JsonString(tokenPath)}
    });
}

std::string CmdListRemoteApps(const std::string& provider, const std::string& accountId) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }
    
    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    
    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }
    
    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    // List app folders first, then per-app stats (avoids heavy recursive listing).
    std::string prefix = accountId + "/";
    auto appIds = prov->ListSubfolders(prefix);
    std::map<std::string, std::pair<int, uint64_t>> appStats; // appId -> (count, totalSize)
    for (const auto& appId : appIds) {
        if (appId.empty()) continue;

        std::vector<ICloudProvider::FileInfo> files;
        if (!prov->ListChecked(prefix + appId + "/", files)) {
            prov->Shutdown();
            return JsonError("Failed to list remote app " + appId);
        }

        auto& stats = appStats[appId];
        for (const auto& f : files) {
            stats.first++;
            stats.second += f.size;
        }
    }
    prov->Shutdown();
    
    // Build JSON array
    std::ostringstream apps;
    apps << "[";
    bool first = true;
    for (const auto& [appId, stats] : appStats) {
        if (!first) apps << ",";
        apps << JsonObject({
            {"app_id", JsonString(appId)},
            {"file_count", JsonInt(stats.first)},
            {"total_size", JsonInt(static_cast<int64_t>(stats.second))}
        });
        first = false;
    }
    apps << "]";
    
    return JsonObject({
        {"success", JsonBool(true)},
        {"apps", apps.str()}
    });
}

std::string CmdListRemoteAppIds(const std::string& provider, const std::string& accountId) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }
    
    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    
    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }
    
    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }
    
    std::string prefix = accountId + "/";
    auto folders = prov->ListSubfolders(prefix);
    prov->Shutdown();
    
    // Build JSON array of app IDs
    std::ostringstream ids;
    ids << "[";
    bool first = true;
    for (const auto& name : folders) {
        if (!first) ids << ",";
        ids << JsonString(name);
        first = false;
    }
    ids << "]";
    
    return JsonObject({
        {"success", JsonBool(true)},
        {"app_ids", ids.str()}
    });
}

std::string CmdListRemoteAppFiles(const std::string& provider, const std::string& accountId, const std::string& appId) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }

    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }

    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    std::string prefix = accountId + "/" + appId + "/";
    std::vector<ICloudProvider::FileInfo> files;
    bool complete = false;
    if (!prov->ListChecked(prefix, files, &complete)) {
        prov->Shutdown();
        return JsonObject({
            {"success", JsonBool(false)},
            {"complete", JsonBool(false)},
            {"error", JsonString("Failed to list remote app files")},
            {"files", "[]"}
        });
    }
    prov->Shutdown();

    std::ostringstream out;
    out << "[";
    bool first = true;
    for (const auto& f : files) {
        if (!first) out << ",";
        out << JsonObject({
            {"path", JsonString(f.path)},
            {"size", JsonInt(static_cast<int64_t>(f.size))},
            {"modified_time", JsonInt(static_cast<int64_t>(f.modifiedTime))}
        });
        first = false;
    }
    out << "]";

    return JsonObject({
        {"success", JsonBool(true)},
        {"complete", JsonBool(complete)},
        {"files", out.str()}
    });
}

std::string CmdDeleteRemoteApp(const std::string& provider, const std::string& accountId, const std::string& appId) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }
    
    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    
    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }
    
    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }
    
    // List all files under accountId/appId/ and delete them
    std::string prefix = accountId + "/" + appId + "/";
    auto files = prov->List(prefix);
    
    int deleted = 0;
    int failed = 0;
    for (const auto& f : files) {
        if (prov->Remove(f.path)) {
            deleted++;
        } else {
            failed++;
        }
    }
    
    prov->Shutdown();
    
    return JsonObject({
        {"success", JsonBool(failed == 0)},
        {"deleted", JsonInt(deleted)},
        {"failed", JsonInt(failed)}
    });
}

std::string CmdListBlobs(const std::string& provider, const std::string& accountId, const std::string& appId) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }
    
    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    
    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }
    
    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }
    
    std::string prefix = accountId + "/" + appId + "/blobs/";
    std::vector<ICloudProvider::FileInfo> files;
    bool complete = false;
    if (!prov->ListChecked(prefix, files, &complete)) {
        prov->Shutdown();
        return JsonObject({
            {"success", JsonBool(false)},
            {"complete", JsonBool(false)},
            {"error", JsonString("Failed to list blobs")},
            {"blobs", "[]"}
        });
    }
    prov->Shutdown();
    
    // Extract just the blob filenames (not full paths)
    std::ostringstream blobs;
    blobs << "[";
    bool first = true;
    for (const auto& f : files) {
        if (f.path.back() == '/') continue;

        std::string filename;
        if (f.path.size() > prefix.size()) {
            filename = f.path.substr(prefix.size());
            if (filename.find('/') != std::string::npos) continue;
        } else {
            continue;
        }
        
        if (!first) blobs << ",";
        blobs << JsonString(filename);
        first = false;
    }
    blobs << "]";
    
    return JsonObject({
        {"success", JsonBool(true)},
        {"complete", JsonBool(complete)},
        {"blobs", blobs.str()}
    });
}

// Search cloud for all stats.json files; returns JSON array of {account_id, app_id, content}.
std::string CmdListAllStats(const std::string& provider) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }
    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    bool supported = false;
    auto hits = prov->SearchByName("stats.json", &supported);
    prov->Shutdown();

    if (!supported) {
        return JsonError("Search not supported for provider: " + provider);
    }

    const std::string accountScope = "0";
    std::unordered_set<std::string> seen;  // "<account>/<app>"
    std::ostringstream apps;
    apps << "[";
    bool first = true;

    auto emit = [&](const std::string& accountId, const std::string& appId,
                    const std::string& content) {
        if (!seen.insert(accountId + "/" + appId).second) return;
        if (!first) apps << ",";
        apps << JsonObject({
            {"account_id", JsonString(accountId)},
            {"app_id", JsonString(appId)},
            {"content", JsonString(content)}
        });
        first = false;
    };

    // Pass 1: account-scope blobs first so they win de-dup over legacy files.
    // Pass 2: legacy per-app blobs for un-migrated apps.
    for (int pass = 0; pass < 2; ++pass) {
        for (const auto& h : hits) {
            // h.path is "<accountId>/<appId>/stats.json".
            size_t s1 = h.path.find('/');
            if (s1 == std::string::npos) continue;
            size_t s2 = h.path.find('/', s1 + 1);
            if (s2 == std::string::npos) continue;
            std::string accountId = h.path.substr(0, s1);
            std::string appId = h.path.substr(s1 + 1, s2 - s1 - 1);
            bool isAccountBlob = (appId == accountScope);
            if (isAccountBlob != (pass == 0)) continue;
            std::string content(
                reinterpret_cast<const char*>(h.content.data()), h.content.size());

            if (isAccountBlob) {
                // {"<appId>": {stats...}} -> one entry per app.
                Json::Value root = Json::Parse(content);
                if (root.type != Json::Type::Object) continue;
                for (const auto& [appIdStr, appVal] : root.objVal) {
                    if (appIdStr == accountScope) continue;
                    emit(accountId, appIdStr, Json::Stringify(appVal));
                }
            } else {
                emit(accountId, appId, content);
            }
        }
    }
    apps << "]";
    return std::string("{\"success\":true,\"apps\":") + apps.str() + "}";
}

std::string CmdDownloadBlob(const std::string& provider, const std::string& accountId,
                            const std::string& appId, const std::string& blobName) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }

    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }

    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    std::string path = accountId + "/" + appId + "/" + blobName;
    std::vector<uint8_t> data;
    bool ok = prov->Download(path, data);
    prov->Shutdown();

    if (!ok) {
        return JsonObject({
            {"success", JsonBool(false)},
            {"found", JsonBool(false)},
            {"error", JsonString("Blob not found")}
        });
    }

    std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    return JsonObject({
        {"success", JsonBool(true)},
        {"found", JsonBool(true)},
        {"content", JsonString(content)}
    });
}

std::string CmdDeleteBlobs(const std::string& provider, const std::string& accountId, const std::string& appId,
                           const std::vector<std::string>& blobNames) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }
    
    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    
    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }
    
    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }
    
    std::string blobDir = accountId + "/" + appId + "/blobs/";
    int deleted = 0;
    int failed = 0;
    std::ostringstream failedNames;
    failedNames << "[";
    bool firstFailed = true;
    
    for (const auto& name : blobNames) {
        if (name.find('/') != std::string::npos || 
            name.find('\\') != std::string::npos ||
            name == ".." || name == ".") {
            failed++;
            if (!firstFailed) failedNames << ",";
            failedNames << JsonString(name);
            firstFailed = false;
            continue;
        }
        
        std::string path = blobDir + name;
        if (prov->Remove(path)) {
            deleted++;
        } else {
            deleted++; // idempotent: treat absent as success
        }
    }
    failedNames << "]";
    
    prov->Shutdown();
    
    return JsonObject({
        {"success", JsonBool(failed == 0)},
        {"deleted", JsonInt(deleted)},
        {"failed", JsonInt(failed)},
        {"failed_names", failedNames.str()}
    });
}

std::string CmdSyncRemoteApp(const std::string& provider, const std::string& accountId, const std::string& appId,
                             const std::string& cloudRootArg) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    uint32_t parsedAccountId = static_cast<uint32_t>(std::strtoul(accountId.c_str(), nullptr, 10));
    uint32_t parsedAppId = static_cast<uint32_t>(std::strtoul(appId.c_str(), nullptr, 10));
    if (parsedAccountId == 0 || parsedAppId == 0) {
        return JsonError("Invalid account_id or app_id");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }

    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }

    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    std::string cloudRoot = NormalizeCloudRoot(cloudRootArg);
    if (cloudRoot.empty()) {
        prov->Shutdown();
        return JsonError("cloud_root is required");
    }
    std::string storageRoot = cloudRoot + "storage/";
#ifdef _WIN32
    for (auto& c : storageRoot) { if (c == '/') c = '\\'; }
#endif

    LocalStorage::Init(storageRoot);
    LocalMetadataStore::Init(storageRoot);
    LocalStorage::InitApp(parsedAccountId, parsedAppId);
    LocalMetadataStore::InitApp(parsedAccountId, parsedAppId);
    PendingOpsJournal::Init(storageRoot);
    CloudStorage::Init(cloudRoot, std::move(prov));

    bool hadNewer = CloudStorage::SyncFromCloud(parsedAccountId, parsedAppId);
    bool drained = CloudWorkQueue::DrainQueueForApp(parsedAccountId, parsedAppId);
    uint64_t localCN = LocalStorage::GetChangeNumber(parsedAccountId, parsedAppId);
    auto localFiles = LocalStorage::GetFileList(parsedAccountId, parsedAppId);
    auto rootTokens = LocalMetadataStore::LoadRootTokens(parsedAccountId, parsedAppId);
    auto fileTokens = LocalMetadataStore::LoadFileTokens(parsedAccountId, parsedAppId);

    CloudStorage::Shutdown();

    return JsonObject({
        {"success", JsonBool(drained)},
        {"had_newer", JsonBool(hadNewer)},
        {"drained", JsonBool(drained)},
        {"local_cn", JsonInt(static_cast<int64_t>(localCN))},
        {"local_file_count", JsonInt(static_cast<int64_t>(localFiles.size()))},
        {"root_token_count", JsonInt(static_cast<int64_t>(rootTokens.size()))},
        {"file_token_count", JsonInt(static_cast<int64_t>(fileTokens.size()))}
    });
}

std::string CmdSyncAllRemoteApps(const std::string& provider, const std::string& accountId,
                                 const std::string& cloudRootArg) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    uint32_t parsedAccountId = static_cast<uint32_t>(std::strtoul(accountId.c_str(), nullptr, 10));
    if (parsedAccountId == 0) {
        return JsonError("Invalid account_id");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }

    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }

    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    std::string cloudRoot = NormalizeCloudRoot(cloudRootArg);
    if (cloudRoot.empty()) {
        prov->Shutdown();
        return JsonError("cloud_root is required");
    }
    std::string storageRoot = cloudRoot + "storage/";
#ifdef _WIN32
    for (auto& c : storageRoot) { if (c == '/') c = '\\'; }
#endif

    LocalStorage::Init(storageRoot);
    LocalMetadataStore::Init(storageRoot);
    PendingOpsJournal::Init(storageRoot);
    CloudStorage::Init(cloudRoot, std::move(prov));

    auto syncedApps = CloudStorage::SyncAllFromCloud(parsedAccountId);
    CloudWorkQueue::DrainQueue();
    CloudStorage::Shutdown();

    std::ostringstream apps;
    apps << "[";
    bool first = true;
    for (uint32_t id : syncedApps) {
        if (!first) apps << ",";
        apps << JsonInt(id);
        first = false;
    }
    apps << "]";

    return JsonObject({
        {"success", JsonBool(true)},
        {"synced_apps", apps.str()},
        {"count", JsonInt(static_cast<int64_t>(syncedApps.size()))}
    });
}

std::string CmdPruneLocalLegacyMetadata(const std::string& cloudRootArg) {
    std::string cloudRoot = NormalizeCloudRoot(cloudRootArg);
    if (cloudRoot.empty()) {
        return JsonError("cloud_root is required");
    }

    auto stats = LegacyMetadataCleanup::PruneLocalLegacyAppMetadata(cloudRoot);
    return JsonObject({
        {"success", JsonBool(stats.errors == 0)},
        {"files_removed", JsonInt(stats.filesRemoved)},
        {"dirs_removed", JsonInt(stats.dirsRemoved)},
        {"errors", JsonInt(stats.errors)}
    });
}

std::string CmdPublishFullManifest(const std::string& provider, const std::string& accountId, const std::string& appId,
                                   const std::string& cloudRootArg) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    uint32_t parsedAccountId = static_cast<uint32_t>(std::strtoul(accountId.c_str(), nullptr, 10));
    uint32_t parsedAppId = static_cast<uint32_t>(std::strtoul(appId.c_str(), nullptr, 10));
    if (parsedAccountId == 0 || parsedAppId == 0) {
        return JsonError("Invalid account_id or app_id");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }

    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }

    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    std::string cloudRoot = NormalizeCloudRoot(cloudRootArg);
    if (cloudRoot.empty()) {
        prov->Shutdown();
        return JsonError("cloud_root is required");
    }
    std::string storageRoot = cloudRoot + "storage/";
#ifdef _WIN32
    for (auto& c : storageRoot) { if (c == '/') c = '\\'; }
#endif

    LocalStorage::Init(storageRoot);
    LocalMetadataStore::Init(storageRoot);
    LocalStorage::InitApp(parsedAccountId, parsedAppId);
    LocalMetadataStore::InitApp(parsedAccountId, parsedAppId);
    PendingOpsJournal::Init(storageRoot);
    CloudStorage::Init(cloudRoot, std::move(prov));

    CloudStorage::Manifest localManifest = CloudStorage::BuildManifestFromLocalBlobs(parsedAccountId, parsedAppId);
    CloudStorage::CloudAppState state;
    state.cn = LocalStorage::GetChangeNumber(parsedAccountId, parsedAppId);
    for (const auto& [name, me] : localManifest) {
        CloudStorage::FileEntry fe;
        fe.sha = me.sha;
        fe.timestamp = me.timestamp;
        fe.size = me.size;
        state.files[name] = std::move(fe);
    }
    bool manifestOk = CloudStorage::PublishCloudState(parsedAccountId, parsedAppId, state);
    bool cnOk = manifestOk;  // CN is included in state file
    bool drained = CloudWorkQueue::DrainQueueForApp(parsedAccountId, parsedAppId);

    CloudStorage::Shutdown();

    return JsonObject({
        {"success", JsonBool(manifestOk && cnOk && drained)},
        {"manifest_published", JsonBool(manifestOk)},
        {"cn_published", JsonBool(cnOk)},
        {"drained", JsonBool(drained)}
    });
}

static std::string ReadSyncPath() {
    std::string configDir = GetConfigDir();
    if (configDir.empty()) return "";

    FILE* f = fopen((configDir + "config.json").c_str(), "rb");
    if (!f) return "";
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len <= 0) { fclose(f); return ""; }
    rewind(f);
    std::string json((size_t)len, '\0');
    json.resize(fread(json.data(), 1, (size_t)len, f));
    fclose(f);

    Json::Value root = Json::Parse(json);
    if (root.type == Json::Type::Object && root.has("sync_path") &&
        root["sync_path"].type == Json::Type::String)
        return root["sync_path"].str();
    return "";
}

static std::string FindInterceptStorageRoot() {
    std::string configDir = GetConfigDir();
    if (!configDir.empty()) {
        std::string configStorage = configDir + "storage";
        std::error_code ec;
        if (std::filesystem::is_directory(FileUtil::Utf8ToPath(configStorage), ec))
            return configStorage;
    }

#ifdef _WIN32
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[512] = {};
        DWORD bufSize = sizeof(buf) - 1;
        DWORD type = 0;
        if (RegQueryValueExA(hKey, "SteamPath", nullptr, &type, (LPBYTE)buf, &bufSize) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            RegCloseKey(hKey);
            std::string steamPath(buf);
            for (char& c : steamPath) { if (c == '/') c = '\\'; }
            if (!steamPath.empty() && steamPath.back() != '\\') steamPath += '\\';
            return steamPath + "cloud_redirect\\storage";
        }
        RegCloseKey(hKey);
    }
#else
    const char* home = getenv("HOME");
    if (home) {
        std::string paths[] = {
            std::string(home) + "/.steam/steam/cloud_redirect/storage",
            std::string(home) + "/.local/share/Steam/cloud_redirect/storage",
        };
        namespace fs = std::filesystem;
        for (auto& p : paths) {
            std::error_code ec;
            if (fs::is_directory(FileUtil::Utf8ToPath(p), ec)) return p;
        }
    }
#endif
    return "";
}

static std::string FindStorageRoot(const std::string& provider) {
    if (provider == "folder" || provider == "local") {
        std::string sp = ReadSyncPath();
        if (!sp.empty()) return sp;
    }
    return FindInterceptStorageRoot();
}

static std::vector<std::string> DiscoverAccountIds(const std::string& provider) {
    std::string storageRoot = FindStorageRoot(provider);
    fprintf(stderr, "[scan] provider=%s storage root=%s\n",
            provider.c_str(), storageRoot.empty() ? "(none)" : storageRoot.c_str());
    if (storageRoot.empty()) return {};

    std::vector<std::string> accounts;
    try {
        namespace fs = std::filesystem;
        for (auto& entry : fs::directory_iterator(FileUtil::Utf8ToPath(storageRoot))) {
            if (!entry.is_directory()) continue;
            std::string name = FileUtil::PathToUtf8(entry.path().filename());
            if (name.empty() || name == "0" || name == "stats") continue;
            // Verify it looks like a numeric account ID.
            bool numeric = true;
            for (char c : name) { if (c < '0' || c > '9') { numeric = false; break; } }
            if (numeric) accounts.push_back(name);
        }
    } catch (...) {}

    std::sort(accounts.begin(), accounts.end());
    fprintf(stderr, "[scan] discovered %zu account(s)\n", accounts.size());
    return accounts;
}

static bool ListAllFiles(ICloudProvider* prov,
                         const std::string& provider,
                         std::vector<ICloudProvider::FileInfo>& outFiles,
                         bool& outComplete,
                         const std::function<void(const std::string& phase,
                                                  const std::string& message,
                                                  int64_t done, int64_t total,
                                                  int64_t found)>& onStatus) {
    outFiles.clear();
    outComplete = false;

    // Try flat listing first (works for R2).
    if (onStatus) onStatus("scanning", "Scanning cloud storage...", -1, -1, -1);
    if (prov->ListChecked("", outFiles, &outComplete)) {
        if (onStatus)
            onStatus("scanning", "Found " + std::to_string(outFiles.size()) + " item(s)",
                     -1, -1, static_cast<int64_t>(outFiles.size()));
        return true;
    }

    // Flat listing failed — fall back to per-account enumeration.
    if (onStatus) onStatus("discovering", "Discovering accounts...", -1, -1, -1);
    auto accountIds = DiscoverAccountIds(provider);
    if (accountIds.empty()) return false;

    int64_t acctTotal = static_cast<int64_t>(accountIds.size());
    if (onStatus)
        onStatus("discovering", "Found " + std::to_string(acctTotal) + " account(s)",
                 0, acctTotal, 0);

    outComplete = true;
    int64_t acctDone = 0;
    for (const auto& acct : accountIds) {
        acctDone++;
        if (onStatus)
            onStatus("scanning",
                     "Scanning account " + std::to_string(acctDone) + " of " +
                         std::to_string(acctTotal) + "...",
                     acctDone, acctTotal, static_cast<int64_t>(outFiles.size()));

        std::vector<ICloudProvider::FileInfo> acctFiles;
        bool acctComplete = false;
        if (!prov->ListChecked(acct + "/", acctFiles, &acctComplete)) {
            return false;
        }
        if (!acctComplete) outComplete = false;
        for (auto& fi : acctFiles) {
            outFiles.push_back(std::move(fi));
        }

        if (onStatus)
            onStatus("scanning",
                     "Found " + std::to_string(outFiles.size()) + " file(s) so far",
                     acctDone, acctTotal, static_cast<int64_t>(outFiles.size()));
    }
    return true;
}

std::string CmdScanAll(const std::string& provider) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }
    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }
    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    // Discover accounts from local storage.
    auto accountIds = DiscoverAccountIds(provider);
    if (accountIds.empty()) {
        prov->Shutdown();
        return JsonError("No accounts found in local storage");
    }

    // For each account, list app folder names (shallow — no file enumeration).
    std::ostringstream out;
    out << "[";
    bool firstApp = true;
    for (const auto& acct : accountIds) {
        auto appIds = prov->ListSubfolders(acct + "/");
        for (const auto& appId : appIds) {
            if (appId.empty() || appId == "0") continue;
            if (!firstApp) out << ",";
            out << JsonObject({
                {"account_id", JsonString(acct)},
                {"app_id", JsonString(appId)}
            });
            firstApp = false;
        }
    }
    out << "]";

    prov->Shutdown();

    return JsonObject({
        {"success", JsonBool(true)},
        {"apps", out.str()}
    });
}

int CmdMigrate(const std::string& srcProvider, const std::string& dstProvider) {
    // Flush each progress line immediately so the UI can parse in real-time.
    auto emitLine = [](const std::string& json) {
        printf("%s\n", json.c_str());
        fflush(stdout);
    };

    // Resolve token paths for both providers.
    std::string srcTokenPath = GetTokenPath(srcProvider);
    if (srcTokenPath.empty()) {
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Cannot determine config directory for source provider")}}));
        return 1;
    }
    std::string dstTokenPath = GetTokenPath(dstProvider);
    if (dstTokenPath.empty()) {
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Cannot determine config directory for dest provider")}}));
        return 1;
    }

    auto emitStatus = [&emitLine](const std::string& phase, const std::string& message,
                                  int64_t done, int64_t total, int64_t found) {
        std::vector<std::pair<std::string, std::string>> obj = {
            {"type", JsonString("status")},
            {"phase", JsonString(phase)},
            {"message", JsonString(message)},
        };
        if (done >= 0) obj.push_back({"done", JsonInt(done)});
        if (total >= 0) obj.push_back({"total", JsonInt(total)});
        if (found >= 0) obj.push_back({"found", JsonInt(found)});
        emitLine(JsonObject(obj));
    };

    emitStatus("authenticating", "Connecting to " + srcProvider + "...", -1, -1, -1);

    // Create and init source provider.
    auto src = CreateCloudProvider(srcProvider);
    if (!src) {
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Unknown source provider: " + srcProvider)}}));
        return 1;
    }
    if (!src->Init(srcTokenPath)) {
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Failed to initialize source provider")}}));
        return 1;
    }
    if (!src->IsAuthenticated()) {
        src->Shutdown();
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Source provider not authenticated")}}));
        return 1;
    }

    emitStatus("authenticating", "Connecting to " + dstProvider + "...", -1, -1, -1);

    // Create and init dest provider.
    auto dst = CreateCloudProvider(dstProvider);
    if (!dst) {
        src->Shutdown();
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Unknown dest provider: " + dstProvider)}}));
        return 1;
    }
    if (!dst->Init(dstTokenPath)) {
        src->Shutdown();
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Failed to initialize dest provider")}}));
        return 1;
    }
    if (!dst->IsAuthenticated()) {
        src->Shutdown();
        dst->Shutdown();
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Dest provider not authenticated")}}));
        return 1;
    }

    std::vector<ICloudProvider::FileInfo> files;
    bool complete = false;
    if (!ListAllFiles(src.get(), srcProvider, files, complete, emitStatus)) {
        src->Shutdown();
        dst->Shutdown();
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Failed to list source files")}}));
        return 1;
    }
    if (!complete) {
        src->Shutdown();
        dst->Shutdown();
        emitLine(JsonObject({{"type", JsonString("error")},
                             {"message", JsonString("Source listing incomplete — aborting to avoid partial migration")}}));
        return 1;
    }

    // Filter out directory markers (trailing slash) — only real files.
    std::vector<ICloudProvider::FileInfo> realFiles;
    realFiles.reserve(files.size());
    for (auto& f : files) {
        if (!f.path.empty() && f.path.back() != '/') {
            realFiles.push_back(std::move(f));
        }
    }

    int64_t total = static_cast<int64_t>(realFiles.size());
    emitLine(JsonObject({{"type", JsonString("start")}, {"total", JsonInt(total)}}));

    int64_t done = 0;
    int64_t migrated = 0;
    int64_t skipped = 0;
    int64_t failed = 0;
    uint64_t totalBytes = 0;

    for (const auto& f : realFiles) {
        done++;

        auto exists = dst->CheckExists(f.path);
        for (int retry = 0; exists == ICloudProvider::ExistsStatus::Error && retry < 3; retry++) {
            exists = dst->CheckExists(f.path);
        }
        if (exists == ICloudProvider::ExistsStatus::Exists) {
            skipped++;
            emitLine(JsonObject({{"type", JsonString("skip")},
                                 {"file", JsonString(f.path)},
                                 {"done", JsonInt(done)},
                                 {"total", JsonInt(total)},
                                 {"reason", JsonString("exists")}}));
            continue;
        }
        if (exists == ICloudProvider::ExistsStatus::Error) {
            failed++;
            emitLine(JsonObject({{"type", JsonString("error")},
                                 {"file", JsonString(f.path)},
                                 {"done", JsonInt(done)},
                                 {"total", JsonInt(total)},
                                 {"message", JsonString("Existence check failed")}}));
            continue;
        }

        // Download from source.
        std::vector<uint8_t> data;
        if (!src->Download(f.path, data)) {
            failed++;
            emitLine(JsonObject({{"type", JsonString("error")},
                                 {"file", JsonString(f.path)},
                                 {"done", JsonInt(done)},
                                 {"total", JsonInt(total)},
                                 {"message", JsonString("Download failed")}}));
            continue;
        }

        // Upload to dest.
        if (!dst->Upload(f.path, data.data(), data.size())) {
            failed++;
            emitLine(JsonObject({{"type", JsonString("error")},
                                 {"file", JsonString(f.path)},
                                 {"done", JsonInt(done)},
                                 {"total", JsonInt(total)},
                                 {"message", JsonString("Upload failed")}}));
            continue;
        }

        migrated++;
        totalBytes += data.size();
        emitLine(JsonObject({{"type", JsonString("progress")},
                             {"file", JsonString(f.path)},
                             {"done", JsonInt(done)},
                             {"total", JsonInt(total)},
                             {"bytes", JsonInt(static_cast<int64_t>(data.size()))}}));
    }

    src->Shutdown();
    dst->Shutdown();

    emitLine(JsonObject({{"type", JsonString("complete")},
                         {"migrated", JsonInt(migrated)},
                         {"skipped", JsonInt(skipped)},
                         {"failed", JsonInt(failed)},
                         {"total_bytes", JsonInt(static_cast<int64_t>(totalBytes))}}));

    return (failed == 0) ? 0 : 1;
}

std::string CmdGcBlobs(const std::string& provider, const std::string& accountId, const std::string& appId,
                       const std::string& cloudRootArg) {
    std::string tokenPath = GetTokenPath(provider);
    if (tokenPath.empty()) {
        return JsonError("Cannot determine config directory");
    }

    uint32_t parsedAccountId = static_cast<uint32_t>(std::strtoul(accountId.c_str(), nullptr, 10));
    uint32_t parsedAppId = static_cast<uint32_t>(std::strtoul(appId.c_str(), nullptr, 10));
    if (parsedAccountId == 0 || parsedAppId == 0) {
        return JsonError("Invalid account_id or app_id");
    }

    auto prov = CreateCloudProvider(provider);
    if (!prov) {
        return JsonError("Unknown provider: " + provider);
    }

    if (!prov->Init(tokenPath)) {
        return JsonError("Failed to initialize provider");
    }

    if (!prov->IsAuthenticated()) {
        prov->Shutdown();
        return JsonError("Not authenticated");
    }

    std::string cloudRoot = NormalizeCloudRoot(cloudRootArg);
    if (cloudRoot.empty()) {
        prov->Shutdown();
        return JsonError("cloud_root is required");
    }
    std::string storageRoot = cloudRoot + "storage/";
#ifdef _WIN32
    for (auto& c : storageRoot) { if (c == '/') c = '\\'; }
#endif

    LocalStorage::Init(storageRoot);
    LocalMetadataStore::Init(storageRoot);
    LocalStorage::InitApp(parsedAccountId, parsedAppId);
    LocalMetadataStore::InitApp(parsedAccountId, parsedAppId);
    PendingOpsJournal::Init(storageRoot);
    CloudStorage::Init(cloudRoot, std::move(prov));

    int result = CloudStorage::GarbageCollectBlobs(parsedAccountId, parsedAppId);

    CloudStorage::Shutdown();

    return JsonObject({
        {"success", JsonBool(result >= 0)},
        {"blobs_deleted", JsonInt(static_cast<int64_t>(result >= 0 ? result : 0))},
        {"error", result < 0 ? JsonString("GC failed: listing incomplete or provider unavailable") : JsonString("")}
    });
}

bool IsCliMode(int argc, char** argv) {
    return argc >= 2 && strcmp(argv[1], "--cli") == 0;
}

static void PrintUsage() {
    fprintf(stderr, "Usage: cloud_redirect --cli <command> [args...]\n");
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "  auth-status <provider>                    Check authentication status\n");
    fprintf(stderr, "  list-remote-apps <provider> <account_id>  List apps in cloud (full scan)\n");
    fprintf(stderr, "  list-remote-app-ids <provider> <account_id>  List app IDs in cloud (fast)\n");
    fprintf(stderr, "  list-remote-app-files <provider> <account_id> <app_id>  List every file path in one remote app\n");
    fprintf(stderr, "  delete-remote-app <provider> <account_id> <app_id>  Delete app from cloud\n");
    fprintf(stderr, "  list-blobs <provider> <account_id> <app_id>  List blob files in app\n");
    fprintf(stderr, "  download-blob <provider> <account_id> <app_id> <blob>  Download a single blob's content\n");
    fprintf(stderr, "  list-all-stats <provider>  Search the cloud for every app's stats.json\n");
    fprintf(stderr, "  delete-blobs <provider> <account_id> <app_id> <blob>...  Delete specific blobs\n");
    fprintf(stderr, "  sync-remote-app <provider> <account_id> <app_id> <cloud_root>  Run SyncFromCloud for one app\n");
    fprintf(stderr, "  sync-all-remote-apps <provider> <account_id> <cloud_root>  Run SyncAllFromCloud for one account\n");
    fprintf(stderr, "  prune-local-legacy-metadata <cloud_root>  Remove local legacy metadata siblings where safe\n");
    fprintf(stderr, "  publish-full-manifest <provider> <account_id> <app_id> <cloud_root>  Publish local inventory manifest and CN\n");
    fprintf(stderr, "  gc-blobs <provider> <account_id> <app_id> <cloud_root>  Delete unreferenced SHA blobs from cloud\n");
    fprintf(stderr, "  scan-all <provider>                                       List all apps across all accounts (single-pass)\n");
    fprintf(stderr, "  migrate <src_provider> <dst_provider>                     Copy all cloud data from one provider to another\n");
    fprintf(stderr, "\nProviders: gdrive, onedrive, r2, s3\n");
}

int RunCli(int argc, char** argv) {
    // Skip program name and "--cli"
    if (argc < 3) {
        PrintUsage();
        return 1;
    }
    
    const char* command = argv[2];
    std::string result;
    
    if (strcmp(command, "auth-status") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: auth-status requires <provider>\n");
            return 1;
        }
        result = CmdAuthStatus(argv[3]);
    }
    else if (strcmp(command, "list-remote-apps") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Error: list-remote-apps requires <provider> <account_id>\n");
            return 1;
        }
        result = CmdListRemoteApps(argv[3], argv[4]);
    }
    else if (strcmp(command, "list-remote-app-ids") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Error: list-remote-app-ids requires <provider> <account_id>\n");
            return 1;
        }
        result = CmdListRemoteAppIds(argv[3], argv[4]);
    }
    else if (strcmp(command, "list-remote-app-files") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Error: list-remote-app-files requires <provider> <account_id> <app_id>\n");
            return 1;
        }
        result = CmdListRemoteAppFiles(argv[3], argv[4], argv[5]);
    }
    else if (strcmp(command, "delete-remote-app") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Error: delete-remote-app requires <provider> <account_id> <app_id>\n");
            return 1;
        }
        result = CmdDeleteRemoteApp(argv[3], argv[4], argv[5]);
    }
    else if (strcmp(command, "list-blobs") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Error: list-blobs requires <provider> <account_id> <app_id>\n");
            return 1;
        }
        result = CmdListBlobs(argv[3], argv[4], argv[5]);
    }
    else if (strcmp(command, "download-blob") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Error: download-blob requires <provider> <account_id> <app_id> <blob>\n");
            return 1;
        }
        result = CmdDownloadBlob(argv[3], argv[4], argv[5], argv[6]);
    }
    else if (strcmp(command, "list-all-stats") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: list-all-stats requires <provider>\n");
            return 1;
        }
        result = CmdListAllStats(argv[3]);
    }
    else if (strcmp(command, "delete-blobs") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Error: delete-blobs requires <provider> <account_id> <app_id> <blob>...\n");
            return 1;
        }
        std::vector<std::string> blobs;
        for (int i = 6; i < argc; i++) {
            blobs.push_back(argv[i]);
        }
        result = CmdDeleteBlobs(argv[3], argv[4], argv[5], blobs);
    }
    else if (strcmp(command, "sync-remote-app") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Error: sync-remote-app requires <provider> <account_id> <app_id> <cloud_root>\n");
            return 1;
        }
        result = CmdSyncRemoteApp(argv[3], argv[4], argv[5], argv[6]);
    }
    else if (strcmp(command, "sync-all-remote-apps") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Error: sync-all-remote-apps requires <provider> <account_id> <cloud_root>\n");
            return 1;
        }
        result = CmdSyncAllRemoteApps(argv[3], argv[4], argv[5]);
    }
    else if (strcmp(command, "prune-local-legacy-metadata") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: prune-local-legacy-metadata requires <cloud_root>\n");
            return 1;
        }
        result = CmdPruneLocalLegacyMetadata(argv[3]);
    }
    else if (strcmp(command, "publish-full-manifest") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Error: publish-full-manifest requires <provider> <account_id> <app_id> <cloud_root>\n");
            return 1;
        }
        result = CmdPublishFullManifest(argv[3], argv[4], argv[5], argv[6]);
    }
    else if (strcmp(command, "gc-blobs") == 0) {
        if (argc < 7) {
            fprintf(stderr, "Error: gc-blobs requires <provider> <account_id> <app_id> <cloud_root>\n");
            return 1;
        }
        result = CmdGcBlobs(argv[3], argv[4], argv[5], argv[6]);
    }
    else if (strcmp(command, "scan-all") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: scan-all requires <provider>\n");
            return 1;
        }
        result = CmdScanAll(argv[3]);
    }
    else if (strcmp(command, "migrate") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Error: migrate requires <src_provider> <dst_provider>\n");
            return 1;
        }
        // migrate streams its own output and returns an exit code directly.
        return CmdMigrate(argv[3], argv[4]);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n", command);
        PrintUsage();
        return 1;
    }
    
    // Output JSON result
    printf("%s\n", result.c_str());
    
    // Check if result indicates success
    return (result.find("\"success\":true") != std::string::npos ||
            result.find("\"authenticated\":true") != std::string::npos) ? 0 : 1;
}

} // namespace CloudRedirectCli

// Unified C export for CLI launchers (both Windows and Linux)
extern "C"
#ifdef _WIN32
__declspec(dllexport)
#endif
int CloudRedirect_CliMain(int argc, char** argv) {
    if (CloudRedirectCli::IsCliMode(argc, argv)) {
        return CloudRedirectCli::RunCli(argc, argv);
    }
    fprintf(stderr, "Usage: cloud_redirect_cli <command> [args...]\n");
    return 1;
}
