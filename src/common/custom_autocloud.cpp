#include "custom_autocloud.h"
#include "json.h"
#include "log.h"
#include "steam_root_ids.h"
#include "autocloud_scan.h"
#include "cloud_intercept.h"
#include "cloud_storage.h"
#include "local_storage.h"
#include "manifest_store.h"
#include "file_util.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <chrono>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {
constexpr uintmax_t kMaxConfigBytes = 1024 * 1024;
constexpr size_t kMaxRulesPerApp = 64;
constexpr size_t kMaxFieldBytes = 512;

bool SafeRelative(const std::string& value) {
    if (value.empty() || value.size() > kMaxFieldBytes) return false;
    if (value[0] == '/' || value[0] == '\\') return false;
    if (value.size() > 1 && std::isalpha((unsigned char)value[0]) && value[1] == ':') return false;
    std::string part;
    for (size_t i = 0; i <= value.size(); ++i) {
        char c = i < value.size() ? value[i] : '/';
        if (c == '/' || c == '\\') {
            if (part == "..") return false;
            part.clear();
        } else {
            part.push_back(c);
        }
    }
    return true;
}

bool SafePattern(const std::string& value) {
    return SafeRelative(value) && value.find('/') == std::string::npos &&
           value.find('\\') == std::string::npos && value != "." && value != "..";
}

const SteamRootIds::Entry* FindRoot(const std::string& root) {
    for (const auto& entry : SteamRootIds::kEntries) {
        if (root == entry.bareName) return &entry;
    }
    return nullptr;
}

std::vector<AutoCloudUtil::AutoCloudRuleNative> Parse(
    const std::string& text, uint32_t appId, std::string* error) {
    auto fail = [&](const std::string& message) {
        if (error) *error = message;
        return std::vector<AutoCloudUtil::AutoCloudRuleNative>{};
    };
    if (appId == 0) return fail("invalid app id");
    Json::Value root = Json::Parse(text);
    if (root.type != Json::Type::Object) return fail("config is not an object");
    const auto& all = root["custom_autocloud"];
    if (all.type == Json::Type::Null) return {};
    if (all.type != Json::Type::Object) return fail("custom_autocloud is not an object");
    const auto& app = all[std::to_string(appId)];
    if (app.type == Json::Type::Null) return {};
    if (app.type != Json::Type::Object) return fail("app entry is not an object");
    const auto& strategy = app["strategy"];
    if (strategy.type != Json::Type::String || strategy.str() != "steam-first")
        return fail("unsupported strategy");
    const auto& list = app["rules"];
    if (list.type != Json::Type::Array || list.size() == 0 || list.size() > kMaxRulesPerApp)
        return fail("invalid rule count");

    std::vector<AutoCloudUtil::AutoCloudRuleNative> rules;
    for (const auto& value : list.arrVal) {
        if (value.type != Json::Type::Object) return fail("rule is not an object");
        const auto& rootValue = value["root"];
        const auto& path = value["path"];
        const auto& pattern = value["pattern"];
        const auto& recursive = value["recursive"];
        if (rootValue.type != Json::Type::String || path.type != Json::Type::String ||
            pattern.type != Json::Type::String || recursive.type != Json::Type::Bool)
            return fail("rule fields have invalid types");
        const auto* knownRoot = FindRoot(rootValue.str());
        if (!knownRoot || !SafeRelative(path.str()) || !SafePattern(pattern.str()))
            return fail("unsafe or unsupported rule");
        AutoCloudUtil::AutoCloudRuleNative rule;
        rule.root = knownRoot->bareName;
        rule.cloudRoot = knownRoot->token;
        rule.path = path.str();
        rule.resolvedPath = rule.path;
        rule.pattern = pattern.str();
        rule.recursive = recursive.boolean();
        rules.push_back(std::move(rule));
    }
    return rules;
}

std::filesystem::path ConfigPath() {
#ifdef _WIN32
    wchar_t buffer[32768];
    DWORD n = GetEnvironmentVariableW(L"APPDATA", buffer, 32768);
    if (n > 0 && n < 32768) return std::filesystem::path(buffer) / L"CloudRedirect" / L"config.json";
#else
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"))
        return std::filesystem::path(xdg) / "CloudRedirect" / "config.json";
    if (const char* home = std::getenv("HOME"))
        return std::filesystem::path(home) / ".config" / "CloudRedirect" / "config.json";
#endif
    return {};
}

#ifndef CLOUDREDIRECT_TESTING
std::mutex g_sessionMutex;
std::unordered_set<uint32_t> g_runningApps;
std::unordered_set<uint32_t> g_rpcApps;
struct SessionBase {
    std::unordered_map<std::string, std::vector<uint8_t>> local;
    CloudStorage::Manifest store;
};
std::unordered_map<uint32_t, SessionBase> g_sessionBases;

std::unordered_map<std::string, std::vector<uint8_t>> LocalHashes(uint32_t appId) {
    std::unordered_map<std::string, std::vector<uint8_t>> result;
    auto scan = AutoCloudScan::GetFileList(CloudIntercept::GetSteamPath(),
        CloudIntercept::GetAccountId(), appId);
    if (!scan.complete) return result;
    for (const auto& file : scan.files) result[file.relativePath] = file.sha;
    return result;
}

bool StoreMatchesLocal(const CloudStorage::Manifest& store,
                       const std::unordered_map<std::string, std::vector<uint8_t>>& local) {
    if (store.size() != local.size()) return false;
    for (const auto& [name, sha] : local) {
        auto it = store.find(name);
        if (it == store.end() || it->second.sha != sha) return false;
    }
    return true;
}

bool StoresEqual(const CloudStorage::Manifest& a, const CloudStorage::Manifest& b) {
    if (a.size() != b.size()) return false;
    for (const auto& [name, value] : a) {
        auto it = b.find(name);
        if (it == b.end() || it->second.sha != value.sha ||
            it->second.timestamp != value.timestamp || it->second.size != value.size) return false;
    }
    return true;
}

bool RestoreManaged(uint32_t appId, const CloudStorage::Manifest& store) {
    auto rules = CustomAutoCloud::GetRules(appId);
    if (rules.empty()) return false;
    auto roots = AutoCloudScan::GetRootTokenDirectories(CloudIntercept::GetSteamPath(), appId,
        CloudIntercept::GetAccountId());
    auto root = roots.find(rules.front().cloudRoot);
    if (root == roots.end() || root->second.empty()) return false;
    for (const auto& [name, entry] : store) {
        if (!SafeRelative(name)) return false;
        bool found = false;
        auto bytes = CloudStorage::RetrieveBlob(CloudIntercept::GetAccountId(), appId, name, &found);
        if (!found || FileUtil::SHA1(bytes.data(), bytes.size()) != entry.sha) return false;
        auto target = std::filesystem::path(root->second) / FileUtil::Utf8ToPath(name);
        std::error_code ec;
        std::filesystem::create_directories(target.parent_path(), ec);
        if (ec) return false;
        if (!FileUtil::AtomicWriteBinary(FileUtil::PathToUtf8(target),
                bytes.empty() ? nullptr : bytes.data(), bytes.size())) return false;
    }
    return true;
}

void WriteStatus(uint32_t appId, const char* state, const char* mode,
                 size_t fileCount, const std::string& error = {}) {
    auto config = ConfigPath();
    if (config.empty()) return;
    auto path = config.parent_path() / "custom_autocloud_status.json";
    static std::mutex statusMutex;
    std::lock_guard<std::mutex> lock(statusMutex);
    Json::Value root = Json::Object();
    std::ifstream current(path, std::ios::binary);
    if (current) {
        std::string text((std::istreambuf_iterator<char>(current)), {});
        auto parsed = Json::Parse(text);
        if (parsed.type == Json::Type::Object) root = std::move(parsed);
    }
    Json::Value status = Json::Object();
    status.objVal["state"] = Json::String(state);
    status.objVal["mode"] = Json::String(mode);
    status.objVal["file_count"] = Json::Number((double)fileCount);
    status.objVal["last_capture_time"] = Json::Number((double)std::time(nullptr));
    status.objVal["error"] = Json::String(error);
    root.objVal[std::to_string(appId)] = std::move(status);
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    FileUtil::AtomicWriteText(FileUtil::PathToUtf8(path), Json::Stringify(root) + "\n");
}

void ManagedCapture(uint32_t appId) {
    {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        if (g_rpcApps.count(appId)) return;
    }
    uint32_t accountId = CloudIntercept::GetAccountId();
    std::string steamPath = CloudIntercept::GetSteamPath();
    if (accountId == 0 || steamPath.empty()) {
        WriteStatus(appId, "error", "managed", 0, "Steam account or path unavailable");
        return;
    }
    auto scan = AutoCloudScan::GetFileList(steamPath, accountId, appId);
    if (!scan.hasRules) return;
    if (!scan.complete) {
        WriteStatus(appId, scan.hasRootCollision ? "conflict" : "error", "managed", 0,
                    scan.hasRootCollision ? "root collision" : "incomplete scan");
        return;
    }
    if (scan.files.empty()) {
        WriteStatus(appId, "configured", "managed", 0);
        return;
    }
    size_t stored = 0;
    for (const auto& file : scan.files) {
        std::ifstream input(FileUtil::Utf8ToPath(file.fullPath), std::ios::binary);
        if (!input) {
            WriteStatus(appId, "error", "managed", stored, "save changed during capture");
            return;
        }
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
        auto sha = FileUtil::SHA1(bytes.data(), bytes.size());
        if (sha != file.sha || !CloudStorage::StoreBlob(accountId, appId, file.relativePath,
                bytes.empty() ? nullptr : bytes.data(), bytes.size()) ||
            !CloudStorage::UpdateManifestEntry(accountId, appId, file.relativePath,
                sha, file.modifiedTime, bytes.size())) {
            WriteStatus(appId, "error", "managed", stored, "atomic publish failed");
            return;
        }
        ++stored;
    }
    uint64_t cn = LocalStorage::IncrementChangeNumber(accountId, appId);
    CloudStorage::SaveManifestSnapshot(accountId, appId, cn);
    WriteStatus(appId, "active", "managed", stored);
}
#endif
} // namespace

namespace CustomAutoCloud {
std::vector<AutoCloudUtil::AutoCloudRuleNative> GetRules(uint32_t appId) {
    auto path = ConfigPath();
    if (path.empty()) return {};
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec || size > kMaxConfigBytes) return {};
    auto mtime = std::filesystem::last_write_time(path, ec);
    if (ec) return {};
    static std::mutex mutex;
    static std::filesystem::file_time_type cachedMtime;
    static uintmax_t cachedSize = static_cast<uintmax_t>(-1);
    static std::string cachedText;
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (mtime != cachedMtime || size != cachedSize) {
            std::ifstream input(path, std::ios::binary);
            if (!input) return {};
            cachedText.assign(std::istreambuf_iterator<char>(input), {});
            cachedMtime = mtime;
            cachedSize = size;
        }
        std::string error;
        auto rules = Parse(cachedText, appId, &error);
        if (!error.empty()) LOG("[CustomAutoCloud] app %u rejected: %s", appId, error.c_str());
        return rules;
    }
}

#ifndef CLOUDREDIRECT_TESTING
void ObserveSteamRpc(uint32_t appId) {
    if (GetRules(appId).empty()) return;
    std::lock_guard<std::mutex> lock(g_sessionMutex);
    g_rpcApps.insert(appId);
    WriteStatus(appId, "active", "steam", 0);
}

void ObserveGamesPlayed(const std::unordered_set<uint32_t>& appIds) {
    std::vector<uint32_t> started, ended;
    {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        for (uint32_t appId : appIds)
            if (!GetRules(appId).empty() && g_runningApps.insert(appId).second) started.push_back(appId);
        for (uint32_t appId : g_runningApps)
            if (!appIds.count(appId)) ended.push_back(appId);
        for (uint32_t appId : ended) g_runningApps.erase(appId);
        for (uint32_t appId : started) g_rpcApps.erase(appId);
    }
    for (uint32_t appId : started) {
        WriteStatus(appId, "configured", "managed", 0);
        std::thread([appId]{
            SessionBase base;
            base.local = LocalHashes(appId);
            base.store = CloudStorage::LoadLocalManifest(CloudIntercept::GetAccountId(), appId);
            {
                std::lock_guard<std::mutex> lock(g_sessionMutex);
                g_sessionBases[appId] = base;
            }
            if (base.store.empty()) {
                ManagedCapture(appId); // first adoption
                base.store = CloudStorage::LoadLocalManifest(CloudIntercept::GetAccountId(), appId);
                std::lock_guard<std::mutex> lock(g_sessionMutex);
                g_sessionBases[appId] = base;
            } else if (base.local.empty()) {
                if (RestoreManaged(appId, base.store)) {
                    base.local = LocalHashes(appId);
                    std::lock_guard<std::mutex> lock(g_sessionMutex);
                    g_sessionBases[appId] = base;
                    WriteStatus(appId, "active", "managed", base.store.size());
                } else {
                    WriteStatus(appId, "error", "managed", base.store.size(), "restore failed");
                }
            } else if (!StoreMatchesLocal(base.store, base.local)) {
                WriteStatus(appId, "conflict", "managed", base.store.size(),
                    "local and CloudRedirect data have no common base");
            } else {
                WriteStatus(appId, "active", "managed", base.store.size());
            }
        }).detach();
    }
    for (uint32_t appId : ended) {
        std::thread([appId]{
            std::this_thread::sleep_for(std::chrono::seconds(3));
            SessionBase base;
            {
                std::lock_guard<std::mutex> lock(g_sessionMutex);
                auto it = g_sessionBases.find(appId);
                if (it == g_sessionBases.end()) return;
                base = it->second;
                g_sessionBases.erase(it);
                if (g_rpcApps.count(appId)) return;
            }
            auto local = LocalHashes(appId);
            auto store = CloudStorage::LoadLocalManifest(CloudIntercept::GetAccountId(), appId);
            bool localChanged = local != base.local;
            bool storeChanged = !StoresEqual(store, base.store);
            if (localChanged && storeChanged) {
                WriteStatus(appId, "conflict", "managed", store.size(),
                    "both local and CloudRedirect data changed");
            } else if (localChanged) {
                ManagedCapture(appId);
            } else {
                WriteStatus(appId, "active", "managed", store.size());
            }
        }).detach();
    }
}
#endif

#ifdef CLOUDREDIRECT_TESTING
std::vector<AutoCloudUtil::AutoCloudRuleNative> ParseConfig(
    const std::string& json, uint32_t appId, std::string* error) {
    return Parse(json, appId, error);
}
#endif
} // namespace CustomAutoCloud
