#include "cloud_intercept.h"
#include "log.h"
#include "file_util.h"
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <fstream>
#include <mutex>
#include <unordered_set>
#include <sstream>
#include <pwd.h>
#include <unistd.h>
#include "yaml_parser.h"

static std::string g_steamPath;
static std::string g_homePath;
static std::atomic<uint32_t> g_accountId{0};
static std::mutex g_mutex;
static std::unordered_set<uint32_t> g_namespaceApps;
static std::mutex g_nsMutex;
static std::atomic<bool> g_initDone{false};

// ── Helpers ─────────────────────────────────────────────────────────────

static std::string GetHome() {
    const char* home = getenv("HOME");
    if (home && home[0]) return home;
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir) return pw->pw_dir;
    return "/tmp";
}

static std::string DetectSteamPath() {
    std::string home = GetHome();
    std::string path = home + "/.local/share/Steam/";
    if (std::filesystem::is_directory(path)) return path;
    path = home + "/.var/app/com.valvesoftware.Steam/.local/share/Steam/";
    if (std::filesystem::is_directory(path)) return path;
    path = home + "/.steam/steam/";
    if (std::filesystem::is_directory(path)) return path;
    return home + "/.local/share/Steam/";
}

// ── Parse SLSsteam config.yaml ──────────────────────────────────────────

static void LoadNamespaceAppsFromSLSsteam() {
    std::string home = GetHome();

    std::vector<std::string> configPaths = {
        home + "/.config/SLSsteam/config.yaml",
        home + "/.var/app/com.valvesoftware.Steam/.config/SLSsteam/config.yaml",
    };

    for (const auto& configPath : configPaths) {
        auto yaml = ParseYamlFile(configPath);
        if (yaml.empty()) continue;

        LOG("[Linux] Reading SLSsteam config: %s", configPath.c_str());

        auto dcIt = yaml.find("DisableCloud");
        if (dcIt == yaml.end() || !dcIt->second.isBool || dcIt->second.boolVal) {
            LOG("[Linux] DisableCloud enabled/missing - cloud saves blocked by SLSsteam");
            return;
        }

        auto appsIt = yaml.find("AdditionalApps");
        if (appsIt == yaml.end() || !appsIt->second.isList || appsIt->second.list.empty()) {
            LOG("[Linux] DisableCloud: no but no AdditionalApps configured");
            return;
        }

        int appCount = 0;
        for (const auto& appStr : appsIt->second.list) {
            char* endp = nullptr;
            unsigned long val = strtoul(appStr.c_str(), &endp, 10);
            if (endp != appStr.c_str() && val > 0 && val <= 0xFFFFFFFF) {
                std::lock_guard<std::mutex> lock(g_nsMutex);
                g_namespaceApps.insert((uint32_t)val);
                appCount++;
            }
        }

        if (appCount > 0) {
            LOG("[Linux] Loaded %d apps from AdditionalApps", appCount);
        } else {
            LOG("[Linux] DisableCloud: no but no AdditionalApps configured");
        }
        return;
    }

    LOG("[Linux] No SLSsteam config found");
}

// ── Parse loginusers.vdf for account ID ─────────────────────────────────
//
// Format:
//   "users"
//   {
//       "76561198014569578"
//       {
//           "MostRecent"  "1"
//           ...
//       }
//   }
// 
// SteamID64 -> AccountID = low 32 bits

static uint32_t LoadAccountIdFromLoginUsers() {
    std::string steamPath = DetectSteamPath();
    std::string vdfPath = steamPath + "config/loginusers.vdf";

    std::ifstream f(vdfPath);
    if (!f) {
        LOG("[Linux] Cannot open loginusers.vdf at %s", vdfPath.c_str());
        return 0;
    }

    std::string line;
    uint64_t mostRecentSteamId = 0;
    uint64_t currentSteamId = 0;
    bool inUser = false;
    int braceDepth = 0;

    while (std::getline(f, line)) {
        // Trim
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        std::string trimmed = line.substr(start);

        if (trimmed == "{") {
            braceDepth++;
            continue;
        }
        if (trimmed == "}") {
            braceDepth--;
            if (braceDepth == 1) inUser = false;
            continue;
        }

        // At depth 1, look for SteamID64 keys (quoted numbers)
        if (braceDepth == 1 && trimmed.size() > 2 && trimmed[0] == '"') {
            size_t endQuote = trimmed.find('"', 1);
            if (endQuote != std::string::npos) {
                std::string key = trimmed.substr(1, endQuote - 1);
                // Check if it's a numeric SteamID64
                char* endp = nullptr;
                uint64_t sid = strtoull(key.c_str(), &endp, 10);
                if (endp == key.c_str() + key.size() && sid > 76561197960265728ULL) {
                    currentSteamId = sid;
                    inUser = true;
                }
            }
        }

        // At depth 2, look for "MostRecent" "1"
        if (inUser && braceDepth == 2) {
            if (trimmed.find("\"MostRecent\"") != std::string::npos &&
                trimmed.find("\"1\"") != std::string::npos) {
                mostRecentSteamId = currentSteamId;
            }
        }
    }

    if (mostRecentSteamId == 0) {
        LOG("[Linux] No MostRecent user found in loginusers.vdf");
        return 0;
    }

    uint32_t accountId = (uint32_t)(mostRecentSteamId & 0xFFFFFFFF);
    LOG("[Linux] Bootstrapped accountId=%u from SteamID64=%llu (loginusers.vdf)",
        accountId, (unsigned long long)mostRecentSteamId);
    return accountId;
}

// ── Public API ──────────────────────────────────────────────────────────

namespace CloudIntercept {

void InitLinux() {
    bool expected = false;
    if (!g_initDone.compare_exchange_strong(expected, true)) return;

    g_homePath = GetHome();

    // Detect Steam path
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_steamPath = DetectSteamPath();
    }
    LOG("[Linux] Steam path: %s", g_steamPath.c_str());

    // Bootstrap account ID from loginusers.vdf
    uint32_t accountId = LoadAccountIdFromLoginUsers();
    if (accountId != 0) {
        g_accountId.store(accountId, std::memory_order_release);
    }

    // Load namespace apps from SLSsteam config
    LoadNamespaceAppsFromSLSsteam();
}

bool IsNamespaceApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_nsMutex);
    return g_namespaceApps.count(appId) > 0;
}

void RegisterNamespaceApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_nsMutex);
    if (g_namespaceApps.insert(appId).second) {
        LOG("[Linux] Dynamically registered namespace app: %u", appId);
    }
}

bool HasNamespaceApps() {
    std::lock_guard<std::mutex> lock(g_nsMutex);
    return !g_namespaceApps.empty();
}

std::string GetSteamPath() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_steamPath.empty())
        g_steamPath = DetectSteamPath();
    return g_steamPath;
}

uint32_t GetAccountId() {
    return g_accountId.load(std::memory_order_acquire);
}

void SetAccountId(uint32_t id) {
    g_accountId.store(id, std::memory_order_release);
    LOG("[Linux] Account ID set: %u", id);
}

void SetSteamPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_steamPath = path;
    if (!g_steamPath.empty() && g_steamPath.back() != '/')
        g_steamPath += '/';
}

void RecordLaunchTime(uint32_t /*appId*/) {
    // TODO: implement playtime tracking on Linux
}

void Shutdown() {
    LOG("[Linux] CloudIntercept shutdown");
}

// Playtime restoration stubs (called from rpc_handlers.cpp)
bool RestorePlaytimeState(uint32_t /*appId*/, uint64_t /*playtime*/, uint64_t /*playtime2wks*/) {
    return false;
}

bool RestoreLastPlayedState(uint32_t /*appId*/, uint64_t /*lastPlayed*/) {
    return false;
}

} // namespace CloudIntercept
