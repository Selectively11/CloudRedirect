#include "local_storage.h"
#include "file_util.h"
#include "log.h"
#include "steam_root_ids.h"
#include <wincrypt.h>
#include <ShlObj.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <system_error>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

namespace LocalStorage {

static std::string g_baseRoot;
static std::unordered_map<uint64_t, uint64_t> g_changeNumbers;
// Lock-graph sink. shared_mutex has no upgrade path.
static std::shared_mutex g_mutex;

static uint64_t FileTimeToUnixSeconds(std::filesystem::file_time_type ftime) {
    auto fileNow = std::filesystem::file_time_type::clock::now();
    auto sysNow = std::chrono::system_clock::now();
    auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
        ftime - fileNow + sysNow
    );
    return (uint64_t)sctp.time_since_epoch().count();
}

static std::filesystem::file_time_type UnixSecondsToFileTime(uint64_t unixSeconds) {
    auto sysTime = std::chrono::system_clock::from_time_t((time_t)unixSeconds);
    auto sysNow = std::chrono::system_clock::now();
    auto fileNow = std::filesystem::file_time_type::clock::now();
    return fileNow + (sysTime - sysNow);
}

// Returns full path, or empty if the filename escapes the app directory.
static std::string ValidateFilename(const std::string& appRoot, const std::string& filename) {
    std::string fullPath = appRoot + filename;
    for (auto& c : fullPath) { if (c == '/') c = '\\'; }

    if (!FileUtil::IsPathWithin(appRoot, fullPath)) {
        LOG("BLOCKED path traversal: filename='%s' root='%s'",
            filename.c_str(), appRoot.c_str());
        return {};
    }

    return fullPath;
}

static uint64_t MakeKey(uint32_t accountId, uint32_t appId) {
    return ((uint64_t)accountId << 32) | appId;
}

static std::string GetAppPathInternal(uint32_t accountId, uint32_t appId) {
    return g_baseRoot + std::to_string(accountId) + "\\" + std::to_string(appId) + "\\";
}

static std::string ToLowerAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return s;
}

static std::string NormalizeSlashes(std::string s) {
    for (auto& c : s) { if (c == '\\') c = '/'; }
    return s;
}

static constexpr uintmax_t kMaxAppInfoBytes = 512ULL * 1024 * 1024;
static constexpr uint32_t kMaxAppInfoStrings = 200000;
static constexpr size_t kMaxAutoCloudScanFiles = 20000;
static constexpr int kMaxAutoCloudScanMillis = 5000;
static constexpr uint64_t kMaxAutoCloudCandidateBytes = 128ULL * 1024 * 1024;

static void ReplaceAll(std::string& s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

static std::string ExpandAutoCloudPathTokens(std::string path, uint32_t accountId) {
    const uint64_t steamId64Base = 76561197960265728ULL;
    const std::string accountIdStr = std::to_string(accountId);
    const std::string steamId64 = std::to_string(steamId64Base + accountId);
    ReplaceAll(path, "{Steam3AccountID}", accountIdStr);
    ReplaceAll(path, "{steam3accountid}", accountIdStr);
    ReplaceAll(path, "{64BitSteamID}", steamId64);
    ReplaceAll(path, "{64bitsteamid}", steamId64);
    ReplaceAll(path, "{SteamID64}", steamId64);
    ReplaceAll(path, "{steamid64}", steamId64);
    return path;
}

static bool IsSafeRelativePath(const std::string& path) {
    if (path.empty()) return true;
    if (path.find(':') != std::string::npos) return false;
    if (!path.empty() && (path.front() == '/' || path.front() == '\\')) return false;
    std::stringstream ss(NormalizeSlashes(path));
    std::string part;
    while (std::getline(ss, part, '/')) {
        if (part == "..") return false;
    }
    return true;
}

static std::string GetKnownFolderPathString(const KNOWNFOLDERID& id) {
    PWSTR wide = nullptr;
    if (FAILED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &wide)) || !wide) return {};
    std::string result = FileUtil::WideToUtf8(wide);
    CoTaskMemFree(wide);
    return result;
}

static bool ReadU32(const std::vector<uint8_t>& data, size_t& offset, uint32_t& out) {
    if (offset + 4 > data.size()) return false;
    out = (uint32_t)data[offset] |
        ((uint32_t)data[offset + 1] << 8) |
        ((uint32_t)data[offset + 2] << 16) |
        ((uint32_t)data[offset + 3] << 24);
    offset += 4;
    return true;
}

static bool ReadI32(const std::vector<uint8_t>& data, size_t& offset, int32_t& out) {
    uint32_t u = 0;
    if (!ReadU32(data, offset, u)) return false;
    out = (int32_t)u;
    return true;
}

static std::string ReadCStringFromBytes(const std::vector<uint8_t>& data, size_t& offset) {
    size_t start = offset;
    while (offset < data.size() && data[offset] != 0) ++offset;
    std::string s(reinterpret_cast<const char*>(data.data() + start), offset - start);
    if (offset < data.size()) ++offset;
    return s;
}

struct AutoCloudRuleNative {
    std::string root;
    std::string path;
    std::string resolvedPath;
    std::string pattern;
    bool recursive = false;
    // Steam UFS platforms bitmask: Windows=1, MacOS=2, Linux=8; -1 = all.
    uint32_t platforms = 0xFFFFFFFFu;
    std::vector<std::string> excludes;
    // Sibling extension tokens (Steam sub_1384DC5D0 uses space delimiter).
    std::vector<std::string> siblings;
};

// Reject empty, "..", leading-dot, slash/backslash, and control-char tokens.
static std::vector<std::string> ParseAutoCloudSiblings(const std::string& raw) {
    std::vector<std::string> out;
    std::string token;
    auto flush = [&]() {
        if (token.empty()) return;
        std::string candidate;
        candidate.swap(token);
        if (candidate == "..") return;
        if (candidate.front() == '.') return;
        for (char c : candidate) {
            if (c == '/' || c == '\\') return;
            if ((unsigned char)c < 0x20) return;
        }
        out.push_back(std::move(candidate));
    };
    for (char c : raw) {
        if (c == ' ' || c == '\t') {
            flush();
        } else {
            token.push_back(c);
        }
    }
    flush();
    return out;
}

static uint32_t ParseAutoCloudPlatformMask(const std::string& name) {
    std::string lower = ToLowerAscii(name);
    if (lower == "windows" || lower == "win") return 1;
    if (lower == "macos" || lower == "osx" || lower == "mac") return 2;
    if (lower == "linux") return 8;
    if (lower == "all") return 0xFFFFFFFFu;
    if (lower == "none") return 0;
    return 0;
}

static bool AutoCloudRuleMatchesCurrentPlatform(uint32_t mask) {
    // We run on Windows; Steam's Windows platform bit is 1.
    return (mask & 1u) != 0;
}

struct AutoCloudRootOverrideNative {
    std::string root;
    std::string os;
    std::string osCompare;
    std::string useInstead;
    std::string addPath;
    std::vector<std::pair<std::string, std::string>> pathTransforms;
};

struct AppInfoKVNode {
    std::string key;
    std::string stringValue;
    int32_t intValue = 0;
    bool hasString = false;
    bool hasInt = false;
    std::vector<AppInfoKVNode> children;
};

static std::vector<AppInfoKVNode> ParseAppInfoKV(const std::vector<uint8_t>& data, size_t& offset,
                                                 const std::vector<std::string>& strings, int depth = 0) {
    std::vector<AppInfoKVNode> nodes;
    if (depth >= 64) return nodes;

    while (offset < data.size()) {
        uint8_t type = data[offset++];
        if (type == 0x08 || type == 0x09) break;

        uint32_t keyIdx = 0;
        if (!ReadU32(data, offset, keyIdx)) break;

        AppInfoKVNode node;
        node.key = keyIdx < strings.size() ? strings[keyIdx] : "";

        switch (type) {
        case 0x00:
            node.children = ParseAppInfoKV(data, offset, strings, depth + 1);
            break;
        case 0x01:
            node.stringValue = ReadCStringFromBytes(data, offset);
            node.hasString = true;
            break;
        case 0x02:
            node.hasInt = ReadI32(data, offset, node.intValue);
            break;
        case 0x03:
        case 0x04:
        case 0x06:
            offset = offset + 4 > data.size() ? data.size() : offset + 4;
            break;
        case 0x07:
        case 0x0A:
            offset = offset + 8 > data.size() ? data.size() : offset + 8;
            break;
        case 0x05:
            ReadCStringFromBytes(data, offset);
            break;
        default:
            return nodes;
        }

        nodes.push_back(std::move(node));
    }

    return nodes;
}

static const AppInfoKVNode* FindChild(const std::vector<AppInfoKVNode>& nodes, const char* key) {
    for (const auto& node : nodes) {
        if (_stricmp(node.key.c_str(), key) == 0) return &node;
    }
    return nullptr;
}

static int WindowsVersionRank(std::string osName) {
    osName = ToLowerAscii(osName);
    if (osName == "windows11" || osName == "win11") return 11;
    if (osName == "windows10" || osName == "win10") return 10;
    if (osName == "windows8" || osName == "windows81" || osName == "win8" || osName == "win81") return 8;
    if (osName == "windows7" || osName == "win7") return 7;
    if (osName == "windows" || osName == "win") return 0;
    return -1;
}

static int CurrentWindowsVersionRank() {
    using RtlGetVersionFn = LONG (WINAPI *)(OSVERSIONINFOW*);
    auto fn = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion"));
    OSVERSIONINFOW vi = {};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn && fn(&vi) == 0) {
        if (vi.dwMajorVersion >= 10) return vi.dwBuildNumber >= 22000 ? 11 : 10;
        if (vi.dwMajorVersion == 6 && vi.dwMinorVersion >= 2) return 8;
        if (vi.dwMajorVersion == 6 && vi.dwMinorVersion == 1) return 7;
    }
    return 10;
}

static bool IsWindowsRootOverrideActive(const AutoCloudRootOverrideNative& overrideRule) {
    int target = WindowsVersionRank(overrideRule.os);
    if (target < 0) return false;

    if (overrideRule.osCompare.empty() || _stricmp(overrideRule.osCompare.c_str(), "=") == 0) {
        return target == 0 || CurrentWindowsVersionRank() == target;
    }
    if (_stricmp(overrideRule.osCompare.c_str(), "<") == 0) {
        return target > 0 && CurrentWindowsVersionRank() < target;
    }
    return false;
}

static void ApplyRootOverridesForCurrentOS(AutoCloudRuleNative& rule,
                                           const std::vector<AutoCloudRootOverrideNative>& overrides) {
    for (const auto& overrideRule : overrides) {
        if (!IsWindowsRootOverrideActive(overrideRule)) continue;
        if (_stricmp(rule.root.c_str(), overrideRule.root.c_str()) != 0) continue;

        if (!overrideRule.useInstead.empty()) {
            rule.root = overrideRule.useInstead;
        }
        rule.resolvedPath = rule.path;
        for (const auto& [find, replace] : overrideRule.pathTransforms) {
            if (!find.empty()) ReplaceAll(rule.resolvedPath, find, replace);
        }
        if (!overrideRule.addPath.empty()) {
            std::string prefix = NormalizeSlashes(overrideRule.addPath);
            while (!prefix.empty() && prefix.back() == '/') prefix.pop_back();
            rule.resolvedPath = rule.resolvedPath.empty() ? prefix : prefix + "/" + rule.resolvedPath;
        }
        return;
    }
}

#ifdef CLOUDREDIRECT_TESTING
static bool WildcardMatchInsensitive(const std::string& pattern, const std::string& text);

bool TestResolveAutoCloudRootOverride(const std::string& root, const std::string& path,
                                      const std::string& overrideRoot,
                                      const std::string& useInstead,
                                      const std::string& addPath,
                                      const std::string& find,
                                      const std::string& replace,
                                      std::string& outRoot,
                                      std::string& outResolvedPath) {
    AutoCloudRuleNative rule;
    rule.root = root;
    rule.path = path;
    rule.resolvedPath = path;

    AutoCloudRootOverrideNative overrideRule;
    overrideRule.root = overrideRoot;
    overrideRule.os = "Windows";
    overrideRule.osCompare = "=";
    overrideRule.useInstead = useInstead;
    overrideRule.addPath = addPath;
    if (!find.empty()) overrideRule.pathTransforms.emplace_back(find, replace);

    ApplyRootOverridesForCurrentOS(rule, {overrideRule});
    outRoot = rule.root;
    outResolvedPath = rule.resolvedPath;
    return true;
}

bool TestIsSafeAutoCloudRelativePath(const std::string& path) {
    return IsSafeRelativePath(path);
}

std::vector<std::string> TestParseAutoCloudSiblings(const std::string& raw) {
    return ParseAutoCloudSiblings(raw);
}

bool TestParseMinimalAutoCloudKVFixture() {
    std::vector<std::string> strings = {
        "appinfo", "ufs", "savefiles", "0", "root", "path", "pattern", "recursive",
        "WinAppDataLocal", "Saves", "*.sav", "rootoverrides", "1", "os", "Windows",
        "oscompare", "=", "useinstead", "WinSavedGames", "addpath", "Migrated"
    };
    std::vector<uint8_t> data;
    auto u32 = [&](uint32_t v) {
        data.push_back((uint8_t)(v & 0xFF));
        data.push_back((uint8_t)((v >> 8) & 0xFF));
        data.push_back((uint8_t)((v >> 16) & 0xFF));
        data.push_back((uint8_t)((v >> 24) & 0xFF));
    };
    auto section = [&](uint32_t key) { data.push_back(0x00); u32(key); };
    auto str = [&](uint32_t key, const char* value) {
        data.push_back(0x01); u32(key);
        data.insert(data.end(), value, value + strlen(value) + 1);
    };
    auto i32 = [&](uint32_t key, int32_t value) {
        data.push_back(0x02); u32(key); u32((uint32_t)value);
    };
    auto end = [&]() { data.push_back(0x08); };

    section(0);      // appinfo
    section(1);      // ufs
    section(2);      // savefiles
    section(3);      // 0
    str(4, "WinAppDataLocal");
    str(5, "Saves");
    str(6, "*.sav");
    i32(7, 1);
    end();
    end();        // savefiles
    section(11);  // rootoverrides
    section(12);  // 1
    str(4, "WinAppDataLocal");
    str(13, "Windows");
    str(15, "=");
    str(17, "WinSavedGames");
    str(19, "Migrated");
    end(); end(); end(); end();

    size_t offset = 0;
    auto tree = ParseAppInfoKV(data, offset, strings);
    const auto* appInfo = FindChild(tree, "appinfo");
    const auto* ufs = appInfo ? FindChild(appInfo->children, "ufs") : nullptr;
    const auto* savefiles = ufs ? FindChild(ufs->children, "savefiles") : nullptr;
    const auto* entry = savefiles && !savefiles->children.empty() ? &savefiles->children.front() : nullptr;
    const auto* root = entry ? FindChild(entry->children, "root") : nullptr;
    const auto* path = entry ? FindChild(entry->children, "path") : nullptr;
    const auto* pattern = entry ? FindChild(entry->children, "pattern") : nullptr;
    const auto* recursive = entry ? FindChild(entry->children, "recursive") : nullptr;
    const auto* rootoverrides = ufs ? FindChild(ufs->children, "rootoverrides") : nullptr;
    const auto* overrideEntry = rootoverrides && !rootoverrides->children.empty() ? &rootoverrides->children.front() : nullptr;
    AutoCloudRootOverrideNative overrideRule;
    if (overrideEntry) {
        const auto* overrideRoot = FindChild(overrideEntry->children, "root");
        const auto* os = FindChild(overrideEntry->children, "os");
        const auto* osCompare = FindChild(overrideEntry->children, "oscompare");
        const auto* useInstead = FindChild(overrideEntry->children, "useinstead");
        const auto* addPath = FindChild(overrideEntry->children, "addpath");
        overrideRule.root = overrideRoot && overrideRoot->hasString ? overrideRoot->stringValue : "";
        overrideRule.os = os && os->hasString ? os->stringValue : "";
        overrideRule.osCompare = osCompare && osCompare->hasString ? osCompare->stringValue : "";
        overrideRule.useInstead = useInstead && useInstead->hasString ? useInstead->stringValue : "";
        overrideRule.addPath = addPath && addPath->hasString ? addPath->stringValue : "";
    }
    AutoCloudRuleNative rule;
    rule.root = root && root->hasString ? root->stringValue : "";
    rule.path = path && path->hasString ? path->stringValue : "";
    rule.resolvedPath = rule.path;
    ApplyRootOverridesForCurrentOS(rule, {overrideRule});
    return root && root->stringValue == "WinAppDataLocal" &&
        path && path->stringValue == "Saves" &&
        pattern && pattern->stringValue == "*.sav" &&
        recursive && recursive->hasInt && recursive->intValue == 1 &&
        rule.root == "WinSavedGames" && rule.resolvedPath == "Migrated/Saves";
}

bool TestAutoCloudPlatformAndExcludeFilters() {
    // String table: indices referenced below.
    std::vector<std::string> strings = {
        "root", "path", "pattern", "recursive",   // 0-3
        "platforms", "exclude",                    // 4-5
        "Windows", "Linux",                        // 6-7
        "WinAppDataLocal", "Saves", "*",           // 8-10
        "*.log"                                    // 11
    };

    std::vector<uint8_t> data;
    auto u32 = [&](uint32_t v) {
        data.push_back((uint8_t)(v & 0xFF));
        data.push_back((uint8_t)((v >> 8) & 0xFF));
        data.push_back((uint8_t)((v >> 16) & 0xFF));
        data.push_back((uint8_t)((v >> 24) & 0xFF));
    };
    auto section = [&](uint32_t key) { data.push_back(0x00); u32(key); };
    auto str = [&](uint32_t key, uint32_t valueIdx) {
        data.push_back(0x01); u32(key);
        const std::string& v = strings[valueIdx];
        data.insert(data.end(), v.begin(), v.end());
        data.push_back(0x00);
    };
    auto i32 = [&](uint32_t key, int32_t value) {
        data.push_back(0x02); u32(key); u32((uint32_t)value);
    };
    auto end = [&]() { data.push_back(0x08); };

    str(0, 8);     // root = "WinAppDataLocal"
    str(1, 9);     // path = "Saves"
    str(2, 10);    // pattern = "*"
    i32(3, 1);     // recursive = 1
    section(4);    // platforms {
    str(0, 6);     //   [anon] = "Windows"
    end();         // }
    section(5);    // exclude {
    str(0, 11);    //   [anon] = "*.log"
    end();         // }

    size_t offset = 0;
    auto tree = ParseAppInfoKV(data, offset, strings);

    AutoCloudRuleNative rule;
    const auto* root = FindChild(tree, "root");
    const auto* path = FindChild(tree, "path");
    const auto* pattern = FindChild(tree, "pattern");
    const auto* recursive = FindChild(tree, "recursive");
    const auto* platforms = FindChild(tree, "platforms");
    const auto* excludes = FindChild(tree, "exclude");
    rule.root = root && root->hasString ? root->stringValue : "";
    rule.path = path && path->hasString ? path->stringValue : "";
    rule.pattern = pattern && pattern->hasString ? pattern->stringValue : "*";
    rule.recursive = recursive && recursive->hasInt && recursive->intValue != 0;
    if (platforms) {
        uint32_t mask = 0;
        for (const auto& plat : platforms->children) {
            if (plat.hasString) mask |= ParseAutoCloudPlatformMask(plat.stringValue);
        }
        rule.platforms = mask;
    }
    if (excludes) {
        for (const auto& ex : excludes->children) {
            if (ex.hasString && !ex.stringValue.empty()) rule.excludes.push_back(ex.stringValue);
        }
    }

    bool basics = rule.root == "WinAppDataLocal" && rule.path == "Saves" &&
        rule.pattern == "*" && rule.recursive &&
        rule.platforms == 1u && rule.excludes.size() == 1 &&
        rule.excludes.front() == "*.log";
    if (!basics) return false;

    if (!AutoCloudRuleMatchesCurrentPlatform(rule.platforms)) return false;
    if (AutoCloudRuleMatchesCurrentPlatform(8u)) return false;

    auto excluded = [&](const char* leaf) {
        for (const auto& ex : rule.excludes) {
            if (WildcardMatchInsensitive(ex, std::string(leaf))) return true;
        }
        return false;
    };
    if (!excluded("debug.log")) return false;
    if (excluded("slot1.sav")) return false;

    return true;
}
#endif

static std::vector<AutoCloudRuleNative> LoadAutoCloudRules(const std::string& steamPath, uint32_t appId) {
    std::vector<AutoCloudRuleNative> rules;
    std::filesystem::path appInfoPath = FileUtil::Utf8ToPath(steamPath) / "appcache" / "appinfo.vdf";
    std::error_code statEc;
    auto appInfoMtime = std::filesystem::last_write_time(appInfoPath, statEc);
    auto appInfoSize = std::filesystem::file_size(appInfoPath, statEc);
    if (statEc) {
        LOG("GetAutoCloudFileList: failed to stat appinfo.vdf: %s", statEc.message().c_str());
        return rules;
    }
    if (appInfoSize > kMaxAppInfoBytes) {
        LOG("GetAutoCloudFileList: appinfo.vdf too large: %llu bytes", (unsigned long long)appInfoSize);
        return rules;
    }

    struct RulesCacheEntry {
        std::filesystem::file_time_type mtime;
        uintmax_t size = 0;
        std::vector<AutoCloudRuleNative> rules;
    };
    static std::mutex cacheMutex;
    static std::unordered_map<std::string, RulesCacheEntry> cache;
    // PathToUtf8 keeps non-ACP codepoints; path::string() would round-trip to '?'.
    std::string cacheKey = FileUtil::PathToUtf8(appInfoPath) + "\n" + std::to_string(appId);
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = cache.find(cacheKey);
        if (it != cache.end() && it->second.mtime == appInfoMtime && it->second.size == appInfoSize) {
            return it->second.rules;
        }
    }

    auto cacheRules = [&](const std::vector<AutoCloudRuleNative>& parsedRules) {
        std::lock_guard<std::mutex> lock(cacheMutex);
        cache[cacheKey] = RulesCacheEntry{appInfoMtime, appInfoSize, parsedRules};
    };

    std::ifstream f(appInfoPath, std::ios::binary | std::ios::ate);
    if (!f) {
        LOG("GetAutoCloudFileList: appinfo.vdf not found: %s", FileUtil::PathToUtf8(appInfoPath).c_str());
        return rules;
    }

    auto fileSize = f.tellg();
    if (fileSize < 16) return rules;
    if (static_cast<uintmax_t>(fileSize) > kMaxAppInfoBytes) {
        LOG("GetAutoCloudFileList: appinfo.vdf too large after open: %llu bytes",
            (unsigned long long)fileSize);
        return rules;
    }
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes((size_t)fileSize);
    if (!f.read(reinterpret_cast<char*>(bytes.data()), fileSize)) return rules;

    size_t offset = 0;
    uint32_t magic = 0, universe = 0, stringOffsetLo = 0, stringOffsetHi = 0;
    if (!ReadU32(bytes, offset, magic) || !ReadU32(bytes, offset, universe) ||
        !ReadU32(bytes, offset, stringOffsetLo) || !ReadU32(bytes, offset, stringOffsetHi)) {
        return rules;
    }
    uint64_t stringOffset = ((uint64_t)stringOffsetHi << 32) | stringOffsetLo;
    if (magic != 0x07564429 || stringOffset >= bytes.size()) {
        LOG("GetAutoCloudFileList: unsupported appinfo.vdf format magic=0x%08X", magic);
        return rules;
    }

    size_t stringTableOffset = (size_t)stringOffset;
    size_t st = stringTableOffset;
    uint32_t stringCount = 0;
    if (!ReadU32(bytes, st, stringCount)) return rules;
    size_t remainingStringBytes = bytes.size() - st;
    if (stringCount > remainingStringBytes || stringCount > kMaxAppInfoStrings) {
        LOG("GetAutoCloudFileList: invalid appinfo string count: %u", stringCount);
        return rules;
    }

    std::vector<std::string> strings;
    strings.reserve(stringCount);
    for (uint32_t i = 0; i < stringCount && st < bytes.size(); ++i) {
        strings.push_back(ReadCStringFromBytes(bytes, st));
    }

    offset = 16;
    while (offset + 8 <= stringTableOffset) {
        uint32_t recordAppId = 0, size = 0;
        if (!ReadU32(bytes, offset, recordAppId)) break;
        if (recordAppId == 0) break;
        if (!ReadU32(bytes, offset, size)) break;
        if (size == 0 || offset + size > stringTableOffset) break;

        if (recordAppId != appId) {
            offset += size;
            continue;
        }

        if (size < 60) return rules;
        std::vector<uint8_t> kv(bytes.begin() + offset + 60, bytes.begin() + offset + size);
        size_t kvOffset = 0;
        auto tree = ParseAppInfoKV(kv, kvOffset, strings);
        const auto* appInfo = FindChild(tree, "appinfo");
        if (!appInfo) return rules;
        const auto* ufs = FindChild(appInfo->children, "ufs");
        if (!ufs) return rules;
        const auto* savefiles = FindChild(ufs->children, "savefiles");
        if (!savefiles) return rules;

        std::vector<AutoCloudRootOverrideNative> overrides;
        const auto* rootoverrides = FindChild(ufs->children, "rootoverrides");
        if (rootoverrides) {
            for (const auto& entry : rootoverrides->children) {
                AutoCloudRootOverrideNative overrideRule;
                const auto* root = FindChild(entry.children, "root");
                const auto* os = FindChild(entry.children, "os");
                const auto* osCompare = FindChild(entry.children, "oscompare");
                const auto* useInstead = FindChild(entry.children, "useinstead");
                const auto* addPath = FindChild(entry.children, "addpath");
                overrideRule.root = root && root->hasString ? root->stringValue : "";
                overrideRule.os = os && os->hasString ? os->stringValue : "";
                overrideRule.osCompare = osCompare && osCompare->hasString ? osCompare->stringValue : "";
                overrideRule.useInstead = useInstead && useInstead->hasString ? useInstead->stringValue : "";
                overrideRule.addPath = addPath && addPath->hasString ? addPath->stringValue : "";

                const auto* transforms = FindChild(entry.children, "pathtransforms");
                if (transforms) {
                    for (const auto& transform : transforms->children) {
                        const auto* find = FindChild(transform.children, "find");
                        const auto* replace = FindChild(transform.children, "replace");
                        overrideRule.pathTransforms.emplace_back(
                            find && find->hasString ? find->stringValue : "",
                            replace && replace->hasString ? replace->stringValue : "");
                    }
                }

                if (!overrideRule.root.empty() &&
                    (!overrideRule.useInstead.empty() || !overrideRule.addPath.empty() ||
                     !overrideRule.pathTransforms.empty())) {
                    overrides.push_back(std::move(overrideRule));
                }
            }
        }

        for (const auto& entry : savefiles->children) {
            AutoCloudRuleNative rule;
            const auto* root = FindChild(entry.children, "root");
            const auto* path = FindChild(entry.children, "path");
            const auto* pattern = FindChild(entry.children, "pattern");
            const auto* recursive = FindChild(entry.children, "recursive");
            rule.root = root && root->hasString ? root->stringValue : "";
            rule.path = path && path->hasString ? path->stringValue : "";
            rule.resolvedPath = rule.path;
            rule.pattern = pattern && pattern->hasString ? pattern->stringValue : "*";
            rule.recursive = recursive && recursive->hasInt && recursive->intValue != 0;

            const auto* platforms = FindChild(entry.children, "platforms");
            if (platforms) {
                uint32_t mask = 0;
                for (const auto& plat : platforms->children) {
                    if (plat.hasString) mask |= ParseAutoCloudPlatformMask(plat.stringValue);
                }
                rule.platforms = mask;
            }

            const auto* excludes = FindChild(entry.children, "exclude");
            if (excludes) {
                for (const auto& ex : excludes->children) {
                    if (ex.hasString && !ex.stringValue.empty()) {
                        rule.excludes.push_back(ex.stringValue);
                    }
                }
            }

            const auto* siblings = FindChild(entry.children, "siblings");
            if (siblings && siblings->hasString && !siblings->stringValue.empty()) {
                rule.siblings = ParseAutoCloudSiblings(siblings->stringValue);
                if (rule.siblings.size() > 32) {
                    LOG("LoadAutoCloudRules: app %u rule root='%s' path='%s' has %zu siblings "
                        "after safety filter (unusually large; proceeding without cap)",
                        appId, rule.root.c_str(), rule.path.c_str(), rule.siblings.size());
                }
            }

            ApplyRootOverridesForCurrentOS(rule, overrides);
            rules.push_back(std::move(rule));
        }
        cacheRules(rules);
        return rules;
    }

    cacheRules(rules);
    return rules;
}

// Caps against exponential backtracking.
static constexpr size_t kMaxWildcardPatternLen = 1024;
static constexpr int    kMaxWildcardStars      = 16;
static constexpr int    kMaxWildcardIterations = 100000;

static bool WildcardMatchImpl(const char* pattern, const char* text, int& iters) {
    if (--iters <= 0) return false;
    while (*pattern) {
        if (*pattern == '*') {
            while (*pattern == '*') ++pattern;
            if (!*pattern) return true;
            while (*text && *text != '/') {
                if (WildcardMatchImpl(pattern, text, iters)) return true;
                if (iters <= 0) return false;
                ++text;
            }
            return false;
        }
        if (!*text) return false;
        if (*text == '/' && *pattern != '/') return false;
        if (*pattern != '?' && std::tolower((unsigned char)*pattern) != std::tolower((unsigned char)*text)) {
            return false;
        }
        ++pattern;
        ++text;
    }
    return *text == 0;
}

static bool WildcardMatchInsensitive(const char* pattern, const char* text) {
    size_t patLen = 0;
    while (patLen <= kMaxWildcardPatternLen && pattern[patLen] != '\0') ++patLen;
    if (patLen > kMaxWildcardPatternLen) return false;

    int stars = 0;
    for (size_t i = 0; i < patLen; ++i) {
        if (pattern[i] == '*' && ++stars > kMaxWildcardStars) return false;
    }

    int iters = kMaxWildcardIterations;
    return WildcardMatchImpl(pattern, text, iters);
}

static bool WildcardMatchInsensitive(const std::string& pattern, const std::string& text) {
    return WildcardMatchInsensitive(pattern.c_str(), text.c_str());
}

static std::vector<std::filesystem::path> GetSteamLibraryPaths(const std::string& steamPath) {
    std::vector<std::filesystem::path> paths;
    auto steamPathFs = FileUtil::Utf8ToPath(steamPath);
    paths.push_back(steamPathFs);

    std::ifstream f(steamPathFs / "config" / "libraryfolders.vdf");
    if (!f) return paths;

    std::string line;
    while (std::getline(f, line)) {
        if (line.find("\"path\"") == std::string::npos) continue;
        auto first = line.find('"', line.find("\"path\"") + 6);
        if (first == std::string::npos) continue;
        auto second = line.find('"', first + 1);
        if (second == std::string::npos) continue;
        std::string path = line.substr(first + 1, second - first - 1);
        size_t pos = 0;
        while ((pos = path.find("\\\\", pos)) != std::string::npos) {
            path.replace(pos, 2, "\\");
            ++pos;
        }
        std::filesystem::path p = FileUtil::Utf8ToPath(path);
        if (!std::filesystem::exists(p)) continue;
        bool seen = false;
        for (const auto& existing : paths) {
            if (_wcsicmp(existing.native().c_str(), p.native().c_str()) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen) paths.push_back(std::move(p));
    }

    return paths;
}

static std::string FindGameInstallPath(const std::string& steamPath, uint32_t appId) {
    for (const auto& libPath : GetSteamLibraryPaths(steamPath)) {
        auto manifestPath = libPath / "steamapps" / ("appmanifest_" + std::to_string(appId) + ".acf");
        std::ifstream mf(manifestPath);
        if (!mf) continue;

        std::string line;
        while (std::getline(mf, line)) {
            auto pos = line.find("\"installdir\"");
            if (pos == std::string::npos) continue;
            auto q1 = line.rfind('"');
            auto q2 = q1 == std::string::npos ? std::string::npos : line.rfind('"', q1 - 1);
            if (q1 != std::string::npos && q2 != std::string::npos && q1 > q2) {
                auto installDir = line.substr(q2 + 1, q1 - q2 - 1);
                return FileUtil::PathToUtf8(libPath / "steamapps" / "common" / installDir);
            }
        }
    }
    return {};
}

// Corrupt => caller quarantines. Legacy "0" reads as Absent.
enum class CNParseResult { Absent, Valid, Corrupt };

static CNParseResult ReadCNFile(const std::string& path, uint64_t& outCn) {
    outCn = 0;
    try {
        std::ifstream f(FileUtil::Utf8ToPath(path), std::ios::binary);
        if (!f) return CNParseResult::Absent;

        // uint64 decimal max = 20 digits; 64 covers any valid trailer.
        constexpr size_t kMaxCNBytes = 64;
        char buf[kMaxCNBytes + 1] = {0};
        f.read(buf, kMaxCNBytes);
        std::streamsize n = f.gcount();
        if (n <= 0) return CNParseResult::Corrupt;

        if (static_cast<size_t>(n) == kMaxCNBytes && f.peek() != EOF) {
            return CNParseResult::Corrupt;
        }

        std::string content(buf, static_cast<size_t>(n));
        // Reject torn writes like "847\0<junk>".
        for (char c : content) {
            if (c == '\0') return CNParseResult::Corrupt;
        }

        while (!content.empty() && (content.back() == '\n' || content.back() == '\r' ||
                                    content.back() == ' ' || content.back() == '\t')) {
            content.pop_back();
        }
        if (content.empty()) return CNParseResult::Corrupt;

        for (char c : content) {
            if (c < '0' || c > '9') return CNParseResult::Corrupt;
        }
        // Legacy: exact "0" treated as Absent.
        if (content == "0") return CNParseResult::Absent;

        size_t consumed = 0;
        unsigned long long v = std::stoull(content, &consumed);
        if (consumed != content.size()) return CNParseResult::Corrupt;
        outCn = static_cast<uint64_t>(v);
        return CNParseResult::Valid;
    } catch (...) {
        return CNParseResult::Corrupt;
    }
}

// Best-effort rename of a corrupt cn.dat.
static void QuarantineCorruptCNFile(const std::string& cnPath, uint32_t appId) {
    static std::atomic<uint64_t> quarantineSeq{0};
    try {
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
        uint64_t seq = quarantineSeq.fetch_add(1, std::memory_order_relaxed);
        uint32_t pid = static_cast<uint32_t>(GetCurrentProcessId());
        std::string base = cnPath + ".corrupt." + std::to_string(us) + "." +
                           std::to_string(pid) + "." + std::to_string(seq);

        // Windows rename() replaces; pick a fresh suffix.
        std::string quarantinePath = base;
        for (int dup = 1; dup < 1000; ++dup) {
            std::error_code existEc;
            if (!std::filesystem::exists(FileUtil::Utf8ToPath(quarantinePath), existEc)) break;
            quarantinePath = base + "." + std::to_string(dup);
        }

        std::error_code ec;
        std::filesystem::rename(FileUtil::Utf8ToPath(cnPath),
                                FileUtil::Utf8ToPath(quarantinePath), ec);
        if (ec) {
            LOG("ERROR GetChangeNumber: cn.dat for app %u was corrupt and could not be "
                "quarantined (%s); subsequent increments may overwrite it",
                appId, ec.message().c_str());
        } else {
            LOG("ERROR GetChangeNumber: cn.dat for app %u was corrupt; quarantined to %s",
                appId, quarantinePath.c_str());
        }
    } catch (...) {
        LOG("ERROR GetChangeNumber: cn.dat for app %u was corrupt and quarantine "
            "raised an exception; file left in place", appId);
    }
}

// Caller holds g_mutex. Returns true on success.
static bool SaveChangeNumberLocked(uint32_t accountId, uint32_t appId) {
    auto key = MakeKey(accountId, appId);
    auto it = g_changeNumbers.find(key);
    if (it == g_changeNumbers.end()) return false;

    std::string cnPath = GetAppPathInternal(accountId, appId) + "cn.dat";
    if (FileUtil::AtomicWriteText(cnPath, std::to_string(it->second))) {
        LOG("SaveChangeNumber: persisted CN=%llu for app %u", it->second, appId);
        return true;
    }
    LOG("SaveChangeNumber: failed to persist CN for app %u", appId);
    return false;
}

void Init(const std::string& baseRoot) {
    g_baseRoot = baseRoot;
    if (!g_baseRoot.empty() && g_baseRoot.back() != '\\')
        g_baseRoot += '\\';
    std::error_code ec;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(g_baseRoot), ec);
    if (ec) {
        LOG("LocalStorage Init: create_directories failed for '%s': %s",
            g_baseRoot.c_str(), ec.message().c_str());
    }
    LOG("LocalStorage initialized at: %s", g_baseRoot.c_str());
}

void InitApp(uint32_t accountId, uint32_t appId) {
    auto appPath = GetAppPathInternal(accountId, appId);
    std::error_code ec;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appPath), ec);
    if (ec) {
        LOG("LocalStorage InitApp: create_directories failed for '%s': %s",
            appPath.c_str(), ec.message().c_str());
    }
    LOG("LocalStorage: account %u app %u path: %s", accountId, appId, appPath.c_str());
}

std::string GetAppPath(uint32_t accountId, uint32_t appId) {
    return GetAppPathInternal(accountId, appId);
}

uint64_t GetChangeNumber(uint32_t accountId, uint32_t appId) {
    // Fast path: shared lock for cache reads (common case)
    {
        std::shared_lock<std::shared_mutex> rlock(g_mutex);
        auto key = MakeKey(accountId, appId);
        auto it = g_changeNumbers.find(key);
        if (it != g_changeNumbers.end()) return it->second;
    }

    // Slow path: exclusive lock for disk load + cache insert
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    auto key = MakeKey(accountId, appId);
    auto it = g_changeNumbers.find(key);
    if (it != g_changeNumbers.end()) return it->second;

    std::string cnPath = GetAppPathInternal(accountId, appId) + "cn.dat";
    uint64_t cn = 0;
    switch (ReadCNFile(cnPath, cn)) {
        case CNParseResult::Valid:
            g_changeNumbers[key] = cn;
            LOG("GetChangeNumber: loaded CN=%llu from disk for app %u", cn, appId);
            return cn;
        case CNParseResult::Corrupt:
            QuarantineCorruptCNFile(cnPath, appId);
            break;
        case CNParseResult::Absent:
            break;
    }

    g_changeNumbers[key] = 1;
    return 1;
}

static std::unordered_map<std::string, TombstoneInfo> LoadDeletedLocked(uint32_t accountId,
                                                                        uint32_t appId,
                                                                        bool* outNeedsRewrite = nullptr);
static bool SaveDeletedLocked(uint32_t accountId, uint32_t appId,
                              const std::unordered_map<std::string, TombstoneInfo>& deleted);

// Lazy load; ++ on a missing key would silently regress to 1.
static void EnsureCNCachedLocked(uint32_t accountId, uint32_t appId) {
    auto key = MakeKey(accountId, appId);
    if (g_changeNumbers.count(key)) return;

    std::string cnPath = GetAppPathInternal(accountId, appId) + "cn.dat";
    uint64_t cn = 1;
    uint64_t parsed = 0;
    switch (ReadCNFile(cnPath, parsed)) {
        case CNParseResult::Valid:
            cn = parsed;
            break;
        case CNParseResult::Corrupt:
            QuarantineCorruptCNFile(cnPath, appId);
            cn = 1;
            break;
        case CNParseResult::Absent:
            cn = 1;
            break;
    }
    g_changeNumbers[key] = cn;
}

void SetChangeNumber(uint32_t accountId, uint32_t appId, uint64_t cn) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    auto key = MakeKey(accountId, appId);

    // Snapshot for rollback on persist failure.
    auto prevIt = g_changeNumbers.find(key);
    bool hadPrev = prevIt != g_changeNumbers.end();
    uint64_t prevCN = hadPrev ? prevIt->second : 0;

    g_changeNumbers[key] = cn;
    if (!SaveChangeNumberLocked(accountId, appId)) {
        if (hadPrev) g_changeNumbers[key] = prevCN;
        else g_changeNumbers.erase(key);
        LOG("SetChangeNumber: persist failed for app %u, rolled back in-memory CN", appId);
        return;
    }
    LOG("SetChangeNumber: CN=%llu for app %u", cn, appId);
}

uint64_t IncrementChangeNumber(uint32_t accountId, uint32_t appId) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    auto key = MakeKey(accountId, appId);
    EnsureCNCachedLocked(accountId, appId);
    uint64_t prevCN = g_changeNumbers[key];
    uint64_t newCN  = prevCN + 1;
    g_changeNumbers[key] = newCN;
    if (!SaveChangeNumberLocked(accountId, appId)) {
        g_changeNumbers[key] = prevCN;
        LOG("IncrementChangeNumber: persist failed for app %u, rolled back to %llu",
            appId, prevCN);
        return prevCN;
    }
    return newCN;
}

std::vector<uint8_t> SHA1(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(20, 0);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            CryptHashData(hHash, data, (DWORD)len, 0);
            DWORD hashLen = 20;
            CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return hash;
}

// Streaming SHA1 (UTF-8 path).
static std::vector<uint8_t> SHA1File(const std::string& path) {
    std::vector<uint8_t> hash(20, 0);
    std::ifstream f(FileUtil::Utf8ToPath(path), std::ios::binary);
    if (!f) return hash;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            char buf[65536];
            while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
                CryptHashData(hHash, (const BYTE*)buf, (DWORD)f.gcount(), 0);
                if (f.eof()) break;
            }
            DWORD hashLen = 20;
            CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return hash;
}

std::vector<FileEntry> GetFileList(uint32_t accountId, uint32_t appId) {
    std::vector<FileEntry> result;

    // Phase 1: collect paths under shared lock; Phase 2: hash unlocked.
    struct PendingFile {
        std::string relPath;
        std::string fullPath;
        uint64_t rawSize;
        uint64_t timestamp;
    };
    std::vector<PendingFile> pending;

    {
        std::shared_lock<std::shared_mutex> lock(g_mutex);
        std::string appRoot = GetAppPathInternal(accountId, appId);
        auto appRootFs = FileUtil::Utf8ToPath(appRoot);
        std::error_code ec;
        if (!std::filesystem::exists(appRootFs, ec) || ec) return result;

        // ec overload: never unwind out of the RPC hot path.
        std::filesystem::recursive_directory_iterator it(
            appRootFs,
            std::filesystem::directory_options::skip_permission_denied,
            ec);
        if (ec) {
            LOG("GetFileList: iterator init failed for '%s': %s",
                appRoot.c_str(), ec.message().c_str());
            return result;
        }
        const std::filesystem::recursive_directory_iterator end;
        while (it != end) {
            const auto& entry = *it;
            std::error_code fileEc;
            if (!entry.is_regular_file(fileEc) || fileEc) {
                it.increment(ec);
                if (ec) break;
                continue;
            }

            std::string relPath = FileUtil::PathToUtf8(std::filesystem::relative(entry.path(), appRootFs, fileEc));
            if (fileEc) {
                it.increment(ec);
                if (ec) break;
                continue;
            }
            for (auto& c : relPath) { if (c == '\\') c = '/'; }

            // Skip our internal metadata files
            if (relPath == "cn.dat" || relPath == "root_token.dat" ||
                relPath == "file_tokens.dat" || relPath == "deleted.dat") {
                it.increment(ec);
                if (ec) break;
                continue;
            }

            std::string fullPath = appRoot + relPath;
            for (auto& c : fullPath) { if (c == '/') c = '\\'; }

            auto ftime = std::filesystem::last_write_time(entry.path(), fileEc);
            if (fileEc) {
                it.increment(ec);
                if (ec) break;
                continue;
            }
            uint64_t ts = FileTimeToUnixSeconds(ftime);

            uint64_t rawSize = 0;
            auto sz = entry.file_size(fileEc);
            if (!fileEc) rawSize = (uint64_t)sz;
            else {
                it.increment(ec);
                if (ec) break;
                continue;
            }

            PendingFile pf;
            pf.relPath = std::move(relPath);
            pf.fullPath = std::move(fullPath);
            pf.rawSize = rawSize;
            pf.timestamp = ts;
            pending.push_back(std::move(pf));

            it.increment(ec);
            if (ec) break;
        }
        if (ec) {
            LOG("GetFileList: iteration aborted for '%s': %s (kept %zu entries)",
                appRoot.c_str(), ec.message().c_str(), pending.size());
        }
    }
    // Phase 2: hash unlocked. Empty/zero SHA = file deleted between phases.
    for (auto& pf : pending) {
        auto sha = SHA1File(pf.fullPath);
        if (sha.empty() || std::all_of(sha.begin(), sha.end(), [](uint8_t b) { return b == 0; }))
            continue;

        FileEntry fe;
        fe.filename = std::move(pf.relPath);
        fe.sha = sha;
        fe.timestamp = pf.timestamp;
        fe.rawSize = pf.rawSize;
        fe.deleted = false;
        fe.rootId = 0;
        result.push_back(std::move(fe));
    }

    return result;
}

std::optional<FileEntry> GetFileEntry(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::string fullPath;
    {
        std::shared_lock<std::shared_mutex> lock(g_mutex);
        std::string appRoot = GetAppPathInternal(accountId, appId);
        fullPath = appRoot + filename;
        for (auto& c : fullPath) { if (c == '/') c = '\\'; }

        std::error_code statEc;
        auto fp = FileUtil::Utf8ToPath(fullPath);
        if (!std::filesystem::exists(fp, statEc) || statEc) return std::nullopt;
        if (!std::filesystem::is_regular_file(fp, statEc) || statEc) return std::nullopt;
    }

    // Phase 2 unlocked; TOCTOU between phases caught by try/catch.
    try {
        auto sha = SHA1File(fullPath);
        auto fp = FileUtil::Utf8ToPath(fullPath);
        std::error_code statEc;
        auto ftime = std::filesystem::last_write_time(fp, statEc);
        if (statEc) return std::nullopt;
        uint64_t ts = FileTimeToUnixSeconds(ftime);

        auto sz = std::filesystem::file_size(fp, statEc);
        if (statEc) return std::nullopt;

        FileEntry fe;
        fe.filename = filename;
        fe.sha = sha;
        fe.timestamp = ts;
        fe.rawSize = (uint64_t)sz;
        fe.deleted = false;
        fe.rootId = 0;
        return fe;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::vector<uint8_t> ReadFile(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::shared_lock<std::shared_mutex> lock(g_mutex);

    std::string appRoot = GetAppPathInternal(accountId, appId);
    std::string fullPath = ValidateFilename(appRoot, filename);
    if (fullPath.empty()) return {};

    std::ifstream f(FileUtil::Utf8ToPath(fullPath), std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>()
    );
}

bool WriteFile(uint32_t accountId, uint32_t appId, const std::string& filename, const uint8_t* data, size_t len) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);

    std::string appRoot = GetAppPathInternal(accountId, appId);
    std::string fullPath = ValidateFilename(appRoot, filename);
    if (fullPath.empty()) {
        LOG("WriteFile BLOCKED: path traversal in filename '%s'", filename.c_str());
        return false;
    }

    auto parent = FileUtil::Utf8ToPath(fullPath).parent_path();
    std::error_code dirEc;
    std::filesystem::create_directories(parent, dirEc);
    if (dirEc) {
        LOG("WriteFile: create_directories failed for '%s': %s",
            FileUtil::PathToUtf8(parent).c_str(), dirEc.message().c_str());
        return false;
    }

    if (!FileUtil::AtomicWriteBinary(fullPath, data, len)) {
        LOG("WriteFile failed: %s (%zu bytes)", fullPath.c_str(), len);
        return false;
    }
    EnsureCNCachedLocked(accountId, appId);
    auto cnKey = MakeKey(accountId, appId);
    uint64_t prevCN = g_changeNumbers[cnKey];
    g_changeNumbers[cnKey] = prevCN + 1;
    if (!SaveChangeNumberLocked(accountId, appId)) {
        // Roll back cache to keep memory aligned with disk; file stays.
        g_changeNumbers[cnKey] = prevCN;
        LOG("WriteFile: cn.dat persist failed for app %u; rolled back in-memory CN, file %s preserved on disk",
            appId, fullPath.c_str());
        return false;
    }
    LOG("WriteFile: app %u %s (%zu bytes)", appId, filename.c_str(), len);
    return true;
}

bool WriteFileNoIncrement(uint32_t accountId, uint32_t appId, const std::string& filename, const uint8_t* data, size_t len) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);

    std::string appRoot = GetAppPathInternal(accountId, appId);
    std::string fullPath = ValidateFilename(appRoot, filename);
    if (fullPath.empty()) {
        LOG("WriteFileNoIncrement BLOCKED: path traversal in filename '%s'", filename.c_str());
        return false;
    }

    auto parent = FileUtil::Utf8ToPath(fullPath).parent_path();
    std::error_code dirEc;
    std::filesystem::create_directories(parent, dirEc);
    if (dirEc) {
        LOG("WriteFileNoIncrement: create_directories failed for '%s': %s",
            FileUtil::PathToUtf8(parent).c_str(), dirEc.message().c_str());
        return false;
    }

    if (!FileUtil::AtomicWriteBinary(fullPath, data, len)) {
        LOG("WriteFileNoIncrement failed: %s (%zu bytes)", fullPath.c_str(), len);
        return false;
    }
    LOG("WriteFileNoIncrement: app %u %s (%zu bytes)", appId, filename.c_str(), len);
    return true;
}

bool DeleteFile(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);

    std::string appRoot = GetAppPathInternal(accountId, appId);
    std::string fullPath = ValidateFilename(appRoot, filename);
    if (fullPath.empty()) {
        LOG("DeleteFile BLOCKED: path traversal in filename '%s'", filename.c_str());
        return false;
    }

    std::error_code ec;
    bool removed = std::filesystem::remove(FileUtil::Utf8ToPath(fullPath), ec);
    if (ec) {
        LOG("DeleteFile: remove failed for '%s': %s",
            fullPath.c_str(), ec.message().c_str());
        return false;
    }
    if (removed) {
        EnsureCNCachedLocked(accountId, appId);
        auto cnKey = MakeKey(accountId, appId);
        uint64_t prevCN = g_changeNumbers[cnKey];
        g_changeNumbers[cnKey] = prevCN + 1;
        if (!SaveChangeNumberLocked(accountId, appId)) {
            // File removed; tombstone at prevCN and roll back cache.
            auto deleted = LoadDeletedLocked(accountId, appId, nullptr);
            uint64_t cnAtDelete = prevCN;
            uint64_t now = static_cast<uint64_t>(std::time(nullptr));
            auto exist = deleted.find(filename);
            if (exist == deleted.end()) {
                deleted[filename] = TombstoneInfo{ cnAtDelete, now };
            } else {
                exist->second.cn = (std::max)(exist->second.cn, cnAtDelete);
                if (exist->second.createTimeUnix == 0) {
                    exist->second.createTimeUnix = now;
                }
            }
            (void)SaveDeletedLocked(accountId, appId, deleted);
            g_changeNumbers[cnKey] = prevCN;
            LOG("DeleteFile: cn.dat persist failed for app %u after removing %s; tombstoned at cn=%llu, rolled back CN",
                appId, filename.c_str(), (unsigned long long)cnAtDelete);
            return false;
        }
        LOG("DeleteFile: app %u %s", appId, filename.c_str());
        return true;
    }
    return false;
}

bool RestoreFileIfUnchanged(uint32_t accountId, uint32_t appId,
                            const std::string& filename,
                            const std::vector<uint8_t>& expectedData,
                            const std::string& backupPath,
                            bool hadOriginal) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);

    std::string appRoot = GetAppPathInternal(accountId, appId);
    std::string fullPath = ValidateFilename(appRoot, filename);
    if (fullPath.empty()) {
        LOG("RestoreFileIfUnchanged BLOCKED: path traversal in filename '%s'", filename.c_str());
        return false;
    }

    std::vector<uint8_t> currentData;
    {
        std::ifstream f(FileUtil::Utf8ToPath(fullPath), std::ios::binary);
        if (f) {
            currentData.assign(std::istreambuf_iterator<char>(f),
                               std::istreambuf_iterator<char>());
        } else if (hadOriginal) {
            LOG("RestoreFileIfUnchanged: %s missing, expected to restore original; skipping",
                filename.c_str());
            return false;
        }
    }
    if (currentData != expectedData) {
        LOG("RestoreFileIfUnchanged: %s modified concurrently; skipping rollback",
            filename.c_str());
        return false;
    }

    std::error_code ec;
    if (hadOriginal) {
        std::filesystem::copy_file(FileUtil::Utf8ToPath(backupPath),
                                   FileUtil::Utf8ToPath(fullPath),
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            LOG("RestoreFileIfUnchanged: copy failed for %s: %s",
                filename.c_str(), ec.message().c_str());
            return false;
        }
    } else {
        std::filesystem::remove(FileUtil::Utf8ToPath(fullPath), ec);
        if (ec) {
            LOG("RestoreFileIfUnchanged: remove failed for %s: %s",
                filename.c_str(), ec.message().c_str());
            return false;
        }
    }
    LOG("RestoreFileIfUnchanged: %s restored (hadOriginal=%d)", filename.c_str(), hadOriginal ? 1 : 0);
    return true;
}

void CleanupEmptyCacheDirs(uint32_t accountId, uint32_t appId,
                           std::vector<std::string> startDirs) {
    if (startDirs.empty()) return;

    std::lock_guard<std::shared_mutex> lock(g_mutex);
    std::string appRoot = GetAppPathInternal(accountId, appId);

    // Deepest first so cascade up to appRoot works on shared parents.
    std::sort(startDirs.begin(), startDirs.end(),
              [](const std::string& a, const std::string& b) { return a.size() > b.size(); });

    for (const auto& startDir : startDirs) {
        FileUtil::CleanupEmptyDirsUpTo(startDir, appRoot);
    }
}

bool SetFileTimestamp(uint32_t accountId, uint32_t appId, const std::string& filename, uint64_t unixSeconds) {
    if (unixSeconds == 0) return false;
    std::lock_guard<std::shared_mutex> lock(g_mutex);

    std::string appRoot = GetAppPathInternal(accountId, appId);
    std::string fullPath = ValidateFilename(appRoot, filename);
    if (fullPath.empty()) {
        LOG("SetFileTimestamp BLOCKED: path traversal in filename '%s'", filename.c_str());
        return false;
    }

    auto fileTime = UnixSecondsToFileTime(unixSeconds);

    std::error_code ec;
    std::filesystem::last_write_time(FileUtil::Utf8ToPath(fullPath), fileTime, ec);
    if (ec) {
        LOG("SetFileTimestamp: failed for %s: %s", filename.c_str(), ec.message().c_str());
        return false;
    }
    LOG("SetFileTimestamp: %s -> %llu", filename.c_str(), unixSeconds);
    return true;
}


AutoCloudScanResult GetAutoCloudFileList(const std::string& steamPath,
                                         uint32_t accountId, uint32_t appId) {
    AutoCloudScanResult outResult;
    std::vector<FileEntry>& result = outResult.files;

    auto rules = LoadAutoCloudRules(steamPath, appId);
    if (rules.empty()) {
        LOG("GetAutoCloudFileList: no appinfo UFS save rules for app %u", appId);
        return outResult;
    }

    std::filesystem::path appUserdataDir = FileUtil::Utf8ToPath(steamPath) / "userdata" /
        std::to_string(accountId) / std::to_string(appId);

    auto addFile = [&](const std::filesystem::directory_entry& fileEntry,
                       const std::string& cloudPath,
                       const std::string& sourcePath,
                       const std::string& rootToken,
                       uint32_t rootId) {
        std::string fileName = FileUtil::PathToUtf8(fileEntry.path().filename());
        if (fileName == "steam_autocloud.vdf") return;

        std::error_code ec;
        uint64_t rawSize = (uint64_t)fileEntry.file_size(ec);
        if (ec) return;
        if (rawSize > kMaxAutoCloudCandidateBytes) {
            LOG("GetAutoCloudFileList: skipping oversized app %u candidate %s (%llu bytes)",
                appId, sourcePath.c_str(), (unsigned long long)rawSize);
            return;
        }

        auto sha = SHA1File(FileUtil::PathToUtf8(fileEntry.path()));
        auto ftime = std::filesystem::last_write_time(fileEntry.path(), ec);
        if (ec) return;
        uint64_t ts = FileTimeToUnixSeconds(ftime);

        FileEntry fe;
        fe.filename = cloudPath;
        fe.sourcePath = sourcePath;
        fe.rootToken = rootToken;
        fe.sha = sha;
        fe.timestamp = ts;
        fe.rawSize = rawSize;
        fe.deleted = false;
        fe.rootId = rootId;
        result.push_back(std::move(fe));
    };

    struct RootMapping {
        std::string dirName;
        std::string rootToken;
        uint32_t rootId;
        std::string envExpansion;
    };
    // Wide variant: getenv() is not thread-safe; ...A() ACP-encodes non-ASCII profiles.
    auto getEnvUtf8 = [](const wchar_t* name) -> std::string {
        wchar_t wbuf[MAX_PATH];
        constexpr DWORD bufLen = (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]));
        DWORD n = GetEnvironmentVariableW(name, wbuf, bufLen);
        if (n == 0 || n >= bufLen) return {};
        return FileUtil::WideToUtf8(wbuf, (size_t)n);
    };

    std::string localLow;
    {
        // Knownfolder ID returns canonical LocalLow; "%LOCALAPPDATA%\..\LocalLow"
        // would slip past the reparse-point gate when LOCALAPPDATA is a junction.
        std::string known = GetKnownFolderPathString(FOLDERID_LocalAppDataLow);
        if (!known.empty()) {
            localLow = known + "\\";
        } else {
            // Fallback if knownfolder API fails (restricted token / corrupt profile).
            std::string tmp = getEnvUtf8(L"LOCALAPPDATA");
            if (!tmp.empty()) localLow = tmp + "\\..\\LocalLow\\";
        }
    }

    std::string localAppData;
    {
        std::string tmp = getEnvUtf8(L"LOCALAPPDATA");
        if (!tmp.empty()) localAppData = tmp + "\\";
    }

    std::string roamingAppData;
    {
        std::string tmp = getEnvUtf8(L"APPDATA");
        if (!tmp.empty()) roamingAppData = tmp + "\\";
    }

    std::string myDocuments;
    {
        std::string known = GetKnownFolderPathString(FOLDERID_Documents);
        if (!known.empty()) {
            myDocuments = known + "\\";
        } else {
            std::string tmp = getEnvUtf8(L"USERPROFILE");
            if (!tmp.empty()) myDocuments = tmp + "\\Documents\\";
        }
    }

    std::string savedGames;
    {
        std::string known = GetKnownFolderPathString(FOLDERID_SavedGames);
        if (!known.empty()) {
            savedGames = known + "\\";
        } else {
            std::string tmp = getEnvUtf8(L"USERPROFILE");
            if (!tmp.empty()) savedGames = tmp + "\\Saved Games\\";
        }
    }

    std::string gameInstallPath = FindGameInstallPath(steamPath, appId);

    // rootId values: Steam ERemoteStorageFileRoot. Triples in steam_root_ids.h.
    auto rootFor = [](const char* bare) -> const SteamRootIds::Entry& {
        for (const auto& e : SteamRootIds::kEntries) {
            if (std::string(e.bareName) == bare) return e;
        }
        // Unreachable: all names below come from the shared table.
        static const SteamRootIds::Entry sentinel{"", "", 0};
        return sentinel;
    };
    const auto& rGameInstall   = rootFor("GameInstall");
    const auto& rLocalLow      = rootFor("WinAppDataLocalLow");
    const auto& rLocal         = rootFor("WinAppDataLocal");
    const auto& rRoaming       = rootFor("WinAppDataRoaming");
    const auto& rMyDocs        = rootFor("WinMyDocuments");
    const auto& rSavedGames    = rootFor("WinSavedGames");
    RootMapping mappings[] = {
        {"",                   "",                      0,                 FileUtil::PathToUtf8(appUserdataDir / "remote")},
        {rGameInstall.bareName, rGameInstall.token,     rGameInstall.rootId, gameInstallPath},
        {rLocalLow.bareName,    rLocalLow.token,        rLocalLow.rootId,    localLow},
        {rLocal.bareName,       rLocal.token,           rLocal.rootId,       localAppData},
        {rRoaming.bareName,     rRoaming.token,         rRoaming.rootId,    roamingAppData},
        {rMyDocs.bareName,      rMyDocs.token,          rMyDocs.rootId,     myDocuments},
        {rSavedGames.bareName,  rSavedGames.token,      rSavedGames.rootId, savedGames},
    };

    std::unordered_map<std::string, std::string> seenRootsByCloudPath;
    // Sibling dedupe; separate from primary so siblings can't trip the abort.
    std::unordered_set<std::string> emittedSiblings;
    bool hasRootCollision = false;
    bool scanLimitHit = false;
    size_t visitedFiles = 0;
    auto scanStart = std::chrono::steady_clock::now();
    auto scanLimitReached = [&]() {
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - scanStart).count();
        if (visitedFiles >= kMaxAutoCloudScanFiles || elapsedMs >= kMaxAutoCloudScanMillis) {
            scanLimitHit = true;
            LOG("GetAutoCloudFileList: stopping app %u scan after %zu files and %lld ms",
                appId, visitedFiles, (long long)elapsedMs);
            return true;
        }
        return false;
    };
    for (const auto& rule : rules) {
        if (!AutoCloudRuleMatchesCurrentPlatform(rule.platforms)) {
            LOG("GetAutoCloudFileList: skipping app %u rule root='%s' path='%s' (platforms mask=0x%x excludes Windows)",
                appId, rule.root.c_str(), rule.path.c_str(), rule.platforms);
            continue;
        }
        const RootMapping* mapping = nullptr;
        std::string ruleRootLower = ToLowerAscii(rule.root);
        for (const auto& candidate : mappings) {
            if (ToLowerAscii(candidate.dirName) == ruleRootLower) {
                mapping = &candidate;
                break;
            }
        }

        if (!mapping) {
            LOG("GetAutoCloudFileList: skipping app %u rule with unknown root '%s'", appId, rule.root.c_str());
            continue;
        }
        if (mapping->envExpansion.empty()) {
            LOG("GetAutoCloudFileList: skipping app %u rule root '%s' because filesystem root is unresolved",
                appId, rule.root.c_str());
            continue;
        }

        std::string normalizedCloudPath = ExpandAutoCloudPathTokens(NormalizeSlashes(rule.path), accountId);
        std::string normalizedScanPath = ExpandAutoCloudPathTokens(NormalizeSlashes(rule.resolvedPath), accountId);
        if (normalizedCloudPath == ".") normalizedCloudPath.clear();
        if (normalizedScanPath == ".") normalizedScanPath.clear();
        if (!IsSafeRelativePath(normalizedCloudPath) || !IsSafeRelativePath(normalizedScanPath)) {
            LOG("GetAutoCloudFileList: skipping unsafe app %u rule path '%s'", appId, rule.path.c_str());
            continue;
        }
        while (!normalizedCloudPath.empty() && normalizedCloudPath.front() == '/') normalizedCloudPath.erase(0, 1);
        while (!normalizedCloudPath.empty() && normalizedCloudPath.back() == '/') normalizedCloudPath.pop_back();
        while (!normalizedScanPath.empty() && normalizedScanPath.front() == '/') normalizedScanPath.erase(0, 1);
        while (!normalizedScanPath.empty() && normalizedScanPath.back() == '/') normalizedScanPath.pop_back();

        std::filesystem::path scanRoot = FileUtil::Utf8ToPath(mapping->envExpansion);
        if (!normalizedScanPath.empty()) {
            std::filesystem::path rel;
            std::stringstream ss(normalizedScanPath);
            std::string part;
            while (std::getline(ss, part, '/')) {
                if (!part.empty()) rel /= FileUtil::Utf8ToPath(part);
            }
            scanRoot /= rel;
        }

        std::error_code scanRootEc;
        if (!std::filesystem::exists(scanRoot, scanRootEc) || scanRootEc ||
            !std::filesystem::is_directory(scanRoot, scanRootEc) || scanRootEc) {
            LOG("GetAutoCloudFileList: app %u rule path missing: root='%s' path='%s' resolved='%s'",
                appId, rule.root.c_str(), rule.path.c_str(),
                FileUtil::PathToUtf8(scanRoot).c_str());
            continue;
        }
        // Refuse junctions/symlinks at the scan root; OneDrive placeholders are exempt.
        std::string scanRootUtf8 = FileUtil::PathToUtf8(scanRoot);
        if (FileUtil::IsPathRedirectingReparsePoint(scanRootUtf8)) {
            LOG("GetAutoCloudFileList: app %u rule scan root is a junction/symlink, refusing to walk: root='%s' path='%s' resolved='%s'",
                appId, rule.root.c_str(), rule.path.c_str(), scanRootUtf8.c_str());
            continue;
        }

        LOG("GetAutoCloudFileList: app %u rule root='%s' path='%s' resolvedPath='%s' pattern='%s' recursive=%u resolved='%s'",
            appId, rule.root.c_str(), rule.path.c_str(), rule.resolvedPath.c_str(),
            rule.pattern.c_str(), rule.recursive ? 1 : 0, scanRootUtf8.c_str());

        auto considerFile = [&](const std::filesystem::directory_entry& entry) {
            std::error_code fileEc;
            // Junction/symlink gate before is_regular_file (which follows reparse points).
            std::string entryUtf8 = FileUtil::PathToUtf8(entry.path());
            if (FileUtil::IsPathRedirectingReparsePoint(entryUtf8)) {
                LOG("GetAutoCloudFileList: app %u skipping junction/symlink entry under '%s': %s",
                    appId, scanRootUtf8.c_str(), entryUtf8.c_str());
                return;
            }
            if (!entry.is_regular_file(fileEc)) return;
            ++visitedFiles;
            std::string relFromRoot = NormalizeSlashes(
                FileUtil::PathToUtf8(std::filesystem::relative(entry.path(), scanRoot, fileEc)));
            if (fileEc) return;
            std::string leaf = FileUtil::PathToUtf8(entry.path().filename());
            if (leaf == "steam_autocloud.vdf") return;
            std::string pattern = NormalizeSlashes(rule.pattern.empty() ? "*" : rule.pattern);
            const std::string& matchTarget = pattern.find('/') == std::string::npos ? leaf : relFromRoot;
            if (!WildcardMatchInsensitive(pattern, matchTarget)) return;

            for (const auto& excludePattern : rule.excludes) {
                std::string exPat = NormalizeSlashes(excludePattern);
                const std::string& exTarget = exPat.find('/') == std::string::npos ? leaf : relFromRoot;
                if (WildcardMatchInsensitive(exPat, exTarget)) return;
            }

            std::string cloudPath = normalizedCloudPath.empty() ? relFromRoot : normalizedCloudPath + "/" + relFromRoot;
            std::string collisionKey = ToLowerAscii(NormalizeSlashes(cloudPath));
            auto seenIt = seenRootsByCloudPath.find(collisionKey);
            if (seenIt != seenRootsByCloudPath.end()) {
                if (seenIt->second != mapping->rootToken) {
                    LOG("GetAutoCloudFileList: root collision for app %u cloud path %s (%s vs %s); aborting bootstrap",
                        appId, cloudPath.c_str(), seenIt->second.c_str(), mapping->rootToken.c_str());
                    hasRootCollision = true;
                }
                return;
            }
            seenRootsByCloudPath[collisionKey] = mapping->rootToken;
            addFile(entry, cloudPath, entryUtf8, mapping->rootToken, mapping->rootId);

            // Sibling expansion (Steam sub_1384DBA40): probe stem.<ext>.
            for (const auto& siblingExt : rule.siblings) {
                if (scanLimitReached()) break;
                ++visitedFiles;
                std::filesystem::path siblingPath = entry.path();
                siblingPath.replace_extension(FileUtil::Utf8ToPath(siblingExt));
                std::error_code sibEc;
                if (!std::filesystem::exists(siblingPath, sibEc) || sibEc) continue;
                std::string siblingPathUtf8 = FileUtil::PathToUtf8(siblingPath);
                if (FileUtil::IsPathRedirectingReparsePoint(siblingPathUtf8)) {
                    LOG("GetAutoCloudFileList: app %u skipping junction/symlink sibling: %s",
                        appId, siblingPathUtf8.c_str());
                    continue;
                }
                if (!std::filesystem::is_regular_file(siblingPath, sibEc) || sibEc) continue;
                std::string siblingRel = NormalizeSlashes(
                    FileUtil::PathToUtf8(std::filesystem::relative(siblingPath, scanRoot, sibEc)));
                if (sibEc || !IsSafeRelativePath(siblingRel)) continue;
                std::string siblingCloudPath = normalizedCloudPath.empty()
                    ? siblingRel
                    : normalizedCloudPath + "/" + siblingRel;
                std::string siblingKey = ToLowerAscii(NormalizeSlashes(siblingCloudPath));
                if (seenRootsByCloudPath.find(siblingKey) != seenRootsByCloudPath.end()) {
                    LOG("GetAutoCloudFileList: sibling %s already claimed by a primary for app %u; skipping",
                        siblingCloudPath.c_str(), appId);
                    continue;
                }
                if (emittedSiblings.find(siblingKey) != emittedSiblings.end()) continue;
                std::filesystem::directory_entry siblingDirEntry(siblingPath, sibEc);
                if (sibEc) continue;
                emittedSiblings.insert(siblingKey);
                addFile(siblingDirEntry, siblingCloudPath, siblingPathUtf8,
                        mapping->rootToken, mapping->rootId);
            }
        };

        if (rule.recursive) {
            std::error_code iterEc;
            std::filesystem::recursive_directory_iterator it(
                scanRoot, std::filesystem::directory_options::skip_permission_denied, iterEc);
            std::filesystem::recursive_directory_iterator end;
            for (; !iterEc && it != end; it.increment(iterEc)) {
                if (scanLimitReached()) break;
                considerFile(*it);
            }
        } else {
            std::error_code iterEc;
            std::filesystem::directory_iterator it(
                scanRoot, std::filesystem::directory_options::skip_permission_denied, iterEc);
            std::filesystem::directory_iterator end;
            for (; !iterEc && it != end; it.increment(iterEc)) {
                if (scanLimitReached()) break;
                considerFile(*it);
            }
        }
        if (scanLimitReached()) break;
    }

    // Routine bounded-scan outcomes; not exceptional.
    outResult.scanLimitHit = scanLimitHit;
    outResult.hasRootCollision = hasRootCollision;
    if (hasRootCollision) {
        result.clear();
        LOG("GetAutoCloudFileList: aborting app %u bootstrap due to root/path collision", appId);
    }

    LOG("GetAutoCloudFileList: found %zu rule-matched Auto-Cloud files for app %u (scanLimitHit=%d, hasRootCollision=%d)",
        result.size(), appId, (int)scanLimitHit, (int)hasRootCollision);
    for (auto& fe : result) {
        LOG("  AC file: root=%u %s (%llu bytes)", fe.rootId, fe.filename.c_str(), fe.rawSize);
    }
    return outResult;
}

bool SaveRootTokens(uint32_t accountId, uint32_t appId, const std::unordered_set<std::string>& tokens) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    std::string appDir = GetAppPathInternal(accountId, appId);
    std::error_code dirEc;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appDir), dirEc);
    if (dirEc) {
        LOG("SaveRootTokens: create_directories failed for '%s': %s",
            appDir.c_str(), dirEc.message().c_str());
        return false;
    }
    std::string path = appDir + "root_token.dat";
    std::string content;
    for (auto& t : tokens) {
        content += t + "\n";
    }
    if (FileUtil::AtomicWriteText(path, content)) {
        LOG("SaveRootTokens: persisted %zu tokens for app %u", tokens.size(), appId);
        return true;
    } else {
        LOG("SaveRootTokens: failed for app %u", appId);
        return false;
    }
}

std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId) {
    std::unordered_set<std::string> tokens;
    bool needsRewrite = false;

    // Read phase: shared lock allows concurrent readers
    {
        std::shared_lock<std::shared_mutex> lock(g_mutex);
        std::string path = GetAppPathInternal(accountId, appId) + "root_token.dat";
        std::ifstream f(FileUtil::Utf8ToPath(path));
        if (f) {
            std::string line;
            while (std::getline(f, line)) {
                std::string original = line;
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (line != original)
                    needsRewrite = true;
                if (!line.empty()) {
                    tokens.insert(line);
                }
            }
            f.close();
            if (!tokens.empty()) {
                LOG("LoadRootTokens: loaded %zu tokens from disk for app %u", tokens.size(), appId);
            }
        }
    }

    if (needsRewrite && !tokens.empty()) {
        LOG("LoadRootTokens: cleaning corrupted tokens for app %u", appId);
        if (!SaveRootTokens(accountId, appId, tokens)) {
            LOG("LoadRootTokens: cleanup rewrite FAILED app %u -- will retry on next load", appId);
        }
    }

    return tokens;
}

bool SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    std::string appDir = GetAppPathInternal(accountId, appId);
    std::error_code dirEc;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appDir), dirEc);
    if (dirEc) {
        LOG("SaveFileTokens: create_directories failed for '%s': %s",
            appDir.c_str(), dirEc.message().c_str());
        return false;
    }
    std::string path = appDir + "file_tokens.dat";
    std::string content;
    for (auto& [cleanName, token] : fileTokens) {
        content += cleanName + "\t" + token + "\n";
    }
    if (FileUtil::AtomicWriteText(path, content)) {
        LOG("SaveFileTokens: persisted %zu entries for app %u", fileTokens.size(), appId);
        return true;
    } else {
        LOG("SaveFileTokens: failed for app %u", appId);
        return false;
    }
}

std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId) {
    std::shared_lock<std::shared_mutex> lock(g_mutex);
    std::string path = GetAppPathInternal(accountId, appId) + "file_tokens.dat";
    std::unordered_map<std::string, std::string> result;
    std::ifstream f(FileUtil::Utf8ToPath(path));
    if (f) {
        std::string line;
        while (std::getline(f, line)) {
            // Strip trailing \r (CRLF)
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (line.empty()) continue;
            auto tab = line.find('\t');
            if (tab == std::string::npos) continue;
            std::string cleanName = line.substr(0, tab);
            std::string token = line.substr(tab + 1);
            if (!cleanName.empty()) {
                result[cleanName] = token;
            }
        }
        if (!result.empty()) {
            LOG("LoadFileTokens: loaded %zu entries from disk for app %u", result.size(), appId);
        }
    }
    return result;
}

// deleted.dat: local-only tombstones, "filename\tcn\tcreateTimeUnix\n".
// File format versions: v1 "filename", v2 "filename\tcn", v3 (current) adds createTimeUnix.
static std::unordered_map<std::string, TombstoneInfo> LoadDeletedLocked(uint32_t accountId,
                                                                        uint32_t appId,
                                                                        bool* outNeedsRewrite) {
    // Caller holds g_mutex (shared or exclusive).
    std::unordered_map<std::string, TombstoneInfo> deleted;
    if (outNeedsRewrite) *outNeedsRewrite = false;
    std::string path = GetAppPathInternal(accountId, appId) + "deleted.dat";
    std::ifstream f(FileUtil::Utf8ToPath(path));
    if (!f) return deleted;

    auto parseUnsigned = [](const std::string& s, uint64_t& out) -> bool {
        if (s.empty()) return false;
        for (char c : s) {
            if (c < '0' || c > '9') return false;
        }
        try {
            out = static_cast<uint64_t>(std::stoull(s));
            return true;
        } catch (...) {
            return false;
        }
    };

    std::string line;
    while (std::getline(f, line)) {
        std::string original = line;
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line != original && outNeedsRewrite) *outNeedsRewrite = true;
        if (line.empty()) continue;

        std::string fname;
        TombstoneInfo info;
        auto firstTab = line.find('\t');
        if (firstTab == std::string::npos) {
            // v1 (filename only)
            fname = line;
            if (outNeedsRewrite) *outNeedsRewrite = true;
        } else {
            fname = line.substr(0, firstTab);
            std::string rest = line.substr(firstTab + 1);
            auto secondTab = rest.find('\t');
            std::string cnStr = (secondTab == std::string::npos) ? rest : rest.substr(0, secondTab);
            if (!parseUnsigned(cnStr, info.cn)) {
                info.cn = 0;
                if (outNeedsRewrite) *outNeedsRewrite = true;
            }
            if (secondTab == std::string::npos) {
                // v2 (filename\tcn) -- legacy, createTime stays 0
                if (outNeedsRewrite) *outNeedsRewrite = true;
            } else {
                std::string ctStr = rest.substr(secondTab + 1);
                if (!parseUnsigned(ctStr, info.createTimeUnix)) {
                    info.createTimeUnix = 0;
                    if (outNeedsRewrite) *outNeedsRewrite = true;
                }
            }
        }
        if (fname.empty()) continue;

        // On dup, keep higher (cn, createTime).
        auto it = deleted.find(fname);
        if (it == deleted.end()) {
            deleted[fname] = info;
        } else {
            TombstoneInfo& kept = it->second;
            bool replace = false;
            if (info.cn > kept.cn) replace = true;
            else if (info.cn == kept.cn) {
                if (info.createTimeUnix > kept.createTimeUnix) replace = true;
            }
            if (replace) kept = info;
        }
    }
    return deleted;
}

static bool SaveDeletedLocked(uint32_t accountId, uint32_t appId,
                              const std::unordered_map<std::string, TombstoneInfo>& deleted) {
    std::string appDir = GetAppPathInternal(accountId, appId);
    std::error_code mkEc;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appDir), mkEc);
    std::string path = appDir + "deleted.dat";
    if (deleted.empty()) {
        std::error_code ec;
        std::filesystem::remove(FileUtil::Utf8ToPath(path), ec);
        if (ec && ec != std::errc::no_such_file_or_directory) {
            LOG("SaveDeletedLocked: failed to remove empty tombstone file for app %u: %s",
                appId, ec.message().c_str());
            return false;
        }
        return true;
    }
    std::string content;
    for (auto& kv : deleted) {
        content += kv.first;
        content += '\t';
        content += std::to_string(kv.second.cn);
        content += '\t';
        content += std::to_string(kv.second.createTimeUnix);
        content += '\n';
    }
    if (!FileUtil::AtomicWriteText(path, content)) {
        LOG("SaveDeletedLocked: FAILED to persist %zu tombstone(s) for app %u -- "
            "deletion may resurrect on next SyncFromCloud", deleted.size(), appId);
        return false;
    }
    return true;
}

std::unordered_map<std::string, TombstoneInfo> LoadDeleted(uint32_t accountId, uint32_t appId) {
    bool needsRewrite = false;
    std::unordered_map<std::string, TombstoneInfo> deleted;
    {
        std::shared_lock<std::shared_mutex> lock(g_mutex);
        deleted = LoadDeletedLocked(accountId, appId, &needsRewrite);
    }
    // Re-read under exclusive lock; don't resurrect post-snapshot deletions.
    if (needsRewrite) {
        std::lock_guard<std::shared_mutex> lock(g_mutex);
        bool latestNeedsRewrite = false;
        auto latest = LoadDeletedLocked(accountId, appId, &latestNeedsRewrite);
        if (latestNeedsRewrite && !latest.empty()) {
            SaveDeletedLocked(accountId, appId, latest);
        }
        deleted = std::move(latest);
    }
    return deleted;
}

void MarkDeleted(uint32_t accountId, uint32_t appId, const std::string& filename,
                 uint64_t cnAtDelete) {
    if (filename.empty()) return;
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    auto deleted = LoadDeletedLocked(accountId, appId, nullptr);
    auto it = deleted.find(filename);
    bool inserted = (it == deleted.end());
    // No-op if existing >= incoming; allow upgrading legacy zero-createTime rows.
    if (!inserted && it->second.cn >= cnAtDelete && it->second.createTimeUnix > 0) {
        return;
    }
    uint64_t mergedCn = inserted ? cnAtDelete : (std::max)(it->second.cn, cnAtDelete);
    deleted[filename] = TombstoneInfo{ mergedCn, now };
    if (!SaveDeletedLocked(accountId, appId, deleted)) {
        LOG("MarkDeleted: app %u tombstone for %s (cn=%llu createTime=%llu) NOT persisted",
            appId, filename.c_str(),
            (unsigned long long)mergedCn, (unsigned long long)now);
        return;
    }
    LOG("MarkDeleted: app %u tombstoned %s at cn=%llu createTime=%llu (%zu total)",
        appId, filename.c_str(),
        (unsigned long long)mergedCn, (unsigned long long)now, deleted.size());
}

void ClearDeleted(uint32_t accountId, uint32_t appId, const std::string& filename) {
    if (filename.empty()) return;
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    auto deleted = LoadDeletedLocked(accountId, appId, nullptr);
    if (deleted.erase(filename) > 0) {
        if (!SaveDeletedLocked(accountId, appId, deleted)) {
            LOG("ClearDeleted: app %u clear for %s NOT persisted", appId, filename.c_str());
            return;
        }
        LOG("ClearDeleted: app %u cleared %s (%zu remaining)",
            appId, filename.c_str(), deleted.size());
    }
}

bool MigrateDeletedKeys(uint32_t accountId, uint32_t appId,
                        const std::function<std::string(const std::string&)>& keyRewrite,
                        std::unordered_map<std::string, TombstoneInfo>& outFinalState,
                        size_t& outMigratedCount) {
    outFinalState.clear();
    outMigratedCount = 0;
    if (!keyRewrite) return true;
    // keyRewrite runs under exclusive lock; it must not re-enter LocalStorage.
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    bool needsFormatRewrite = false;
    auto current = LoadDeletedLocked(accountId, appId, &needsFormatRewrite);
    std::unordered_map<std::string, TombstoneInfo> migrated;
    migrated.reserve(current.size());
    bool anyChanged = needsFormatRewrite;
    for (auto& kv : current) {
        std::string newKey = keyRewrite(kv.first);
        if (newKey != kv.first) {
            ++outMigratedCount;
            anyChanged = true;
        }
        auto it = migrated.find(newKey);
        if (it == migrated.end()) {
            migrated.emplace(std::move(newKey), kv.second);
        } else {
            // Collision: keep higher (cn, createTime).
            bool incomingNewer = kv.second.cn > it->second.cn ||
                (kv.second.cn == it->second.cn &&
                 kv.second.createTimeUnix > it->second.createTimeUnix);
            if (incomingNewer) it->second = kv.second;
            anyChanged = true;
        }
    }
    if (anyChanged) {
        if (!SaveDeletedLocked(accountId, appId, migrated)) {
            LOG("MigrateDeletedKeys: app %u rewrite of %zu tombstone(s) NOT persisted",
                appId, migrated.size());
            outFinalState = std::move(migrated);
            return false;
        }
        LOG("MigrateDeletedKeys: app %u migrated %zu key(s) (format_upgrade=%d), final tombstone count %zu",
            appId, outMigratedCount, needsFormatRewrite ? 1 : 0, migrated.size());
    }
    outFinalState = std::move(migrated);
    return true;
}

void EvictTombstonesNotIn(uint32_t accountId, uint32_t appId,
                          const std::unordered_set<std::string>& keepSet,
                          uint64_t listingCapturedAtUnix) {
    std::lock_guard<std::shared_mutex> lock(g_mutex);
    auto deleted = LoadDeletedLocked(accountId, appId, nullptr);
    if (deleted.empty()) return;

    size_t before = deleted.size();
    int evicted = 0;
    int protectedByCutoff = 0;
    for (auto it = deleted.begin(); it != deleted.end(); ) {
        if (keepSet.count(it->first) != 0) {
            ++it;
            continue;
        }
        // Evict only if the tombstone predates the listing snapshot; legacy (createTime=0) qualifies.
        bool predatesListing = (it->second.createTimeUnix == 0) ||
                               (listingCapturedAtUnix > 0 &&
                                it->second.createTimeUnix < listingCapturedAtUnix);
        if (!predatesListing) {
            ++protectedByCutoff;
            ++it;
            continue;
        }
        it = deleted.erase(it);
        ++evicted;
    }
    if (evicted == 0) {
        if (protectedByCutoff > 0) {
            LOG("EvictTombstonesNotIn: app %u nothing evicted (%d tombstone(s) protected by listing-time cutoff)",
                appId, protectedByCutoff);
        }
        return;
    }

    if (!SaveDeletedLocked(accountId, appId, deleted)) {
        LOG("EvictTombstonesNotIn: app %u batch eviction (%d entries) NOT persisted",
            appId, evicted);
        return;
    }
    LOG("EvictTombstonesNotIn: app %u evicted %d tombstone(s) confirmed absent from cloud (%zu -> %zu, %d protected by cutoff)",
        appId, evicted, before, deleted.size(), protectedByCutoff);
}

bool IsDeleted(uint32_t accountId, uint32_t appId, const std::string& filename) {
    if (filename.empty()) return false;
    std::shared_lock<std::shared_mutex> lock(g_mutex);
    // Stream rather than build the full map; one tombstone lookup costs O(lines) I/O only.
    std::string path = GetAppPathInternal(accountId, appId) + "deleted.dat";
    auto fsPath = FileUtil::Utf8ToPath(path);
    // Fail closed when the file exists but is unreadable; fail-open would let deleted saves resurrect.
    std::error_code existEc;
    bool fileExists = std::filesystem::exists(fsPath, existEc);
    if (existEc) {
        LOG("IsDeleted: app %u exists() failed for deleted.dat (%s); failing closed for %s",
            appId, existEc.message().c_str(), filename.c_str());
        return true;
    }
    if (!fileExists) return false;
    std::ifstream f(fsPath);
    if (!f) {
        LOG("IsDeleted: app %u deleted.dat exists but stream-open failed; failing closed for %s",
            appId, filename.c_str());
        return true;
    }
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty()) continue;
        auto tab = line.find('\t');
        std::string fname = (tab == std::string::npos) ? line : line.substr(0, tab);
        if (fname == filename) return true;
    }
    return false;
}

} // namespace LocalStorage
