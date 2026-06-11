#pragma once
// Shared utilities for AutoCloud parsing and scanning.
// Used by both local_storage.cpp and autocloud_scan.cpp.

#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <unordered_map>
#include <utility>

#ifdef _WIN32
#include <shlobj.h>
#include "file_util.h"
#endif

#include "log.h"

#ifndef _WIN32
#include <strings.h>
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#define _wcsicmp wcscasecmp
#endif

namespace AutoCloudUtil {

// Constants

static constexpr uintmax_t kMaxAppInfoBytes = 512ULL * 1024 * 1024;
static constexpr uint32_t kMaxAppInfoStrings = 200000;
static constexpr size_t kMaxAutoCloudScanFiles = 20000;
static constexpr int kMaxAutoCloudScanMillis = 5000;
// No per-file size cap; storage is bounded by the app's cloud quota.

// Wildcard matching caps against exponential backtracking.
static constexpr size_t kMaxWildcardPatternLen = 1024;
static constexpr int kMaxWildcardStars = 16;
static constexpr int kMaxWildcardIterations = 100000;

// String utilities

inline std::string ToLowerAscii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return (char)std::tolower(c);
    });
    return s;
}

inline std::string NormalizeSlashes(std::string s) {
    for (auto& c : s) { if (c == '\\') c = '/'; }
    return s;
}

inline void ReplaceAll(std::string& s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

inline std::string ExpandAutoCloudPathTokens(std::string path, uint32_t accountId) {
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

inline bool IsSafeRelativePath(const std::string& path) {
    if (path.empty()) return true;
    if (path.find('\0') != std::string::npos) return false;
    if (path.find(':') != std::string::npos) return false;
    if (!path.empty() && (path.front() == '/' || path.front() == '\\')) return false;
    std::stringstream ss(NormalizeSlashes(path));
    std::string part;
    while (std::getline(ss, part, '/')) {
        if (part == "..") return false;
    }
    return true;
}

// Filesystem time conversion

inline uint64_t FileTimeToUnixSeconds(std::filesystem::file_time_type ftime) {
    auto fileNow = std::filesystem::file_time_type::clock::now();
    auto sysNow = std::chrono::system_clock::now();
    auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
        ftime - fileNow + sysNow
    );
    return (uint64_t)sctp.time_since_epoch().count();
}

inline std::filesystem::file_time_type UnixSecondsToFileTime(uint64_t unixSeconds) {
    auto sysTime = std::chrono::system_clock::from_time_t((time_t)unixSeconds);
    auto sysNow = std::chrono::system_clock::now();
    auto fileNow = std::filesystem::file_time_type::clock::now();
    return fileNow + (sysTime - sysNow);
}

// Platform-specific path resolution

#ifdef _WIN32
inline std::string GetKnownFolderPathString(const KNOWNFOLDERID& id) {
    PWSTR wide = nullptr;
    if (FAILED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &wide)) || !wide) return {};
    std::string result = FileUtil::WideToUtf8(wide);
    CoTaskMemFree(wide);
    return result;
}
#endif

// Binary KV parsing for appinfo.vdf

inline bool ReadU32(const std::vector<uint8_t>& data, size_t& offset, uint32_t& out) {
    if (offset + 4 > data.size()) return false;
    out = (uint32_t)data[offset] |
        ((uint32_t)data[offset + 1] << 8) |
        ((uint32_t)data[offset + 2] << 16) |
        ((uint32_t)data[offset + 3] << 24);
    offset += 4;
    return true;
}

inline bool ReadI32(const std::vector<uint8_t>& data, size_t& offset, int32_t& out) {
    uint32_t u = 0;
    if (!ReadU32(data, offset, u)) return false;
    out = (int32_t)u;
    return true;
}

inline std::string ReadCStringFromBytes(const std::vector<uint8_t>& data, size_t& offset) {
    size_t start = offset;
    while (offset < data.size() && data[offset] != 0) ++offset;
    std::string s(reinterpret_cast<const char*>(data.data() + start), offset - start);
    if (offset < data.size()) ++offset;
    return s;
}

// AutoCloud rule structures

struct AutoCloudRuleNative {
    std::string root;
    std::string cloudRoot;
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

enum class AutoCloudEffectivePlatform {
    Current,
    Windows,
    Linux,
};

// Sibling parsing

// Reject invalid sibling tokens.
inline std::vector<std::string> ParseAutoCloudSiblings(const std::string& raw) {
    std::vector<std::string> out;
    std::string token;
    auto flush = [&]() {
        if (token.empty()) return;
        std::string candidate;
        candidate.swap(token);
        if (candidate == "..") return;
        if (candidate.front() == '.') return;
        for (char c : candidate) {
            if (c == '/' || c == '\\' || c == ':') return;
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

// Platform mask parsing

inline uint32_t ParseAutoCloudPlatformMask(const std::string& name) {
    std::string lower = ToLowerAscii(name);
    if (lower == "windows" || lower == "win") return 1;
    if (lower == "macos" || lower == "osx" || lower == "mac") return 2;
    if (lower == "linux") return 8;
    if (lower == "all") return 0xFFFFFFFFu;
    if (lower == "none") return 0;
    return 0;
}

inline bool AutoCloudRuleMatchesPlatform(uint32_t mask, AutoCloudEffectivePlatform platform) {
    if (platform == AutoCloudEffectivePlatform::Windows) return (mask & 1u) != 0;
    if (platform == AutoCloudEffectivePlatform::Linux) return (mask & 8u) != 0;
#ifdef _WIN32
    return (mask & 1u) != 0;  // Windows = bit 0
#else
    return (mask & 8u) != 0;  // Linux = bit 3
#endif
}

inline bool AutoCloudRuleMatchesCurrentPlatform(uint32_t mask) {
    return AutoCloudRuleMatchesPlatform(mask, AutoCloudEffectivePlatform::Current);
}

// appinfo.vdf KV tree parsing

inline std::vector<AppInfoKVNode> ParseAppInfoKV(const std::vector<uint8_t>& data, size_t& offset,
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

inline const AppInfoKVNode* FindChild(const std::vector<AppInfoKVNode>& nodes, const char* key) {
    for (const auto& node : nodes) {
        if (_stricmp(node.key.c_str(), key) == 0) return &node;
    }
    return nullptr;
}

// Windows version detection for root overrides

inline int WindowsVersionRank(std::string osName) {
    osName = ToLowerAscii(osName);
    if (osName == "windows11" || osName == "win11") return 11;
    if (osName == "windows10" || osName == "win10") return 10;
    if (osName == "windows8" || osName == "windows81" || osName == "win8" || osName == "win81") return 8;
    if (osName == "windows7" || osName == "win7") return 7;
    if (osName == "windows" || osName == "win") return 0;
    return -1;
}

inline bool IsLinuxOS(const std::string& osName) {
    std::string lower = ToLowerAscii(osName);
    return lower == "linux";
}

#ifndef _WIN32
// See autocloud_path_resolver.h for Linux path resolution.
#include "autocloud_path_resolver.h"
#endif

// Current Windows version detection

inline int CurrentWindowsVersionRank() {
#ifdef _WIN32
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
#else
    return -1;  // Not Windows -- root overrides for Windows versions never match
#endif
}

// Root override applicability checks

inline bool IsWindowsRootOverrideActive(const AutoCloudRootOverrideNative& overrideRule) {
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

inline bool IsLinuxRootOverrideActive(const AutoCloudRootOverrideNative& overrideRule) {
#ifdef _WIN32
    return false;
#else
    return IsLinuxOS(overrideRule.os);
#endif
}

inline bool IsRootOverrideActiveForPlatform(const AutoCloudRootOverrideNative& overrideRule,
                                            AutoCloudEffectivePlatform platform) {
    if (platform == AutoCloudEffectivePlatform::Windows) return IsWindowsRootOverrideActive(overrideRule);
    if (platform == AutoCloudEffectivePlatform::Linux) return IsLinuxOS(overrideRule.os);
#ifdef _WIN32
    return IsWindowsRootOverrideActive(overrideRule);
#else
    return IsLinuxRootOverrideActive(overrideRule);
#endif
}

inline void ApplyRootOverridesForPlatform(AutoCloudRuleNative& rule,
                                          const std::vector<AutoCloudRootOverrideNative>& overrides,
                                          AutoCloudEffectivePlatform platform) {
    for (const auto& overrideRule : overrides) {
        bool active = IsRootOverrideActiveForPlatform(overrideRule, platform);
        bool rootMatch = _stricmp(rule.root.c_str(), overrideRule.root.c_str()) == 0;
        LOG("ApplyRootOverride: rule.root='%s' vs override.root='%s' os='%s' active=%d rootMatch=%d -> useinstead='%s'",
            rule.root.c_str(), overrideRule.root.c_str(), overrideRule.os.c_str(),
            active ? 1 : 0, rootMatch ? 1 : 0, overrideRule.useInstead.c_str());
        if (!active) continue;
        if (!rootMatch) continue;

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

#ifndef _WIN32
    if (platform != AutoCloudEffectivePlatform::Windows) {
        std::string linuxRoot = AutoCloudPathResolver::WindowsRootToLinux(rule.root);
        if (!linuxRoot.empty()) {
            rule.root = linuxRoot;
        } else if (!rule.root.empty() && rule.root != "GameInstall" && rule.root[0] != '%') {
            LOG("ApplyRootOverridesForCurrentOS: No Linux mapping for Windows root '%s', game may fail to sync",
                rule.root.c_str());
        }
    }
#endif
}

inline void ApplyRootOverridesForCurrentOS(AutoCloudRuleNative& rule,
                                           const std::vector<AutoCloudRootOverrideNative>& overrides) {
    ApplyRootOverridesForPlatform(rule, overrides, AutoCloudEffectivePlatform::Current);
}

// Wildcard matching (case-insensitive)

inline bool WildcardMatchImpl(const char* pattern, const char* text, int& iters) {
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

inline bool WildcardMatchInsensitive(const char* pattern, const char* text) {
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

inline bool WildcardMatchInsensitive(const std::string& pattern, const std::string& text) {
    return WildcardMatchInsensitive(pattern.c_str(), text.c_str());
}

} // namespace AutoCloudUtil
