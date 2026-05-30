#include "local_storage.h"
#include "autocloud_scan.h"
#include "autocloud_util.h"
#include "cloud_metadata_paths.h"
#include "file_util.h"
#include "log.h"
#include "steam_root_ids.h"

using CloudIntercept::kCNFilename;
using CloudIntercept::kLegacyCNFilename;
using CloudIntercept::kRootTokenFilename;
using CloudIntercept::kLegacyRootTokenFilename;
using CloudIntercept::kFileTokensFilename;
using CloudIntercept::kLegacyFileTokensFilename;
#ifdef _WIN32
#include <wincrypt.h>
#include <ShlObj.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#else
#include <cstdlib>
#include <unistd.h>
#include <pwd.h>
#endif
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <system_error>

#ifndef _WIN32
// POSIX equivalents for Windows string comparison functions
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#define _wcsicmp wcscasecmp
#endif

namespace LocalStorage {

static std::string g_baseRoot;
static std::unordered_map<uint64_t, uint64_t> g_changeNumbers;
// Lock-graph sink. shared_mutex has no upgrade path.
static std::shared_mutex g_mutex;

using AutoCloudUtil::AppInfoKVNode;
using AutoCloudUtil::AutoCloudRootOverrideNative;
using AutoCloudUtil::AutoCloudRuleMatchesCurrentPlatform;
using AutoCloudUtil::AutoCloudRuleNative;
using AutoCloudUtil::ApplyRootOverridesForCurrentOS;
using AutoCloudUtil::ExpandAutoCloudPathTokens;
using AutoCloudUtil::FileTimeToUnixSeconds;
using AutoCloudUtil::FindChild;
#ifdef _WIN32
using AutoCloudUtil::GetKnownFolderPathString;
#endif
using AutoCloudUtil::IsSafeRelativePath;
using AutoCloudUtil::kMaxAppInfoBytes;
using AutoCloudUtil::kMaxAppInfoStrings;
using AutoCloudUtil::kMaxAutoCloudCandidateBytes;
using AutoCloudUtil::kMaxAutoCloudScanFiles;
using AutoCloudUtil::kMaxAutoCloudScanMillis;
using AutoCloudUtil::NormalizeSlashes;
using AutoCloudUtil::ParseAppInfoKV;
using AutoCloudUtil::ParseAutoCloudPlatformMask;
using AutoCloudUtil::ParseAutoCloudSiblings;
using AutoCloudUtil::ReadCStringFromBytes;
using AutoCloudUtil::ReadI32;
using AutoCloudUtil::ReadU32;
using AutoCloudUtil::ToLowerAscii;
using AutoCloudUtil::UnixSecondsToFileTime;
using AutoCloudUtil::WildcardMatchInsensitive;

// Lexical-only check so first writes work before the per-app blob directory exists on disk.
static std::string ValidateFilename(const std::string& appRoot, const std::string& filename) {
    if (!IsSafeRelativePath(filename)) {
        LOG("BLOCKED path traversal: filename='%s' root='%s'",
            filename.c_str(), appRoot.c_str());
        return {};
    }
    std::string fullPath = appRoot + filename;
#ifdef _WIN32
    for (auto& c : fullPath) { if (c == '/') c = '\\'; }
#endif
    return fullPath;
}

static uint64_t MakeKey(uint32_t accountId, uint32_t appId) {
    return ((uint64_t)accountId << 32) | appId;
}

static std::string GetAppPathInternal(uint32_t accountId, uint32_t appId) {
#ifdef _WIN32
    return g_baseRoot + std::to_string(accountId) + "\\" + std::to_string(appId) + "\\";
#else
    return g_baseRoot + std::to_string(accountId) + "/" + std::to_string(appId) + "/";
#endif
}

#ifdef CLOUDREDIRECT_TESTING
// Test helpers for the local copies of AutoCloud parsing functions.

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
    rule.cloudRoot = root;
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
    rule.cloudRoot = rule.root;
    rule.path = path && path->hasString ? path->stringValue : "";
    rule.resolvedPath = rule.path;
    ApplyRootOverridesForCurrentOS(rule, {overrideRule});
    return root && root->stringValue == "WinAppDataLocal" &&
        path && path->stringValue == "Saves" &&
        pattern && pattern->stringValue == "*.sav" &&
        recursive && recursive->hasInt && recursive->intValue == 1 &&
        rule.cloudRoot == "WinAppDataLocal" &&
        rule.root == "WinSavedGames" && rule.resolvedPath == "Migrated/Saves";
}

bool TestRootOverridePreservesCloudIdentity() {
    AutoCloudRuleNative rule;
    rule.root = "WinAppDataLocalLow";
    rule.cloudRoot = rule.root;
    rule.path = "Team Cherry/Hollow Knight Silksong/{Steam3AccountID}";
    rule.resolvedPath = rule.path;

    AutoCloudRootOverrideNative overrideRule;
    overrideRule.root = "WinAppDataLocalLow";
#ifdef _WIN32
    overrideRule.os = "Windows";
    overrideRule.useInstead = "WinMyDocuments";
#else
    overrideRule.os = "Linux";
    overrideRule.useInstead = "LinuxHome";
#endif
    overrideRule.osCompare = "=";
    overrideRule.pathTransforms.emplace_back(
        "Team Cherry/Hollow Knight Silksong/{Steam3AccountID}",
        ".config/unity3d/Team Cherry/Hollow Knight Silksong/{Steam3AccountID}");

    ApplyRootOverridesForCurrentOS(rule, { overrideRule });
    return rule.cloudRoot == "WinAppDataLocalLow" &&
        rule.root == overrideRule.useInstead &&
        rule.resolvedPath == ".config/unity3d/Team Cherry/Hollow Knight Silksong/{Steam3AccountID}";
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
    std::error_code mtimeEc, sizeEc;
    auto appInfoMtime = std::filesystem::last_write_time(appInfoPath, mtimeEc);
    auto appInfoSize = std::filesystem::file_size(appInfoPath, sizeEc);
    if (mtimeEc || sizeEc) {
        LOG("GetAutoCloudFileList: failed to stat appinfo.vdf: %s",
            (mtimeEc ? mtimeEc : sizeEc).message().c_str());
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
            rule.cloudRoot = rule.root;
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
#ifdef _WIN32
            if (_wcsicmp(existing.native().c_str(), p.native().c_str()) == 0) {
#else
            if (existing == p) {  // case-sensitive on Linux (correct for ext4/btrfs)
#endif
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

bool IsAppInstalled(const std::string& steamPath, uint32_t appId) {
    return AutoCloudScan::IsAppInstalled(steamPath, appId);
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
        uint32_t pid = static_cast<uint32_t>(
#ifdef _WIN32
            GetCurrentProcessId()
#else
            getpid()
#endif
        );
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

static void RemoveLegacyMetadataIfPresent(const std::string& legacyPath,
                                          const char* legacyName,
                                          uint32_t appId) {
    std::error_code ec;
    bool removed = std::filesystem::remove(FileUtil::Utf8ToPath(legacyPath), ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        LOG("RemoveLegacyMetadataIfPresent: failed to remove %s for app %u: %s",
            legacyName, appId, ec.message().c_str());
    } else if (removed) {
        LOG("RemoveLegacyMetadataIfPresent: removed %s for app %u",
            legacyName, appId);
    }
}

// Caller holds g_mutex. Returns true on success.
static bool SaveChangeNumberLocked(uint32_t accountId, uint32_t appId) {
    auto key = MakeKey(accountId, appId);
    auto it = g_changeNumbers.find(key);
    if (it == g_changeNumbers.end()) return false;

    std::string appDir = GetAppPathInternal(accountId, appId);
    std::string cnPath = appDir + kCNFilename;
    if (FileUtil::AtomicWriteText(cnPath, std::to_string(it->second))) {
        LOG("SaveChangeNumber: persisted CN=%llu for app %u", it->second, appId);
        RemoveLegacyMetadataIfPresent(appDir + kLegacyCNFilename, kLegacyCNFilename, appId);
        return true;
    }
    LOG("SaveChangeNumber: failed to persist CN for app %u", appId);
    return false;
}

void Init(const std::string& baseRoot) {
    g_baseRoot = baseRoot;
#ifdef _WIN32
    if (!g_baseRoot.empty() && g_baseRoot.back() != '\\')
        g_baseRoot += '\\';
#else
    if (!g_baseRoot.empty() && g_baseRoot.back() != '/')
        g_baseRoot += '/';
#endif
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
    {
        std::shared_lock<std::shared_mutex> rlock(g_mutex);
        auto key = MakeKey(accountId, appId);
        auto it = g_changeNumbers.find(key);
        if (it != g_changeNumbers.end()) return it->second;
    }

    std::lock_guard<std::shared_mutex> lock(g_mutex);
    auto key = MakeKey(accountId, appId);
    auto it = g_changeNumbers.find(key);
    if (it != g_changeNumbers.end()) return it->second;

    std::string appPath = GetAppPathInternal(accountId, appId);
    std::string cnPath = appPath + kCNFilename;
    std::string legacyCnPath = appPath + kLegacyCNFilename;
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

    switch (ReadCNFile(legacyCnPath, cn)) {
        case CNParseResult::Valid:
            g_changeNumbers[key] = cn;
            LOG("GetChangeNumber: migrating CN=%llu from legacy path for app %u", cn, appId);
            SaveChangeNumberLocked(accountId, appId);  // Write to new location
            return cn;
        case CNParseResult::Corrupt:
            QuarantineCorruptCNFile(legacyCnPath, appId);
            break;
        case CNParseResult::Absent:
            break;
    }

    g_changeNumbers[key] = 1;
    return 1;
}

// Lazy load; ++ on a missing key would silently regress to 1.
static void EnsureCNCachedLocked(uint32_t accountId, uint32_t appId) {
    auto key = MakeKey(accountId, appId);
    if (g_changeNumbers.count(key)) return;

    std::string appPath = GetAppPathInternal(accountId, appId);
    std::string cnPath = appPath + kCNFilename;
    std::string legacyCnPath = appPath + kLegacyCNFilename;
    uint64_t cn = 1;
    uint64_t parsed = 0;

    switch (ReadCNFile(cnPath, parsed)) {
        case CNParseResult::Valid:
            cn = parsed;
            g_changeNumbers[key] = cn;
            return;
        case CNParseResult::Corrupt:
            QuarantineCorruptCNFile(cnPath, appId);
            break;
        case CNParseResult::Absent:
            break;
    }

    switch (ReadCNFile(legacyCnPath, parsed)) {
        case CNParseResult::Valid:
            cn = parsed;
            g_changeNumbers[key] = cn;
            SaveChangeNumberLocked(accountId, appId);  // Migrate to new location
            return;
        case CNParseResult::Corrupt:
            QuarantineCorruptCNFile(legacyCnPath, appId);
            break;
        case CNParseResult::Absent:
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
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            if (len > UINT32_MAX) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return {}; }
            if (!CryptHashData(hHash, data, (DWORD)len, 0)) {
                LOG("SHA1: CryptHashData failed (err=%lu)", GetLastError());
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return {};
            }
            DWORD hashLen = 20;
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
                LOG("SHA1: CryptGetHashParam failed (err=%lu)", GetLastError());
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return {};
            }
            CryptDestroyHash(hHash);
        } else {
            LOG("SHA1: CryptCreateHash failed (err=%lu)", GetLastError());
            CryptReleaseContext(hProv, 0);
            return {};
        }
        CryptReleaseContext(hProv, 0);
    } else {
        LOG("SHA1: CryptAcquireContextW failed (err=%lu)", GetLastError());
        return {};
    }
#else
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
             h3 = 0x10325476, h4 = 0xC3D2E1F0;
    uint64_t totalBits = (uint64_t)len * 8;
    std::vector<uint8_t> msg(data, data + len);
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back((uint8_t)(totalBits >> (i * 8)));
    auto rotl = [](uint32_t x, int n) -> uint32_t { return (x << n) | (x >> (32 - n)); };
    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)msg[chunk + i*4] << 24) | ((uint32_t)msg[chunk + i*4+1] << 16) |
                   ((uint32_t)msg[chunk + i*4+2] << 8)  | ((uint32_t)msg[chunk + i*4+3]);
        for (int i = 16; i < 80; ++i)
            w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;            k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;            k = 0xCA62C1D6; }
            uint32_t temp = rotl(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl(b, 30); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    auto store = [&hash](int off, uint32_t v) {
        hash[off] = (uint8_t)(v >> 24); hash[off+1] = (uint8_t)(v >> 16);
        hash[off+2] = (uint8_t)(v >> 8);  hash[off+3] = (uint8_t)v;
    };
    store(0, h0); store(4, h1); store(8, h2); store(12, h3); store(16, h4);
#endif
    return hash;
}

// Streaming SHA1 (UTF-8 path).
static std::vector<uint8_t> SHA1File(const std::string& path) {
    std::ifstream f(FileUtil::Utf8ToPath(path), std::ios::binary);
    if (!f) return {};

    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    if (size < 0) return {};
    if (size == 0) { static const uint8_t empty = 0; return SHA1(&empty, 0); }
    f.seekg(0);
    std::vector<uint8_t> buf((size_t)size);
    if (!f.read(reinterpret_cast<char*>(buf.data()), (size_t)size)) {
        auto actual = f.gcount();
        if (actual == 0) return {};
        buf.resize(static_cast<size_t>(actual));
    }
    return SHA1(buf.data(), buf.size());
}

std::vector<FileEntry> GetFileList(uint32_t accountId, uint32_t appId) {
    std::vector<FileEntry> result;

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

            // Keep file inventory aligned with the shared internal-metadata list.
            if (CloudIntercept::IsReservedBlobFilename(relPath)) {
                it.increment(ec);
                if (ec) break;
                continue;
            }

            std::string fullPath = appRoot + relPath;
#ifdef _WIN32
            for (auto& c : fullPath) { if (c == '/') c = '\\'; }
#endif

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
    for (auto& pf : pending) {
        auto sha = SHA1File(pf.fullPath);
        if (sha.empty()) {
            std::error_code existEc;
            if (std::filesystem::exists(FileUtil::Utf8ToPath(pf.fullPath), existEc) && !existEc) {
                LOG("GetFileList: SHA1 failed for existing file %s (I/O error, not deleted)",
                    pf.fullPath.c_str());
            }
            continue;
        }

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
        fullPath = ValidateFilename(appRoot, filename);
        if (fullPath.empty()) return std::nullopt;

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
        // File is durable; keep incremented in-memory CN so cloud sync sees it.
        LOG("WriteFile: cn.dat persist failed for app %u; file %s preserved on disk, CN will advance on next write",
            appId, fullPath.c_str());
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

#ifdef _WIN32
    SetLastError(0);
#endif
    if (!FileUtil::AtomicWriteBinary(fullPath, data, len)) {
#ifdef _WIN32
        DWORD lastErr = GetLastError();
        LOG("WriteFileNoIncrement failed: %s (%zu bytes, GetLastError=%lu)",
            fullPath.c_str(), len, (unsigned long)lastErr);
#else
        int lastErr = errno;
        LOG("WriteFileNoIncrement failed: %s (%zu bytes, errno=%d: %s)",
            fullPath.c_str(), len, lastErr, strerror(lastErr));
#endif
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
            g_changeNumbers[cnKey] = prevCN;
            LOG("DeleteFile: cn.dat persist failed for app %u after removing %s; rolled back CN",
                appId, filename.c_str());
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

} // namespace LocalStorage