#include "autocloud_scan.h"
#include "autocloud_util.h"
#include "file_util.h"
#include "log.h"
#include "steam_root_ids.h"
#include "vdf.h"
#ifdef _WIN32
#include <ShlObj.h>
#pragma comment(lib, "Shell32.lib")
#else
#include <cstdlib>
#include <unistd.h>
#include <pwd.h>
#endif
#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#ifndef _WIN32
// POSIX equivalents for Windows string comparison functions
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#define _wcsicmp wcscasecmp
#endif

namespace {

using AutoCloudUtil::AppInfoKVNode;
using AutoCloudUtil::AutoCloudEffectivePlatform;
using AutoCloudUtil::AutoCloudRootOverrideNative;
using AutoCloudUtil::AutoCloudRuleMatchesPlatform;
using AutoCloudUtil::AutoCloudRuleNative;
using AutoCloudUtil::ApplyRootOverridesForPlatform;
using AutoCloudUtil::ExpandAutoCloudPathTokens;
using AutoCloudUtil::FileTimeToUnixSeconds;
using AutoCloudUtil::FindChild;
#ifdef _WIN32
using AutoCloudUtil::GetKnownFolderPathString;
#endif
using AutoCloudUtil::IsSafeRelativePath;
using AutoCloudUtil::IsLinuxOS;
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
using AutoCloudUtil::ReadU32;
using AutoCloudUtil::ToLowerAscii;
using AutoCloudUtil::WildcardMatchInsensitive;

// ============================================================================
// Steam library path discovery
// ============================================================================

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

// ============================================================================
// AutoCloud rules loading
// ============================================================================

// Check compat.vdf to detect Proton (matches CCompatManager::LoadPlatformOverrideCache).
static AutoCloudEffectivePlatform DetectEffectivePlatform(const std::string& steamPath, uint32_t appId,
                                                          uint32_t accountId = 0) {
#ifdef _WIN32
    return AutoCloudEffectivePlatform::Current;  // Windows is always Windows
#else
    // Use known accountId or first numeric userdata folder.
    std::filesystem::path userdataPath = FileUtil::Utf8ToPath(steamPath) / "userdata";
    std::error_code ec;
    std::string userId;
    if (accountId != 0) {
        userId = std::to_string(accountId);
    } else {
        for (const auto& entry : std::filesystem::directory_iterator(userdataPath, ec)) {
            if (entry.is_directory(ec) && !ec) {
                std::string name = entry.path().filename().string();
                if (!name.empty() && name != "0" && std::all_of(name.begin(), name.end(), ::isdigit)) {
                    userId = name;
                    break;
                }
            }
        }
    }
    if (userId.empty()) {
        LOG("DetectEffectivePlatform: no userdata folder found, assuming native");
        return AutoCloudEffectivePlatform::Current;
    }

    // Parse compat.vdf for platform_overrides.
    std::filesystem::path compatPath = userdataPath / userId / "config" / "compat.vdf";
    std::ifstream f(compatPath);
    if (f) {
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        f.close();

        std::string appIdStr = std::to_string(appId);
        const char* sectionPath[] = {"platform_overrides", appIdStr.c_str()};
        
        std::string dest, src;
        VdfUtil::ForEachFieldInSection(content, sectionPath, 2, [&](const VdfUtil::FieldInfo& field) {
            if (field.key == "dest") dest = std::string(field.value);
            else if (field.key == "src") src = std::string(field.value);
            return true;
        });

        if (dest == "linux" && src == "windows") {
            LOG("DetectEffectivePlatform: app %u has platform override (dest=%s, src=%s) = Proton",
                appId, dest.c_str(), src.c_str());
            return AutoCloudEffectivePlatform::Windows;
        }

        // App not listed in compat.vdf = native Linux.
        LOG("DetectEffectivePlatform: app %u not in compat.vdf platform_overrides = native Linux",
            appId);
        return AutoCloudEffectivePlatform::Current;
    }

    // No compat.vdf; check pfx as fallback.
    std::string pfxPath = steamPath + "/steamapps/compatdata/" + std::to_string(appId) + "/pfx";
    if (std::filesystem::exists(pfxPath, ec) && !ec) {
        LOG("DetectEffectivePlatform: app %u has compatdata/pfx folder = Proton (no compat.vdf)",
            appId);
        return AutoCloudEffectivePlatform::Windows;
    }

    // No compat.vdf and no pfx = native Linux.
    LOG("DetectEffectivePlatform: app %u no compat.vdf or pfx, defaulting to native Linux",
        appId);
    return AutoCloudEffectivePlatform::Linux;
#endif
}

static std::vector<AutoCloudRuleNative> LoadAutoCloudRules(const std::string& steamPath, uint32_t appId,
                                                           AutoCloudEffectivePlatform effectivePlatform) {
    std::vector<AutoCloudRuleNative> rules;

    // Cache key includes effective platform so Proton vs native don't collide
    const char* platformTag = (effectivePlatform == AutoCloudEffectivePlatform::Windows) ? "windows" :
                              (effectivePlatform == AutoCloudEffectivePlatform::Linux) ? "linux" : "current";

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
    std::string cacheKey = FileUtil::PathToUtf8(appInfoPath) + "\n" +
        std::to_string(appId) + "\n" + platformTag;
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
    // Reject truncation on 32-bit builds (SIZE_MAX is 32 bits there).
    if (magic != 0x07564429 || stringOffset >= bytes.size() || stringOffset > SIZE_MAX) {
        LOG("GetAutoCloudFileList: unsupported appinfo.vdf format magic=0x%08X", magic);
        return rules;
    }

    size_t stringTableOffset = static_cast<size_t>(stringOffset);
    size_t st = stringTableOffset;
    uint32_t stringCount = 0;
    if (!ReadU32(bytes, st, stringCount)) return rules;
    size_t remainingStringBytes = bytes.size() - st;
    if (stringCount > remainingStringBytes || stringCount > kMaxAppInfoStrings) {
        LOG("GetAutoCloudFileList: invalid appinfo string count: %u", stringCount);
        return rules;
    }

    std::vector<std::string> strings;
    try {
        strings.reserve(stringCount);
    } catch (const std::bad_alloc&) {
        LOG("GetAutoCloudFileList: string table allocation failed for count %u", stringCount);
        return rules;
    }
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

            // Apply rootoverrides per effective platform.
#ifdef _WIN32
            ApplyRootOverridesForPlatform(rule, overrides, effectivePlatform);
#else
            if (effectivePlatform == AutoCloudEffectivePlatform::Windows) {
                // Proton: only apply Linux overrides that reference the compatdata prefix.
                bool hasProtonOverride = false;
                for (const auto& overrideRule : overrides) {
                    if (AutoCloudUtil::IsLinuxOS(overrideRule.os) &&
                        _stricmp(rule.root.c_str(), overrideRule.root.c_str()) == 0) {
                        // Check if addPath contains Proton prefix indicators
                        if (overrideRule.addPath.find("compatdata") != std::string::npos ||
                            overrideRule.addPath.find("/pfx/") != std::string::npos) {
                            hasProtonOverride = true;
                            break;
                        }
                    }
                }
                if (hasProtonOverride) {
                    // Apply; has Proton-specific paths
                    ApplyRootOverridesForPlatform(rule, overrides, AutoCloudEffectivePlatform::Linux);
                }
                // Skip; GetFileList maps Windows roots to Proton prefix
            } else {
                // Native Linux: apply Linux rootoverrides
                ApplyRootOverridesForPlatform(rule, overrides, AutoCloudEffectivePlatform::Linux);
            }
#endif
            rules.push_back(std::move(rule));
        }
        cacheRules(rules);
        return rules;
    }

    cacheRules(rules);
    return rules;
}

// ============================================================================
// SHA1 for files
// ============================================================================

// Whole-file SHA1; bounded by kMaxAutoCloudCandidateBytes.
static std::vector<uint8_t> SHA1File(const std::string& path) {
    std::ifstream f(FileUtil::Utf8ToPath(path), std::ios::binary);
    if (!f) return {};

    // Read entire file and hash it
    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    if (size < 0 || static_cast<uint64_t>(size) > kMaxAutoCloudCandidateBytes) {
        return {};
    }
    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buf.data()), size)) {
        return {};  // Empty vector signals error
    }
    return FileUtil::SHA1(buf.data(), buf.size());
}

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

namespace AutoCloudScan {

bool IsAppInstalled(const std::string& steamPath, uint32_t appId) {
    for (const auto& libPath : GetSteamLibraryPaths(steamPath)) {
        auto manifestPath = libPath / "steamapps" / ("appmanifest_" + std::to_string(appId) + ".acf");
        std::error_code ec;
        if (std::filesystem::exists(manifestPath, ec) && !ec) return true;
    }
    return false;
}

ScanResult GetFileList(const std::string& steamPath,
                       uint32_t accountId, uint32_t appId) {
    ScanResult outResult;

    // Detect effective platform: Proton games run as Windows effective platform
    AutoCloudEffectivePlatform effectivePlatform = DetectEffectivePlatform(steamPath, appId, accountId);
    LOG("GetAutoCloudFileList: app %u effective platform=%s",
        appId, effectivePlatform == AutoCloudEffectivePlatform::Windows ? "Windows" :
               effectivePlatform == AutoCloudEffectivePlatform::Linux ? "Linux" : "Current");

    auto rules = LoadAutoCloudRules(steamPath, appId, effectivePlatform);
    if (rules.empty()) {
        LOG("GetAutoCloudFileList: no appinfo UFS save rules for app %u", appId);
        return outResult;
    }
    outResult.hasRules = true;

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
        if (sha.empty()) {
            LOG("GetAutoCloudFileList: skipping app %u file %s (SHA1 read error)",
                appId, sourcePath.c_str());
            return;
        }
        auto ftime = std::filesystem::last_write_time(fileEntry.path(), ec);
        if (ec) return;
        uint64_t ts = FileTimeToUnixSeconds(ftime);

        FileEntry fe;
        fe.relativePath = cloudPath;
        fe.fullPath = sourcePath;
        fe.size = rawSize;
        fe.modifiedTime = ts;
        fe.rootToken = rootToken;
        fe.rootId = rootId;
        fe.sha = std::move(sha);
        outResult.files.push_back(std::move(fe));
    };

    struct RootMapping {
        std::string dirName;
        std::string rootToken;
        uint32_t rootId;
        std::string envExpansion;
    };
#ifdef _WIN32
    // Wide API; getenv() is not thread-safe, ...A() mangles non-ASCII.
    auto getEnvUtf8 = [](const wchar_t* name) -> std::string {
        wchar_t wbuf[MAX_PATH];
        constexpr DWORD bufLen = (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]));
        DWORD n = GetEnvironmentVariableW(name, wbuf, bufLen);
        if (n == 0 || n >= bufLen) return {};
        return FileUtil::WideToUtf8(wbuf, (size_t)n);
    };

    std::string localLow;
    {
        // Knownfolder returns canonical LocalLow; avoids junction issues with "..".
        std::string known = GetKnownFolderPathString(FOLDERID_LocalAppDataLow);
        if (!known.empty()) {
            localLow = known + "\\";
        } else {
            // Fallback via USERPROFILE if knownfolder fails.
            std::string tmp = getEnvUtf8(L"USERPROFILE");
            if (!tmp.empty()) localLow = tmp + "\\AppData\\LocalLow\\";
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

    std::string programData;
    {
        std::string known = GetKnownFolderPathString(FOLDERID_ProgramData);
        if (!known.empty()) {
            programData = known + "\\";
        } else {
            programData = "C:\\ProgramData\\";
        }
    }
#else
    // Linux: map Windows known folders to XDG/home equivalents
    auto getEnvStr = [](const char* name) -> std::string {
        const char* val = getenv(name);
        return val ? std::string(val) : std::string();
    };
    std::string home = getEnvStr("HOME");
    if (home.empty()) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }

    // Map Windows known-folder roots to XDG/home equivalents
    std::string localLow = home + "/.local/share/";
    std::string localAppData = home + "/.local/share/";
    std::string roamingAppData = home + "/.config/";
    std::string myDocuments = home + "/Documents/";
    std::string savedGames = home + "/.local/share/";
    std::string programData = "/usr/share/";

    // Proton: override Windows roots to compatdata prefix paths.
    std::string compatdataBase = steamPath + "/steamapps/compatdata/" + std::to_string(appId);
    std::string pfxBase = compatdataBase + "/pfx/drive_c/users/steamuser/";
    if (effectivePlatform == AutoCloudEffectivePlatform::Windows) {
        LOG("GetAutoCloudFileList: app %u has Proton prefix, using compatdata paths", appId);
        localAppData = pfxBase + "Local Settings/Application Data/";
        localLow = pfxBase + "AppData/LocalLow/";
        roamingAppData = pfxBase + "Application Data/";
        myDocuments = pfxBase + "My Documents/";
        savedGames = pfxBase + "Saved Games/";
        programData = compatdataBase + "/pfx/drive_c/ProgramData/";
    }
#endif

    std::string gameInstallPath = FindGameInstallPath(steamPath, appId);

    // rootId values: Steam ERemoteStorageFileRoot. Triples in steam_root_ids.h.
    auto rootFor = [](const char* bare) -> const SteamRootIds::Entry& {
        for (const auto& e : SteamRootIds::kEntries) {
            if (std::string(e.bareName) == bare) return e;
        }
        // Unknown root ID
        LOG("WARN: rootFor called with unknown root '%s' - check steam_root_ids.h", bare);
        static const SteamRootIds::Entry sentinel{"", "", 0};
        return sentinel;
    };
    const auto& rGameInstall   = rootFor("GameInstall");
    const auto& rLocalLow      = rootFor("WinAppDataLocalLow");
    const auto& rLocal         = rootFor("WinAppDataLocal");
    const auto& rRoaming       = rootFor("WinAppDataRoaming");
    const auto& rMyDocs        = rootFor("WinMyDocuments");
    const auto& rSavedGames    = rootFor("WinSavedGames");
    const auto& rProgramData   = rootFor("WinProgramData");
#ifndef _WIN32
    const auto& rLinuxHome     = rootFor("LinuxHome");
    const auto& rLinuxXdgData  = rootFor("LinuxXdgDataHome");
    const auto& rLinuxXdgCfg   = rootFor("LinuxXdgConfigHome");

    std::string linuxHome = home + "/";
    std::string linuxXdgDataHome;
    {
        std::string xdg = getEnvStr("XDG_DATA_HOME");
        linuxXdgDataHome = xdg.empty() ? (home + "/.local/share/") : (xdg + "/");
    }
    std::string linuxXdgConfigHome;
    {
        std::string xdg = getEnvStr("XDG_CONFIG_HOME");
        linuxXdgConfigHome = xdg.empty() ? (home + "/.config/") : (xdg + "/");
    }
#endif
    RootMapping mappings[] = {
        {"",                   "",                      0,                 FileUtil::PathToUtf8(appUserdataDir / "remote")},
        {rGameInstall.bareName, rGameInstall.token,     rGameInstall.rootId, gameInstallPath},
        {rLocalLow.bareName,    rLocalLow.token,        rLocalLow.rootId,    localLow},
        {rLocal.bareName,       rLocal.token,           rLocal.rootId,       localAppData},
        {rRoaming.bareName,     rRoaming.token,         rRoaming.rootId,    roamingAppData},
        {rMyDocs.bareName,      rMyDocs.token,          rMyDocs.rootId,     myDocuments},
        {rSavedGames.bareName,  rSavedGames.token,      rSavedGames.rootId, savedGames},
        {rProgramData.bareName, rProgramData.token,     rProgramData.rootId, programData},
#ifndef _WIN32
        {rLinuxHome.bareName,   rLinuxHome.token,       rLinuxHome.rootId,   linuxHome},
        {rLinuxXdgData.bareName, rLinuxXdgData.token,   rLinuxXdgData.rootId, linuxXdgDataHome},
        {rLinuxXdgCfg.bareName, rLinuxXdgCfg.token,     rLinuxXdgCfg.rootId, linuxXdgConfigHome},
#endif
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
        if (!AutoCloudRuleMatchesPlatform(rule.platforms, effectivePlatform)) {
            LOG("GetAutoCloudFileList: skipping app %u rule root='%s' path='%s' (platforms mask=0x%x excludes effective platform)",
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

        const RootMapping* cloudMapping = mapping;
        std::string cloudRootLower = ToLowerAscii(rule.cloudRoot);
        for (const auto& candidate : mappings) {
            if (ToLowerAscii(candidate.dirName) == cloudRootLower) {
                cloudMapping = &candidate;
                break;
            }
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
        // Refuse junctions/symlinks at scan root (OneDrive placeholders exempt).
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
            // Junction/symlink gate before is_regular_file.
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
                if (seenIt->second != cloudMapping->rootToken) {
                    LOG("GetAutoCloudFileList: root collision for app %u cloud path %s (%s vs %s); aborting bootstrap",
                        appId, cloudPath.c_str(), seenIt->second.c_str(), cloudMapping->rootToken.c_str());
                    hasRootCollision = true;
                }
                return;
            }
            seenRootsByCloudPath[collisionKey] = cloudMapping->rootToken;
            addFile(entry, cloudPath, entryUtf8, cloudMapping->rootToken, cloudMapping->rootId);

            // Sibling expansion (Steam sub_1384DBA40): probe stem.<ext>.
            for (const auto& siblingExt : rule.siblings) {
                if (scanLimitReached()) break;
                std::filesystem::path siblingPath = entry.path();
                siblingPath.replace_extension(FileUtil::Utf8ToPath(siblingExt));
                std::error_code sibEc;
                if (!std::filesystem::exists(siblingPath, sibEc) || sibEc) continue;
                ++visitedFiles;
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
                        cloudMapping->rootToken, cloudMapping->rootId);
            }
        };

        if (rule.recursive) {
            std::error_code iterEc;
            std::filesystem::recursive_directory_iterator it(
                scanRoot, std::filesystem::directory_options::skip_permission_denied, iterEc);
            std::filesystem::recursive_directory_iterator end;
            for (; !iterEc && it != end; it.increment(iterEc)) {
                if (scanLimitReached() || hasRootCollision) break;
                considerFile(*it);
            }
            if (iterEc) {
                LOG("GetAutoCloudFileList: directory iteration error in %s: %s",
                    FileUtil::PathToUtf8(scanRoot).c_str(), iterEc.message().c_str());
                scanLimitHit = true;
            }
        } else {
            std::error_code iterEc;
            std::filesystem::directory_iterator it(
                scanRoot, std::filesystem::directory_options::skip_permission_denied, iterEc);
            std::filesystem::directory_iterator end;
            for (; !iterEc && it != end; it.increment(iterEc)) {
                if (scanLimitReached() || hasRootCollision) break;
                considerFile(*it);
            }
            if (iterEc) {
                LOG("GetAutoCloudFileList: directory iteration error in %s: %s",
                    FileUtil::PathToUtf8(scanRoot).c_str(), iterEc.message().c_str());
                scanLimitHit = true;
            }
        }
        if (scanLimitReached() || hasRootCollision) break;
    }

    // Routine bounded-scan outcomes; not exceptional.
    outResult.complete = !scanLimitHit && !hasRootCollision;
    outResult.hasRootCollision = hasRootCollision;
    if (hasRootCollision) {
        outResult.files.clear();
        LOG("GetAutoCloudFileList: aborting app %u bootstrap due to root/path collision", appId);
    }

    LOG("GetAutoCloudFileList: found %zu rule-matched Auto-Cloud files for app %u (scanLimitHit=%d, hasRootCollision=%d)",
        outResult.files.size(), appId, (int)scanLimitHit, (int)hasRootCollision);
    for (const auto& fe : outResult.files) {
        LOG("  AC file: root=%u %s (%llu bytes)", fe.rootId, fe.relativePath.c_str(), (unsigned long long)fe.size);
    }
    return outResult;
}

// ============================================================================
// GetRootOverrides - exposes raw rootoverrides for cross-platform mapping
// ============================================================================

std::vector<AutoCloudUtil::AutoCloudRootOverrideNative> GetRootOverrides(
    const std::string& steamPath, uint32_t appId) {

    std::vector<AutoCloudUtil::AutoCloudRootOverrideNative> result;

    std::filesystem::path appInfoPath = FileUtil::Utf8ToPath(steamPath) / "appcache" / "appinfo.vdf";
    std::error_code statEc;
    auto appInfoSize = std::filesystem::file_size(appInfoPath, statEc);
    if (statEc || appInfoSize > kMaxAppInfoBytes) return result;

    std::ifstream f(appInfoPath, std::ios::binary | std::ios::ate);
    if (!f) return result;

    auto fileSize = f.tellg();
    if (fileSize < 16 || static_cast<uintmax_t>(fileSize) > kMaxAppInfoBytes) return result;
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes((size_t)fileSize);
    if (!f.read(reinterpret_cast<char*>(bytes.data()), fileSize)) return result;

    size_t offset = 0;
    uint32_t magic = 0, universe = 0, stringOffsetLo = 0, stringOffsetHi = 0;
    if (!ReadU32(bytes, offset, magic) || !ReadU32(bytes, offset, universe) ||
        !ReadU32(bytes, offset, stringOffsetLo) || !ReadU32(bytes, offset, stringOffsetHi)) {
        return result;
    }
    uint64_t stringOffset = ((uint64_t)stringOffsetHi << 32) | stringOffsetLo;
    if (magic != 0x07564429 || stringOffset >= bytes.size() || stringOffset > SIZE_MAX) return result;

    size_t stringTableOffset = static_cast<size_t>(stringOffset);
    size_t st = stringTableOffset;
    uint32_t stringCount = 0;
    if (!ReadU32(bytes, st, stringCount)) return result;
    if (stringCount > bytes.size() - st || stringCount > kMaxAppInfoStrings) return result;

    std::vector<std::string> strings;
    try { strings.reserve(stringCount); } catch (...) { return result; }
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

        if (recordAppId != appId) { offset += size; continue; }

        if (size < 60) return result;
        std::vector<uint8_t> kv(bytes.begin() + offset + 60, bytes.begin() + offset + size);
        size_t kvOffset = 0;
        auto tree = ParseAppInfoKV(kv, kvOffset, strings);
        const auto* appInfo = FindChild(tree, "appinfo");
        if (!appInfo) return result;
        const auto* ufs = FindChild(appInfo->children, "ufs");
        if (!ufs) return result;

        const auto* rootoverrides = FindChild(ufs->children, "rootoverrides");
        if (!rootoverrides) return result;

        for (const auto& entry : rootoverrides->children) {
            AutoCloudUtil::AutoCloudRootOverrideNative overrideRule;
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
                result.push_back(std::move(overrideRule));
            }
        }
        return result;
    }
    return result;
}

std::unordered_map<std::string, std::string> GetRootTokenDirectories(
    const std::string& steamPath, uint32_t appId, uint32_t accountId) {
    std::unordered_map<std::string, std::string> result;

    AutoCloudEffectivePlatform effectivePlatform = DetectEffectivePlatform(steamPath, appId, accountId);

#ifdef _WIN32
    auto getEnvUtf8 = [](const wchar_t* name) -> std::string {
        wchar_t wbuf[MAX_PATH];
        constexpr DWORD bufLen = (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]));
        DWORD n = GetEnvironmentVariableW(name, wbuf, bufLen);
        if (n == 0 || n >= bufLen) return {};
        return FileUtil::WideToUtf8(wbuf, (size_t)n);
    };

    std::string localLow;
    {
        std::string known = GetKnownFolderPathString(FOLDERID_LocalAppDataLow);
        if (!known.empty()) {
            localLow = known + "\\";
        } else {
            std::string tmp = getEnvUtf8(L"USERPROFILE");
            if (!tmp.empty()) localLow = tmp + "\\AppData\\LocalLow\\";
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

    std::string programData;
    {
        std::string known = GetKnownFolderPathString(FOLDERID_ProgramData);
        if (!known.empty()) {
            programData = known + "\\";
        } else {
            programData = "C:\\ProgramData\\";
        }
    }
#else
    auto getEnvStr = [](const char* name) -> std::string {
        const char* val = getenv(name);
        return val ? std::string(val) : std::string();
    };
    std::string home = getEnvStr("HOME");
    if (home.empty()) {
        struct passwd* pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }

    std::string localLow = home + "/.local/share/";
    std::string localAppData = home + "/.local/share/";
    std::string roamingAppData = home + "/.config/";
    std::string myDocuments = home + "/Documents/";
    std::string savedGames = home + "/.local/share/";
    std::string programData = "/usr/share/";

    std::string compatdataBase = steamPath + "/steamapps/compatdata/" + std::to_string(appId);
    std::string pfxBase = compatdataBase + "/pfx/drive_c/users/steamuser/";
    if (effectivePlatform == AutoCloudEffectivePlatform::Windows) {
        localAppData = pfxBase + "Local Settings/Application Data/";
        localLow = pfxBase + "AppData/LocalLow/";
        roamingAppData = pfxBase + "Application Data/";
        myDocuments = pfxBase + "My Documents/";
        savedGames = pfxBase + "Saved Games/";
        programData = compatdataBase + "/pfx/drive_c/ProgramData/";
    }

    std::string linuxHome = home + "/";
    std::string linuxXdgDataHome;
    {
        std::string xdg = getEnvStr("XDG_DATA_HOME");
        linuxXdgDataHome = xdg.empty() ? (home + "/.local/share/") : (xdg + "/");
    }
    std::string linuxXdgConfigHome;
    {
        std::string xdg = getEnvStr("XDG_CONFIG_HOME");
        linuxXdgConfigHome = xdg.empty() ? (home + "/.config/") : (xdg + "/");
    }
#endif

    std::string gameInstallPath = FindGameInstallPath(steamPath, appId);
    if (!gameInstallPath.empty()) {
#ifdef _WIN32
        gameInstallPath += "\\";
#else
        gameInstallPath += "/";
#endif
    }

    // Build the token -> directory mapping
    if (!gameInstallPath.empty())
        result["%GameInstall%"] = gameInstallPath;
    if (!localLow.empty())
        result["%WinAppDataLocalLow%"] = localLow;
    if (!localAppData.empty())
        result["%WinAppDataLocal%"] = localAppData;
    if (!roamingAppData.empty())
        result["%WinAppDataRoaming%"] = roamingAppData;
    if (!myDocuments.empty())
        result["%WinMyDocuments%"] = myDocuments;
    if (!savedGames.empty())
        result["%WinSavedGames%"] = savedGames;
    if (!programData.empty())
        result["%WinProgramData%"] = programData;
#ifndef _WIN32
    if (!linuxHome.empty())
        result["%LinuxHome%"] = linuxHome;
    if (!linuxXdgDataHome.empty())
        result["%LinuxXdgDataHome%"] = linuxXdgDataHome;
    if (!linuxXdgConfigHome.empty())
        result["%LinuxXdgConfigHome%"] = linuxXdgConfigHome;
#endif

    return result;
}

} // namespace AutoCloudScan
