#include "local_metadata_store.h"
#include "cloud_metadata_paths.h"
#include "file_util.h"
#include "log.h"

#include <ctime>
#include <filesystem>
#include <fstream>
#include <shared_mutex>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

using CloudIntercept::kRootTokenFilename;
using CloudIntercept::kLegacyRootTokenFilename;
using CloudIntercept::kFileTokensFilename;
using CloudIntercept::kLegacyFileTokensFilename;
using CloudIntercept::kDeletedFilename;
using CloudIntercept::kLegacyDeletedFilename;

namespace LocalMetadataStore {

static std::string g_baseRoot;
static std::shared_mutex g_metadataMutex;

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

static std::string GetAppPathInternal(uint32_t accountId, uint32_t appId) {
#ifdef _WIN32
    return g_baseRoot + std::to_string(accountId) + "\\" + std::to_string(appId) + "\\";
#else
    return g_baseRoot + std::to_string(accountId) + "/" + std::to_string(appId) + "/";
#endif
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
        LOG("LocalMetadataStore Init: create_directories failed for '%s': %s",
            g_baseRoot.c_str(), ec.message().c_str());
    }
    LOG("LocalMetadataStore initialized at: %s", g_baseRoot.c_str());
}

void InitApp(uint32_t accountId, uint32_t appId) {
    auto appPath = GetAppPathInternal(accountId, appId);
    std::error_code ec;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appPath), ec);
    if (ec) {
        LOG("LocalMetadataStore InitApp: create_directories failed for '%s': %s",
            appPath.c_str(), ec.message().c_str());
    }
    LOG("LocalMetadataStore: account %u app %u path: %s", accountId, appId, appPath.c_str());
}

bool SaveRootTokens(uint32_t accountId, uint32_t appId, const std::unordered_set<std::string>& tokens) {
    std::lock_guard<std::shared_mutex> lock(g_metadataMutex);
    std::string appDir = GetAppPathInternal(accountId, appId);
    std::error_code dirEc;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appDir), dirEc);
    if (dirEc) {
        LOG("SaveRootTokens: create_directories failed for '%s': %s",
            appDir.c_str(), dirEc.message().c_str());
        return false;
    }
    std::string path = appDir + kRootTokenFilename;
    std::string content;
    for (auto& t : tokens) {
        content += t + "\n";
    }
    if (FileUtil::AtomicWriteText(path, content)) {
        LOG("SaveRootTokens: persisted %zu tokens for app %u", tokens.size(), appId);
        RemoveLegacyMetadataIfPresent(appDir + kLegacyRootTokenFilename,
                                      kLegacyRootTokenFilename, appId);
        return true;
    } else {
        LOG("SaveRootTokens: failed for app %u", appId);
        return false;
    }
}

std::unordered_set<std::string> LoadRootTokens(uint32_t accountId, uint32_t appId) {
    std::unordered_set<std::string> tokens;
    bool needsRewrite = false;
    bool fromLegacy = false;

    // Read phase: shared lock allows concurrent readers
    {
        std::shared_lock<std::shared_mutex> lock(g_metadataMutex);
        std::string appPath = GetAppPathInternal(accountId, appId);
        std::string path = appPath + kRootTokenFilename;
        std::string legacyPath = appPath + kLegacyRootTokenFilename;

        std::ifstream f(FileUtil::Utf8ToPath(path));
        if (!f) {
            f.open(FileUtil::Utf8ToPath(legacyPath));
            if (f) fromLegacy = true;
        }
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
                LOG("LoadRootTokens: loaded %zu tokens from %s for app %u",
                    tokens.size(), fromLegacy ? "legacy path" : "disk", appId);
            }
        }
    }

    // Migrate from legacy or rewrite if corrupted.
        // Skip if canonical file already exists.
    if ((fromLegacy || needsRewrite) && !tokens.empty()) {
        if (fromLegacy) {
            LOG("LoadRootTokens: migrating tokens for app %u", appId);
        } else {
            LOG("LoadRootTokens: cleaning corrupted tokens for app %u", appId);
        }
        (void)SaveRootTokens(accountId, appId, tokens);
    }

    return tokens;
}

bool SaveFileTokens(uint32_t accountId, uint32_t appId,
                    const std::unordered_map<std::string, std::string>& fileTokens,
                    const std::unordered_set<std::string>& validRootTokens) {
    std::lock_guard<std::shared_mutex> lock(g_metadataMutex);
    std::string appDir = GetAppPathInternal(accountId, appId);
    std::error_code dirEc;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(appDir), dirEc);
    if (dirEc) {
        LOG("SaveFileTokens: create_directories failed for '%s': %s",
            appDir.c_str(), dirEc.message().c_str());
        return false;
    }

    // Always save to disk; load-time filtering handles correctness.
    std::unordered_map<std::string, std::string> toSave;
    toSave.reserve(fileTokens.size());
    size_t rejectedCount = 0;
    for (const auto& [cleanName, token] : fileTokens) {
        if (validRootTokens.empty() || validRootTokens.count(token) ||
            CloudIntercept::IsInternalMetadataFile(cleanName)) {
            toSave[cleanName] = token;
        } else {
            LOG("SaveFileTokens: app %u WARNING '%s' -> '%s' (root token not in valid set -- saving anyway)",
                appId, cleanName.c_str(), token.c_str());
            toSave[cleanName] = token;
            ++rejectedCount;
        }
    }
    if (rejectedCount > 0)
        LOG("SaveFileTokens: app %u warning: %zu entries with unverified root tokens saved", appId, rejectedCount);

    std::string path = appDir + kFileTokensFilename;
    std::string content;
    for (auto& [cleanName, token] : toSave) {
        content += cleanName + "\t" + token + "\n";
    }
    if (FileUtil::AtomicWriteText(path, content)) {
        LOG("SaveFileTokens: persisted %zu entries for app %u", toSave.size(), appId);
        RemoveLegacyMetadataIfPresent(appDir + kLegacyFileTokensFilename,
                                      kLegacyFileTokensFilename, appId);
        return true;
    } else {
        LOG("SaveFileTokens: failed for app %u", appId);
        return false;
    }
}

std::unordered_map<std::string, std::string> LoadFileTokens(uint32_t accountId, uint32_t appId,
                                                            const std::unordered_set<std::string>& validRootTokens) {
    std::shared_lock<std::shared_mutex> lock(g_metadataMutex);
    std::string appPath = GetAppPathInternal(accountId, appId);
    std::string path = appPath + kFileTokensFilename;
    std::string legacyPath = appPath + kLegacyFileTokensFilename;
    std::unordered_map<std::string, std::string> result;
    bool fromLegacy = false;

    std::ifstream f(FileUtil::Utf8ToPath(path));
    if (!f) {
        f.open(FileUtil::Utf8ToPath(legacyPath));
        if (f) fromLegacy = true;
    }
    if (f) {
        std::string line;
        while (std::getline(f, line)) {
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
        f.close();
        if (!result.empty()) {
            LOG("LoadFileTokens: loaded %zu entries from %s for app %u",
                result.size(), fromLegacy ? "legacy path" : "disk", appId);
        }
    }

    // Migrate from legacy if needed. Skip if canonical file already
    // exists (prior session or concurrent thread may have migrated).
    if (fromLegacy && !result.empty()) {
        std::string canonicalPath = appPath + kFileTokensFilename;
        if (!std::filesystem::exists(FileUtil::Utf8ToPath(canonicalPath))) {
            // Re-check under exclusive lock.
            lock.unlock();
            // Re-check existence to mitigate TOCTOU with concurrent migration.
            if (!std::filesystem::exists(FileUtil::Utf8ToPath(canonicalPath))) {
                LOG("LoadFileTokens: migrating file tokens for app %u", appId);
                SaveFileTokens(accountId, appId, result, validRootTokens);
            }
        }
    }

    // Filter against valid root tokens and metadata files.
    if (validRootTokens.empty()) return result;
    std::unordered_map<std::string, std::string> filtered;
    filtered.reserve(result.size());
    for (auto& [cleanName, token] : result) {
        if (validRootTokens.count(token) || CloudIntercept::IsInternalMetadataFile(cleanName)) {
            filtered[cleanName] = token;
        }
    }
    return filtered;
}

// deleted.cloudredirect: tombstones, "filename\tcn\tcreateTimeUnix\n".
static std::unordered_map<std::string, TombstoneInfo> LoadDeletedLocked(uint32_t accountId,
                                                                         uint32_t appId,
                                                                         bool* outNeedsRewrite) {
    // Caller holds g_metadataMutex (shared or exclusive).
    std::unordered_map<std::string, TombstoneInfo> deleted;
    if (outNeedsRewrite) *outNeedsRewrite = false;
    std::string appPath = GetAppPathInternal(accountId, appId);
    std::string path = appPath + kDeletedFilename;
    std::string legacyPath = appPath + kLegacyDeletedFilename;
    bool fromLegacy = false;

    std::ifstream f(FileUtil::Utf8ToPath(path));
    if (!f) {
        f.open(FileUtil::Utf8ToPath(legacyPath));
        if (f) {
            fromLegacy = true;
            if (outNeedsRewrite) *outNeedsRewrite = true;  // Trigger migration
        } else {
            return deleted;
        }
    }

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
                // v2 (filename\tcn) - legacy, createTime stays 0
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
    std::string path = appDir + kDeletedFilename;
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
        std::shared_lock<std::shared_mutex> lock(g_metadataMutex);
        deleted = LoadDeletedLocked(accountId, appId, &needsRewrite);
    }
    // Re-read under exclusive lock.
    if (needsRewrite) {
        std::lock_guard<std::shared_mutex> lock(g_metadataMutex);
        bool latestNeedsRewrite = false;
        auto latest = LoadDeletedLocked(accountId, appId, &latestNeedsRewrite);
        if (latestNeedsRewrite) {
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
    std::lock_guard<std::shared_mutex> lock(g_metadataMutex);
    auto deleted = LoadDeletedLocked(accountId, appId, nullptr);
    auto it = deleted.find(filename);
    bool inserted = (it == deleted.end());
    // No-op if existing >= incoming.
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
    std::lock_guard<std::shared_mutex> lock(g_metadataMutex);
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
    // Read under exclusive lock, release before callback to avoid deadlock.
    std::unique_lock<std::shared_mutex> lock(g_metadataMutex);
    bool needsFormatRewrite = false;
    auto current = LoadDeletedLocked(accountId, appId, &needsFormatRewrite);
    // Copy keys so we can rewrite outside the lock.
    std::vector<std::pair<std::string, std::string>> rewrites;
    rewrites.reserve(current.size());
    for (auto& kv : current) {
        rewrites.emplace_back(kv.first, std::string{});
    }
    lock.unlock();
    // Call keyRewrite on each key OUTSIDE the lock.
    for (auto& rw : rewrites) {
        rw.second = keyRewrite(rw.first);
    }
    // Re-acquire lock to apply and persist.
    lock.lock();
    // Re-read under lock to guard against concurrent modification.
    current = LoadDeletedLocked(accountId, appId, &needsFormatRewrite);
    // Build a lookup from old keys to avoid O(n^2).
    std::unordered_map<std::string, TombstoneInfo> oldLookup;
    for (auto& kv : current) oldLookup[kv.first] = kv.second;
    std::unordered_map<std::string, TombstoneInfo> migrated;
    migrated.reserve(current.size());
    // Snapshot original keys for concurrent-add detection.
    std::unordered_set<std::string> originalKeys;
    originalKeys.reserve(rewrites.size());
    for (const auto& rw : rewrites) originalKeys.insert(rw.first);

    bool anyChanged = needsFormatRewrite;
    for (auto& rw : rewrites) {
        auto it = oldLookup.find(rw.first);
        if (it == oldLookup.end()) continue;
        std::string newKey = std::move(rw.second);
        auto tombstone = it->second;
        if (newKey != rw.first) {
            ++outMigratedCount;
            anyChanged = true;
        }
        auto mit = migrated.find(newKey);
        if (mit == migrated.end()) {
            migrated.emplace(std::move(newKey), tombstone);
        } else {
            // Collision: keep higher (cn, createTime).
            bool incomingNewer = tombstone.cn > mit->second.cn ||
                (tombstone.cn == mit->second.cn &&
                 tombstone.createTimeUnix > mit->second.createTimeUnix);
            if (incomingNewer) mit->second = tombstone;
            anyChanged = true;
        }
    }
    // Preserve concurrent additions.
    for (const auto& kv : current) {
        if (originalKeys.count(kv.first)) continue;
        migrated.emplace(kv.first, kv.second);
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
    std::lock_guard<std::shared_mutex> lock(g_metadataMutex);
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
        // Evict tombstones older than the listing snapshot.
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
    std::shared_lock<std::shared_mutex> lock(g_metadataMutex);
    // Stream rather than build full map.
    std::string appPath = GetAppPathInternal(accountId, appId);
    std::string path = appPath + kDeletedFilename;
    std::string legacyPath = appPath + kLegacyDeletedFilename;
    auto fsPath = FileUtil::Utf8ToPath(path);
    auto legacyFsPath = FileUtil::Utf8ToPath(legacyPath);

    // Check new path first, then legacy
    std::error_code existEc;
    bool fileExists = std::filesystem::exists(fsPath, existEc);
    if (existEc) {
        LOG("IsDeleted: app %u exists() failed for deleted file (%s); failing closed for %s",
            appId, existEc.message().c_str(), filename.c_str());
        return true;
    }
    if (!fileExists) {
        fileExists = std::filesystem::exists(legacyFsPath, existEc);
        if (existEc) {
            LOG("IsDeleted: app %u exists() failed for legacy deleted file (%s); failing closed for %s",
                appId, existEc.message().c_str(), filename.c_str());
            return true;
        }
        if (!fileExists) return false;
        fsPath = legacyFsPath;
    }

    std::ifstream f(fsPath);
    if (!f) {
        LOG("IsDeleted: app %u deleted file exists but stream-open failed for %s "
            "-- treating as NOT deleted (fail-open to prevent sync suppression)",
            appId, filename.c_str());
        return false;
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

} // namespace LocalMetadataStore
