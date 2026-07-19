#include "stats_store.h"
#ifndef _WIN32
#include <unistd.h>
#endif
#include "json.h"
#include "vdf.h"
#include "log.h"
#include "file_util.h"
#include "metadata_sync.h"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <thread>
#include <unordered_set>
#include <condition_variable>

namespace fs = std::filesystem;

namespace StatsStore {

static std::string g_storageRoot;
static std::string g_cloudRoot;   // CR root; legacy Playtime/*.bin live under <root>/storage/<acct>/0/Playtime
static std::string g_steamPath;   // e.g. "C:\Games\Steam\" (used to locate native blobs)
static std::mutex g_mutex;

// Caller holds g_mutex.
uint32_t ComputeCrcLocked(const AppStats& stats);
// Used above its definition.
static bool ParseAppStatsJson(const std::string& content, AppStats& out);
// Used above its definition.
static size_t CountUnlockedAchievements(const std::vector<AchievementBlock>& a);
static bool ReconcileAchievementBits(std::vector<StatEntry>& stats,
                                     std::vector<AchievementBlock>& achievements);
static std::unordered_map<uint32_t, AppStats> g_cache;
static std::unordered_map<uint32_t, bool> g_dirty;

// Cloud-backing provider (installed by the platform layer; see SetCloudProvider).
// Account-wide blob: one network read for every app, not one per app.
static CloudPullAllFn g_cloudPullAll;
static CloudPushAllFn g_cloudPushAll;
// Reads a single legacy per-app stats blob, for one-time migration into the
// consolidated account blob. May be null on platforms that never wrote per-app.
static CloudPullLegacyFn g_cloudPullLegacy;
// Reads a single first-format playtime blob (Playtime/<appId>.bin) from the cloud.
static CloudPullLegacyPlaytimeFn g_cloudPullLegacyPlaytime;

// Cached account blob (appId -> stats JSON). Guarded by g_mutex.
static std::unordered_map<uint32_t, std::string> g_cloudBlobByApp;
// Apps already merged with account blob this fetch cycle. g_mutex.
static std::unordered_set<uint32_t> g_cloudBlobMerged;
// True when the account blob needs re-upload. g_mutex.
static bool g_accountBlobDirty = false;

// Apps whose native import was attempted. g_mutex.
static std::unordered_map<uint32_t, bool> g_importAttempted;

// Last seen accountId for switch detection. 0 = none. g_mutex.
static uint32_t g_lastSeenAccountId = 0;
// accountId for on-disk path scoping. Set on first account seen.
static uint32_t g_diskAccountId = 0;

// Active play sessions: appId -> session start (unix time). Guarded by g_mutex.
static std::unordered_map<uint32_t, uint32_t> g_activeSessions;

// Apps reset this session; push replaces (not merges) these. g_mutex.
static std::unordered_set<uint32_t> g_resetApps;

// Resolves the current Steam accountId for locating native UserGameStats blobs.
static AccountIdProvider g_accountIdProvider;
// Fired when an import finds no schema for an app (platform requests it).
static SchemaMissingCallback g_schemaMissingCb;
// True for apps we manage; reconcile seeds their playtime from localconfig.vdf.
static NamespacePredicate g_isNamespaceApp;

// Seed completion signal: set true once SeedApps finishes loading cloud blob + stats.
static std::atomic<bool> g_seedDone{false};
static std::mutex g_seedMutex;
static std::condition_variable g_seedCv;

// Persist to disk; pushCloud=false writes locally only (used by startup reconcile).
static void WriteAppStats(uint32_t appId, const AppStats& stats, bool pushCloud,
                          bool bypassDiskMerge = false);

// allowShrink: migration repair can lower double-counted buckets.
static void RecomputePlaytimeTotals(PlaytimeData& pt, bool allowShrink = false);
static bool EndSessionLocked(uint32_t appId);
static AppStats& GetOrCreateLocked(uint32_t appId);
static std::mutex& g_pushInFlightMutex = *new std::mutex();

void SetCloudProvider(CloudPullAllFn pullAll, CloudPushAllFn pushAll,
                      CloudPullLegacyFn pullLegacy,
                      CloudPullLegacyPlaytimeFn pullLegacyPlaytime) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_cloudPullAll = std::move(pullAll);
    g_cloudPushAll = std::move(pushAll);
    g_cloudPullLegacy = std::move(pullLegacy);
    g_cloudPullLegacyPlaytime = std::move(pullLegacyPlaytime);
}

// Pull account blob into g_cloudBlobByApp. Caller must NOT hold g_mutex.
static bool RefreshCloudBlobCache() {
    CloudPullAllFn pull;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        pull = g_cloudPullAll;
    }
    if (!pull) return false;

    std::unordered_map<uint32_t, std::string> fetched;
    if (!pull(fetched)) return false;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_isNamespaceApp) {
        size_t before = fetched.size();
        for (auto it = fetched.begin(); it != fetched.end(); ) {
            if (!g_isNamespaceApp(it->first))
                it = fetched.erase(it);
            else
                ++it;
        }
        if (fetched.size() != before)
            LOG("[Stats] Cloud blob decontamination: %zu -> %zu app(s)", before, fetched.size());
    }
    static bool firstRefresh = true;
    size_t prevCount = g_cloudBlobByApp.size();
    g_cloudBlobByApp = std::move(fetched);
    g_cloudBlobMerged.clear();
    if (firstRefresh || g_cloudBlobByApp.size() != prevCount)
        LOG("[Stats] Cloud blob refreshed: %zu app(s)", g_cloudBlobByApp.size());
    if (firstRefresh) {
        size_t appsWithData = 0;
        for (const auto& [appId, json] : g_cloudBlobByApp) {
            AppStats cs;
            if (!ParseAppStatsJson(json, cs)) continue;
            if (!cs.achievements.empty() || !cs.stats.empty() || cs.playtime.minutesForever)
                appsWithData++;
        }
        if (appsWithData)
            LOG("[Stats] Cloud blob: %zu/%zu app(s) have stats/playtime data",
                appsWithData, g_cloudBlobByApp.size());
        firstRefresh = false;
    }
    return true;
}

// Return the cached cloud JSON for one app (from the last account-blob pull).
// Caller holds g_mutex. Empty string if the app has no cloud stats.
static std::string CloudJsonForAppLocked(uint32_t appId) {
    auto it = g_cloudBlobByApp.find(appId);
    return it != g_cloudBlobByApp.end() ? it->second : std::string();
}

void SetAccountIdProvider(AccountIdProvider provider) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_accountIdProvider = std::move(provider);
}

void SetSchemaMissingCallback(SchemaMissingCallback cb) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_schemaMissingCb = std::move(cb);
}

void SetNamespacePredicate(NamespacePredicate pred) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_isNamespaceApp = std::move(pred);
}

// ── Native UserGameStats (BKV) reader ────────────────────────────────────
// Binary-KV tree: cache > <statId> > data + AchievementTimes.
namespace {

enum BkvType : uint8_t {
    BKV_SECTION = 0x00,
    BKV_STRING  = 0x01,
    BKV_INT     = 0x02,
    BKV_FLOAT   = 0x03,
    BKV_UINT64  = 0x07,
    BKV_END     = 0x08,
    BKV_INT64   = 0x0A,
};

struct BkvNode {
    BkvType type{};
    std::string name;
    uint32_t intVal = 0;
    float    floatVal = 0.0f;
    uint64_t uint64Val = 0;
    int64_t  int64Val = 0;
    std::string strVal;
    std::vector<BkvNode> children;
};

constexpr int    BKV_MAX_DEPTH = 128;
constexpr size_t BKV_MAX_NODES = 100000;

bool BkvRead(const uint8_t* data, size_t len, size_t& pos,
             std::vector<BkvNode>& out, int depth, size_t& totalNodes) {
    if (depth > BKV_MAX_DEPTH) return false;
    while (pos < len) {
        uint8_t tag = data[pos++];
        if (tag == BKV_END) return true;

        BkvNode node;
        node.type = static_cast<BkvType>(tag);

        const char* nameStart = reinterpret_cast<const char*>(data + pos);
        size_t nameEnd = pos;
        while (nameEnd < len && data[nameEnd] != 0) nameEnd++;
        if (nameEnd >= len) return false;
        node.name.assign(nameStart, nameEnd - pos);
        pos = nameEnd + 1;

        switch (node.type) {
        case BKV_SECTION:
            if (!BkvRead(data, len, pos, node.children, depth + 1, totalNodes))
                return false;
            break;
        case BKV_STRING: {
            const char* s = reinterpret_cast<const char*>(data + pos);
            size_t end = pos;
            while (end < len && data[end] != 0) end++;
            if (end >= len) return false;
            node.strVal.assign(s, end - pos);
            pos = end + 1;
            break;
        }
        case BKV_INT:
        case BKV_FLOAT:
            if (pos + 4 > len) return false;
            if (node.type == BKV_INT) std::memcpy(&node.intVal, data + pos, 4);
            else                      std::memcpy(&node.floatVal, data + pos, 4);
            pos += 4;
            break;
        case BKV_UINT64:
            if (pos + 8 > len) return false;
            std::memcpy(&node.uint64Val, data + pos, 8);
            pos += 8;
            break;
        case BKV_INT64:
            if (pos + 8 > len) return false;
            std::memcpy(&node.int64Val, data + pos, 8);
            pos += 8;
            break;
        default:
            return false;
        }
        if (++totalNodes > BKV_MAX_NODES) return false;
        out.push_back(std::move(node));
    }
    return depth == 0;
}

const BkvNode* BkvFind(const std::vector<BkvNode>& nodes, const std::string& name) {
    for (const auto& n : nodes)
        if (n.name == name) return &n;
    return nullptr;
}

// Coerce a "data" node's numeric value to uint32 (stat values and achievement
// bitfields are stored as INT; we only need the 32-bit payload for the wire).
uint32_t BkvDataAsU32(const BkvNode& dataNode) {
    switch (dataNode.type) {
        case BKV_INT:    return dataNode.intVal;
        case BKV_UINT64: return (uint32_t)dataNode.uint64Val;
        case BKV_INT64:  return (uint32_t)dataNode.int64Val;
        case BKV_FLOAT: { uint32_t v; std::memcpy(&v, &dataNode.floatVal, 4); return v; }
        default:         return 0;
    }
}

// Map (statId,bit) -> display name from schema BKV. Prefers English display name.
std::unordered_map<uint64_t, std::string>
ParseSchemaAchievementNames(const std::vector<BkvNode>& schemaRoot) {
    std::unordered_map<uint64_t, std::string> names;

    // Root is a single <appId> section; descend to "stats".
    const BkvNode* statsSec = nullptr;
    for (const auto& top : schemaRoot) {
        if (top.type != BKV_SECTION) continue;
        if (auto* s = BkvFind(top.children, "stats")) { statsSec = s; break; }
        if (top.name == "stats") { statsSec = &top; break; }
    }
    if (!statsSec) return names;

    for (const auto& stat : statsSec->children) {
        if (stat.type != BKV_SECTION) continue;
        bool numeric = !stat.name.empty();
        for (char c : stat.name) { if (c < '0' || c > '9') { numeric = false; break; } }
        if (!numeric) continue;
        uint32_t statId = (uint32_t)strtoul(stat.name.c_str(), nullptr, 10);

        const BkvNode* bits = BkvFind(stat.children, "bits");
        if (!bits) continue;

        for (const auto& bitSec : bits->children) {
            if (bitSec.type != BKV_SECTION) continue;
            bool bnum = !bitSec.name.empty();
            for (char c : bitSec.name) { if (c < '0' || c > '9') { bnum = false; break; } }
            if (!bnum) continue;
            uint32_t bit = (uint32_t)strtoul(bitSec.name.c_str(), nullptr, 10);
            if (bit >= 32) continue;

            std::string display;
            if (const BkvNode* disp = BkvFind(bitSec.children, "display")) {
                if (const BkvNode* nameSec = BkvFind(disp->children, "name")) {
                    if (const BkvNode* eng = BkvFind(nameSec->children, "english"))
                        display = eng->strVal;
                    // Fall back to the first localized string if no english.
                    if (display.empty() && !nameSec->children.empty())
                        display = nameSec->children.front().strVal;
                }
            }
            if (display.empty()) {
                if (const BkvNode* apiName = BkvFind(bitSec.children, "name"))
                    display = apiName->strVal;
            }
            if (!display.empty())
                names[((uint64_t)statId << 32) | bit] = display;
        }
    }
    return names;
}

// Parse merge strategy from schema (type_int + resolution_method).
std::unordered_map<uint32_t, StatMerge>
ParseSchemaMergeMethods(const std::vector<BkvNode>& schemaRoot) {
    std::unordered_map<uint32_t, StatMerge> out;

    const BkvNode* statsSec = nullptr;
    for (const auto& top : schemaRoot) {
        if (top.type != BKV_SECTION) continue;
        if (auto* s = BkvFind(top.children, "stats")) { statsSec = s; break; }
        if (top.name == "stats") { statsSec = &top; break; }
    }
    if (!statsSec) return out;

    for (const auto& stat : statsSec->children) {
        if (stat.type != BKV_SECTION) continue;
        bool numeric = !stat.name.empty();
        for (char c : stat.name) { if (c < '0' || c > '9') { numeric = false; break; } }
        if (!numeric) continue;
        uint32_t statId = (uint32_t)strtoul(stat.name.c_str(), nullptr, 10);

        int typeInt = 0, resMeth = 0;
        if (const BkvNode* ti = BkvFind(stat.children, "type_int"))
            typeInt = (int)ti->intVal;
        if (const BkvNode* rm = BkvFind(stat.children, "resolution_method"))
            resMeth = (int)rm->intVal;

        if (typeInt == 4) {
            out[statId] = StatMerge::BitwiseOr;
        } else if (resMeth == 1) {
            out[statId] = StatMerge::BitwiseOr;
        } else if (resMeth == 2) {
            // type_int: 1=INT (signed), 2=FLOAT, 3=AVGRATE (float)
            out[statId] = (typeInt >= 2) ? StatMerge::MaxFloat : StatMerge::MaxInt;
        } else {
            out[statId] = StatMerge::Overwrite;
        }
    }
    return out;
}

} // namespace


static uint32_t NowUnix() {
    return (uint32_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Per-account directory: stats/<accountId>/. Returns empty if no account is
// known yet; callers must not perform disk I/O with an empty path.
static std::string AccountStatsDir() {
    if (g_diskAccountId != 0)
        return g_storageRoot + "/" + std::to_string(g_diskAccountId);
    LOG("[Stats] WARNING: AccountStatsDir called with g_diskAccountId=0");
    return std::string();
}

static std::string StatsPath(uint32_t appId) {
    std::string dir = AccountStatsDir();
    if (dir.empty()) return std::string();
    return dir + "/" + std::to_string(appId) + ".json";
}

static std::string SchemaPath(uint32_t appId) {
    std::string dir = AccountStatsDir();
    if (dir.empty()) return std::string();
    return dir + "/schemas/" + std::to_string(appId) + ".bin";
}

static uint32_t Crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(int32_t)(crc & 1)));
        }
    }
    return ~crc;
}

// Seed playtime from localconfig.vdf (catches sessions without CR loaded).
static void ReconcileLocalConfig(const std::string& cloudRoot, const std::string& steamPath) {
    std::error_code ec;
    fs::path userdataDir = fs::path(steamPath) / "userdata";
    if (!fs::exists(userdataDir, ec)) return;

    // Only reconcile current account to prevent cross-account contamination.
    uint32_t currentAcct = g_accountIdProvider ? g_accountIdProvider() : 0;
    if (currentAcct == 0) return;
    std::string acctIdStr = std::to_string(currentAcct);

    int reconciled = 0;
    fs::path acctDir = userdataDir / acctIdStr;
    if (!fs::is_directory(acctDir, ec)) return;

    fs::path lcPath = acctDir / "config" / "localconfig.vdf";
    if (!fs::exists(lcPath, ec)) return;

    std::ifstream f(lcPath);
    if (!f.good()) return;
    std::string vdf((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    f.close();
    if (vdf.empty()) return;

    // Find the apps section: UserLocalConfigStore > Software > Valve > Steam > {Apps|apps}.
    // Steam has shipped both casings of the leaf key across builds.
    const char* appsKey = "apps";
    const char* basePath[] = {"UserLocalConfigStore", "Software", "Valve", "Steam", appsKey};
    size_t appsStart = 0, appsEnd = 0;
    if (!VdfUtil::FindVdfSectionRange(vdf, basePath, 5, appsStart, appsEnd)) {
        appsKey = "Apps";
        basePath[4] = appsKey;
        if (!VdfUtil::FindVdfSectionRange(vdf, basePath, 5, appsStart, appsEnd)) {
            LOG("[Stats] Reconcile: apps section not found in %s", lcPath.string().c_str());
            return;
        }
    }
    // Enumerate child sections (each is an appid)
    VdfUtil::ForEachChildInSection(vdf, basePath, 5, [&](std::string_view name) -> bool {
            uint32_t appId = 0;
            // Parse appid from section name
            for (char c : name) {
                if (c < '0' || c > '9') return true; // skip non-numeric
                appId = appId * 10 + (c - '0');
            }
            if (appId == 0) return true;

            // We only manage namespace apps. Real owned games keep their native,
            // server-tracked playtime and are never reconciled or synced.
            bool isNs = g_isNamespaceApp && g_isNamespaceApp(appId);
            if (!isNs) return true;

            std::string appIdStr = std::to_string(appId);
            const char* appPath[] = {"UserLocalConfigStore", "Software", "Valve", "Steam", appsKey, appIdStr.c_str()};
            uint32_t vdfLastPlayed = 0;
            uint32_t vdfPlaytime = 0;
            uint32_t vdfPlaytime2wks = 0;

            VdfUtil::ForEachFieldInSection(vdf, appPath, 6, [&](const VdfUtil::FieldInfo& fi) -> bool {
                if (fi.key == "LastPlayed")
                    try { vdfLastPlayed = (uint32_t)std::stoul(std::string(fi.value)); } catch (...) {}
                else if (fi.key == "Playtime")
                    try { vdfPlaytime = (uint32_t)std::stoul(std::string(fi.value)); } catch (...) {}
                else if (fi.key == "Playtime2wks")
                    try { vdfPlaytime2wks = (uint32_t)std::stoul(std::string(fi.value)); } catch (...) {}
                return true;
            });
            if (vdfLastPlayed == 0 && vdfPlaytime == 0) return true;

            auto cacheIt = g_cache.find(appId);
            if (cacheIt == g_cache.end()) {
                LoadAppStats(appId, g_cache[appId]);
                cacheIt = g_cache.find(appId);
            }
            AppStats& stats = cacheIt->second;

            bool changed = false;
            if (vdfLastPlayed > stats.playtime.lastPlayedTime) {
                stats.playtime.lastPlayedTime = vdfLastPlayed;
                changed = true;
            }

            // Recompute migrated bucket shortfall (repairs double-counted totals).
            static const std::string kMigratedBucket = "__migrated_localconfig";
            if (vdfPlaytime > 0) {
                uint64_t otherTotal = 0;
                for (const auto& [dev, dp] : stats.playtime.perDevice) {
                    if (dev == kMigratedBucket) {
                        // Include other platforms' fields from the migrated bucket
                        // to prevent double-counting across platforms.
#ifdef _WIN32
                        otherTotal += (uint64_t)dp.mac + dp.lin;
#elif defined(__APPLE__)
                        otherTotal += (uint64_t)dp.windows + dp.lin;
#else
                        otherTotal += (uint64_t)dp.windows + dp.mac;
#endif
                    } else {
                        otherTotal += (uint64_t)dp.windows + dp.mac + dp.lin;
                    }
                }
                uint32_t shortfall = (vdfPlaytime > otherTotal)
                    ? (uint32_t)(vdfPlaytime - otherTotal) : 0u;
                DevicePlaytime& mig = stats.playtime.perDevice[kMigratedBucket];
#ifdef _WIN32
                mig.windows = shortfall;
#elif defined(__APPLE__)
                mig.mac = shortfall;
#else
                mig.lin = shortfall;
#endif
                stats.playtime.minutesLastTwoWeeks =
                    (std::max)(stats.playtime.minutesLastTwoWeeks, vdfPlaytime2wks);
                RecomputePlaytimeTotals(stats.playtime, /*allowShrink=*/true);
                changed = true;
            }

            if (!changed) return true;

            RecomputePlaytimeTotals(stats.playtime, /*allowShrink=*/true);

            WriteAppStats(appId, stats, false, /*bypassDiskMerge=*/true);
            reconciled++;
            return true;
        });
    if (reconciled > 0) {
        LOG("[Stats] Reconciled %d apps from localconfig.vdf", reconciled);
    }
}

void Init(const std::string& storageRoot, const std::string& steamPath) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_storageRoot = storageRoot + "/stats";
    g_cloudRoot = storageRoot;
    g_steamPath = steamPath;
    fs::create_directories(g_storageRoot);
    fs::create_directories(g_storageRoot + "/schemas");

    LOG("[Stats] Store initialized at %s", g_storageRoot.c_str());
}

// Migrate unscoped stats files to account-scoped directory. Caller holds g_mutex.
static void MigrateUnscopedFiles(uint32_t accountId) {
    std::error_code ec;
    fs::path rootDir = FileUtil::Utf8ToPath(g_storageRoot);
    fs::path acctDir = rootDir / std::to_string(accountId);
    fs::create_directories(acctDir, ec);
    fs::create_directories(acctDir / "schemas", ec);

    size_t moved = 0;
    // Move top-level .json files (stats/<appId>.json -> stats/<accountId>/<appId>.json)
    for (const auto& entry : fs::directory_iterator(rootDir, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        if (entry.path().extension() != ".json") continue;
        fs::path dest = acctDir / entry.path().filename();
        if (!fs::exists(dest, ec)) {
            fs::rename(entry.path(), dest, ec);
            ++moved;
        } else {
            fs::remove(entry.path(), ec); // account dir already has data; discard stale
        }
    }
    // Move schemas (stats/schemas/<appId>.bin -> stats/<accountId>/schemas/<appId>.bin)
    fs::path oldSchemas = rootDir / "schemas";
    if (fs::is_directory(oldSchemas, ec)) {
        for (const auto& entry : fs::directory_iterator(oldSchemas, ec)) {
            if (!entry.is_regular_file(ec)) continue;
            if (entry.path().extension() != ".bin") continue;
            fs::path dest = acctDir / "schemas" / entry.path().filename();
            if (!fs::exists(dest, ec)) {
                fs::rename(entry.path(), dest, ec);
                ++moved;
            } else {
                fs::remove(entry.path(), ec);
            }
        }
    }
    if (moved)
        LOG("[Stats] Migrated %zu unscoped stats file(s) into account dir %u", moved, accountId);
}

// Ensure the per-account disk directory exists. Called under g_mutex.
static void EnsureAccountDir() {
    if (g_diskAccountId == 0) return;
    std::error_code ec;
    std::string dir = AccountStatsDir();
    fs::create_directories(FileUtil::Utf8ToPath(dir), ec);
    fs::create_directories(FileUtil::Utf8ToPath(dir + "/schemas"), ec);
}

bool ResetForAccountSwitch(uint32_t newAccountId) {
    std::unique_lock<std::mutex> lock(g_mutex);
    // First account seen this process: record it, nothing to wipe. A genuine
    // switch is only newAccountId != g_lastSeenAccountId with a prior non-zero
    // value. accountId 0 (not-yet-resolved) must never be treated as a switch.
    if (newAccountId == 0) return false;
    if (g_lastSeenAccountId == 0) {
        g_lastSeenAccountId = newAccountId;
        g_diskAccountId = newAccountId;
        EnsureAccountDir();
        // Migrate any leftover non-scoped files from prior versions into the
        // per-account directory so existing users don't lose their stats history.
        MigrateUnscopedFiles(newAccountId);
        LOG("[Stats] First account seen: %u (disk path: %s)", newAccountId, AccountStatsDir().c_str());
        return false;
    }
    if (newAccountId == g_lastSeenAccountId) return false;

    // Genuine account switch: drain active sessions so in-flight playtime is not
    // silently lost, push the old account's blob, then hard-clear everything.
    LOG("[Stats] Account switch %u -> %u: clearing %zu cached app(s), %zu dirty, "
        "%zu active session(s)", g_lastSeenAccountId, newAccountId,
        g_cache.size(), g_dirty.size(), g_activeSessions.size());

    // Drain active sessions: accrue elapsed minutes into cache + cloud blob.
    // Copy keys first -- EndSessionLocked erases from g_activeSessions.
    std::vector<uint32_t> activeApps;
    activeApps.reserve(g_activeSessions.size());
    for (const auto& [appId, _] : g_activeSessions)
        activeApps.push_back(appId);
    for (uint32_t appId : activeApps)
        EndSessionLocked(appId);

    // Push the old account's blob synchronously before clearing state.
    // g_accountIdProvider already returns newAccountId, so bypass the normal
    // push path and use the old account ID directly.
    if (g_accountBlobDirty && g_cloudPushAll) {
        auto snapshot = g_cloudBlobByApp;
        auto push = g_cloudPushAll;
        uint32_t oldAccountId = g_lastSeenAccountId;
        LOG("[Stats] Account switch: flushing blob for outgoing account %u (%zu app(s))",
            oldAccountId, snapshot.size());
        g_accountBlobDirty = false;
        // Release g_mutex for the blocking push, then re-acquire.
        lock.unlock();
        {
            std::lock_guard<std::mutex> pushLock(g_pushInFlightMutex);
            push(snapshot);
        }
        lock.lock();
    }

    g_cache.clear();
    g_importAttempted.clear();
    g_cloudBlobByApp.clear();
    g_cloudBlobMerged.clear();
    g_dirty.clear();
    g_activeSessions.clear();
    g_resetApps.clear();
    g_accountBlobDirty = false;
    g_seedDone.store(false, std::memory_order_release);
    g_lastSeenAccountId = newAccountId;
    g_diskAccountId = newAccountId;
    EnsureAccountDir();
    // No need to wipe the old account's disk files -- they're in a separate
    // directory (stats/<oldAccountId>/) and won't be read by the new account.
    return true;
}

void ResetForTesting() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_cache.clear();
    g_importAttempted.clear();
    g_cloudBlobByApp.clear();
    g_cloudBlobMerged.clear();
    g_dirty.clear();
    g_activeSessions.clear();
    g_resetApps.clear();
    g_accountBlobDirty = false;
    g_lastSeenAccountId = 0;
    g_diskAccountId = 0;
}

// Import native UserGameStats + schema blobs. Caller holds g_mutex.
static bool ImportNativeStats(uint32_t appId, AppStats& out) {
    if (g_steamPath.empty() || !g_accountIdProvider) return false;
    uint32_t accountId = g_accountIdProvider();
    if (accountId == 0) return false;

    // Schema: appcache/stats/UserGameStatsSchema_<appId>.bin
    {
        fs::path schemaPath = FileUtil::Utf8ToPath(g_steamPath) / "appcache" / "stats"
            / ("UserGameStatsSchema_" + std::to_string(appId) + ".bin");
        std::ifstream sf(schemaPath, std::ios::binary);
        if (sf.good()) {
            out.schema.assign(std::istreambuf_iterator<char>(sf),
                              std::istreambuf_iterator<char>());
        }
        // Refresh schema from Steam's server (picks up newly-added achievements).
        if (g_schemaMissingCb)
            g_schemaMissingCb(appId);
    }

    // Stats: appcache/stats/UserGameStats_<accountId>_<appId>.bin
    fs::path statsPath = FileUtil::Utf8ToPath(g_steamPath) / "appcache" / "stats"
        / ("UserGameStats_" + std::to_string(accountId) + "_" + std::to_string(appId) + ".bin");
    std::ifstream f(statsPath, std::ios::binary);
    if (!f.good())
        return !out.schema.empty();
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    f.close();
    if (blob.empty())
        return !out.schema.empty();

    size_t pos = 0, nodeCount = 0;
    std::vector<BkvNode> root;
    if (!BkvRead(blob.data(), blob.size(), pos, root, 0, nodeCount))
        return !out.schema.empty();

    const BkvNode* cache = BkvFind(root, "cache");
    if (!cache)
        return !out.schema.empty();

    // Parse the schema (if present) for human-readable achievement names and
    // per-stat merge strategies (type_int / resolution_method).
    std::unordered_map<uint64_t, std::string> achNames;
    std::unordered_map<uint32_t, StatMerge> mergeMethods;
    if (!out.schema.empty()) {
        size_t spos = 0, snodes = 0;
        std::vector<BkvNode> sroot;
        if (BkvRead(out.schema.data(), out.schema.size(), spos, sroot, 0, snodes)) {
            achNames = ParseSchemaAchievementNames(sroot);
            mergeMethods = ParseSchemaMergeMethods(sroot);
        }
    }

    size_t importedStats = 0, importedAch = 0;
    for (const auto& stat : cache->children) {
        if (stat.type != BKV_SECTION) continue;       // skip crc / PendingChanges
        // Section name is the decimal stat id.
        uint32_t statId = 0;
        bool numeric = !stat.name.empty();
        for (char c : stat.name) { if (c < '0' || c > '9') { numeric = false; break; } }
        if (!numeric) continue;
        statId = (uint32_t)strtoul(stat.name.c_str(), nullptr, 10);

        const BkvNode* dataNode = BkvFind(stat.children, "data");
        if (!dataNode) continue;
        uint32_t value = BkvDataAsU32(*dataNode);

        StatMerge mm = StatMerge::Overwrite;
        auto mmIt = mergeMethods.find(statId);
        if (mmIt != mergeMethods.end()) mm = mmIt->second;
        out.stats.push_back(StatEntry{statId, value, mm});
        ++importedStats;

        // Achievement unlock times -> AchievementBlock. The 'data' INT is the
        // unlocked-bit bitfield; AchievementTimes holds per-bit timestamps.
        const BkvNode* achTimes = BkvFind(stat.children, "AchievementTimes");
        if (achTimes) {
            AchievementBlock blk{};
            blk.statId = statId;
            blk.bits = value;
            for (const auto& bitNode : achTimes->children) {
                if (bitNode.type != BKV_INT) continue;
                uint32_t bit = (uint32_t)strtoul(bitNode.name.c_str(), nullptr, 10);
                if (bit < 32) blk.unlockTimes[bit] = bitNode.intVal;
            }
            // Attach human-readable names from the schema (for all 32 bits that
            // have one, not just unlocked -- the UI may show locked ones too).
            if (!achNames.empty()) {
                for (uint32_t bit = 0; bit < 32; bit++) {
                    auto it = achNames.find(((uint64_t)statId << 32) | bit);
                    if (it != achNames.end()) blk.names[bit] = it->second;
                }
            }
            out.achievements.push_back(blk);
            ++importedAch;
        }
    }

    ReconcileAchievementBits(out.stats, out.achievements);
    return importedStats > 0 || !out.schema.empty();
}

// Writes UserGameStats .bin for SLSsteam's NO_CONNECTION fallback.
// Format: cache { crc; PendingChanges; <statId> { data; AchievementTimes { <bit>=ts } } }

namespace {

class BkvWriter {
public:
    void BeginSection(const char* name) {
        m_buf.push_back(BKV_SECTION);
        WriteCStr(name);
    }
    void EndSection() { m_buf.push_back(BKV_END); }

    void WriteInt(const char* name, uint32_t val) {
        m_buf.push_back(BKV_INT);
        WriteCStr(name);
        WriteU32(val);
    }

    const std::vector<uint8_t>& Data() const { return m_buf; }

private:
    void WriteCStr(const char* s) {
        while (*s) m_buf.push_back(static_cast<uint8_t>(*s++));
        m_buf.push_back(0);
    }
    void WriteU32(uint32_t v) {
        m_buf.push_back(v & 0xFF);
        m_buf.push_back((v >> 8) & 0xFF);
        m_buf.push_back((v >> 16) & 0xFF);
        m_buf.push_back((v >> 24) & 0xFF);
    }

    std::vector<uint8_t> m_buf;
};

} // anon namespace

// Caller holds g_mutex.
static bool ExportNativeStats(uint32_t appId, const AppStats& stats) {
    if (g_steamPath.empty() || !g_accountIdProvider) return false;
    uint32_t accountId = g_accountIdProvider();
    if (accountId == 0) return false;

    if (stats.stats.empty() && stats.achievements.empty()) return false;

    std::unordered_map<uint32_t, const AchievementBlock*> achMap;
    for (const auto& a : stats.achievements)
        achMap[a.statId] = &a;

    std::unordered_set<uint32_t> emittedAch;

    BkvWriter bkv;
    bkv.BeginSection("cache");
    bkv.WriteInt("crc", stats.crcStats);
    bkv.WriteInt("PendingChanges", 0);

    for (const auto& s : stats.stats) {
        char statName[16];
        snprintf(statName, sizeof(statName), "%u", s.statId);

        bkv.BeginSection(statName);
        bkv.WriteInt("data", s.value);

        auto achIt = achMap.find(s.statId);
        if (achIt != achMap.end()) {
            emittedAch.insert(s.statId);
            const AchievementBlock& blk = *achIt->second;
            bkv.BeginSection("AchievementTimes");
            for (uint32_t bit = 0; bit < 32; bit++) {
                if (blk.unlockTimes[bit] != 0) {
                    char bitName[8];
                    snprintf(bitName, sizeof(bitName), "%u", bit);
                    bkv.WriteInt(bitName, blk.unlockTimes[bit]);
                }
            }
            bkv.EndSection(); // AchievementTimes
        }
        bkv.EndSection(); // stat section
    }

    // Orphan AchievementBlocks (no matching StatEntry, e.g. cross-device merge).
    for (const auto& a : stats.achievements) {
        if (emittedAch.count(a.statId)) continue;
        char statName[16];
        snprintf(statName, sizeof(statName), "%u", a.statId);
        bkv.BeginSection(statName);
        bkv.WriteInt("data", a.bits);  // bitfield is the stat value for achievement stats
        bkv.BeginSection("AchievementTimes");
        for (uint32_t bit = 0; bit < 32; bit++) {
            if (a.unlockTimes[bit] != 0) {
                char bitName[8];
                snprintf(bitName, sizeof(bitName), "%u", bit);
                bkv.WriteInt(bitName, a.unlockTimes[bit]);
            }
        }
        bkv.EndSection(); // AchievementTimes
        bkv.EndSection(); // stat section
    }

    bkv.EndSection(); // cache
    bkv.EndSection(); // root terminator

    fs::path statsDir = FileUtil::Utf8ToPath(g_steamPath) / "appcache" / "stats";
    std::error_code ec;
    fs::create_directories(statsDir, ec);

    fs::path statsPath = statsDir /
        ("UserGameStats_" + std::to_string(accountId) + "_" + std::to_string(appId) + ".bin");
    std::ofstream f(statsPath, std::ios::binary | std::ios::trunc);
    if (!f.good()) {
        LOG("[Stats] ExportNativeStats app=%u: failed to open %s",
            appId, statsPath.string().c_str());
        return false;
    }
    f.write(reinterpret_cast<const char*>(bkv.Data().data()), bkv.Data().size());
    f.close();

    // Schema too, if available (Steam needs it for achievement names/icons).
    if (!stats.schema.empty()) {
        fs::path schemaPath = statsDir /
            ("UserGameStatsSchema_" + std::to_string(appId) + ".bin");
        std::ofstream sf(schemaPath, std::ios::binary | std::ios::trunc);
        if (sf.good())
            sf.write(reinterpret_cast<const char*>(stats.schema.data()), stats.schema.size());
    }

    LOG("[Stats] ExportNativeStats app=%u: wrote %zu bytes (%zu stats, %zu ach blocks)",
        appId, bkv.Data().size(), stats.stats.size(), stats.achievements.size());
    return true;
}

// Parse the JSON document (stats/achievements/playtime) into `out`.
// Does NOT touch the separate on-disk schema blob.
static bool ParseAppStatsJson(const std::string& content, AppStats& out) {
    auto root = Json::Parse(content);
    if (root.isNull()) return false;

    out.crcStats = (uint32_t)root["crc_stats"].integer();
    out.stats.clear();
    out.achievements.clear();
    out.playtime = {};

    const auto& statsArr = root["stats"];
    if (statsArr.type == Json::Type::Array) {
        for (size_t i = 0; i < statsArr.size(); i++) {
            const auto& item = statsArr[i];
            StatEntry e;
            e.statId = (uint32_t)item["id"].integer();
            e.value = (uint32_t)item["value"].integer();
            const auto& mf = item["merge"];
            if (mf.type == Json::Type::Number)
                e.merge = static_cast<StatMerge>((uint8_t)mf.integer());
            out.stats.push_back(e);
        }
    }

    const auto& achArr = root["achievements"];
    if (achArr.type == Json::Type::Array) {
        for (size_t i = 0; i < achArr.size(); i++) {
            const auto& item = achArr[i];
            AchievementBlock blk = {};
            blk.statId = (uint32_t)item["stat_id"].integer();
            blk.bits = (uint32_t)item["bits"].integer();
            const auto& times = item["unlock_times"];
            if (times.type == Json::Type::Array) {
                for (size_t j = 0; j < times.size() && j < 32; j++) {
                    blk.unlockTimes[j] = (uint32_t)times[j].integer();
                }
            }
            const auto& names = item["names"];
            if (names.type == Json::Type::Array) {
                for (size_t j = 0; j < names.size() && j < 32; j++)
                    blk.names[j] = names[j].str();
            }
            out.achievements.push_back(blk);
        }
    }

    ReconcileAchievementBits(out.stats, out.achievements);

    const auto& pt = root["playtime"];
    if (pt.type == Json::Type::Object) {
        out.playtime.minutesForever = (uint32_t)pt["minutes_forever"].integer();
        out.playtime.minutesLastTwoWeeks = (uint32_t)pt["minutes_2weeks"].integer();
        out.playtime.lastPlayedTime = (uint32_t)pt["last_played"].integer();
        out.playtime.playtimeWindows = (uint32_t)pt["windows"].integer();
        out.playtime.playtimeMac = (uint32_t)pt["mac"].integer();
        out.playtime.playtimeLinux = (uint32_t)pt["linux"].integer();

        // Per-device sub-totals (authoritative). Object: deviceId -> {windows,mac,linux}.
        const auto& pd = pt["per_device"];
        if (pd.type == Json::Type::Object) {
            for (const auto& [dev, v] : pd.objVal) {
                if (v.type != Json::Type::Object) continue;
                DevicePlaytime dp;
                dp.windows = (uint32_t)v["windows"].integer();
                dp.mac     = (uint32_t)v["mac"].integer();
                dp.lin     = (uint32_t)v["linux"].integer();
                out.playtime.perDevice[dev] = dp;
            }
        }
        // Empty perDevice with real platform totals (legacy blob or off-playtime
        // push): shim totals into synthetic legacy buckets so they aren't zeroed.
        if (out.playtime.perDevice.empty()) {
            if (out.playtime.playtimeWindows)
                out.playtime.perDevice["__legacy_windows"].windows = out.playtime.playtimeWindows;
            if (out.playtime.playtimeMac)
                out.playtime.perDevice["__legacy_mac"].mac = out.playtime.playtimeMac;
            if (out.playtime.playtimeLinux)
                out.playtime.perDevice["__legacy_linux"].lin = out.playtime.playtimeLinux;
        }
        RecomputePlaytimeTotals(out.playtime);
    }

    return true;
}

// Serialize the stats document (everything except the raw schema blob) to JSON.
static std::string BuildAppStatsJson(const AppStats& stats) {
    Json::Value root = Json::Object();
    root.objVal["crc_stats"] = Json::Number(stats.crcStats);

    Json::Value statsArr = Json::Array();
    for (auto& s : stats.stats) {
        Json::Value item = Json::Object();
        item.objVal["id"] = Json::Number(s.statId);
        item.objVal["value"] = Json::Number(s.value);
        if (s.merge != StatMerge::Overwrite)
            item.objVal["merge"] = Json::Number((uint32_t)s.merge);
        statsArr.arrVal.push_back(std::move(item));
    }
    root.objVal["stats"] = std::move(statsArr);

    Json::Value achArr = Json::Array();
    for (auto& a : stats.achievements) {
        Json::Value item = Json::Object();
        item.objVal["stat_id"] = Json::Number(a.statId);
        item.objVal["bits"] = Json::Number(a.bits);
        Json::Value times = Json::Array();
        for (int i = 0; i < 32; i++) {
            times.arrVal.push_back(Json::Number(a.unlockTimes[i]));
        }
        item.objVal["unlock_times"] = std::move(times);
        // Human-readable per-bit names from the schema (may be empty strings).
        bool anyName = false;
        for (int i = 0; i < 32; i++) if (!a.names[i].empty()) { anyName = true; break; }
        if (anyName) {
            Json::Value namesArr = Json::Array();
            for (int i = 0; i < 32; i++)
                namesArr.arrVal.push_back(Json::String(a.names[i]));
            item.objVal["names"] = std::move(namesArr);
        }
        achArr.arrVal.push_back(std::move(item));
    }
    root.objVal["achievements"] = std::move(achArr);

    Json::Value pt = Json::Object();
    pt.objVal["minutes_forever"] = Json::Number(stats.playtime.minutesForever);
    pt.objVal["minutes_2weeks"] = Json::Number(stats.playtime.minutesLastTwoWeeks);
    pt.objVal["last_played"] = Json::Number(stats.playtime.lastPlayedTime);
    pt.objVal["windows"] = Json::Number(stats.playtime.playtimeWindows);
    pt.objVal["mac"] = Json::Number(stats.playtime.playtimeMac);
    pt.objVal["linux"] = Json::Number(stats.playtime.playtimeLinux);
    // Authoritative per-device sub-totals (the merge source of truth).
    Json::Value perDev = Json::Object();
    for (const auto& [dev, dp] : stats.playtime.perDevice) {
        Json::Value d = Json::Object();
        d.objVal["windows"] = Json::Number(dp.windows);
        d.objVal["mac"] = Json::Number(dp.mac);
        d.objVal["linux"] = Json::Number(dp.lin);
        perDev.objVal[dev] = std::move(d);
    }
    pt.objVal["per_device"] = std::move(perDev);
    root.objVal["playtime"] = std::move(pt);

    return Json::Stringify(root);
}

// Hostname matches Steam's machine_names convention; stable across restarts.
static const std::string& ThisDeviceId() {
    static const std::string id = [] {
#ifdef _WIN32
        char buf[256]; DWORD len = sizeof(buf);
        if (GetComputerNameA(buf, &len) && len > 0) return std::string(buf, len);
#else
        char buf[256];
        if (gethostname(buf, sizeof(buf)) == 0) return std::string(buf);
#endif
        return std::string("UNKNOWN");
    }();
    return id;
}

// Recompute the derived totals from the authoritative per-device sub-totals.
static void RecomputePlaytimeTotals(PlaytimeData& pt, bool allowShrink) {
    uint64_t win = 0, mac = 0, lin = 0;
    for (const auto& [dev, dp] : pt.perDevice) {
        win += dp.windows; mac += dp.mac; lin += dp.lin;
    }
    auto clamp32 = [](uint64_t v) -> uint32_t {
        return v > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)v;
    };
    if (allowShrink) {
        // Migration repair: the bucket sum is now authoritative and may be lower
        // than before (a double-count was removed).
        pt.playtimeWindows = clamp32(win);
        pt.playtimeMac     = clamp32(mac);
        pt.playtimeLinux   = clamp32(lin);
        pt.minutesForever  = clamp32(win + mac + lin);
        return;
    }
    // Floor at prior value -- playtime only goes up.
    pt.playtimeWindows = (std::max)(pt.playtimeWindows, clamp32(win));
    pt.playtimeMac     = (std::max)(pt.playtimeMac,     clamp32(mac));
    pt.playtimeLinux   = (std::max)(pt.playtimeLinux,   clamp32(lin));
    pt.minutesForever  = (std::max)(pt.minutesForever,  clamp32(win + mac + lin));
}

// Accrue minutes onto THIS device's own per-device sub-total for this platform.
static void AccrueLocalPlaytime(PlaytimeData& pt, uint32_t minutes) {
    DevicePlaytime& mine = pt.perDevice[ThisDeviceId()];
#ifdef _WIN32
    mine.windows += minutes;
#elif defined(__APPLE__)
    mine.mac += minutes;
#else
    mine.lin += minutes;
#endif
    RecomputePlaytimeTotals(pt);
}

static bool IsLegacyDeviceKey(const std::string& key) {
    return key.rfind("__legacy_", 0) == 0;
}

// Recomputed each launch from localconfig; never max-merge from external sources.
static bool IsReconcileOwnedKey(const std::string& key) {
    return key == "__migrated_localconfig";
}

static bool IsSyntheticKey(const std::string& key) {
    return IsLegacyDeviceKey(key) || IsReconcileOwnedKey(key);
}

// Union-merge playtime (max per device+platform). Legacy-only blobs are discounted
// by real-device totals; reconcile-owned buckets are never adopted from src.
static void MergePlaytime(PlaytimeData& dst, const PlaytimeData& src) {
    bool srcHasRealKeys = false;
    for (const auto& [dev, sdp] : src.perDevice) {
        if (!IsSyntheticKey(dev)) { srcHasRealKeys = true; break; }
    }
    bool srcLegacyOnly = !src.perDevice.empty() && !srcHasRealKeys;

    // Union real device keys first (so the discount below sees all of them).
    for (const auto& [dev, sdp] : src.perDevice) {
        if (IsSyntheticKey(dev)) continue;
        DevicePlaytime& ddp = dst.perDevice[dev];
        ddp.windows = (std::max)(ddp.windows, sdp.windows);
        ddp.mac     = (std::max)(ddp.mac,     sdp.mac);
        ddp.lin     = (std::max)(ddp.lin,     sdp.lin);
    }

    // Per-platform sums of real (attributed) minutes, for the legacy discount.
    uint64_t realWin = 0, realMac = 0, realLin = 0;
    if (srcLegacyOnly) {
        for (const auto& [dev, ddp] : dst.perDevice) {
            if (IsSyntheticKey(dev)) continue;
            realWin += ddp.windows; realMac += ddp.mac; realLin += ddp.lin;
        }
    }
    auto discounted = [](uint32_t legacyVal, uint64_t realSum) -> uint32_t {
        return legacyVal > realSum ? (uint32_t)(legacyVal - realSum) : 0u;
    };

    for (const auto& [dev, sdp] : src.perDevice) {
        if (IsReconcileOwnedKey(dev)) continue;   // never adopt from external source
        if (!IsLegacyDeviceKey(dev)) continue;
        DevicePlaytime eff = sdp;
        if (srcLegacyOnly) {
            eff.windows = discounted(sdp.windows, realWin);
            eff.mac     = discounted(sdp.mac,     realMac);
            eff.lin     = discounted(sdp.lin,     realLin);
        }
        DevicePlaytime& ddp = dst.perDevice[dev];
        ddp.windows = (std::max)(ddp.windows, eff.windows);
        ddp.mac     = (std::max)(ddp.mac,     eff.mac);
        ddp.lin     = (std::max)(ddp.lin,     eff.lin);
    }

    dst.minutesLastTwoWeeks = (std::max)(dst.minutesLastTwoWeeks, src.minutesLastTwoWeeks);
    dst.lastPlayedTime = (std::max)(dst.lastPlayedTime, src.lastPlayedTime);
    RecomputePlaytimeTotals(dst);
}

// Union-merge achievements (monotonic unlocks). Returns true if dst changed.
static bool MergeAchievements(std::vector<AchievementBlock>& dst,
                              const std::vector<AchievementBlock>& src) {
    bool changed = false;
    for (const auto& s : src) {
        AchievementBlock* d = nullptr;
        for (auto& a : dst) { if (a.statId == s.statId) { d = &a; break; } }
        if (!d) {
            dst.push_back(s);
            changed = true;
            continue;
        }
        if ((d->bits | s.bits) != d->bits) { d->bits |= s.bits; changed = true; }
        for (int bit = 0; bit < 32; ++bit) {
            if (d->unlockTimes[bit] == 0 && s.unlockTimes[bit] != 0) {
                d->unlockTimes[bit] = s.unlockTimes[bit];
                changed = true;
            }
            if (d->names[bit].empty() && !s.names[bit].empty())
                d->names[bit] = s.names[bit];
        }
    }
    return changed;
}

// Count individual unlocked achievement bits across all blocks. For diagnostics:
// "9 vs 8" cloud/native mismatches are about unlocked bits, not block count.
static size_t CountUnlockedAchievements(const std::vector<AchievementBlock>& a) {
    size_t n = 0;
    for (const auto& blk : a)
        for (int bit = 0; bit < 32; ++bit)
            if (blk.unlockTimes[bit] != 0) ++n;
    return n;
}

// OR each achievement block's `bits` into the matching stat value (MergeAchievements
// updates bits but not stats[].value). Only `a.bits`, so revoked unlocks stay cleared.
static bool ReconcileAchievementBits(std::vector<StatEntry>& stats,
                                     std::vector<AchievementBlock>& achievements) {
    bool changed = false;
    for (auto& a : achievements) {
        // Promote unlock times → bits only when the bit is already set (not orphaned).
        // But DO promote bits → stat_val unconditionally (the actual bug fix).
        for (auto& s : stats) {
            if (s.statId == a.statId) {
                if ((s.value | a.bits) != s.value) { s.value |= a.bits; changed = true; }
                break;
            }
        }
    }
    return changed;
}

// Resolve the effective merge method for two entries (prefer the one that has a
// non-default method; if both are set they should agree since they come from the
// same schema -- pick the more protective one).
static StatMerge EffectiveMerge(StatMerge a, StatMerge b) {
    if (a != StatMerge::Overwrite) return a;
    return b;
}

// Apply schema-aware merge for a single stat value. Returns the merged value.
static uint32_t MergedValue(uint32_t dst, uint32_t src, StatMerge method) {
    switch (method) {
        case StatMerge::BitwiseOr:
            return dst | src;
        case StatMerge::MaxInt: {
            int32_t d, s;
            std::memcpy(&d, &dst, 4);
            std::memcpy(&s, &src, 4);
            return (s > d) ? src : dst;
        }
        case StatMerge::MaxFloat: {
            float df, sf;
            std::memcpy(&df, &dst, 4);
            std::memcpy(&sf, &src, 4);
            return (sf > df) ? src : dst;
        }
        default: // Overwrite: source wins
            return src;
    }
}

// Merge src into dst per-stat: Overwrite for authoritative native reimport, OR/MAX
// for cloud merge (regression-safe). Returns true if dst changed.
static bool MergeStatValues(std::vector<StatEntry>& dst,
                            const std::vector<StatEntry>& src) {
    bool changed = false;
    for (const auto& s : src) {
        bool found = false;
        for (auto& d : dst) {
            if (d.statId == s.statId) {
                StatMerge method = EffectiveMerge(d.merge, s.merge);
                // Adopt the merge method from src if dst didn't have one.
                if (d.merge == StatMerge::Overwrite && s.merge != StatMerge::Overwrite)
                    d.merge = s.merge;
                uint32_t merged = MergedValue(d.value, s.value, method);
                if (d.value != merged) { d.value = merged; changed = true; }
                found = true;
                break;
            }
        }
        if (!found) { dst.push_back(s); changed = true; }
    }
    return changed;
}

// Fold `incoming` onto `base` (same app) with the in-store monotonic rules:
// union playtime, union achievements, stat-value merge. Pure function.
std::string MergeAppStatsJson(const std::string& base, const std::string& incoming) {
    AppStats baseStats, incomingStats;
    bool haveBase = !base.empty() && ParseAppStatsJson(base, baseStats);
    bool haveIncoming = !incoming.empty() && ParseAppStatsJson(incoming, incomingStats);

    // Degenerate cases: if only one side parses, it is the answer. If neither
    // parses, prefer the caller's own outgoing copy.
    if (!haveBase && !haveIncoming) return incoming;
    if (!haveBase) return incoming;
    if (!haveIncoming) return base;

    // Union/max both sides; order-independent for monotonic fields.
    MergePlaytime(baseStats.playtime, incomingStats.playtime);
    MergeAchievements(baseStats.achievements, incomingStats.achievements);
    MergeStatValues(baseStats.stats, incomingStats.stats);
    ReconcileAchievementBits(baseStats.stats, baseStats.achievements);
    // Recompute crc over the merged result, not either side's stale token.
    baseStats.crcStats = ComputeCrcLocked(baseStats);
    return BuildAppStatsJson(baseStats);
}

// No network; safe under g_mutex. Returns true if local data existed.
static bool LoadAppStatsLocalOnly(uint32_t appId, AppStats& out) {
    if (g_diskAccountId == 0) return false;   // no account yet; skip disk I/O
    std::string path = StatsPath(appId);
    bool haveLocal = false;

    std::ifstream f(path);
    if (f.good()) {
        std::string local((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
        f.close();
        if (!local.empty() && ParseAppStatsJson(local, out))
            haveLocal = true;
    }
    if (haveLocal) {
        std::string schemaPath = SchemaPath(appId);
        std::ifstream sf(schemaPath, std::ios::binary);
        if (sf.good()) {
            out.schema.assign(std::istreambuf_iterator<char>(sf),
                              std::istreambuf_iterator<char>());
        }
    }
    return haveLocal;
}

// Merge cached cloud blob for one app. Caller holds g_mutex.
static bool MergeCloudBlobLocked(uint32_t appId, AppStats& out, bool haveLocal) {
    if (g_resetApps.count(appId)) return false;
    std::string cloud = CloudJsonForAppLocked(appId);
    if (cloud.empty()) return false;
    AppStats cloudStats;
    if (!ParseAppStatsJson(cloud, cloudStats)) return false;
    size_t localHad = CountUnlockedAchievements(out.achievements);
    size_t cloudHad = CountUnlockedAchievements(cloudStats.achievements);
    if (!haveLocal) {
        out = std::move(cloudStats);
    } else {
        MergePlaytime(out.playtime, cloudStats.playtime);
        // Union-merge achievements (unlocks are monotonic -- never let a local copy
        // hide another device's unlock) and stat values, so cloud progress is
        // preserved instead of clobbered on next push.
        MergeAchievements(out.achievements, cloudStats.achievements);
        MergeStatValues(out.stats, cloudStats.stats);
        ReconcileAchievementBits(out.stats, out.achievements);
        // Schema is descriptive; adopt cloud's only when we hold none.
        if (out.schema.empty() && !cloudStats.schema.empty())
            out.schema = std::move(cloudStats.schema);
    }
    g_cloudBlobMerged.insert(appId);
    size_t haveAfter = CountUnlockedAchievements(out.achievements);
    if (haveAfter != localHad || cloudHad > localHad)
        LOG("[Stats] CloudBlob merge app=%u: local=%zu cloud=%zu -> %zu unlocked%s",
            appId, localHad, cloudHad, haveAfter,
            cloudHad > localHad ? " (cloud had more)" : "");
    return true;
}

bool LoadAppStats(uint32_t appId, AppStats& out) {
    if (g_diskAccountId == 0) return false;   // no account yet; skip disk I/O
    std::string path = StatsPath(appId);
    bool haveLocal = false;

    std::ifstream f(path);
    if (f.good()) {
        std::string local((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());
        f.close();
        if (!local.empty() && ParseAppStatsJson(local, out))
            haveLocal = true;
    }

    // Consult the cached account blob (pulled once by SeedApps/RefreshFromCloud).
    // No per-app network read -- the whole account blob was fetched in one shot.
    if (MergeCloudBlobLocked(appId, out, haveLocal)) {
        haveLocal = true;
        WriteAppStats(appId, out, false);
    }

    if (!haveLocal) return false;

    // Load schema blob if exists (separate binary sidecar).
    std::string schemaPath = SchemaPath(appId);
    std::ifstream sf(schemaPath, std::ios::binary);
    if (sf.good()) {
        out.schema.assign(std::istreambuf_iterator<char>(sf),
                          std::istreambuf_iterator<char>());
    }
    return true;
}

// Persist locally and, when pushCloud, queue a cloud upload. Reconcile writes
// locally only; the cloud is written on session end, when playtime accrues.
static void WriteAppStats(uint32_t appId, const AppStats& stats, bool pushCloud,
                          bool bypassDiskMerge) {
    if (g_diskAccountId == 0) return;   // no account yet; skip disk I/O
    std::string path = StatsPath(appId);

    // Max-merge on-disk playtime so partial writes never regress minutes.
    // bypassDiskMerge: migration repair needs to shrink a bucket.
    AppStats merged = stats;
    if (!bypassDiskMerge) {
        std::ifstream rf(path);
        if (rf.good()) {
            std::string existing((std::istreambuf_iterator<char>(rf)),
                                 std::istreambuf_iterator<char>());
            rf.close();
            AppStats prior;
            if (!existing.empty() && ParseAppStatsJson(existing, prior))
                MergePlaytime(merged.playtime, prior.playtime);
        }
    }

    // Max-merge the cached cloud playtime so an achievement-path push carrying
    // empty playtime can't regress account-wide minutes. Skipped on bypassDiskMerge.
    if (pushCloud && !bypassDiskMerge) {
        auto it = g_cloudBlobByApp.find(appId);
        if (it != g_cloudBlobByApp.end() && !it->second.empty()) {
            AppStats cloudPrior;
            if (ParseAppStatsJson(it->second, cloudPrior))
                MergePlaytime(merged.playtime, cloudPrior.playtime);
        }
    }

    std::string json = BuildAppStatsJson(merged);

    std::ofstream f(path, std::ios::trunc);
    f << json;
    f.close();

    if (!merged.schema.empty()) {
        std::string schemaPath = SchemaPath(appId);
        std::ofstream sf(schemaPath, std::ios::binary | std::ios::trunc);
        sf.write(reinterpret_cast<const char*>(merged.schema.data()), merged.schema.size());
    }

    if (pushCloud) {
        // Flag account blob for coalesced push.
        g_cloudBlobByApp[appId] = json;
        g_accountBlobDirty = true;
    }
}

// Push account blob if dirty. Serialized, detached worker (curl blocks).
static void PushAccountBlobIfDirty() {
    CloudPushAllFn push;
    std::unordered_map<uint32_t, std::string> snapshot;
    uint32_t snapshotAccountId;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_accountBlobDirty || !g_cloudPushAll) return;
        if (!g_accountIdProvider) return;
        snapshotAccountId = g_accountIdProvider();
        if (snapshotAccountId == 0) return;
        push = g_cloudPushAll;
        snapshot = g_cloudBlobByApp;     // copy under lock
        g_accountBlobDirty = false;       // clear before releasing (re-set on later change)
    }
    std::thread([push = std::move(push), snapshot = std::move(snapshot), snapshotAccountId]() {
        std::lock_guard<std::mutex> pushLock(g_pushInFlightMutex);
        {
    std::unique_lock<std::mutex> lock(g_mutex);
            uint32_t currentAcct = g_accountIdProvider ? g_accountIdProvider() : 0;
            if (currentAcct != snapshotAccountId) {
                LOG("[Stats] PushAccountBlob ABORTED: account switched %u -> %u between snapshot and push",
                    snapshotAccountId, currentAcct);
                return;
            }
        }
        push(snapshot);
    }).detach();
}

void SaveAppStats(uint32_t appId, const AppStats& stats) {
    WriteAppStats(appId, stats, true);
}

// Import native stats if absent. Retries until accountId is ready. Caller holds mutex.
static void EnsureNativeImportLocked(uint32_t appId, AppStats& stats) {
    // Also retry if we have data but no schema (required to serve achievements).
    if (!stats.stats.empty() && !stats.schema.empty()) return;
    // Retry if schema is still missing (may have been written after first try).
    if (g_importAttempted.count(appId) && !stats.schema.empty()) return;
    if (!g_accountIdProvider || g_accountIdProvider() == 0) {
        // accountId not ready yet (not logged in) -- don't mark attempted; retry later.
        return;
    }

    AppStats native;
    native.playtime = stats.playtime; // preserve any playtime already loaded
    bool imported = ImportNativeStats(appId, native);
    g_importAttempted[appId] = true; // accountId was valid; this is a definitive attempt
    if (imported) {
        // Adopt the schema even on a schema-only import (no native stats blob).
        bool schemaAdopted = false;
        if (!native.schema.empty()) {
            stats.schema = std::move(native.schema);
            schemaAdopted = true;
        }
        // Merge (not overwrite) -- cloud may hold more unlocks than native.
        size_t haveBefore = CountUnlockedAchievements(stats.achievements);
        size_t nativeHas  = CountUnlockedAchievements(native.achievements);
        bool merged = false;
        if (!native.achievements.empty())
            merged |= MergeAchievements(stats.achievements, native.achievements);
        if (!native.stats.empty())
            merged |= MergeStatValues(stats.stats, native.stats);
        merged |= ReconcileAchievementBits(stats.stats, stats.achievements);
        size_t haveAfter = CountUnlockedAchievements(stats.achievements);
        // If cloud (haveBefore) held more than native, the merge must keep the
        // superset -- haveAfter dropping below haveBefore means an unlock was lost.
        if (haveAfter < haveBefore)
            LOG("[Stats] NativeImport merge app=%u: unlock regressed (%zu -> %zu)",
                appId, haveBefore, haveAfter);
        if (merged || schemaAdopted) {
            stats.crcStats = ComputeCrcLocked(stats);
            g_dirty[appId] = true;
            SaveAppStats(appId, stats);
        }
    }
}

// Re-import native blob, merging new unlocks. Caller holds mutex.
static bool ReimportNativeStatsLocked(uint32_t appId, AppStats& stats) {
    if (!g_accountIdProvider || g_accountIdProvider() == 0) return false;

    AppStats native;
    if (!ImportNativeStats(appId, native)) return false;

    bool changed = MergeStatValues(stats.stats, native.stats);
    if (MergeAchievements(stats.achievements, native.achievements)) changed = true;
    if (ReconcileAchievementBits(stats.stats, stats.achievements)) changed = true;
    if (stats.schema.empty() && !native.schema.empty()) {
        stats.schema = std::move(native.schema);
        changed = true;
    }
    if (changed) stats.crcStats = ComputeCrcLocked(stats);
    return changed;
}

void CaptureNativeUnlocks(uint32_t appId) {
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        AppStats& stats = GetOrCreateLocked(appId);
        size_t beforeCount = CountUnlockedAchievements(stats.achievements);
        if (ReimportNativeStatsLocked(appId, stats)) {
            size_t afterCount = CountUnlockedAchievements(stats.achievements);
            g_dirty[appId] = true;
            SaveAppStats(appId, stats);   // updates account blob + dirty flag
            g_dirty[appId] = false;
            changed = true;
            LOG("[Stats] Captured native unlocks for app %u (crc=%u) %zu->%zu unlocked",
                appId, stats.crcStats, beforeCount, afterCount);
        }
    }
    // A genuine unlock just landed -- push the account blob now (off-lock).
    if (changed) PushAccountBlobIfDirty();
}

// Caller MUST hold g_mutex.
static AppStats& GetOrCreateLocked(uint32_t appId) {
    auto it = g_cache.find(appId);
    if (it != g_cache.end()) {
        // Late-merge cloud blob if not yet absorbed this fetch cycle.
        if (!g_cloudBlobMerged.count(appId)) {
            uint32_t crcBefore = it->second.crcStats;
            if (MergeCloudBlobLocked(appId, it->second, /*haveLocal=*/true)) {
                it->second.crcStats = ComputeCrcLocked(it->second);
                WriteAppStats(appId, it->second, false);
                if (it->second.crcStats != crcBefore)
                    LOG("[Stats] Late-merged app %u from cloud blob (%zu ach block(s), schema=%zu)",
                        appId, it->second.achievements.size(), it->second.schema.size());
            }
        }
        // Ensure native stats are imported on first actual stats access (and on
        // later retries once accountId is ready).
        EnsureNativeImportLocked(appId, it->second);
        return it->second;
    }

    AppStats& stats = g_cache[appId];
    bool loaded = LoadAppStats(appId, stats);
    if (!loaded) {
        stats.crcStats = 0;
        stats.playtime = {};
    }
    EnsureNativeImportLocked(appId, stats);
    return stats;
}

AppStats& GetOrCreate(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return GetOrCreateLocked(appId);
}

// Thread-safe copy under the lock for read handlers.
AppStats Snapshot(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return GetOrCreateLocked(appId);
}

// Clears stats/achievements only (playtime/schema survive).
void ResetStats(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    AppStats& stats = GetOrCreateLocked(appId);
    stats.stats.clear();
    stats.achievements.clear();
    stats.crcStats = 0;
    g_dirty[appId] = true;
    g_resetApps.insert(appId);
    WriteAppStats(appId, stats, /*pushCloud=*/true);
    g_dirty[appId] = false;
}

// Migrate legacy per-app blobs into the consolidated account blob.
static void MigrateLegacyBlobs(const std::vector<uint32_t>& appIds) {
    CloudPullLegacyFn pullLegacy;
    std::vector<uint32_t> missing;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_cloudPullLegacy) return;
        pullLegacy = g_cloudPullLegacy;
        for (uint32_t appId : appIds) {
            if (appId == 0) continue;
            if (g_cloudBlobByApp.find(appId) == g_cloudBlobByApp.end())
                missing.push_back(appId);
        }
    }
    for (uint32_t appId : missing) {
        std::string legacy = pullLegacy(appId);   // network, off-lock
        if (legacy.empty()) continue;
        AppStats parsed;
        if (!ParseAppStatsJson(legacy, parsed)) continue;
        std::lock_guard<std::mutex> lock(g_mutex);
        // Re-check: another path may have populated it while we were off-lock.
        if (g_cloudBlobByApp.find(appId) != g_cloudBlobByApp.end()) continue;
        g_cloudBlobByApp[appId] = legacy;
        g_accountBlobDirty = true;
        LOG("[Stats] Migrated legacy per-app blob for app %u (forever=%u)",
            appId, parsed.playtime.minutesForever);
    }
}

// Parse the first-format playtime JSON ({"LastPlayed","Playtime","Playtime2wks"}).
static bool ParseLegacyPlaytimeBin(const std::string& content, uint32_t& mins,
                                   uint32_t& lastPlayed, uint32_t& twoWks) {
    Json::Value root = Json::Parse(content);
    if (root.type != Json::Type::Object) return false;
    mins = lastPlayed = twoWks = 0;
    try { mins       = (uint32_t)std::stoul(root["Playtime"].str()); } catch (...) {}
    try { lastPlayed = (uint32_t)std::stoul(root["LastPlayed"].str()); } catch (...) {}
    try { twoWks     = (uint32_t)std::stoul(root["Playtime2wks"].str()); } catch (...) {}
    return true;
}

// Fold legacy playtime (shortfall above existing buckets). No g_mutex.
static void ApplyLegacyPlaytime(uint32_t appId, uint32_t mins,
                                uint32_t lastPlayed, uint32_t twoWks) {
    static const std::string kMigratedBucket = "__migrated_localconfig";
    if (mins == 0) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    AppStats& stats = GetOrCreateLocked(appId);

    // Total already represented by every bucket OTHER than the migrated one.
    // Includes other platforms' fields from the migrated bucket to prevent double-counting.
    uint64_t otherTotal = 0;
    for (const auto& [dev, dp] : stats.playtime.perDevice) {
        if (dev == kMigratedBucket) {
#ifdef _WIN32
            otherTotal += (uint64_t)dp.mac + dp.lin;
#elif defined(__APPLE__)
            otherTotal += (uint64_t)dp.windows + dp.lin;
#else
            otherTotal += (uint64_t)dp.windows + dp.mac;
#endif
        } else {
            otherTotal += (uint64_t)dp.windows + dp.mac + dp.lin;
        }
    }
    // Only the part of the .bin total not already covered elsewhere.
    uint32_t shortfall = (mins > otherTotal) ? (uint32_t)(mins - otherTotal) : 0u;

    DevicePlaytime& mig = stats.playtime.perDevice[kMigratedBucket];
    // Set the bucket to the shortfall (recomputed each run, not a running max) so the
    // v2 repair can shrink a previously double-counted bucket (402 -> 0).
#ifdef _WIN32
    mig.windows = shortfall;
#elif defined(__APPLE__)
    mig.mac = shortfall;
#else
    mig.lin = shortfall;
#endif
    stats.playtime.minutesLastTwoWeeks =
        (std::max)(stats.playtime.minutesLastTwoWeeks, twoWks);
    if (lastPlayed > stats.playtime.lastPlayedTime)
        stats.playtime.lastPlayedTime = lastPlayed;
    RecomputePlaytimeTotals(stats.playtime, /*allowShrink=*/true);
    g_dirty[appId] = true;
    // bypassDiskMerge: this write must be allowed to shrink __migrated_localconfig.
    WriteAppStats(appId, stats, true, /*bypassDiskMerge=*/true);
    LOG("[Stats] Migrated legacy playtime app %u: .bin=%u, other=%llu -> +%u (forever now %u)",
        appId, mins, (unsigned long long)otherTotal, shortfall, stats.playtime.minutesForever);
}

// Migrate 2.2.x Playtime/*.bin format. Done-marker prevents reruns.
static void MigrateLegacyPlaytimeBins(const std::vector<uint32_t>& appIds) {
    std::error_code ec;

    // Pass 1: global marker for local scan. Pass 2: per-app markers for cloud.
    fs::path donePath = FileUtil::Utf8ToPath(g_storageRoot) / ".legacy_playtime_migrated_v2";
    fs::path cloudMarkerDir = FileUtil::Utf8ToPath(g_storageRoot) / ".legacy_pt_cloud_v2";
    bool pass1Done = fs::exists(donePath, ec);

    // Pass 1: local .bin files (fast, no network). Only process the CURRENT
    // account's directory to avoid cross-account contamination.
    if (!pass1Done && !g_cloudRoot.empty()) {
        uint32_t currentAcct = g_accountIdProvider ? g_accountIdProvider() : 0;
        if (currentAcct != 0) {
            fs::path ptDir = FileUtil::Utf8ToPath(g_cloudRoot) / "storage"
                / std::to_string(currentAcct) / "0" / "Playtime";
            if (fs::exists(ptDir, ec)) {
                for (auto& entry : fs::directory_iterator(ptDir, ec)) {
                    if (!entry.is_regular_file()) continue;
                    const std::string fn = entry.path().filename().string();
                    bool isBin = entry.path().extension() == ".bin";
                    bool isV1  = fn.size() > 13 &&
                                 fn.compare(fn.size() - 13, 13, ".bin.migrated") == 0;
                    if (!isBin && !isV1) continue;
                    std::string num = fn.substr(0, fn.find('.'));
                    uint32_t appId = 0;
                    try { appId = (uint32_t)std::stoul(num); } catch (...) {}
                    if (appId == 0) continue;
                    std::ifstream f(entry.path());
                    if (!f.good()) continue;
                    std::string content((std::istreambuf_iterator<char>(f)),
                                        std::istreambuf_iterator<char>());
                    f.close();
                    uint32_t mins, lastPlayed, twoWks;
                    if (ParseLegacyPlaytimeBin(content, mins, lastPlayed, twoWks))
                        ApplyLegacyPlaytime(appId, mins, lastPlayed, twoWks);
                    std::error_code renEc;
                    fs::path v2 = ptDir / (num + ".bin.migrated.v2");
                    fs::rename(entry.path(), v2, renEc);
                }
            }
        }
    }

    // Mark pass 1 done so the whole-disk scan never repeats.
    if (!pass1Done)
        std::ofstream(donePath.string(), std::ios::trunc) << "1";

    // Pass 2: cloud copies (the .bin may exist only in the cloud). Per-app guarded:
    // skip apps already recovered, retry the rest. Max-merge prefers higher local/cloud.
    CloudPullLegacyPlaytimeFn pullPt;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        pullPt = g_cloudPullLegacyPlaytime;
    }
    if (!pullPt) return;
    ec.clear();   // ec was threaded through pass-1 fs calls; only trust it fresh
    fs::create_directories(cloudMarkerDir, ec);
    if (ec) {
        // Can't persist per-app counters -> a sync network pull would run every
        // launch with no way to give up. Bail rather than spin.
        LOG("[Stats] legacy pt cloud marker dir unavailable (%s); skipping cloud pass",
            ec.message().c_str());
        return;
    }
    // Marker contents: "done" once recovered/given up; a number = empty-pull attempts
    // so far (retry next launch). After kMaxTries empties we stop -- the format is
    // frozen, so a missing bin won't appear.
    static const int kMaxTries = 8;
    for (uint32_t appId : appIds) {
        if (appId == 0) continue;
        fs::path mk = cloudMarkerDir / std::to_string(appId);
        int tries = 0;
        {
            std::ifstream mf(mk);
            if (mf.good()) {
                std::string s((std::istreambuf_iterator<char>(mf)),
                              std::istreambuf_iterator<char>());
                if (s == "done") continue;          // recovered or exhausted
                try { tries = std::stoi(s); } catch (...) {}
            }
        }
        std::string json = pullPt(appId);          // network, off-lock
        if (json.empty()) {
            if (++tries >= kMaxTries)
                std::ofstream(mk.string(), std::ios::trunc) << "done";  // give up
            else
                std::ofstream(mk.string(), std::ios::trunc) << tries;   // retry later
            continue;
        }
        uint32_t mins, lastPlayed, twoWks;
        if (ParseLegacyPlaytimeBin(json, mins, lastPlayed, twoWks))
            ApplyLegacyPlaytime(appId, mins, lastPlayed, twoWks);
        std::ofstream(mk.string(), std::ios::trunc) << "done";          // recovered
        LOG("[Stats] Cloud legacy playtime recovered app %u (%u min)", appId, mins);
    }
}

void SeedApps(const std::vector<uint32_t>& appIds) {
    // Wait for g_diskAccountId so disk I/O is account-scoped (bg thread, safe to block).
    if (g_diskAccountId == 0) {
        uint32_t acct = 0;
        for (int i = 0; i < 60; ++i) {
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                if (g_accountIdProvider) acct = g_accountIdProvider();
            }
            if (acct != 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        if (acct == 0) {
            LOG("[Stats] SeedApps: no accountId after 30 s, aborting");
            g_seedDone.store(true, std::memory_order_release);
            g_seedCv.notify_all();
            return;
        }
        ResetForAccountSwitch(acct);
    }
    // Reconcile playtime from localconfig.vdf for the CURRENT account only.
    // Deferred from Init (where accountId is unknown) to here (post-login).
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ReconcileLocalConfig(g_cloudRoot, g_steamPath);
    }
    // One network read for the whole account, not one per app. GetOrCreate then
    // reads each app's entry from the cached blob (no further network).
    RefreshCloudBlobCache();
    // Recover stats stranded under the old per-app cloud layout.
    MigrateLegacyBlobs(appIds);
    // Recover playtime from the very first 2.2.x per-app .bin format (local+cloud).
    MigrateLegacyPlaytimeBins(appIds);
    for (uint32_t appId : appIds) {
        if (appId == 0) continue;
        GetOrCreate(appId);  // merges cached cloud blob + imports native + loads local
    }
    // Write .bin files for SLSsteam's NO_CONNECTION fallback.
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (uint32_t appId : appIds) {
            if (appId == 0) continue;
            auto it = g_cache.find(appId);
            if (it != g_cache.end())
                ExportNativeStats(appId, it->second);
        }
    }
    // SeedApps also materializes imported native stats; flush the account blob
    // once so newly-seeded local stats reach the cloud.
    PushAccountBlobIfDirty();

    // Signal waiters (HandleGetUserStats blocks until seed completes).
    g_seedDone.store(true, std::memory_order_release);
    g_seedCv.notify_all();
    LOG("[Stats] SeedApps complete (%zu app(s)); waiters released", appIds.size());
}

bool WaitForSeed(uint32_t timeoutMs) {
    if (g_seedDone.load(std::memory_order_acquire)) return true;
    std::unique_lock<std::mutex> lock(g_seedMutex);
    return g_seedCv.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                             [] { return g_seedDone.load(std::memory_order_acquire); });
}

void RetryNativeImportsAfterLogin() {
    // Needs a resolved accountId; the whole point is to run AFTER login so the
    // import that the boot-time sweep skipped (accountReady=0) can succeed.
    std::string steamPath;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_accountIdProvider || g_accountIdProvider() == 0) {
            LOG("[Stats] RetryNativeImports: accountId not ready, skipping");
            return;
        }
        if (g_steamPath.empty() || !g_isNamespaceApp) {
            LOG("[Stats] RetryNativeImports: steamPath/namespace predicate unset, skipping");
            return;
        }
        steamPath = g_steamPath;
    }

    // Enumerate native schema blobs: appcache/stats/UserGameStatsSchema_<appId>.bin.
    // Each such app has a schema on disk; a namespace app among them that never
    // imported (boot sweep ran pre-login) is exactly what we want to retry.
    std::error_code ec;
    fs::path statsDir = FileUtil::Utf8ToPath(steamPath) / "appcache" / "stats";
    if (!fs::is_directory(statsDir, ec)) {
        LOG("[Stats] RetryNativeImports: %s not a directory, skipping", statsDir.string().c_str());
        return;
    }

    const std::string kPrefix = "UserGameStatsSchema_";
    int considered = 0, imported = 0;
    for (const auto& entry : fs::directory_iterator(statsDir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec)) continue;
        std::string fname = entry.path().filename().string();
        if (fname.rfind(kPrefix, 0) != 0) continue;
        // Strip prefix and ".bin" suffix to recover the appId.
        size_t dot = fname.rfind(".bin");
        if (dot == std::string::npos || dot <= kPrefix.size()) continue;
        std::string idStr = fname.substr(kPrefix.size(), dot - kPrefix.size());
        if (idStr.empty()) continue;
        uint32_t appId = 0;
        bool numeric = true;
        for (char c : idStr) {
            if (c < '0' || c > '9') { numeric = false; break; }
            appId = appId * 10 + (uint32_t)(c - '0');
        }
        if (!numeric || appId == 0) continue;
        if (!g_isNamespaceApp(appId)) continue;
        ++considered;
        // Sample emptiness before/after the import under one lock hold so only an
        // empty->populated transition counts as a genuine new import.
        std::lock_guard<std::mutex> lock(g_mutex);
        auto preIt = g_cache.find(appId);
        bool hadData = preIt != g_cache.end() &&
                       (!preIt->second.stats.empty() || !preIt->second.schema.empty());
        AppStats& s = GetOrCreateLocked(appId);
        bool hasData = !s.stats.empty() || !s.schema.empty();
        if (!hadData && hasData) ++imported;
    }
    LOG("[Stats] RetryNativeImports: considered %d namespace app(s) with schema, %d have data",
        considered, imported);
    // Deliberately NO PushAccountBlobIfDirty() here: the sweep only flags dirty;
    // the next natural push (unlock capture / EndSession / FlushAll) uploads.
}

std::vector<uint32_t> RefreshFromCloud(const std::vector<uint32_t>& appIds) {
    std::vector<uint32_t> changed;
    // One network read for the whole account, then iterate from the cache.
    if (!RefreshCloudBlobCache()) return changed;
    for (uint32_t appId : appIds) {
        if (appId == 0) continue;

        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_resetApps.count(appId)) continue;
        AppStats cloudStats;
        std::string cloud = CloudJsonForAppLocked(appId);
        if (cloud.empty() || !ParseAppStatsJson(cloud, cloudStats)) continue;
        // Hydrate from disk first -- operator[] would default-construct empty and wipe on push.
        auto cacheIt = g_cache.find(appId);
        if (cacheIt == g_cache.end()) {
            // Hydrate from DISK only -- the cloud blob is already in `cloudStats`
            // and is merged below. LoadAppStats would do a second network pull
            // while holding g_mutex, stalling game-facing store calls.
            AppStats fresh;
            LoadAppStatsLocalOnly(appId, fresh);
            cacheIt = g_cache.emplace(appId, std::move(fresh)).first;
        }
        AppStats& cur = cacheIt->second;

        PlaytimeData before = cur.playtime;
        MergePlaytime(cur.playtime, cloudStats.playtime);
        // Achievements/stats are monotonic across devices -- union-merge them too,
        // not just playtime, or a cloud unlock is dropped and the next local push
        // overwrites it on the cloud.
        bool achChanged = MergeAchievements(cur.achievements, cloudStats.achievements);
        bool statChanged = MergeStatValues(cur.stats, cloudStats.stats);
        if (ReconcileAchievementBits(cur.stats, cur.achievements)) { achChanged = true; statChanged = true; }
        bool playtimeChanged = (cur.playtime.minutesForever != before.minutesForever ||
                                cur.playtime.lastPlayedTime != before.lastPlayedTime);
        // Another device advanced this app -> persist locally and report.
        if (playtimeChanged || achChanged || statChanged) {
            // The crc is the sync token Steam echoes; recompute it when the data
            // changed or it stops matching what we serve.
            if (achChanged || statChanged)
                cur.crcStats = ComputeCrcLocked(cur);
            WriteAppStats(appId, cur, false);
            if (achChanged || statChanged)
                ExportNativeStats(appId, cur);
            changed.push_back(appId);
            LOG("[Stats] Cloud advanced app %u: forever %u -> %u (win=%u mac=%u linux=%u) ach=%d stat=%d",
                appId, before.minutesForever, cur.playtime.minutesForever,
                cur.playtime.playtimeWindows, cur.playtime.playtimeMac,
                cur.playtime.playtimeLinux, achChanged ? 1 : 0, statChanged ? 1 : 0);
        }
    }
    return changed;
}

// Deterministic CRC over stats + achievements (opaque sync token; client echoes it verbatim).
static void AppendU32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(v & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >> 24) & 0xFF);
}

uint32_t ComputeCrcLocked(const AppStats& stats) {
    // Sort stat ids so insertion order can't change the token.
    std::vector<const StatEntry*> sortedStats;
    sortedStats.reserve(stats.stats.size());
    for (auto& s : stats.stats) sortedStats.push_back(&s);
    std::sort(sortedStats.begin(), sortedStats.end(),
              [](const StatEntry* a, const StatEntry* b) { return a->statId < b->statId; });

    std::vector<uint8_t> buf;
    for (auto* s : sortedStats) {
        AppendU32(buf, s->statId);
        AppendU32(buf, s->value);
    }

    // Fold achievement unlock times (sorted by statId, then bit).
    std::vector<const AchievementBlock*> sortedAch;
    sortedAch.reserve(stats.achievements.size());
    for (auto& a : stats.achievements) sortedAch.push_back(&a);
    std::sort(sortedAch.begin(), sortedAch.end(),
              [](const AchievementBlock* a, const AchievementBlock* b) { return a->statId < b->statId; });
    for (auto* a : sortedAch) {
        AppendU32(buf, a->statId);
        AppendU32(buf, a->bits);
        for (int bit = 0; bit < 32; ++bit)
            if (a->unlockTimes[bit]) { AppendU32(buf, (uint32_t)bit); AppendU32(buf, a->unlockTimes[bit]); }
    }

    return buf.empty() ? 0 : Crc32(buf.data(), buf.size());
}

uint32_t SetStat(uint32_t appId, uint32_t statId, uint32_t value) {
    std::lock_guard<std::mutex> lock(g_mutex);
    // Seed before mutating, else a first-touch Set builds a near-empty record the
    // push would publish over cross-device data.
    AppStats& stats = GetOrCreateLocked(appId);

    bool found = false;
    for (auto& s : stats.stats) {
        if (s.statId == statId) {
            s.value = value;
            found = true;
            break;
        }
    }
    if (!found) {
        stats.stats.push_back({statId, value});
    }

    g_dirty[appId] = true;
    stats.crcStats = ComputeCrcLocked(stats);
    return stats.crcStats;
}

uint32_t SetStats(uint32_t appId, const std::vector<StatEntry>& entries) {
    std::lock_guard<std::mutex> lock(g_mutex);
    AppStats& stats = GetOrCreateLocked(appId);   // seed before mutate+push

    for (auto& e : entries) {
        bool found = false;
        for (auto& s : stats.stats) {
            if (s.statId == e.statId) {
                s.value = e.value;
                found = true;
                break;
            }
        }
        if (!found) {
            stats.stats.push_back(e);
        }
    }

    g_dirty[appId] = true;
    stats.crcStats = ComputeCrcLocked(stats);
    return stats.crcStats;
}

uint32_t SetAchievement(uint32_t appId, uint32_t statId, uint32_t bit, uint32_t unlockTime) {
    std::lock_guard<std::mutex> lock(g_mutex);
    AppStats& stats = GetOrCreateLocked(appId);   // seed before mutate+push

    AchievementBlock* blk = nullptr;
    for (auto& a : stats.achievements) {
        if (a.statId == statId) { blk = &a; break; }
    }
    if (!blk) {
        stats.achievements.push_back({});
        blk = &stats.achievements.back();
        blk->statId = statId;
        blk->bits = 0;
        memset(blk->unlockTimes, 0, sizeof(blk->unlockTimes));
    }

    if (bit < 32) {
        blk->bits |= (1u << bit);
        blk->unlockTimes[bit] = unlockTime;
    }

    g_dirty[appId] = true;
    stats.crcStats = ComputeCrcLocked(stats);
    return stats.crcStats;
}

void SetSchema(uint32_t appId, const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(g_mutex);
    AppStats& stats = GetOrCreateLocked(appId);   // seed before mutate+push
    stats.schema.assign(data, data + len);
    g_dirty[appId] = true;
}

std::vector<uint8_t> GetSchema(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return GetOrCreateLocked(appId).schema;  // seed; returns by-value under lock
}

static bool EndSessionLocked(uint32_t appId);

void StartSession(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    // Flush any open session first: native Steam resumes the existing per-app
    // timer rather than re-arming, so a duplicate GamesPlayed can't drop minutes.
    EndSessionLocked(appId);
    g_activeSessions[appId] = NowUnix();
    AppStats& stats = GetOrCreateLocked(appId);   // seed before mutate+push
    stats.playtime.lastPlayedTime = NowUnix();
    g_dirty[appId] = true;
    LOG("[Stats] Session started for app %u", appId);
}

// Accrue + persist the in-flight session for `appId`, erasing it from
// g_activeSessions. Caller holds g_mutex. Returns false if no session was open.
// Shared by EndSession and the re-entrant-StartSession flush.
static bool EndSessionLocked(uint32_t appId) {
    auto it = g_activeSessions.find(appId);
    if (it == g_activeSessions.end()) return false;

    uint32_t now = NowUnix();
    uint32_t elapsed = (now > it->second) ? (now - it->second) : 0;
    // Wall-clock sanity cap: a forward clock jump (NTP correction, suspend/
    // resume) must not over-count a session. Backward jumps already clamp to 0.
    const uint32_t kMaxSessionSecs = 24u * 60 * 60;
    if (elapsed > kMaxSessionSecs) elapsed = kMaxSessionSecs;
    uint32_t minutes = elapsed / 60;
    g_activeSessions.erase(it);

    // Seed first so the cloud blob's cross-device unlocks are in the record we
    // build+push (else EndSession drops another device's achievements).
    AppStats& stats = GetOrCreateLocked(appId);
    // Accrue onto THIS device's own per-device sub-total (keyed by device id), so
    // a session here can never overwrite another device's contribution -- even a
    // same-platform device's -- under the last-writer-wins cloud blob.
    AccrueLocalPlaytime(stats.playtime, minutes);
    // Do NOT accumulate minutesLastTwoWeeks: native Steam reads Playtime2wks as an
    // authoritative stored VDF field, surfaced via ReconcileLocalConfig.
    stats.playtime.lastPlayedTime = now;

    // Steam flushes the native blob on game close; merge any new unlocks (also
    // catches another device's). Gated on sync_achievements, not sync_playtime
    // (EndSession runs under the latter).
    if (MetadataSync::syncAchievements.load(std::memory_order_relaxed) &&
        ReimportNativeStatsLocked(appId, stats))
        LOG("[Stats] Session end: merged new native achievements/stats for app %u (crc=%u)",
            appId, stats.crcStats);

    g_dirty[appId] = true;
    SaveAppStats(appId, stats);   // updates account blob + dirty flag
    g_dirty[appId] = false;
    ExportNativeStats(appId, stats);
    LOG("[Stats] Session ended for app %u: +%u min (total %u)",
        appId, minutes, stats.playtime.minutesForever);
    return true;
}

void EndSession(uint32_t appId) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!EndSessionLocked(appId)) return;
    }
    // Push the account blob off-lock (the platform pushAll queues it async, so
    // this never blocks the net thread at game close).
    PushAccountBlobIfDirty();
}

PlaytimeData GetPlaytime(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    AppStats& stats = GetOrCreateLocked(appId);   // seed before read
    PlaytimeData pt = stats.playtime;

    auto it = g_activeSessions.find(appId);
    if (it != g_activeSessions.end()) {
        uint32_t now = NowUnix();
        uint32_t elapsed = (now > it->second) ? (now - it->second) : 0;
        // Wall-clock sanity cap, matching EndSession: a forward clock jump must not
        // over-count the in-progress session's live playtime estimate.
        const uint32_t kMaxSessionSecs = 24u * 60 * 60;
        if (elapsed > kMaxSessionSecs) elapsed = kMaxSessionSecs;
        uint32_t minutes = elapsed / 60;
        pt.minutesForever += minutes;
        pt.minutesLastTwoWeeks += minutes;
#ifdef _WIN32
        pt.playtimeWindows += minutes;
#elif defined(__APPLE__)
        pt.playtimeMac += minutes;
#else
        pt.playtimeLinux += minutes;
#endif
    }
    return pt;
}

uint32_t GetDiskAccountId() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_diskAccountId;
}

std::vector<uint32_t> GetTrackedApps() {
    std::lock_guard<std::mutex> lock(g_mutex);
    std::vector<uint32_t> out;
    out.reserve(g_cache.size());
    for (const auto& [appId, stats] : g_cache) {
        if (stats.playtime.minutesForever > 0 || stats.playtime.lastPlayedTime > 0)
            out.push_back(appId);
    }
    return out;
}

std::unordered_set<uint32_t> ConsumeResetApps() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return std::move(g_resetApps);
}

void FlushAll() {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        int flushed = 0;
        for (auto& [appId, dirty] : g_dirty) {
            if (dirty) {
                auto it = g_cache.find(appId);
                if (it != g_cache.end())
                    SaveAppStats(appId, it->second);
                dirty = false;
                flushed++;
            }
        }
        if (flushed)
            LOG("[Stats] Flushed %d app(s) to disk", flushed);
    }
    // Push the account blob once for all flushed apps (outside the lock).
    PushAccountBlobIfDirty();
}

} // namespace StatsStore
