#include "stats_store.h"
#include "json.h"
#include "vdf.h"
#include "log.h"
#include "file_util.h"

#include <fstream>
#include <sstream>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <cstring>

namespace fs = std::filesystem;

namespace StatsStore {

static std::string g_storageRoot;
static std::string g_steamPath;   // e.g. "C:\Games\Steam\" (used to locate native blobs)
static std::mutex g_mutex;

// Forward decl: deterministic CRC over an AppStats (caller holds g_mutex).
uint32_t ComputeCrcLocked(const AppStats& stats);
static std::unordered_map<uint32_t, AppStats> g_cache;
static std::unordered_map<uint32_t, bool> g_dirty;

// Cloud-backing provider (installed by the platform layer; see SetCloudProvider).
static CloudPullFn g_cloudPull;
static CloudPushFn g_cloudPush;

// Resolves the current Steam accountId for locating native UserGameStats blobs.
static AccountIdProvider g_accountIdProvider;
// Fired when an import finds no schema for an app (platform requests it).
static SchemaMissingCallback g_schemaMissingCb;
// True for apps we manage; reconcile seeds their playtime from localconfig.vdf.
static NamespacePredicate g_isNamespaceApp;

// Persist to disk; pushCloud=false writes locally only (used by startup reconcile).
static void WriteAppStats(uint32_t appId, const AppStats& stats, bool pushCloud);

void SetCloudProvider(CloudPullFn pull, CloudPushFn push) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_cloudPull = std::move(pull);
    g_cloudPush = std::move(push);
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
// Steam stores per-user stats as a binary-KV tree in
//   appcache\stats\UserGameStats_<accountId>_<appId>.bin
// Tree shape:
//   cache (SECTION)
//     ├── crc (INT)            -- Steam's own token (we recompute our own)
//     ├── PendingChanges (INT)
//     └── <statId> (SECTION)   -- decimal-string name
//           ├── data (INT/FLOAT/UINT64/INT64)   -- stat value (achievement: bitfield)
//           └── AchievementTimes (SECTION)       -- optional
//                 └── <bit> (INT)  -- unlock unix timestamp per bit index
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

// Build a (statId,bit) -> human-readable achievement name map from the parsed
// schema BKV tree. Schema shape:
//   <appId> (SECTION)
//     stats (SECTION)
//       <statId> (SECTION)
//         bits (SECTION)
//           <bit> (SECTION)
//             name "ACHIEVEMENT_x"            (api name, fallback)
//             display (SECTION) > name (SECTION) > english "Human Name"
// Prefers the English display name; falls back to the api name.
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

} // namespace

// Active play sessions: appId -> session start (unix time)
static std::unordered_map<uint32_t, uint32_t> g_activeSessions;

static uint32_t NowUnix() {
    return (uint32_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string StatsPath(uint32_t appId) {
    return g_storageRoot + "/" + std::to_string(appId) + ".json";
}

static std::string SchemaPath(uint32_t appId) {
    return g_storageRoot + "/schemas/" + std::to_string(appId) + ".bin";
}

// Simple CRC32 over stat id/value pairs
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

// Reconcile playtime from Steam's localconfig.vdf.
// Steam writes Playtime/Playtime2wks/LastPlayed under
//   UserLocalConfigStore > Software > Valve > Steam > Apps > {appid}
// If localconfig has more playtime than our stats JSON, update ours.
// This catches sessions where the user played without CloudRedirect loaded.
static void ReconcileLocalConfig(const std::string& cloudRoot, const std::string& steamPath) {
    std::error_code ec;
    fs::path userdataDir = fs::path(steamPath) / "userdata";
    if (!fs::exists(userdataDir, ec)) return;

    // Only reconcile accounts that have storage in our cloud_redirect directory
    fs::path storageDir = fs::path(cloudRoot) / "storage";
    std::vector<std::string> ourAccounts;
    if (fs::exists(storageDir, ec)) {
        for (auto& entry : fs::directory_iterator(storageDir, ec)) {
            if (entry.is_directory())
                ourAccounts.push_back(entry.path().filename().string());
        }
    }
    if (ourAccounts.empty()) return;

    int reconciled = 0;
    for (auto& acctId : ourAccounts) {
        fs::path acctDir = userdataDir / acctId;
        if (!fs::is_directory(acctDir, ec)) continue;

        fs::path lcPath = acctDir / "config" / "localconfig.vdf";
        if (!fs::exists(lcPath, ec)) continue;

        std::ifstream f(lcPath);
        if (!f.good()) continue;
        std::string vdf((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
        f.close();
        if (vdf.empty()) continue;

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
                continue;
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
            LOG("[Stats] Reconcile: considering app %u (ns=1)", appId);

            // localconfig "Apps\<id>\Playtime" is the server's cross-platform total
            // (sub_1389C7930 -> sub_1389CB7D0 writes it from GetLastPlayedTimes
            // response field 4), not this machine's minutes -- and we write it
            // ourselves by answering those RPCs. So take only LastPlayed (a display
            // hint) here; per-platform fields are owned by EndSession.
            std::string appIdStr = std::to_string(appId);
            const char* appPath[] = {"UserLocalConfigStore", "Software", "Valve", "Steam", appsKey, appIdStr.c_str()};
            uint32_t vdfLastPlayed = 0;

            VdfUtil::ForEachFieldInSection(vdf, appPath, 6, [&](const VdfUtil::FieldInfo& fi) -> bool {
                if (fi.key == "LastPlayed")
                    try { vdfLastPlayed = (uint32_t)std::stoul(std::string(fi.value)); } catch (...) {}
                return true;
            });
            if (vdfLastPlayed == 0) return true;

            auto cacheIt = g_cache.find(appId);
            if (cacheIt == g_cache.end()) {
                LoadAppStats(appId, g_cache[appId]);
                cacheIt = g_cache.find(appId);
            }
            AppStats& stats = cacheIt->second;

            if (vdfLastPlayed <= stats.playtime.lastPlayedTime) return true;
            stats.playtime.lastPlayedTime = vdfLastPlayed;

            // Local-only persist: startup reconcile must not push to the cloud.
            WriteAppStats(appId, stats, false);
            reconciled++;
            LOG("[Stats] Reconciled app %u lastPlayed=%u (playtime owned by session tracking: win=%u mac=%u linux=%u)",
                appId, vdfLastPlayed,
                stats.playtime.playtimeWindows, stats.playtime.playtimeMac,
                stats.playtime.playtimeLinux);
            return true;
        });
    }
    if (reconciled > 0) {
        LOG("[Stats] Reconciled %d apps from localconfig.vdf", reconciled);
    }
}

void Init(const std::string& storageRoot, const std::string& steamPath) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_storageRoot = storageRoot + "/stats";
    g_steamPath = steamPath;
    fs::create_directories(g_storageRoot);
    fs::create_directories(g_storageRoot + "/schemas");

    ReconcileLocalConfig(storageRoot, steamPath);

    LOG("[Stats] Store initialized at %s", g_storageRoot.c_str());
}

// Import Steam's native UserGameStats + schema blobs for an app into `out`.
// Returns true if real stat data was imported. Used to seed our authoritative
// store on first access (so we can answer GetUserStats with real data).
// Caller must hold g_mutex (reads g_steamPath / g_accountIdProvider).
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
        // No schema on disk -> ask the platform to fetch it from Steam's server
        // (so achievement names become available on the next import).
        if (out.schema.empty() && g_schemaMissingCb)
            g_schemaMissingCb(appId);
    }

    // Stats: appcache/stats/UserGameStats_<accountId>_<appId>.bin
    fs::path statsPath = FileUtil::Utf8ToPath(g_steamPath) / "appcache" / "stats"
        / ("UserGameStats_" + std::to_string(accountId) + "_" + std::to_string(appId) + ".bin");
    std::ifstream f(statsPath, std::ios::binary);
    if (!f.good()) return false;
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());
    f.close();
    if (blob.empty()) return false;

    size_t pos = 0, nodeCount = 0;
    std::vector<BkvNode> root;
    if (!BkvRead(blob.data(), blob.size(), pos, root, 0, nodeCount)) {
        LOG("[Stats] ImportNativeStats app=%u: BKV parse failed (%zu bytes)", appId, blob.size());
        return false;
    }

    const BkvNode* cache = BkvFind(root, "cache");
    if (!cache) return false;

    // Parse the schema (if present) for human-readable achievement names.
    std::unordered_map<uint64_t, std::string> achNames;
    if (!out.schema.empty()) {
        size_t spos = 0, snodes = 0;
        std::vector<BkvNode> sroot;
        if (BkvRead(out.schema.data(), out.schema.size(), spos, sroot, 0, snodes))
            achNames = ParseSchemaAchievementNames(sroot);
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

        out.stats.push_back(StatEntry{statId, value});
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

    LOG("[Stats] ImportNativeStats app=%u: imported %zu stat(s), %zu achievement block(s), schema=%zu bytes",
        appId, importedStats, importedAch, out.schema.size());
    return importedStats > 0;
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

    const auto& pt = root["playtime"];
    if (pt.type == Json::Type::Object) {
        out.playtime.minutesForever = (uint32_t)pt["minutes_forever"].integer();
        out.playtime.minutesLastTwoWeeks = (uint32_t)pt["minutes_2weeks"].integer();
        out.playtime.lastPlayedTime = (uint32_t)pt["last_played"].integer();
        out.playtime.playtimeWindows = (uint32_t)pt["windows"].integer();
        out.playtime.playtimeMac = (uint32_t)pt["mac"].integer();
        out.playtime.playtimeLinux = (uint32_t)pt["linux"].integer();
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
    root.objVal["playtime"] = std::move(pt);

    return Json::Stringify(root);
}

// Max-merge each platform's forever field (the total is their sum), so a stale
// local or older cloud blob can't regress another device's time.
static void MergePlaytime(PlaytimeData& dst, const PlaytimeData& src) {
    dst.playtimeWindows = (std::max)(dst.playtimeWindows, src.playtimeWindows);
    dst.playtimeMac     = (std::max)(dst.playtimeMac,     src.playtimeMac);
    dst.playtimeLinux   = (std::max)(dst.playtimeLinux,   src.playtimeLinux);
    dst.minutesLastTwoWeeks = (std::max)(dst.minutesLastTwoWeeks, src.minutesLastTwoWeeks);
    dst.lastPlayedTime  = (std::max)(dst.lastPlayedTime,  src.lastPlayedTime);
    dst.minutesForever  = dst.playtimeWindows + dst.playtimeMac + dst.playtimeLinux;
}

// Union-merge achievements: an unlock is monotonic, so a bit stays unlocked if
// either side has it. The existing unlock timestamp wins (so a re-import can't
// rewrite an earlier unlock, including one another device recorded); native fills
// bits we don't yet hold. Names are adopted from src when we lack them. Returns
// true if dst changed.
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

// Merge the latest stat values from src into dst (this device's native stats are
// authoritative for their own values). Returns true if dst changed.
static bool MergeStatValues(std::vector<StatEntry>& dst,
                            const std::vector<StatEntry>& src) {
    bool changed = false;
    for (const auto& s : src) {
        bool found = false;
        for (auto& d : dst) {
            if (d.statId == s.statId) {
                if (d.value != s.value) { d.value = s.value; changed = true; }
                found = true;
                break;
            }
        }
        if (!found) { dst.push_back(s); changed = true; }
    }
    return changed;
}

bool LoadAppStats(uint32_t appId, AppStats& out) {
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

    // Always consult the cloud and merge per-platform: a local copy from a
    // prior session must not hide another device's playtime in the cloud.
    std::string cloud;
    if (g_cloudPull && g_cloudPull(appId, cloud) && !cloud.empty()) {
        AppStats cloudStats;
        if (ParseAppStatsJson(cloud, cloudStats)) {
            if (!haveLocal) {
                out = std::move(cloudStats);
                haveLocal = true;
            } else {
                MergePlaytime(out.playtime, cloudStats.playtime);
                // Adopt cloud achievements/stats/schema when we hold none.
                if (out.stats.empty() && !cloudStats.stats.empty())
                    out.stats = std::move(cloudStats.stats);
                if (out.achievements.empty() && !cloudStats.achievements.empty())
                    out.achievements = std::move(cloudStats.achievements);
                if (out.schema.empty() && !cloudStats.schema.empty())
                    out.schema = std::move(cloudStats.schema);
            }
            // Materialize the merged result locally for fast subsequent reads.
            WriteAppStats(appId, out, false);
            LOG("[Stats] Merged app %u with cloud blob (forever=%u win=%u mac=%u linux=%u)",
                appId, out.playtime.minutesForever, out.playtime.playtimeWindows,
                out.playtime.playtimeMac, out.playtime.playtimeLinux);
        }
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
static void WriteAppStats(uint32_t appId, const AppStats& stats, bool pushCloud) {
    std::string path = StatsPath(appId);
    std::string json = BuildAppStatsJson(stats);

    std::ofstream f(path, std::ios::trunc);
    f << json;
    f.close();

    if (!stats.schema.empty()) {
        std::string schemaPath = SchemaPath(appId);
        std::ofstream sf(schemaPath, std::ios::binary | std::ios::trunc);
        sf.write(reinterpret_cast<const char*>(stats.schema.data()), stats.schema.size());
    }

    if (pushCloud && g_cloudPush) g_cloudPush(appId, json);
}

void SaveAppStats(uint32_t appId, const AppStats& stats) {
    WriteAppStats(appId, stats, true);
}

// Apps for which native import has been successfully attempted (imported real
// data OR confirmed Steam genuinely has none). Distinct from a cache entry,
// because reconcile/session-tracking can create an empty cache entry before any
// import runs -- we must still import on first stats access in that case.
static std::unordered_map<uint32_t, bool> g_importAttempted;

// Seed `stats` from Steam's native UserGameStats blob if we hold no stat data
// yet. Retries across calls while accountId is unavailable (returns 0); only
// marks "attempted" once we had a real accountId to look with. Caller holds mutex.
static void EnsureNativeImportLocked(uint32_t appId, AppStats& stats) {
    if (!stats.stats.empty()) return;                 // already have data
    if (g_importAttempted.count(appId)) return;        // already tried with a valid acct
    if (!g_accountIdProvider || g_accountIdProvider() == 0) {
        // accountId not ready yet (not logged in) -- don't mark attempted; retry later.
        return;
    }

    AppStats native;
    native.playtime = stats.playtime; // preserve any playtime already loaded
    bool imported = ImportNativeStats(appId, native);
    g_importAttempted[appId] = true; // accountId was valid; this is a definitive attempt
    if (imported) {
        stats.stats = std::move(native.stats);
        stats.achievements = std::move(native.achievements);
        if (!native.schema.empty()) stats.schema = std::move(native.schema);
        stats.crcStats = ComputeCrcLocked(stats);
        g_dirty[appId] = true;
        SaveAppStats(appId, stats);
    }
}

// Re-read Steam's native blob and merge any newly unlocked achievements / updated
// stat values into the cached store. Unlike EnsureNativeImportLocked this runs
// even when we already hold data -- it is the capture point for unlocks earned
// during a session that has just ended (Steam flushes the blob on game close).
// Merges (never overwrites) so cross-device unlocks survive. Caller holds mutex.
static bool ReimportNativeStatsLocked(uint32_t appId, AppStats& stats) {
    if (!g_accountIdProvider || g_accountIdProvider() == 0) return false;

    AppStats native;
    if (!ImportNativeStats(appId, native)) return false;

    bool changed = MergeStatValues(stats.stats, native.stats);
    if (MergeAchievements(stats.achievements, native.achievements)) changed = true;
    if (stats.schema.empty() && !native.schema.empty()) {
        stats.schema = std::move(native.schema);
        changed = true;
    }
    if (changed) stats.crcStats = ComputeCrcLocked(stats);
    return changed;
}

void CaptureNativeUnlocks(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto& stats = g_cache[appId];
    // Make sure the base data exists (first observation may precede any import).
    if (stats.stats.empty()) EnsureNativeImportLocked(appId, stats);
    if (ReimportNativeStatsLocked(appId, stats)) {
        g_dirty[appId] = true;
        SaveAppStats(appId, stats);   // pushes to cloud
        g_dirty[appId] = false;
        LOG("[Stats] Captured native unlocks for app %u (crc=%u)", appId, stats.crcStats);
    }
}

AppStats& GetOrCreate(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_cache.find(appId);
    if (it != g_cache.end()) {
        // Cache hit, but a reconcile/session path may have created an empty
        // entry before import ran. Ensure native stats are imported on first
        // actual stats access (and on later retries once accountId is ready).
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

void SeedApps(const std::vector<uint32_t>& appIds) {
    for (uint32_t appId : appIds) {
        if (appId == 0) continue;
        GetOrCreate(appId);  // pulls cloud blob + imports native + loads local
    }
}

std::vector<uint32_t> RefreshFromCloud(const std::vector<uint32_t>& appIds) {
    std::vector<uint32_t> changed;
    if (!g_cloudPull) return changed;
    for (uint32_t appId : appIds) {
        if (appId == 0) continue;
        std::string cloud;
        if (!g_cloudPull(appId, cloud) || cloud.empty()) continue;
        AppStats cloudStats;
        if (!ParseAppStatsJson(cloud, cloudStats)) continue;

        std::lock_guard<std::mutex> lock(g_mutex);
        AppStats& cur = g_cache[appId];
        PlaytimeData before = cur.playtime;
        MergePlaytime(cur.playtime, cloudStats.playtime);
        // Another device advanced this app's playtime -> persist locally and report.
        if (cur.playtime.minutesForever != before.minutesForever ||
            cur.playtime.lastPlayedTime != before.lastPlayedTime) {
            WriteAppStats(appId, cur, false);
            changed.push_back(appId);
            LOG("[Stats] Cloud advanced app %u: forever %u -> %u (win=%u mac=%u linux=%u)",
                appId, before.minutesForever, cur.playtime.minutesForever,
                cur.playtime.playtimeWindows, cur.playtime.playtimeMac,
                cur.playtime.playtimeLinux);
        }
    }
    return changed;
}

// Deterministic, order-independent CRC over stat values AND achievement
// unlock state. This is our opaque sync token (per IDA: the client just stores
// and echoes whatever crc we send; it never recomputes). It MUST be stable
// (same data -> same crc) and change when stats/achievements change.
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

uint32_t ComputeCrc(uint32_t appId) {
    return ComputeCrcLocked(g_cache[appId]); // caller holds g_mutex
}

uint32_t SetStat(uint32_t appId, uint32_t statId, uint32_t value) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto& stats = g_cache[appId];

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
    stats.crcStats = ComputeCrc(appId);
    return stats.crcStats;
}

uint32_t SetStats(uint32_t appId, const std::vector<StatEntry>& entries) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto& stats = g_cache[appId];

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
    stats.crcStats = ComputeCrc(appId);
    return stats.crcStats;
}

uint32_t SetAchievement(uint32_t appId, uint32_t statId, uint32_t bit, uint32_t unlockTime) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto& stats = g_cache[appId];

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
    stats.crcStats = ComputeCrc(appId);
    return stats.crcStats;
}

void SetSchema(uint32_t appId, const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto& stats = g_cache[appId];
    stats.schema.assign(data, data + len);
    g_dirty[appId] = true;
}

const std::vector<uint8_t>& GetSchema(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_cache[appId].schema;
}

void StartSession(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_activeSessions[appId] = NowUnix();
    auto& stats = g_cache[appId];
    if (stats.playtime.lastPlayedTime == 0) {
        LoadAppStats(appId, stats);
    }
    // Seed achievements/stats from Steam's native blob too -- not every app gets
    // a GetUserStats RPC, so launching the game is our reliable trigger to import
    // (and then cloud-sync) the real stat/achievement data, not just playtime.
    EnsureNativeImportLocked(appId, stats);
    stats.playtime.lastPlayedTime = NowUnix();
    g_dirty[appId] = true;
    LOG("[Stats] Session started for app %u", appId);
}

void EndSession(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_activeSessions.find(appId);
    if (it == g_activeSessions.end()) return;

    uint32_t now = NowUnix();
    uint32_t elapsed = (now > it->second) ? (now - it->second) : 0;
    uint32_t minutes = elapsed / 60;
    g_activeSessions.erase(it);

    auto& stats = g_cache[appId];
    // Accrue only this platform's field; a session here can't overwrite another
    // device's cloud playtime.
#ifdef _WIN32
    stats.playtime.playtimeWindows += minutes;
#elif defined(__APPLE__)
    stats.playtime.playtimeMac += minutes;
#else
    stats.playtime.playtimeLinux += minutes;
#endif
    stats.playtime.minutesForever = stats.playtime.playtimeWindows
        + stats.playtime.playtimeMac + stats.playtime.playtimeLinux;
    stats.playtime.minutesLastTwoWeeks += minutes;
    stats.playtime.lastPlayedTime = now;

    // Steam flushes the native blob on game close; merge any new unlocks (also
    // catches another device's, so they're never lost).
    if (ReimportNativeStatsLocked(appId, stats))
        LOG("[Stats] Session end: merged new native achievements/stats for app %u (crc=%u)",
            appId, stats.crcStats);

    // Queue the push (not a blocking curl on the net thread, which raced at close).
    g_dirty[appId] = true;
    SaveAppStats(appId, stats);
    g_dirty[appId] = false;
    LOG("[Stats] Session ended for app %u: +%u min (total %u)",
        appId, minutes, stats.playtime.minutesForever);
}

PlaytimeData GetPlaytime(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto& stats = g_cache[appId];
    PlaytimeData pt = stats.playtime;

    auto it = g_activeSessions.find(appId);
    if (it != g_activeSessions.end()) {
        uint32_t now = NowUnix();
        uint32_t elapsed = (now > it->second) ? (now - it->second) : 0;
        uint32_t minutes = elapsed / 60;
        pt.minutesForever += minutes;
        pt.minutesLastTwoWeeks += minutes;
    }
    return pt;
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

void FlushAll() {
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& [appId, dirty] : g_dirty) {
        if (dirty) {
            auto it = g_cache.find(appId);
            if (it != g_cache.end()) {
                SaveAppStats(appId, it->second);
                LOG("[Stats] Flushed app %u to disk", appId);
            }
            dirty = false;
        }
    }
}

} // namespace StatsStore
