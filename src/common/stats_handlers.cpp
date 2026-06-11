#include "stats_handlers.h"
#include "stats_store.h"
#include "metadata_sync.h"
#include "protobuf.h"
#include "log.h"

#include <cstring>
#include <mutex>
#include <unordered_set>

namespace StatsHandlers {

// Track which apps have active game sessions for playtime
static std::unordered_set<uint32_t> g_activeApps;
static std::mutex g_sessionMutex;

// Namespace-app predicate (installed by the platform layer). When unset, we
// fail CLOSED -- track nothing -- so real games are never accidentally synced.
static NamespacePredicate g_isNamespaceApp;

void SetNamespacePredicate(NamespacePredicate pred) {
    g_isNamespaceApp = std::move(pred);
}

static bool IsNamespaceApp(uint32_t appId) {
    return g_isNamespaceApp && g_isNamespaceApp(appId);
}

void Init() {
    LOG("[Stats] Handlers initialized");
}

// Player.GetUserStats#1 handler
// Request: steamid(1), appid(2), sha_schema(3), crc_stats(4)
// Response: sha_schema(1), crc_stats(2), schema(3), stats[](4)
//   Stats sub: stat_id(1), stat_value(2), unlock_times[](3)
//     Unlock_Time sub: achievement_bit(1), unlock_time(2)
CloudIntercept::RpcResult HandleGetUserStats(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint32_t clientCrc = 0;
    auto* crcField = PB::FindField(reqBody, 4); // crc_stats
    if (crcField) clientCrc = (uint32_t)crcField->varintVal;

    LOG("[Stats] GetUserStats app=%u clientCrc=%u", appId, clientCrc);

    // Snapshot seeds our store from Steam's native UserGameStats blob on first
    // access, then returns a COPY taken under the store lock -- safe to read here
    // while background threads (poller / unlock capture) mutate the live entry.
    StatsStore::AppStats stats = StatsStore::Snapshot(appId);

    PB::Writer resp;

    // crc_stats is a server-owned opaque token the client echoes back; it adopts
    // our stats only when our crc (response field 2) differs from its own (request
    // field 4). So always report OUR crc and send schema+stats only when the client
    // is stale; matching crc -> client no-ops. (CAPIJobRequestUserStats @
    // steamclient!0x138A45A20 / legacy sub_138A44F70.)

    // Field 2: crc_stats (always our authoritative token)
    resp.WriteVarint(2, stats.crcStats);

    if (clientCrc == stats.crcStats) {
        // Client already in sync with us -> no-op response (crc only).
        LOG("[Stats]   app=%u up-to-date (crc=%u); sending crc-only no-op", appId, stats.crcStats);
        return CloudIntercept::RpcResult(std::move(resp));
    }

    // Client is stale -> push our authoritative schema + full stats so it adopts
    // them. Schema is REQUIRED by the client when stats are present (else it
    // logs "missing schema in response" and discards).
    if (!stats.schema.empty()) {
        resp.WriteBytes(3, stats.schema.data(), stats.schema.size());
        LOG("[Stats]   Sending schema (%zu bytes)", stats.schema.size());
    } else if (!stats.stats.empty()) {
        // We have stats but no schema -> the client would reject the stats.
        // Safer to send crc only (no stats) so the client keeps its own data
        // rather than discarding everything. This should be rare (import always
        // grabs the schema when the stats blob exists).
        LOG("[Stats]   app=%u WARNING: have %zu stats but no schema; sending crc-only to avoid client-side discard",
            appId, stats.stats.size());
        return CloudIntercept::RpcResult(std::move(resp));
    }

    // Field 4: stats (repeated)
    for (auto& s : stats.stats) {
        PB::Writer statMsg;
        statMsg.WriteVarint(1, s.statId);   // stat_id
        statMsg.WriteVarint(2, s.value);    // stat_value

        for (auto& a : stats.achievements) {
            if (a.statId == s.statId) {
                for (uint32_t bit = 0; bit < 32; bit++) {
                    if (a.unlockTimes[bit] != 0) {
                        PB::Writer unlockMsg;
                        unlockMsg.WriteVarint(1, bit);               // achievement_bit
                        unlockMsg.WriteFixed32(2, a.unlockTimes[bit]); // unlock_time
                        statMsg.WriteSubmessage(3, unlockMsg);       // unlock_times
                    }
                }
                break;
            }
        }

        resp.WriteSubmessage(4, statMsg);
    }

    LOG("[Stats]   Returning %zu stats, crc=%u", stats.stats.size(), stats.crcStats);
    return CloudIntercept::RpcResult(std::move(resp));
}

// Player.ClientGetLastPlayedTimes#1 handler
//
// Wire format reversed from steamclient64.dll (CPlayer_GetLastPlayedTimes_*
// FileDescriptor + the client consumer sub_1389C7930 -> CUser::GetAppMinutesPlayedData):
//   Request:  min_last_played(1, uint32)
//   Response: games(1, repeated Game)
//     Game:   appid(1, int32), last_playtime(2, uint32),
//             playtime_2weeks(3, int32), playtime_forever(4, int32),
//             first_playtime(5, uint32),
//             playtime_windows_forever(6), playtime_mac_forever(7),
//             playtime_linux_forever(8)
// This response populates Steam's in-memory minutes-played record (read by the
// library UI). Writes one Game submessage (field 1).
static void WriteGame(PB::Writer& out, uint32_t appId, const StatsStore::PlaytimeData& pt) {
    PB::Writer game;
    game.WriteVarint(1, appId);                       // appid (int32)
    game.WriteVarint(2, pt.lastPlayedTime);           // last_playtime (uint32)
    game.WriteVarint(3, pt.minutesLastTwoWeeks);      // playtime_2weeks (int32)
    game.WriteVarint(4, pt.minutesForever);           // playtime_forever (int32)
    if (pt.playtimeWindows) game.WriteVarint(6, pt.playtimeWindows);
    if (pt.playtimeMac)     game.WriteVarint(7, pt.playtimeMac);
    if (pt.playtimeLinux)   game.WriteVarint(8, pt.playtimeLinux);
    out.WriteSubmessage(1, game);                     // games (repeated)
}

CloudIntercept::RpcResult HandleGetLastPlayedTimes(const std::vector<PB::Field>& reqBody) {
    uint32_t minLastPlayed = 0;
    auto* minField = PB::FindField(reqBody, 1);
    if (minField) minLastPlayed = (uint32_t)minField->varintVal;

    PB::Writer resp;
    size_t emitted = 0;

    for (uint32_t appId : StatsStore::GetTrackedApps()) {
        StatsStore::PlaytimeData pt = StatsStore::GetPlaytime(appId);

        // min_last_played is the client's watermark: skip games it already has
        // data at/after. Always emit if we have no last-played stamp.
        if (minLastPlayed != 0 && pt.lastPlayedTime != 0 &&
            pt.lastPlayedTime < minLastPlayed)
            continue;
        if (pt.minutesForever == 0 && pt.lastPlayedTime == 0)
            continue;

        WriteGame(resp, appId, pt);
        ++emitted;
    }

    LOG("[Stats] GetLastPlayedTimes: returned %zu game(s) (min_last_played=%u)",
        emitted, minLastPlayed);
    return CloudIntercept::RpcResult(std::move(resp));
}

// Build a CPlayer_LastPlayedTimes_Notification body (repeated Game games, field 1)
// for the given apps. The platform layer injects this as a server notification so
// a running client adopts the new playtime live. Empty if no app has playtime.
PB::Writer BuildLastPlayedNotificationBody(const std::vector<uint32_t>& appIds) {
    PB::Writer body;
    for (uint32_t appId : appIds) {
        StatsStore::PlaytimeData pt = StatsStore::GetPlaytime(appId);
        if (pt.minutesForever == 0 && pt.lastPlayedTime == 0) continue;
        WriteGame(body, appId, pt);
    }
    return body;
}

// Legacy EMsg 818: CMsgClientGetUserStats
// Request: game_id(1,fixed64), crc_stats(2,uint32), schema_local_version(3,int32), steam_id_for_user(4,fixed64)
// Response: game_id(1,fixed64), eresult(2,int32), crc_stats(3,uint32), schema(4,bytes),
//           stats[](5), achievement_blocks[](6)
std::optional<std::vector<uint8_t>> HandleLegacyGetUserStats(
    const uint8_t* body, size_t bodyLen, uint64_t steamId) {
    (void)steamId;

    auto fields = PB::Parse(body, bodyLen);

    // Extract game_id (field 1, fixed64)
    uint64_t gameId = 0;
    auto* f1 = PB::FindField(fields, 1);
    if (f1) gameId = f1->varintVal;

    // AppID is lower 24 bits of game_id
    uint32_t appId = (uint32_t)(gameId & 0xFFFFFF);
    if (appId == 0) return std::nullopt; // pass through

    uint32_t clientCrc = 0;
    auto* f2 = PB::FindField(fields, 2);
    if (f2) clientCrc = (uint32_t)f2->varintVal;

    int32_t schemaVersion = -1;
    auto* f3 = PB::FindField(fields, 3);
    if (f3) schemaVersion = (int32_t)f3->varintVal;

    LOG("[Stats] Legacy GetUserStats app=%u gameId=%llu clientCrc=%u schemaVer=%d",
        appId, (unsigned long long)gameId, clientCrc, schemaVersion);

    StatsStore::AppStats stats = StatsStore::Snapshot(appId);

    // If client has no schema (version=-1) and we don't have one either,
    // pass through to let the real server provide the schema.
    if (schemaVersion == -1 && stats.schema.empty()) {
        LOG("[Stats]   No schema available, passing through to server");
        return std::nullopt;
    }

    PB::Writer resp;
    resp.WriteFixed64(1, gameId);           // game_id
    resp.WriteVarint(2, 1);                 // eresult = OK
    resp.WriteVarint(3, stats.crcStats);    // crc_stats

    // schema (field 4) - send if client CRC differs
    if (clientCrc != stats.crcStats && !stats.schema.empty()) {
        resp.WriteBytes(4, stats.schema.data(), stats.schema.size());
    }

    // stats (field 5, repeated submessage): stat_id(1), stat_value(2)
    for (auto& s : stats.stats) {
        PB::Writer statMsg;
        statMsg.WriteVarint(1, s.statId);
        statMsg.WriteVarint(2, s.value);
        resp.WriteSubmessage(5, statMsg);
    }

    // achievement_blocks (field 6, repeated): achievement_id(1,uint32), unlock_time[](2, repeated fixed32)
    for (auto& a : stats.achievements) {
        PB::Writer achMsg;
        achMsg.WriteVarint(1, a.statId);
        for (int i = 0; i < 32; i++) {
            achMsg.WriteFixed32(2, a.unlockTimes[i]);
        }
        resp.WriteSubmessage(6, achMsg);
    }

    return resp.Data();
}

// Legacy EMsg 820: CMsgClientStoreUserStats2
// Request: game_id(1,fixed64), settor_steam_id(2,fixed64), settee_steam_id(3,fixed64),
//          crc_stats(4,uint32), explicit_reset(5,bool), stats[](6)
//   Stats sub: stat_id(1), stat_value(2)
// Response (EMsg 821): game_id(1), eresult(2), crc_stats(3), stats_failed_validation[](4), stats_out_of_date(5)
std::optional<std::vector<uint8_t>> HandleLegacyStoreUserStats2(
    const uint8_t* body, size_t bodyLen, uint64_t steamId) {
    (void)steamId;

    auto fields = PB::Parse(body, bodyLen);

    uint64_t gameId = 0;
    auto* f1 = PB::FindField(fields, 1);
    if (f1) gameId = f1->varintVal;

    uint32_t appId = (uint32_t)(gameId & 0xFFFFFF);
    if (appId == 0) return std::nullopt;

    bool explicitReset = false;
    auto* f5 = PB::FindField(fields, 5);
    if (f5) explicitReset = (f5->varintVal != 0);

    LOG("[Stats] Legacy StoreUserStats2 app=%u gameId=%llu reset=%d",
        appId, (unsigned long long)gameId, explicitReset);

    if (explicitReset) {
        StatsStore::ResetStats(appId);   // clears stats/achievements under the store lock
    }

    std::vector<StatsStore::StatEntry> entries;
    for (auto& f : fields) {
        if (f.fieldNum == 6 && f.wireType == PB::LengthDelimited) {
            auto sub = PB::Parse(f.data, f.dataLen);
            uint32_t statId = 0, statVal = 0;
            auto* sid = PB::FindField(sub, 1);
            auto* sval = PB::FindField(sub, 2);
            if (sid) statId = (uint32_t)sid->varintVal;
            if (sval) statVal = (uint32_t)sval->varintVal;
            entries.push_back({statId, statVal});
        }
    }

    uint32_t newCrc = StatsStore::SetStats(appId, entries);
    LOG("[Stats]   Stored %zu stats, newCrc=%u", entries.size(), newCrc);

    PB::Writer resp;
    resp.WriteFixed64(1, gameId);       // game_id
    resp.WriteVarint(2, 1);             // eresult = OK
    resp.WriteVarint(3, newCrc);        // crc_stats
    // No failed validations - we accept everything

    StatsStore::FlushAll();

    return resp.Data();
}

// Observe CMsgClientGamesPlayed (EMsg 5410) to track playtime.
// We don't intercept this - just peek at it as it passes through.
// Message: games_played[](1) -> game_id(2, fixed64)
void ObserveGamesPlayed(const uint8_t* body, size_t bodyLen) {
    auto fields = PB::Parse(body, bodyLen);

    std::unordered_set<uint32_t> currentApps;

    for (auto& f : fields) {
        if (f.fieldNum == 1 && f.wireType == PB::LengthDelimited) {
            auto sub = PB::Parse(f.data, f.dataLen);
            auto* gameIdField = PB::FindField(sub, 2); // game_id (fixed64)
            if (gameIdField) {
                uint64_t gameId = gameIdField->varintVal;
                uint32_t appId = (uint32_t)(gameId & 0xFFFFFF);
                // Only track namespace/lua apps. Real owned games keep their
                // server-side playtime; we must never record or sync theirs.
                if (appId != 0 && IsNamespaceApp(appId)) {
                    currentApps.insert(appId);
                }
            }
        }
    }

    std::lock_guard<std::mutex> lock(g_sessionMutex);

    for (uint32_t appId : currentApps) {
        if (g_activeApps.find(appId) == g_activeApps.end()) {
            StatsStore::StartSession(appId);
            g_activeApps.insert(appId);
        }
    }

    std::vector<uint32_t> ended;
    for (uint32_t appId : g_activeApps) {
        if (currentApps.find(appId) == currentApps.end()) {
            StatsStore::EndSession(appId);
            ended.push_back(appId);
        }
    }
    for (uint32_t appId : ended) {
        g_activeApps.erase(appId);
    }
}

// Observe CMsgClientStoreUserStats2 (EMsg 5466, game_id field 1) -- sent on
// unlock. The body has no timestamps, but Steam writes them to the native blob in
// the same store job, so re-read the blob here to sync the new unlocks.
void ObserveStoreUserStats(const uint8_t* body, size_t bodyLen) {
    // Raw flag only -- this is SHARED (Windows+Linux) code. The ST-gate
    // (AchievementsEnabled / StGateOpen) is applied by the WINDOWS callers at
    // their hook sites; baking it in here would force Linux OFF since
    // steamToolsPresent is structurally always-false on Linux.
    if (!MetadataSync::syncAchievements.load(std::memory_order_relaxed)) return;

    auto fields = PB::Parse(body, bodyLen);
    auto* gameIdField = PB::FindField(fields, 1); // game_id (fixed64)
    if (!gameIdField) return;

    uint32_t appId = (uint32_t)(gameIdField->varintVal & 0xFFFFFF);
    if (appId == 0 || !IsNamespaceApp(appId)) return;

    StatsStore::CaptureNativeUnlocks(appId);
}

void Shutdown() {
    {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        for (uint32_t appId : g_activeApps) {
            StatsStore::EndSession(appId);
        }
        g_activeApps.clear();
    }
    StatsStore::FlushAll();
    LOG("[Stats] Shutdown complete");
}

} // namespace StatsHandlers
