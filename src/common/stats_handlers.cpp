#include "stats_handlers.h"
#include "stats_store.h"
#include "metadata_sync.h"
#include "protobuf.h"
#include "log.h"
#include "custom_autocloud.h"

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

// Player.GetUserStats#1 handler. Wire: req{appid(2),crc(4)} -> resp{crc(2),schema(3),stats(4)}.
CloudIntercept::RpcResult HandleGetUserStats(uint32_t appId, const std::vector<PB::Field>& reqBody) {
    uint32_t clientCrc = 0;
    auto* crcField = PB::FindField(reqBody, 4); // crc_stats
    if (crcField) clientCrc = (uint32_t)crcField->varintVal;

    LOG("[Stats] GetUserStats app=%u clientCrc=%u", appId, clientCrc);

    if (MetadataSync::syncAchievements.load(std::memory_order_relaxed)) {
        if (!StatsStore::WaitForSeed(10000))
            LOG("[Stats] GetUserStats app=%u: seed timed out after 10 s", appId);
    }

    // Snapshot: thread-safe copy taken under the store lock.
    StatsStore::AppStats stats = StatsStore::Snapshot(appId);

    PB::Writer resp;

    // Client adopts stats only when our crc differs from its echoed crc.

    // Field 2: crc_stats (always our authoritative token)
    resp.WriteVarint(2, stats.crcStats);

    if (clientCrc == stats.crcStats) {
        // Client already in sync with us -> no-op response (crc only).
        LOG("[Stats]   app=%u up-to-date (crc=%u); sending crc-only no-op", appId, stats.crcStats);
        return CloudIntercept::RpcResult(std::move(resp));
    }

    // Client stale -- send schema + stats. Schema required or client discards.
    if (!stats.schema.empty()) {
        resp.WriteBytes(3, stats.schema.data(), stats.schema.size());
        LOG("[Stats]   Sending schema (%zu bytes)", stats.schema.size());
    } else if (!stats.stats.empty()) {
        // Stats without schema -> client rejects. Send crc-only to be safe.
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

// Player.ClientGetLastPlayedTimes#1 handler.
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

// Build LastPlayedTimes notification body for live UI injection.
PB::Writer BuildLastPlayedNotificationBody(const std::vector<uint32_t>& appIds) {
    PB::Writer body;
    for (uint32_t appId : appIds) {
        StatsStore::PlaytimeData pt = StatsStore::GetPlaytime(appId);
        if (pt.minutesForever == 0 && pt.lastPlayedTime == 0) continue;
        WriteGame(body, appId, pt);
    }
    return body;
}

// Legacy EMsg 818: CMsgClientGetUserStats (game_id, crc, schema, stats, ach_blocks).
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

    // Count unlocked bits for diagnostics: schema present but zero unlocks is the
    // "served 0 achievements despite cloud data" signature.
    size_t unlockedBits = 0;
    for (const auto& a : stats.achievements)
        for (int i = 0; i < 32; i++)
            if (a.unlockTimes[i]) unlockedBits++;
    LOG("[Stats]   Serve snapshot app=%u: schema=%zuB ach_blocks=%zu unlocked_bits=%zu "
        "stats=%zu crc=%u(client=%u)%s", appId, stats.schema.size(),
        stats.achievements.size(), unlockedBits, stats.stats.size(),
        stats.crcStats, clientCrc,
        stats.achievements.empty() ? " [WARN: no achievement data in store]" : "");

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

    // schema (field 4): send when CRC differs OR the client has no schema yet
    // (clientCrc==0 / schemaVersion==-1); CRC-only would withhold it in the empty-store case.
    bool sentSchema = false;
    if (!stats.schema.empty() &&
        (clientCrc != stats.crcStats || clientCrc == 0 || schemaVersion == -1)) {
        resp.WriteBytes(4, stats.schema.data(), stats.schema.size());
        sentSchema = true;
    }

    // OR each achievement block's `bits` into the matching stat value; MergeAchievements
    // updates bits without touching stats[].value (the "9 served, 8 displayed" bug).
    for (auto& a : stats.achievements) {
        for (auto& s : stats.stats) {
            if (s.statId == a.statId) {
                if ((s.value | a.bits) != s.value) {
                    LOG("[Stats]   Reconcile stat %u: val 0x%X -> 0x%X (synced from ach bits)",
                        s.statId, s.value, s.value | a.bits);
                    s.value |= a.bits;
                }
                break;
            }
        }
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

    auto out = resp.Data();
    LOG("[Stats]   819 built app=%u: %zuB (schema_sent=%d ach_blocks=%zu stats=%zu)",
        appId, out.size(), sentSchema ? 1 : 0, stats.achievements.size(), stats.stats.size());
    return out;
}

// Legacy EMsg 820: CMsgClientStoreUserStats2. Response is EMsg 821.
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

    LOG("[Stats] Legacy StoreUserStats2 app=%u gameId=%llu reset=%d ns=%d",
        appId, (unsigned long long)gameId, explicitReset, IsNamespaceApp(appId) ? 1 : 0);

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

    StatsStore::FlushAll();

    return resp.Data();
}

// Observe CMsgClientGamesPlayed (EMsg 5410) for playtime session tracking.
void ObserveGamesPlayed(const uint8_t* body, size_t bodyLen) {
    auto fields = PB::Parse(body, bodyLen);

    std::unordered_set<uint32_t> currentApps;
    std::unordered_set<uint32_t> allApps;

    for (auto& f : fields) {
        if (f.fieldNum == 1 && f.wireType == PB::LengthDelimited) {
            auto sub = PB::Parse(f.data, f.dataLen);
            auto* gameIdField = PB::FindField(sub, 2); // game_id (fixed64)
            if (gameIdField) {
                uint64_t gameId = gameIdField->varintVal;
                uint32_t appId = (uint32_t)(gameId & 0xFFFFFF);
                if (appId != 0) allApps.insert(appId);
                // Only track namespace/lua apps. Real owned games keep their
                // server-side playtime; we must never record or sync theirs.
                if (appId != 0 && IsNamespaceApp(appId)) {
                    currentApps.insert(appId);
                }
            }
        }
    }
    CustomAutoCloud::ObserveGamesPlayed(allApps);
    if (!MetadataSync::syncPlaytime.load(std::memory_order_relaxed)) return;

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

// Observe StoreUserStats2 (EMsg 5466) -- re-read native blob for new unlocks.
void ObserveStoreUserStats(const uint8_t* body, size_t bodyLen) {
    // Raw flag only: shared code; Windows callers apply the ST-gate at their hook sites.
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
