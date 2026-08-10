#pragma once
#include "protobuf.h"
#include "rpc_handlers.h"
#include <vector>
#include <cstdint>
#include <optional>
#include <functional>

namespace StatsHandlers {

// Service RPC method names
inline constexpr const char* RPC_GET_USER_STATS = "Player.GetUserStats#1";
inline constexpr const char* RPC_GET_LAST_PLAYED = "Player.ClientGetLastPlayedTimes#1";
// Server->client notification method (we push this to update playtime live).
inline constexpr const char* RPC_GET_LAST_PLAYED_NOTIFY = "PlayerClient.NotifyLastPlayedTimes#1";

// Predicate restricting playtime tracking to namespace apps only.
using NamespacePredicate = std::function<bool(uint32_t appId)>;
void SetNamespacePredicate(NamespacePredicate pred);

// Legacy EMsg numbers
inline constexpr uint32_t EMSG_CLIENT_GET_USER_STATS      = 818;
inline constexpr uint32_t EMSG_CLIENT_GET_USER_STATS_RESP = 819;
inline constexpr uint32_t EMSG_CLIENT_STORE_USER_STATS2   = 820;
inline constexpr uint32_t EMSG_CLIENT_STORE_USER_STATS_RESP = 821;
inline constexpr uint32_t EMSG_CLIENT_GAMES_PLAYED        = 5410;

// Call after StatsStore::Init.
void Init();

// Service RPC handler for Player.GetUserStats#1
CloudIntercept::RpcResult HandleGetUserStats(uint32_t appId, const std::vector<PB::Field>& reqBody);

// Service RPC handler for Player.ClientGetLastPlayedTimes#1
CloudIntercept::RpcResult HandleGetLastPlayedTimes(const std::vector<PB::Field>& reqBody);

// Build a LastPlayedTimes notification body for live injection.
PB::Writer BuildLastPlayedNotificationBody(const std::vector<uint32_t>& appIds);

// Legacy EMsg handlers - return response body bytes
// Returns nullopt if this EMsg should pass through to real server
std::optional<std::vector<uint8_t>> HandleLegacyGetUserStats(
    const uint8_t* body, size_t bodyLen, uint64_t steamId);

std::optional<std::vector<uint8_t>> HandleLegacyStoreUserStats2(
    const uint8_t* body, size_t bodyLen, uint64_t steamId);

// Observe CMsgClientGamesPlayed (EMsg 5410) for playtime tracking. Returns the
// apps whose session just ended, so a platform with a live writer can push their
// fresh minutes into the running client -- the cloud poller only ever queues apps
// the CLOUD advanced, so a local session would otherwise sit unseen until Steam's
// next natural GetLastPlayedTimes (in practice: a restart).
std::vector<uint32_t> ObserveGamesPlayed(const uint8_t* body, size_t bodyLen);

// Observe CMsgClientStoreUserStats2 (EMsg 5466) to capture achievement unlocks
// the moment the game stores them. body = serialized message; game_id is field 1.
void ObserveStoreUserStats(const uint8_t* body, size_t bodyLen);

void Shutdown();

} // namespace StatsHandlers
