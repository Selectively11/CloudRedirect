#pragma once
// sc_resolver.h -- Runtime resolution of steamclient64.dll addresses.
// Replaces hardcoded RVAs with RTTI walks, pattern scans, and
// instruction operand extraction so CloudRedirect survives Steam updates.

#include <cstdint>

namespace ScResolver {

// Results of auto-resolution. All fields are absolute addresses (0 = failed).
struct ResolvedAddrs {
    // ── Vtables (RTTI) ─────────────────────────────────────────────────
    uintptr_t ccmInterfaceVtable;         // CCMInterface::vftable
    uintptr_t serviceTransportVtable;     // CClientUnifiedServiceTransport::vftable

    // ── Globals ────────────────────────────────────────────────────────
    uintptr_t globalEngine;               // &g_pCSteamEngine (pointer-to-pointer)
    uintptr_t refCountGlobal;             // &g_refCountPtr
    uintptr_t jobCurGlobal;               // &g_pJobCur

    // ── Protobuf helpers ───────────────────────────────────────────────
    uintptr_t parseFromArray;             // protobuf::ParseFromArray(msg, data, size)
    uintptr_t serializeToArray;           // protobuf::SerializeToArray(msg, buf, size)

    // ── Packet routing ─────────────────────────────────────────────────
    uintptr_t wrapPacket;                 // CNetPacket -> CProtoBufNetPacket wrapper
    uintptr_t bRouteMsgToJob;             // CJobMgr::BRouteMsgToJob
    uintptr_t releaseWrapped;             // CProtoBufNetPacket release
    uintptr_t refCountHelper;             // InterlockedIncrement64 helper
    uintptr_t findJob;                    // CUtlSortedVector::Find (job lookup)

    // ── Manifest pinning ───────────────────────────────────────────────
    uintptr_t buildDepotDependency;       // CUserAppManager::BuildDepotDependency

    // ── Playtime ───────────────────────────────────────────────────────
    uintptr_t getAppMinutesPlayedData;    // CUser playtime record getter
    uintptr_t flushAppMinutesPlayed;      // CUser playtime record flush
    uintptr_t setAppLastPlayedTime;       // CUser last-played-time setter

    // ── Struct offsets (0 = not resolved) ──────────────────────────────
    uint32_t engineOffJobMgr;             // CSteamEngine -> CJobMgr
    uint32_t engineOffGlobalHandle;       // CSteamEngine -> uint32 global user handle
    uint32_t engineOffUserMap;            // CSteamEngine -> CUtlSortedVector user map
    uint32_t ccmOffConnContext;           // CCMInterface -> connection context ptr
    uint32_t userOffCcmInterface;         // CBaseUser -> CCMInterface
    uint32_t engineOffAppInfoCache;       // CSteamEngine -> CAppInfoCache

    // ── KV Injector ────────────────────────────────────────────────────
    uintptr_t getAppInfo;                 // CAppInfoCache::GetAppInfo
    uintptr_t getSection;                 // CAppInfoCache::GetSection
    uintptr_t readConfigU64;              // CAppInfoCache::ReadAppConfigUint64
    uintptr_t kvFindKey;                  // KeyValues::FindKey
    uintptr_t kvGetUint64;                // KeyValues::GetUint64
    uintptr_t kvGetInt;                   // KeyValues::GetInt
    uintptr_t kvSetUint64;               // KeyValues::SetUint64
    uintptr_t kvSetInt;                   // KeyValues::SetInt
    uintptr_t kvSetString;               // KeyValues::SetString
};

// Run all resolvers against the loaded steamclient64.dll.
// steamClientBase: base address of steamclient64.dll in memory.
// hardcoded: fallback RVAs (current build). Used for validation and as fallback.
// Returns resolved addresses. Check individual fields for 0 (failure).
ResolvedAddrs Resolve(uintptr_t steamClientBase);

// Print a comparison of resolved vs hardcoded RVAs for verification.
void LogComparison(const ResolvedAddrs& resolved, uintptr_t steamClientBase);

} // namespace ScResolver
