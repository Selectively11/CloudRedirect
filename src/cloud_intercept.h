#pragma once
#include "cloud_metadata_paths.h"
#include "common.h"

namespace CloudIntercept {

// CNetPacket struct (passed as second arg to RecvPkt)
// Layout confirmed from IDA: sub_138E59C30 (AddRef), sub_138D02530 (wrapper creator)
//   +0:  padding (8 bytes, never read in critical path)
//   +8:  pointer to raw packet data
//   +16: packet data size (uint32)
//   +20: reference count (uint32, AddRef increments; must start at 0)
//   +24: owned data copy pointer (QWORD, must be NULL initially)
struct CNetPacket {
    uint64_t pad0;             // +0   padding (not accessed by RecvPkt path)
    uint8_t* pubData;          // +8   packet data pointer
    uint32_t cubData;          // +16  packet byte count
    uint32_t m_cRef;           // +20  reference count, starts at 1 to prevent pool recycling (see cloud_intercept.cpp)
    uint8_t* ownedDataCopy;    // +24  owned data copy ptr, MUST be NULL
};

// RecvPkt takes only 2 params: (thisptr, CNetPacket*)
using RecvPktFn = int64_t(__fastcall*)(void* thisptr, CNetPacket* pkt);

// initialize the cloud intercept layer (reads config, sets up state)
void Init(const std::string& steamPath);

// hook the saved-original RecvPkt pointer to monitor incoming packets
void InstallRecvPktMonitor(void* savedOrigPtrAddr);

// install inline detour on steamclient64 for manifest pinning
void InstallManifestPinHook();

// compute payload base and set up cave replacement buffer globals
void SetSendPktAddr(void* recvPktGlobalAddr);

// called from the exported CloudOnSendPkt. returns true if packet was handled.
bool OnSendPkt(void* thisptr, const uint8_t* data, uint32_t size);

// get the 32-bit account ID from the captured SteamID
uint32_t GetAccountId();

// get the Steam installation path (with trailing backslash)
const std::string& GetSteamPath();

// sync toggles
bool SyncAchievementsEnabled();
bool SyncPlaytimeEnabled();
bool SyncLuasEnabled();

// record the launch timestamp for internal playtime tracking
void RecordLaunchTime(uint32_t appId);

// signal shutdown
void Shutdown();

} // namespace CloudIntercept
