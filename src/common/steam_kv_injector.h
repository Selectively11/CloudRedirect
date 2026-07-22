#pragma once
// Inject ufs.quota/maxnumfiles and savefiles rules into Steam's in-memory KV
// for namespace apps missing PICS data.

#include <cstdint>
#include <string>
#include <vector>

namespace SteamKvInjector {

struct ResolvedKvAddrs {
    void**    globalEnginePtrPtr = nullptr;
    uintptr_t getAppInfo    = 0;
    uintptr_t getSection    = 0;
    uintptr_t readConfigU64 = 0;
    uintptr_t kvFindKey     = 0;
    uintptr_t kvGetUint64   = 0;
    uintptr_t kvGetInt      = 0;
    uintptr_t kvSetUint64   = 0;
    uintptr_t kvSetInt      = 0;
    uintptr_t kvSetString   = 0;
    uint32_t  appInfoCacheOffset = 0;
};

void Configure(const ResolvedKvAddrs& addrs);

bool Init();

bool IsReady();

// Read current ufs.quota/maxnumfiles from KV. False if injector not ready.
bool ReadAppQuota(uint32_t appId, uint64_t& outQuotaBytes, uint32_t& outMaxNumFiles);

// Write quota/maxnumfiles into KV. Won't clobber existing non-zero values.
bool InjectAppQuota(uint32_t appId, uint64_t quotaBytes, uint32_t maxNumFiles);

// Raise live ufs maxnumfiles/quota to at least the given floor. Idempotent.
bool EnsureMaxNumFilesFloor(uint32_t appId, uint32_t floorFiles, uint64_t floorBytes);

// A single AutoCloud save-file rule for KV injection.
struct SaveFileRule {
    std::string root;       // e.g. "WinAppDataLocal"
    std::string path;       // e.g. "Katana_ZERO"
    std::string pattern;    // e.g. "*.zero"
    bool recursive = false;
    uint32_t platforms = 0xFFFFFFFFu;  // bitmask: Win=1, Mac=2, Linux=8; -1=all
};

// Inject savefiles rules into UFS KV. Won't clobber existing children.
bool InjectSaveFiles(uint32_t appId, const std::vector<SaveFileRule>& rules);

// Dynamically-resolved engine global pointer (Linux only). Returns the address
// of the pointer variable (void**) so callers can dereference it at call time.
// Null if Init hasn't resolved it yet.
void** GetEngineGlobalPtr();

} // namespace SteamKvInjector
