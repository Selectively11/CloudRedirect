#include "vtable_hook.h"
#include "log.h"

#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <mutex>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>

// RTTI typestring for CClientUnifiedServiceTransport (Itanium ABI mangled)
static constexpr const char RTTI_NAME[] = "30CClientUnifiedServiceTransport";

// Steam's loader hides libraries from dl_iterate_phdr; parse /proc/self/maps.

static struct { uintptr_t start; uintptr_t end; } g_readableRanges[64];
static int g_readableCount = 0;
static struct { uintptr_t start; uintptr_t end; } g_writableRanges[64];
static int g_writableCount = 0;

uintptr_t VtableHook::FindSteamclient(size_t& outSize)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
    {
        Log::Error("cannot open /proc/self/maps");
        return 0;
    }

    uintptr_t base = 0;
    uintptr_t end  = 0;
    uintptr_t lastSteamEnd = 0;
    bool lastWasSteam = false;
    g_readableCount = 0;
    g_writableCount = 0;
    char line[512];

    while (fgets(line, sizeof(line), f))
    {
        uintptr_t start_addr, end_addr;
        char perms[5] = {};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start_addr, &end_addr, perms) < 3)
            continue;

        bool isSteamclient = (strstr(line, "steamclient.so") != nullptr);
        bool isContiguous = (lastWasSteam && start_addr == lastSteamEnd);

        if (isSteamclient || isContiguous)
        {
            if (base == 0 || start_addr < base)
                base = start_addr;
            if (end_addr > end)
                end = end_addr;
            lastSteamEnd = end_addr;
            lastWasSteam = true;

            if (perms[0] == 'r' && g_readableCount < 64)
            {
                g_readableRanges[g_readableCount].start = start_addr;
                g_readableRanges[g_readableCount].end = end_addr;
                g_readableCount++;
            }
            // .data.rel.ro lives in rw- pages
            if (perms[0] == 'r' && perms[1] == 'w' && g_writableCount < 64)
            {
                g_writableRanges[g_writableCount].start = start_addr;
                g_writableRanges[g_writableCount].end = end_addr;
                g_writableCount++;
            }
        }
        else
        {
            lastWasSteam = false;
        }
    }
    fclose(f);

    if (base == 0)
    {
        Log::Error("steamclient.so not found in /proc/self/maps");
        return 0;
    }

    outSize = end - base;
    Log::Info("steamclient.so base=%p end=%p size=0x%zx (%d readable, %d writable ranges)", 
              (void*)base, (void*)end, outSize, g_readableCount, g_writableCount);
    return base;
}

// Helper: check if an address range is within a readable mapping
static bool IsReadable(uintptr_t addr, size_t len)
{
    uintptr_t addrEnd = addr + len;
    if (addrEnd < addr) return false;  // overflow on 32-bit
    for (int i = 0; i < g_readableCount; i++)
    {
        if (addr >= g_readableRanges[i].start && addrEnd <= g_readableRanges[i].end)
            return true;
    }
    return false;
}

// Safe memory probe using write() to /dev/null — avoids SIGSEGV
static bool CanReadMemory(const void* addr, size_t len)
{
    static std::once_flag devnullOnce;
    static int devnull = -1;
    std::call_once(devnullOnce, []() {
        devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    });
    if (devnull < 0)
        return false;
    return (write(devnull, addr, len) == (ssize_t)len);
}

void** VtableHook::FindTransportVtable(uintptr_t steamBase, size_t steamSize)
{
    const size_t nameLen = strlen(RTTI_NAME);

    // Scan rw- pages (.data.rel.ro) for vtable pointer references.

    // Find the RTTI typestring in readable ranges
    const uint8_t* rttiStr = nullptr;
    for (int r = 0; r < g_readableCount && !rttiStr; r++)
    {
        // Only scan smaller ranges likely to be .rodata (skip huge .text)
        size_t rangeSize = g_readableRanges[r].end - g_readableRanges[r].start;
        if (rangeSize < nameLen) continue;

        const uint8_t* rStart = reinterpret_cast<const uint8_t*>(g_readableRanges[r].start);
        const uint8_t* rEnd = reinterpret_cast<const uint8_t*>(g_readableRanges[r].end);

        for (const uint8_t* p = rStart; p < rEnd - nameLen; p++)
        {
            if (memcmp(p, RTTI_NAME, nameLen + 1) == 0)
            {
                rttiStr = p;
                break;
            }
        }
    }

    if (!rttiStr)
    {
        Log::Error("RTTI string '%s' not found in steamclient.so", RTTI_NAME);
        return nullptr;
    }
    uintptr_t rttiStrAddr = reinterpret_cast<uintptr_t>(rttiStr);
    Log::Debug("RTTI typestring at %p (offset 0x%zx)", rttiStr, rttiStrAddr - steamBase);

    // Itanium ABI: vtable is at fixed offset from RTTI typestring.

    // Known offset from RTTI string to vtable function pointers
    static const uintptr_t KNOWN_VTABLE_OFFSETS[] = {
        0x227F450,  // ubuntu12_32/steamclient.so (May 12 2026 - latest)
        0x227F490,  // ubuntu12_32/steamclient.so (new Steam Runtime, May 2026)
        0x227C510,  // ubuntu12_32/steamclient.so (old Steam Runtime)
        0x2246E50,  // linux32/steamclient.so build May 2026
        0x2245E70,  // linux32/steamclient.so build Apr 2026
    };

    for (size_t i = 0; i < sizeof(KNOWN_VTABLE_OFFSETS)/sizeof(KNOWN_VTABLE_OFFSETS[0]); i++)
    {
        uintptr_t candidateVtable = rttiStrAddr + KNOWN_VTABLE_OFFSETS[i];
        if (!IsReadable(candidateVtable, 44)) continue;

        void** vt = reinterpret_cast<void**>(candidateVtable);
        // Sanity: slots 5, 7, 8 (the ones we hook) should be code pointers within steamclient
        uintptr_t slot5 = reinterpret_cast<uintptr_t>(vt[5]);
        uintptr_t slot7 = reinterpret_cast<uintptr_t>(vt[7]);
        uintptr_t slot8 = reinterpret_cast<uintptr_t>(vt[8]);
        if (slot5 >= steamBase && slot5 < steamBase + steamSize &&
            slot7 >= steamBase && slot7 < steamBase + steamSize &&
            slot8 >= steamBase && slot8 < steamBase + steamSize)
        {
            Log::Info("CClientUnifiedServiceTransport vtable at %p (offset 0x%zx, method=offset[%zu])",
                      vt, candidateVtable - steamBase, i);
            Log::Debug("  slot5=%p  slot7=%p  slot8=%p", vt[5], vt[7], vt[8]);
            return vt;
        }
    }

    // Fallback: pointer scan of ALL readable ranges (typeinfo may be in .rodata)
    Log::Debug("Offset-based lookup failed, trying pointer scan of %d readable ranges...", g_readableCount);
    const uintptr_t* typeinfoPtr = nullptr;
    for (int r = 0; r < g_readableCount && !typeinfoPtr; r++)
    {
        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (g_readableRanges[r].start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            g_readableRanges[r].end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p < scanEnd; p++)
        {
            if (*p == rttiStrAddr)
            {
                typeinfoPtr = p - 1;
                Log::Debug("Found RTTI pointer at %p in range %d", p, r);
                break;
            }
        }
    }

    if (!typeinfoPtr)
    {
        Log::Error("typeinfo struct not found for CClientUnifiedServiceTransport");
        return nullptr;
    }
    uintptr_t typeinfoAddr = reinterpret_cast<uintptr_t>(typeinfoPtr);
    Log::Debug("typeinfo at %p (offset 0x%zx)", typeinfoPtr, typeinfoAddr - steamBase);

        // Find vtable in readable ranges
    void** vtableFuncs = nullptr;
    for (int r = 0; r < g_readableCount && !vtableFuncs; r++)
    {
        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (g_readableRanges[r].start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            g_readableRanges[r].end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p < scanEnd; p++)
        {
            if (*p == typeinfoAddr)
            {
                if (p > scanStart && *(p - 1) == 0)
                {
                    vtableFuncs = reinterpret_cast<void**>(const_cast<uintptr_t*>(p + 1));
                    Log::Debug("Found vtable pointer at %p in range %d", p, r);
                    break;
                }
            }
        }
    }

    if (!vtableFuncs)
    {
        Log::Error("vtable for CClientUnifiedServiceTransport not found");
        return nullptr;
    }

    // Verify slots 0-8 are readable before accessing
    if (!IsReadable(reinterpret_cast<uintptr_t>(vtableFuncs), 9 * sizeof(void*)))
    {
        Log::Error("CClientUnifiedServiceTransport vtable at %p but slots 0-8 not readable", vtableFuncs);
        return nullptr;
    }

    Log::Info("CClientUnifiedServiceTransport vtable at %p (offset 0x%zx)",
              vtableFuncs, reinterpret_cast<uintptr_t>(vtableFuncs) - steamBase);
    Log::Debug("  slot5=%p  slot7=%p  slot8=%p",
               vtableFuncs[5], vtableFuncs[7], vtableFuncs[8]);
    return vtableFuncs;
}

static bool MakeWritable(void* addr, size_t len)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(pageSize - 1);
    uintptr_t endAddr = reinterpret_cast<uintptr_t>(addr) + len;
    size_t pageLen = ((endAddr - page) + (pageSize - 1)) & ~(pageSize - 1);
    return mprotect(reinterpret_cast<void*>(page), pageLen, PROT_READ | PROT_WRITE) == 0;
}

static bool MakeReadOnly(void* addr, size_t len)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(pageSize - 1);
    uintptr_t endAddr = reinterpret_cast<uintptr_t>(addr) + len;
    size_t pageLen = ((endAddr - page) + (pageSize - 1)) & ~(pageSize - 1);
    return mprotect(reinterpret_cast<void*>(page), pageLen, PROT_READ) == 0;
}

// Defined in cloud_hooks.cpp
extern "C" {
    int hook_BYieldingSend(void* pThis, const char* methodName, void* request, void* response, int* flags);
    int hook_NotificationDirect(void* pThis, const char* methodName, void* body, int* flags);
    int hook_SyncSend2(void* pThis, const char* methodName, void* buf, unsigned int bufLen, void* response, int* flags);
    bool hook_IsCloudEnabledForApp(void* pThis, unsigned int appId);
}

bool VtableHook::InstallHooks(void** vtable, VtableInfo& info)
{
    info.vtable = vtable;
    info.origSlot5 = vtable[5];
    info.origSlot7 = vtable[7];
    info.origSlot8 = vtable[8];

    // The vtable lives in .data.rel.ro — need to make it writable
    void* slotBase = &vtable[5];
    size_t span = reinterpret_cast<uintptr_t>(&vtable[8]) - reinterpret_cast<uintptr_t>(&vtable[5]) + 8;

    if (!MakeWritable(slotBase, span))
    {
        Log::Error("mprotect RW failed on vtable");
        return false;
    }

    vtable[5] = reinterpret_cast<void*>(&hook_BYieldingSend);
    vtable[7] = reinterpret_cast<void*>(&hook_NotificationDirect);
    vtable[8] = reinterpret_cast<void*>(&hook_SyncSend2);

    // Restore read-only (non-fatal if it fails).
    MakeReadOnly(slotBase, span);

    Log::Info("Vtable hooks installed: slot5=%p slot7=%p slot8=%p",
              vtable[5], vtable[7], vtable[8]);
    return true;
}

void VtableHook::RemoveHooks(const VtableInfo& info)
{
    if (!info.vtable) return;

    void* slotBase = &info.vtable[5];
    size_t span = reinterpret_cast<uintptr_t>(&info.vtable[8]) - reinterpret_cast<uintptr_t>(&info.vtable[5]) + 8;

    if (MakeWritable(slotBase, span))
    {
        info.vtable[5] = info.origSlot5;
        info.vtable[7] = info.origSlot7;
        info.vtable[8] = info.origSlot8;
        MakeReadOnly(slotBase, span);
        Log::Info("Vtable hooks removed");
    }
    else
    {
        Log::Warn("mprotect RW failed during hook removal");
    }
}

static constexpr const char RTTI_REMOTE_STORAGE[] = "18CUserRemoteStorage";

static bool IsWithinSteamclient(uintptr_t ptr, uintptr_t steamBase, size_t steamSize)
{
    return ptr >= steamBase && ptr < steamBase + steamSize;
}

static bool IsLikelyAppCloudEnabledSlot(void** vtable, size_t slotIndex, uintptr_t steamBase, size_t steamSize)
{
    uintptr_t fn = reinterpret_cast<uintptr_t>(vtable[slotIndex]);
    if (!IsWithinSteamclient(fn, steamBase, steamSize) || !IsReadable(fn, 30))
        return false;

    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);

    // Pattern A (older builds): args passed via esp offsets
    //   +0:  55 57 56 53 E8 ?? ?? ?? ??  (push ebp/edi/esi/ebx + call PIC thunk)
    //   +9:  81 C3 ?? ?? ?? ??          (add ebx, imm32)
    //   +15: 83 EC 0C                   (sub esp, 0x0C)
    //   +18: 8B 74 24 24                (mov esi, [esp+0x24] - appId)
    //   +22: 8B 7C 24 20                (mov edi, [esp+0x20] - this)
    if (p[0] == 0x55 && p[1] == 0x57 && p[2] == 0x56 && p[3] == 0x53 && p[4] == 0xE8 &&
        p[15] == 0x83 && p[16] == 0xEC && p[17] == 0x0C &&
        p[18] == 0x8B && p[19] == 0x74 && p[20] == 0x24 && p[21] == 0x24 &&
        p[22] == 0x8B && p[23] == 0x7C && p[24] == 0x24 && p[25] == 0x20)
        return true;

    // Pattern B (May 2026+): esi/ebx pushed after PIC fixup, args via ebp
    //   +0:  55 89 E5 57 E8 ?? ?? ?? ??  (push ebp; mov ebp,esp; push edi; call PIC)
    //   +9:  81 C7/C3 ?? ?? ?? ??       (add edi/ebx, imm32)
    //   +15: 56 53                      (push esi; push ebx)
    //   +17: 83 EC                      (sub esp, imm8)
    //   +20: 8B 45 0C                   (mov eax, [ebp+0Ch] - appId arg)
    //   +23: 85 C0                      (test eax, eax - appId null check)
    //   +25: 0F 84                      (jz near - distinct from jnz in other methods)
    if (p[0] == 0x55 && p[1] == 0x89 && p[2] == 0xE5 && p[3] == 0x57 && p[4] == 0xE8 &&
        p[9] == 0x81 &&
        p[15] == 0x56 && p[16] == 0x53 &&
        p[17] == 0x83 && p[18] == 0xEC &&
        p[20] == 0x8B && p[21] == 0x45 && p[22] == 0x0C &&
        p[23] == 0x85 && p[24] == 0xC0 &&
        p[25] == 0x0F && p[26] == 0x84)
        return true;

    return false;
}

static size_t ResolveCloudEnabledSlot(void** vtable, uintptr_t steamBase, size_t steamSize)
{
    for (size_t slot = 0; slot < 32; ++slot) {
        if (IsLikelyAppCloudEnabledSlot(vtable, slot, steamBase, steamSize))
            return slot;
    }
    return SIZE_MAX;
}

void** VtableHook::FindRemoteStorageVtable(uintptr_t steamBase, size_t steamSize)
{
    const size_t nameLen = strlen(RTTI_REMOTE_STORAGE);

    // Find RTTI string in readable ranges
    const uint8_t* rttiStr = nullptr;
    for (int r = 0; r < g_readableCount && !rttiStr; r++)
    {
        const uint8_t* rStart = reinterpret_cast<const uint8_t*>(g_readableRanges[r].start);
        const uint8_t* rEnd = reinterpret_cast<const uint8_t*>(g_readableRanges[r].end);
        if ((size_t)(rEnd - rStart) <= nameLen) continue;

        for (const uint8_t* p = rStart; p < rEnd - nameLen; p++)
        {
            if (memcmp(p, RTTI_REMOTE_STORAGE, nameLen + 1) == 0)
            {
                rttiStr = p;
                break;
            }
        }
    }

    if (!rttiStr)
    {
        Log::Error("RTTI string '%s' not found in steamclient.so", RTTI_REMOTE_STORAGE);
        return nullptr;
    }
    uintptr_t rttiStrAddr = reinterpret_cast<uintptr_t>(rttiStr);
    Log::Debug("CUserRemoteStorage RTTI typestring at %p (offset 0x%zx)", rttiStr, rttiStrAddr - steamBase);

    // Try offset-based lookup first (fast, crash-safe)
    static const uintptr_t KNOWN_STORAGE_OFFSETS[] = {
        0x224AF00,  // ubuntu12_32/steamclient.so (May 12 2026 - latest)
        0x224AF40,  // ubuntu12_32/steamclient.so (new Steam Runtime, May 2026)
        0x2247FA0,  // ubuntu12_32/steamclient.so (old Steam Runtime)
        0x221C280,  // linux32/steamclient.so build May 2026
        0x221B2A0,  // linux32/steamclient.so build Apr 2026
    };

    for (size_t i = 0; i < sizeof(KNOWN_STORAGE_OFFSETS)/sizeof(KNOWN_STORAGE_OFFSETS[0]); i++)
    {
        uintptr_t candidateVtable = rttiStrAddr + KNOWN_STORAGE_OFFSETS[i];
        if (!IsReadable(candidateVtable, 25 * sizeof(void*))) continue;

        void** vt = reinterpret_cast<void**>(candidateVtable);
        // Find the IsCloudEnabledForApp slot first, then validate it
        size_t cloudEnabledSlot = ResolveCloudEnabledSlot(vt, steamBase, steamSize);
        if (cloudEnabledSlot == SIZE_MAX)
            continue;
        
        uintptr_t slotAddr = reinterpret_cast<uintptr_t>(vt[cloudEnabledSlot]);
        if (slotAddr >= steamBase && slotAddr < steamBase + steamSize)
        {
            Log::Info("CUserRemoteStorage vtable at %p (offset 0x%zx, method=offset[%zu])",
                      vt, candidateVtable - steamBase, i);
            Log::Debug("  cloud-enabled slot%zu=%p", cloudEnabledSlot, vt[cloudEnabledSlot]);
            return vt;
        }
    }

    // Fallback: pointer scan
    Log::Debug("Offset-based lookup failed for CUserRemoteStorage, trying pointer scan...");

    // Find typeinfo referencing string
    const uintptr_t* typeinfoPtr = nullptr;
    for (int r = 0; r < g_readableCount && !typeinfoPtr; r++)
    {
        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (g_readableRanges[r].start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            g_readableRanges[r].end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p < scanEnd; p++)
        {
            if (*p == rttiStrAddr)
            {
                typeinfoPtr = p - 1;
                break;
            }
        }
    }

    if (!typeinfoPtr)
    {
        Log::Error("typeinfo struct not found for CUserRemoteStorage");
        return nullptr;
    }
    uintptr_t typeinfoAddr = reinterpret_cast<uintptr_t>(typeinfoPtr);
    Log::Debug("CUserRemoteStorage typeinfo at %p", typeinfoPtr);

    // Find vtable referencing typeinfo
    void** vtableFuncs = nullptr;
    for (int r = 0; r < g_readableCount && !vtableFuncs; r++)
    {
        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (g_readableRanges[r].start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            g_readableRanges[r].end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p < scanEnd; p++)
        {
            if (*p == typeinfoAddr)
            {
                if (p > scanStart && *(p - 1) == 0)
                {
                    vtableFuncs = reinterpret_cast<void**>(const_cast<uintptr_t*>(p + 1));
                    break;
                }
            }
        }
    }

    if (!vtableFuncs)
    {
        Log::Error("vtable for CUserRemoteStorage not found");
        return nullptr;
    }

    if (!IsReadable(reinterpret_cast<uintptr_t>(vtableFuncs), 25 * sizeof(void*)))
    {
        Log::Error("CUserRemoteStorage vtable at %p but candidate slots are not readable", vtableFuncs);
        return nullptr;
    }

    size_t cloudEnabledSlot = ResolveCloudEnabledSlot(vtableFuncs, steamBase, steamSize);
    if (cloudEnabledSlot == SIZE_MAX)
    {
        Log::Error("CUserRemoteStorage vtable at %p but could not resolve cloud-enabled slot", vtableFuncs);
        return nullptr;
    }

    Log::Info("CUserRemoteStorage vtable at %p (cloud-enabled slot%zu=%p)",
              vtableFuncs, cloudEnabledSlot, vtableFuncs[cloudEnabledSlot]);
    return vtableFuncs;
}

bool VtableHook::InstallCloudEnabledHook(void** vtable, CloudEnabledHookInfo& info)
{
    size_t slotIndex = ResolveCloudEnabledSlot(vtable, 0, UINTPTR_MAX);
    if (slotIndex == SIZE_MAX)
    {
        Log::Error("Could not resolve CUserRemoteStorage cloud-enabled slot");
        return false;
    }

    info.vtable = vtable;
    info.slotIndex = slotIndex;
    info.origSlot = vtable[slotIndex];

    void* slotAddr = &vtable[slotIndex];
    if (!MakeWritable(slotAddr, sizeof(void*)))
    {
        Log::Error("mprotect RW failed on RemoteStorage vtable slot %zu", slotIndex);
        return false;
    }

    vtable[slotIndex] = reinterpret_cast<void*>(&hook_IsCloudEnabledForApp);
    MakeReadOnly(slotAddr, sizeof(void*));

    Log::Info("IsCloudEnabledForApp hook installed at slot %zu (orig=%p)", slotIndex, info.origSlot);
    return true;
}

void VtableHook::RemoveCloudEnabledHook(const CloudEnabledHookInfo& info)
{
    if (!info.vtable) return;

    void* slotAddr = &info.vtable[info.slotIndex];
    if (MakeWritable(slotAddr, sizeof(void*)))
    {
        info.vtable[info.slotIndex] = info.origSlot;
        MakeReadOnly(slotAddr, sizeof(void*));
        Log::Info("IsCloudEnabledForApp hook removed");
    }
}
