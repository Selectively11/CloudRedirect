#include "gamesplayed_hook.h"
#include "stats_handlers.h"
#include "metadata_sync.h"
#include "log.h"

#include <atomic>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace GamesPlayedHook {

// CProtoBufMsg 32-bit layout (reversed from ctor): EMsg at +20 (high bit is the
// send flag, mask it off), body protobuf object pointer at +32.
static constexpr size_t OFF_EMSG = 20;
static constexpr size_t OFF_BODY = 32;
static constexpr uint32_t EMSG_MASK = 0x7FFFFFFF;

// CMsgClientGamesPlayed EMsg variants.
static constexpr uint32_t EMSG_GAMES_PLAYED               = 742;
static constexpr uint32_t EMSG_GAMES_PLAYED_NO_DATABLOB   = 715;
static constexpr uint32_t EMSG_GAMES_PLAYED_WITH_DATABLOB = 5410;
// CMsgClientStoreUserStats2 -- sent when a game unlocks an achievement / sets a stat.
static constexpr uint32_t EMSG_STORE_USER_STATS2         = 5466;

// Serialize a protobuf message object to raw bytes; installed by the platform
// layer so this file stays free of the protobuf-helper plumbing.
static SerializeBodyFn g_serializeBody = nullptr;

void SetSerializer(SerializeBodyFn fn) { g_serializeBody = fn; }

static std::atomic<bool> g_installed{false};
static std::atomic<bool> g_shuttingDown{false};
static std::atomic<int>  g_inFlight{0};

// Detour bookkeeping.
static uint8_t* g_funcStart = nullptr;     // resolved CCMInterface::Send entry
static uint8_t* g_hookPoint = nullptr;     // funcStart + PROLOGUE_LEN
static uint8_t  g_savedBytes[16];          // original bytes at the hook point
static size_t   g_savedLen = 0;
static uint8_t* g_trampoline = nullptr;    // executable: stolen bytes + jmp back

// The PIC prologue (push ebp/edi/esi/ebx; call get_pc_thunk; add ebx, delta) is
// position-locked, so we detour AFTER it. At the hook point ebx already holds
// the GOT base and the 4 register pushes are done.
//   +15: 83 EC 1C            sub  esp, 1Ch
//   +18: 8B 74 24 30         mov  esi, [esp+0x30]   ; a1 = cmInterface
//   +22: 8B 44 24 34         mov  eax, [esp+0x34]   ; a2 = msg
static constexpr size_t PROLOGUE_LEN = 15;  // bytes before the hook point
static constexpr size_t STOLEN_LEN   = 11;  // 3 esp-relative insns (position-independent)
static constexpr size_t RESUME_OFF   = PROLOGUE_LEN + STOLEN_LEN; // +26

// Signature for CCMInterface::Send entry. Wildcards (??) cover the PIC-relative
// call displacement and the add-ebx immediate, which both move with load addr.
// The struct offset at [esi+0x4F8] (connection state) shifted from 0x4FC in
// older builds — both are matched by wildcarding the low byte of the displacement.
//   55 57 56 53                push ebp/edi/esi/ebx
//   E8 ?? ?? ?? ??             call get_pc_thunk.bx
//   81 C3 ?? ?? ?? ??          add  ebx, <PIC delta>
//   83 EC 1C                   sub  esp, 1Ch
//   8B 74 24 30                mov  esi, [esp+0x30]
//   8B 44 24 34                mov  eax, [esp+0x34]
//   8B 96 F8/FC 04 00 00       mov  edx, [esi+0x4F8/0x4FC]
static const uint8_t  kSigBytes[] = {
    0x55,0x57,0x56,0x53, 0xE8,0,0,0,0, 0x81,0xC3,0,0,0,0,
    0x83,0xEC,0x1C, 0x8B,0x74,0x24,0x30, 0x8B,0x44,0x24,0x34,
    0x8B,0x96,0,0x04,0x00,0x00
};
static const uint8_t  kSigMask[] = {
    1,1,1,1, 1,0,0,0,0, 1,1,0,0,0,0,
    1,1,1, 1,1,1,1, 1,1,1,1,
    1,1,0,1,1,1
};
static constexpr size_t kSigLen = sizeof(kSigBytes);

// Hook: runs on Steam's network thread. Pure observer -- never blocks sends.
extern "C" int GamesPlayedHook_OnSend(int cmInterface, void* msg) {
    (void)cmInterface;
    g_inFlight.fetch_add(1, std::memory_order_acquire);
    if (!g_shuttingDown.load(std::memory_order_acquire) && msg && g_serializeBody) {
        uint32_t emsg = *(uint32_t*)((uint8_t*)msg + OFF_EMSG) & EMSG_MASK;

        bool isGamesPlayed = (emsg == EMSG_GAMES_PLAYED ||
                              emsg == EMSG_GAMES_PLAYED_NO_DATABLOB ||
                              emsg == EMSG_GAMES_PLAYED_WITH_DATABLOB);
        bool isStoreStats = (emsg == EMSG_STORE_USER_STATS2);

        if ((isGamesPlayed && MetadataSync::syncPlaytime.load(std::memory_order_relaxed)) ||
            (isStoreStats && MetadataSync::syncAchievements.load(std::memory_order_relaxed))) {
            void* bodyObj = *(void**)((uint8_t*)msg + OFF_BODY);
            if (bodyObj) {
                size_t len = 0;
                const uint8_t* bytes = g_serializeBody(bodyObj, &len);
                if (bytes && len > 0) {
                    if (isGamesPlayed) {
                        LOG("[Stats] GamesPlayed observed (emsg=%u, %zu bytes) -> session tracking",
                            emsg, len);
                        StatsHandlers::ObserveGamesPlayed(bytes, len);
                    } else {
                        LOG("[Stats] StoreUserStats2 observed (emsg=%u, %zu bytes) -> capturing unlocks",
                            emsg, len);
                        StatsHandlers::ObserveStoreUserStats(bytes, len);
                    }
                }
            }
        }
    }
    g_inFlight.fetch_sub(1, std::memory_order_release);
    return 0;
}

// 32-bit trampoline. Stolen insns load esi/eax first, then call OnSend.
// OnSend always returns 0; block path is dead but structurally kept.
//
//   <STOLEN_LEN stolen bytes>          ; sub esp,1Ch; mov esi,[esp+30]=a1; mov eax,[esp+34]=a2
//   pushad                            ; 60
//   push eax                          ; 50   arg2 = msg (a2)
//   push esi                          ; 56   arg1 = cmInterface (a1)
//   mov  eax, <OnSend>                ; B8 xx xx xx xx
//   call eax                          ; FF D0
//   add  esp, 8                       ; 83 C4 08
//   test eax, eax                     ; 85 C0
//   jnz  block_path                   ; 75 xx
//   popad                             ; 61
//   push <resume>                     ; 68 xx xx xx xx
//   ret                               ; C3
// block_path:
//   popad                             ; 61
//   add  esp, 1Ch                     ; 83 C4 1C    (undo stolen sub esp)
//   mov  eax, 1                       ; B8 01 00 00 00
//   pop  ebx                          ; 5B
//   pop  esi                          ; 5E
//   pop  edi                          ; 5F
//   pop  ebp                          ; 5D
//   ret                               ; C3
static bool BuildTrampoline(uint8_t* hookPoint) {
    long pageSize = sysconf(_SC_PAGESIZE);
    g_trampoline = (uint8_t*)mmap(nullptr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_trampoline == MAP_FAILED) {
        g_trampoline = nullptr;
        LOG("[GamesPlayed] mmap trampoline failed");
        return false;
    }

    uint8_t* p = g_trampoline;
    auto emit = [&](std::initializer_list<uint8_t> bytes) {
        for (uint8_t b : bytes) *p++ = b;
    };
    auto emit32 = [&](uint32_t v) {
        *p++ = v & 0xFF; *p++ = (v >> 8) & 0xFF; *p++ = (v >> 16) & 0xFF; *p++ = (v >> 24) & 0xFF;
    };

    // Stolen bytes first -- they set up esp and load esi=a1, eax=a2.
    memcpy(p, hookPoint, STOLEN_LEN);
    p += STOLEN_LEN;

    emit({0x60});                         // pushad
    emit({0x50});                         // push eax (a2=msg)
    emit({0x56});                         // push esi (a1=cmInterface)
    emit({0xB8}); emit32((uint32_t)(uintptr_t)&GamesPlayedHook_OnSend); // mov eax, OnSend
    emit({0xFF, 0xD0});                   // call eax
    emit({0x83, 0xC4, 0x08});             // add esp, 8
    emit({0x85, 0xC0});                   // test eax, eax
    // jnz block_path (offset filled below)
    uint8_t* jnzPatch = p;
    emit({0x75, 0x00});                   // jnz +?? (patched)

    // --- pass-through path ---
    emit({0x61});                         // popad
    uintptr_t resume = (uintptr_t)(hookPoint - PROLOGUE_LEN) + RESUME_OFF;
    emit({0x68}); emit32((uint32_t)resume); // push resume
    emit({0xC3});                           // ret

    // --- block path: skip the original send, return 1 ---
    uint8_t* blockAddr = p;
    jnzPatch[1] = (uint8_t)(blockAddr - (jnzPatch + 2)); // patch jnz offset
    emit({0x61});                         // popad
    emit({0x83, 0xC4, 0x1C});             // add esp, 1Ch (undo stolen sub esp)
    emit({0xB8}); emit32(1);              // mov eax, 1 (return success)
    emit({0x5B});                         // pop ebx
    emit({0x5E});                         // pop esi
    emit({0x5F});                         // pop edi
    emit({0x5D});                         // pop ebp
    emit({0xC3});                         // ret
    return true;
}

static bool FindBySignature(uintptr_t base, size_t size, uint8_t*& outFuncStart) {
    if (size < kSigLen) return false;
    const uint8_t* start = (const uint8_t*)base;
    const uint8_t* end = start + size - kSigLen;
    for (const uint8_t* s = start; s <= end; ++s) {
        bool match = true;
        for (size_t i = 0; i < kSigLen; ++i) {
            if (kSigMask[i] && s[i] != kSigBytes[i]) { match = false; break; }
        }
        if (match) {
            outFuncStart = const_cast<uint8_t*>(s);
            return true;
        }
    }
    return false;
}

static bool MakeWritable(void* addr, size_t len) {
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(pageSize - 1);
    uintptr_t endAddr = (uintptr_t)addr + len;
    size_t pageLen = ((endAddr - page) + (pageSize - 1)) & ~(size_t)(pageSize - 1);
    return mprotect((void*)page, pageLen, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

bool Install(uintptr_t steamclientBase, size_t steamclientSize) {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) return true;

    uint8_t* funcStart = nullptr;
    if (!FindBySignature(steamclientBase, steamclientSize, funcStart)) {
        LOG("[GamesPlayed] CCMInterface::Send signature not found -- playtime tracking disabled");
        g_installed.store(false);
        return false;
    }
    LOG("[GamesPlayed] CCMInterface::Send found at %p (sc+0x%zx)",
        funcStart, (size_t)((uintptr_t)funcStart - steamclientBase));

    g_funcStart = funcStart;
    g_hookPoint = funcStart + PROLOGUE_LEN;

    if (!BuildTrampoline(g_hookPoint)) {
        g_installed.store(false);
        return false;
    }

    g_savedLen = STOLEN_LEN;
    memcpy(g_savedBytes, g_hookPoint, g_savedLen);

    if (!MakeWritable(g_hookPoint, g_savedLen)) {
        LOG("[GamesPlayed] mprotect RWX failed at hook point");
        g_installed.store(false);
        return false;
    }

    // E9 rel32 jmp to the trampoline; pad remaining stolen bytes with NOP.
    int32_t rel = (int32_t)((uintptr_t)g_trampoline - ((uintptr_t)g_hookPoint + 5));
    g_hookPoint[0] = 0xE9;
    memcpy(g_hookPoint + 1, &rel, 4);
    for (size_t i = 5; i < g_savedLen; ++i) g_hookPoint[i] = 0x90; // nop

    __builtin___clear_cache((char*)g_hookPoint, (char*)g_hookPoint + g_savedLen);
    LOG("[GamesPlayed] Inline detour installed at %p -> trampoline %p", g_hookPoint, g_trampoline);
    return true;
}

void Remove() {
    if (!g_installed.load(std::memory_order_acquire)) return;
    g_shuttingDown.store(true, std::memory_order_release);

    if (g_hookPoint && MakeWritable(g_hookPoint, g_savedLen)) {
        memcpy(g_hookPoint, g_savedBytes, g_savedLen);
        __builtin___clear_cache((char*)g_hookPoint, (char*)g_hookPoint + g_savedLen);
    }
    for (int i = 0; i < 300 && g_inFlight.load(std::memory_order_acquire) > 0; ++i)
        usleep(10000); // up to 3s

    g_installed.store(false, std::memory_order_release);
}

} // namespace GamesPlayedHook
