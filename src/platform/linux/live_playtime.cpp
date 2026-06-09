#include "live_playtime.h"
#include "log.h"

#include <atomic>
#include <cstring>
#include <csetjmp>
#include <csignal>
#include <mutex>
#include <queue>
#include <sys/mman.h>
#include <unistd.h>

namespace LivePlaytime {

// Resolved steamclient.so entry points (file offsets from IDA, base added at
// runtime; sig-scanned below).
//   sub_182F530  writer:   (CUser*, Game** games, int count) -> syncTime
//   sub_182F840  wrapper:  (CUser*, Response_msg*) -> calls writer (games@+20,count@+12)
//   sub_2AC91C0  msg ctor: zeroes the CProtoBufMsg wrapper
//   sub_2ACA490  msg init: allocates the inner MessageLite body at wrapper[8]
//   sub_2AC8970  msg dtor
//   sub_1132CD0  registry int write (CUser+2648 obj, 3, key, val)
//   off_2E15B4C  CProtoBufMsg<...Response> typed wrapper vtable
//   off_2EA3FFC  CPlayer_GetLastPlayedTimes_Response descriptor
using WriterFn   = int(*)(int pUser, int games, int count);
using WrapperFn  = int(*)(int pUser, int respMsg);
using MsgCtorFn  = void(*)(int self, int a2, int a3);
using MsgInitFn  = void(*)(int self);
using MsgDtorFn  = void(*)(int self);

static uintptr_t g_base = 0;
static ParseFromArrayFn g_parseFromArray = nullptr;
static WrapperFn  g_wrapper = nullptr;   // sub_182F840
static MsgCtorFn  g_msgCtor = nullptr;
static MsgInitFn  g_msgInit = nullptr;
static MsgDtorFn  g_msgDtor = nullptr;
static uintptr_t  g_respWrapperVt = 0;   // base + 0x2E15B4C
static uintptr_t  g_respDescriptor = 0;  // base + 0x2EA3FFC

// Inner CPlayer_GetLastPlayedTimes_Response (32-bit): games array ptr @ +20,
// element count @ +12. CProtoBufMsg wrapper: inner body at wrapper[8].
static constexpr size_t RESP_OFF_GAMES_ARRAY = 20;
static constexpr size_t RESP_OFF_GAMES_COUNT = 12;
static constexpr size_t WRAP_INNER_SLOT      = 8;   // wrapper[8] = m_pProtoBufBody
static constexpr size_t WRAP_DWORDS          = 12;  // wrapper allocation (msg ctor writes up to +0x1C)

// Captured CUser pointer (recorded by the writer-entry detour).
static std::atomic<int> g_pUser{0};

// Signature scan; PIC call/add displacements are wildcarded.
struct Sig { const uint8_t* bytes; const uint8_t* mask; size_t len; };

// writer sub_182F530:  E8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 55 89 E5 57 56 53 83 EC 3C 8B 4D 10 89 45 D0 85 C9 0F 8E
static const uint8_t kWriterB[] = {0xE8,0,0,0,0, 0x05,0,0,0,0, 0x55,0x89,0xE5,0x57,0x56,0x53,0x83,0xEC,0x3C,0x8B,0x4D,0x10,0x89,0x45,0xD0,0x85,0xC9,0x0F,0x8E};
static const uint8_t kWriterM[] = {1,0,0,0,0, 1,0,0,0,0, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};

// Wrapper sub_182F840 loads games@[a2+20]/count@[a2+12]; Apply() inlines those,
// so only the writer + message helpers are sig-scanned.

// msg ctor sub_2AC91C0: 57 56 53 8B 74 24 10 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 83 EC 08 C7 46 04 00 00 00 00
static const uint8_t kCtorB[] = {0x57,0x56,0x53,0x8B,0x74,0x24,0x10,0xE8,0,0,0,0,0x81,0xC3,0,0,0,0,0x83,0xEC,0x08,0xC7,0x46,0x04,0,0,0,0};
static const uint8_t kCtorM[] = {1,1,1,1,1,1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,1,1,1,1,0,0,0,0};

// msg init sub_2ACA490: 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 83 EC 04 8B 74 24 10 8B 46 20 85 C0 74 22
static const uint8_t kInitB[] = {0x56,0x53,0xE8,0,0,0,0,0x81,0xC3,0,0,0,0,0x83,0xEC,0x04,0x8B,0x74,0x24,0x10,0x8B,0x46,0x20,0x85,0xC0,0x74,0x22};
static const uint8_t kInitM[] = {1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1};

// msg dtor sub_2AC8970: 57 56 E8 ?? ?? ?? ?? 81 C6 ?? ?? ?? ?? 53 8B 5C 24 10 8B 53 28
static const uint8_t kDtorB[] = {0x57,0x56,0xE8,0,0,0,0,0x81,0xC6,0,0,0,0,0x53,0x8B,0x5C,0x24,0x10,0x8B,0x53,0x28};
static const uint8_t kDtorM[] = {1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,1,1,1,1,1,1};

static void* ScanSig(uintptr_t base, size_t size, const uint8_t* b, const uint8_t* m, size_t len) {
    if (size < len) return nullptr;
    const uint8_t* s = (const uint8_t*)base;
    const uint8_t* end = s + size - len;
    for (; s <= end; ++s) {
        bool ok = true;
        for (size_t i = 0; i < len; ++i)
            if (m[i] && s[i] != b[i]) { ok = false; break; }
        if (ok) return (void*)s;
    }
    return nullptr;
}

// Crash guard: a layout mismatch in the parse/writer calls faults to SIGSEGV;
// convert it to a skipped update instead of a crash.
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_inCall = 0;
static void CrashHandler(int sig) {
    if (g_inCall) siglongjmp(g_jmp, sig);
    raise(sig);
}
class CallGuard {
public:
    CallGuard() {
        struct sigaction sa = {};
        sa.sa_handler = CrashHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESETHAND;
        sigaction(SIGSEGV, &sa, &m_segv);
        sigaction(SIGBUS, &sa, &m_bus);
        g_inCall = 1;
    }
    ~CallGuard() {
        g_inCall = 0;
        sigaction(SIGSEGV, &m_segv, nullptr);
        sigaction(SIGBUS, &m_bus, nullptr);
    }
private:
    struct sigaction m_segv = {};
    struct sigaction m_bus = {};
};

// CUser-capture detour on the writer entry. Writer (__cdecl) prologue:
//   +0x00 call get_pc_thunk; +0x05 add eax,delta   (PIC)
//   +0x0A push ebp; +0x0B mov ebp,esp
//   +0x0D push edi; +0x0E push esi; +0x0F push ebx; +0x10 sub esp,0x3C
// Detour at +0x0D (frame established, a1=CUser at [ebp+8]); the stolen bytes are
// position-independent and run in the trampoline before resuming.
static constexpr size_t WRITER_PROLOGUE = 0x0D; // detour point offset
static constexpr size_t WRITER_STOLEN   = 6;    // 57 56 53 83 EC 3C
static constexpr size_t WRITER_RESUME   = WRITER_PROLOGUE + WRITER_STOLEN;

static std::atomic<bool> g_captureInstalled{false};
static uint8_t* g_writerStart = nullptr;
static uint8_t* g_hookPoint = nullptr;
static uint8_t  g_savedBytes[16];
static size_t   g_savedLen = 0;
static uint8_t* g_trampoline = nullptr;

// Recorded on the writer's natural entry. ebp+8 = a1 = CUser.
extern "C" void LivePlaytime_CaptureUser(int pUser) {
    if (pUser && !g_pUser.load(std::memory_order_acquire)) {
        g_pUser.store(pUser, std::memory_order_release);
        LOG("[Stats] Captured CUser=%p for live playtime updates", (void*)(uintptr_t)pUser);
    }
}

static bool MakeWritable(void* addr, size_t len) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(ps - 1);
    uintptr_t endA = (uintptr_t)addr + len;
    size_t pl = ((endA - page) + (ps - 1)) & ~(size_t)(ps - 1);
    return mprotect((void*)page, pl, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

// Trampoline: run stolen bytes, then read CUser from [ebp+8] and call the
// capture hook, then resume. ebp is already valid at the hook point.
//   <stolen: push edi; push esi; push ebx; sub esp,0x3C>
//   pushad
//   push dword [ebp+8]        ; a1 = CUser
//   mov  eax, LivePlaytime_CaptureUser
//   call eax
//   add  esp, 4
//   popad
//   push <resume>
//   ret
static bool BuildTrampoline(uint8_t* hookPoint) {
    long ps = sysconf(_SC_PAGESIZE);
    g_trampoline = (uint8_t*)mmap(nullptr, ps, PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_trampoline == MAP_FAILED) { g_trampoline = nullptr; return false; }

    uint8_t* p = g_trampoline;
    auto emit = [&](std::initializer_list<uint8_t> b) { for (uint8_t x : b) *p++ = x; };
    auto emit32 = [&](uint32_t v) { *p++=v&0xFF; *p++=(v>>8)&0xFF; *p++=(v>>16)&0xFF; *p++=(v>>24)&0xFF; };

    memcpy(p, hookPoint, WRITER_STOLEN);  // stolen prologue insns
    p += WRITER_STOLEN;

    emit({0x60});                                   // pushad
    emit({0xFF, 0x75, 0x08});                       // push dword [ebp+8]  (CUser)
    emit({0xB8}); emit32((uint32_t)(uintptr_t)&LivePlaytime_CaptureUser); // mov eax, hook
    emit({0xFF, 0xD0});                             // call eax
    emit({0x83, 0xC4, 0x04});                       // add esp, 4
    emit({0x61});                                   // popad

    uintptr_t resume = (uintptr_t)g_writerStart + WRITER_RESUME;
    emit({0x68}); emit32((uint32_t)resume);         // push resume
    emit({0xC3});                                   // ret
    return true;
}

bool Resolve(uintptr_t base, size_t size, ParseFromArrayFn parse) {
    g_base = base;
    g_parseFromArray = parse;

    void* writer = ScanSig(base, size, kWriterB, kWriterM, sizeof(kWriterB));
    void* ctor   = ScanSig(base, size, kCtorB,   kCtorM,   sizeof(kCtorB));
    void* init   = ScanSig(base, size, kInitB,   kInitM,   sizeof(kInitB));
    void* dtor   = ScanSig(base, size, kDtorB,   kDtorM,   sizeof(kDtorB));

    if (!writer || !ctor || !init || !dtor) {
        LOG("[Stats] LivePlaytime: signature scan incomplete (writer=%p ctor=%p init=%p dtor=%p) -- live UI updates disabled",
            writer, ctor, init, dtor);
        return false;
    }

    g_writerStart = (uint8_t*)writer;
    g_msgCtor = (MsgCtorFn)ctor;
    g_msgInit = (MsgInitFn)init;
    g_msgDtor = (MsgDtorFn)dtor;
    g_respWrapperVt  = base + 0x2E15B4C;
    g_respDescriptor = base + 0x2EA3FFC;

    LOG("[Stats] LivePlaytime resolved: writer=%p ctor=%p init=%p dtor=%p",
        writer, ctor, init, dtor);
    return true;
}

bool InstallUserCapture() {
    if (!g_writerStart) return false;
    bool expected = false;
    if (!g_captureInstalled.compare_exchange_strong(expected, true)) return true;

    g_hookPoint = g_writerStart + WRITER_PROLOGUE;
    if (!BuildTrampoline(g_hookPoint)) {
        g_captureInstalled.store(false);
        return false;
    }
    g_savedLen = WRITER_STOLEN;
    memcpy(g_savedBytes, g_hookPoint, g_savedLen);
    if (!MakeWritable(g_hookPoint, g_savedLen)) {
        g_captureInstalled.store(false);
        return false;
    }
    int32_t rel = (int32_t)((uintptr_t)g_trampoline - ((uintptr_t)g_hookPoint + 5));
    g_hookPoint[0] = 0xE9;
    memcpy(g_hookPoint + 1, &rel, 4);
    for (size_t i = 5; i < g_savedLen; ++i) g_hookPoint[i] = 0x90; // nop pad
    __builtin___clear_cache((char*)g_hookPoint, (char*)g_hookPoint + g_savedLen);
    LOG("[Stats] LivePlaytime CUser-capture detour installed at %p", g_hookPoint);
    return true;
}

void RemoveUserCapture() {
    if (!g_captureInstalled.load(std::memory_order_acquire)) return;
    if (g_hookPoint && MakeWritable(g_hookPoint, g_savedLen)) {
        memcpy(g_hookPoint, g_savedBytes, g_savedLen);
        __builtin___clear_cache((char*)g_hookPoint, (char*)g_hookPoint + g_savedLen);
    }
    g_captureInstalled.store(false, std::memory_order_release);
}

bool Ready() {
    return g_msgCtor && g_msgInit && g_msgDtor && g_parseFromArray &&
           g_pUser.load(std::memory_order_acquire) != 0;
}

void Apply(const std::vector<uint8_t>& respBody) {
    if (respBody.empty() || !Ready()) return;
    int pUser = g_pUser.load(std::memory_order_acquire);

    // CProtoBufMsg<CPlayer_GetLastPlayedTimes_Response> on the stack (sub_182F8A0):
    // ctor zeroes it, [0]=typed vtable, [1]=descriptor, init allocates the inner
    // MessageLite body at wrapper[8].
    uint32_t wrapper[WRAP_DWORDS] = {0};

    CallGuard guard;
    if (sigsetjmp(g_jmp, 1) != 0) {
        LOG("[Stats] LivePlaytime::Apply crashed in steamclient call -- skipped");
        return;
    }

    g_msgCtor((int)(uintptr_t)wrapper, 0, 0);
    wrapper[0] = (uint32_t)g_respWrapperVt;
    wrapper[1] = (uint32_t)g_respDescriptor;
    g_msgInit((int)(uintptr_t)wrapper);

    int inner = (int)wrapper[WRAP_INNER_SLOT];
    if (!inner) {
        LOG("[Stats] LivePlaytime::Apply: inner body alloc failed");
        return;
    }

    if (!g_parseFromArray((void*)(uintptr_t)inner, respBody.data(), (int)respBody.size())) {
        LOG("[Stats] LivePlaytime::Apply: ParseFromArray failed (%zu bytes)", respBody.size());
        g_msgDtor((int)(uintptr_t)wrapper);
        return;
    }

    // sub_182F840: v = *(inner+20); if (v) v += 4; writer(pUser, v, *(inner+12)).
    int arrayBase = *(int*)((uint8_t*)(uintptr_t)inner + RESP_OFF_GAMES_ARRAY);
    int count     = *(int*)((uint8_t*)(uintptr_t)inner + RESP_OFF_GAMES_COUNT);
    int games     = arrayBase ? (arrayBase + 4) : 0;

    if (games && count > 0) {
        auto writer = (WriterFn)(g_writerStart);
        writer(pUser, games, count);
        LOG("[Stats] LivePlaytime::Apply: pushed %d game(s) to live client map", count);
    } else {
        LOG("[Stats] LivePlaytime::Apply: no games parsed (count=%d)", count);
    }

    g_msgDtor((int)(uintptr_t)wrapper);
}

// ── Net-thread-safe queue ──────────────────────────────────────────────────
static std::queue<std::vector<uint8_t>> g_queue;
static std::mutex g_queueMutex;

void Queue(const std::vector<uint8_t>& respBody) {
    if (respBody.empty()) return;
    std::lock_guard<std::mutex> lock(g_queueMutex);
    g_queue.push(respBody);
}

void DrainOnNetThread() {
    if (!Ready()) return;
    std::vector<std::vector<uint8_t>> batch;
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        while (!g_queue.empty()) {
            batch.push_back(std::move(g_queue.front()));
            g_queue.pop();
        }
    }
    for (auto& body : batch)
        Apply(body);
}

} // namespace LivePlaytime
