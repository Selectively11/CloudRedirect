#include "achievement_inject.h"
#include "stats_handlers.h"
#include "cloud_intercept.h"
#include "protobuf.h"
#include "log.h"

#include <atomic>
#include <cstring>
#include <csetjmp>
#include <csignal>
#include <mutex>
#include <queue>
#include <unistd.h>

namespace AchievementInject {

// ── Resolved steamclient.so entry points (file offsets from IDA) ────────────
//   sub_2AC1EC0  WrapPacket:     (rawPkt{?,data@+4,size@+8}, 1) -> CProtoBufNetPacket*
//   sub_2A6A1E0  BRouteMsgToJob: (jobMgr, connCtx, wrappedPkt, route, -1) -> routed?
//   dword_2ECDB40 (.bss)         engine global pointer; jobMgr = *engine + 0x1B8
// CProtoBufMsg layout (32-bit): EMsg @ +20, header buffer ptr @ +28, body @ +32.
// Parsed CM header: jobid_target @ hdr+7, jobid_source @ hdr+15 (byte offsets).
using WrapPacketFn    = void*(*)(void* rawPkt, char addRef);
using BRouteMsgFn     = char(*)(int jobMgr, int connCtx, void* wrappedPkt, void* route, int from);

static constexpr uintptr_t RVA_WRAP_PACKET = 0x2AC1EC0;
static constexpr uintptr_t RVA_BROUTE      = 0x2A6A1E0;
static constexpr uintptr_t RVA_ENGINE_GLOBAL = 0x2ECDB40;
static constexpr uintptr_t RVA_JOBCUR_GLOBAL = 0x2F00A60;  // g_pJobCur (current job)
static constexpr uint32_t  ENGINE_OFF_JOBMGR = 0x1B8;   // jobMgr = *engine + 0x1B8
static constexpr uint32_t  CCM_OFF_CONNCTX   = 1404;    // connCtx = *(cmInterface+1404)
static constexpr uint32_t  JOB_OFF_JOBID     = 16;      // CJob+16 = jobid (CJob ctor sub_2A5A170)

static constexpr uint32_t EMSG_GET_USER_STATS  = 818;
static constexpr uint32_t EMSG_GET_USER_STATS_RESP = 819;
static constexpr uint32_t EMSG_PROTO_FLAG = 0x80000000u;

// CMsgProtoBufHeader field numbers. Routing is by jobid_target; steamid is
// included so the response header validates against the connection.
static constexpr uint32_t HDR_F_STEAMID   = 1;   // fixed64
static constexpr uint32_t HDR_F_JOBID_TARGET = 11; // fixed64

static uintptr_t  g_base = 0;
static WrapPacketFn g_wrapPacket = nullptr;
static BRouteMsgFn  g_bRoute = nullptr;
static SerializeBodyFn g_serializeBody = nullptr;

// ── Signatures (PIC call/add displacements wildcarded) ──────────────────────
// sub_2AC1EC0: 55 89 E5 57 E8 ?? ?? ?? ?? 81 C7 ?? ?? ?? ?? 56 53 83 EC 5C 8B 5D 08 65 8B 15
static const uint8_t kWrapB[] = {0x55,0x89,0xE5,0x57,0xE8,0,0,0,0,0x81,0xC7,0,0,0,0,0x56,0x53,0x83,0xEC,0x5C,0x8B,0x5D,0x08,0x65,0x8B,0x15};
static const uint8_t kWrapM[] = {1,1,1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1};
// sub_2A6A1E0: 55 89 E5 57 56 E8 ?? ?? ?? ?? 81 C6 ?? ?? ?? ?? 53 83 EC 7C 8B 45 08 8B 4D 14 89 45 90
static const uint8_t kRouteB[] = {0x55,0x89,0xE5,0x57,0x56,0xE8,0,0,0,0,0x81,0xC6,0,0,0,0,0x53,0x83,0xEC,0x7C,0x8B,0x45,0x08,0x8B,0x4D,0x14,0x89,0x45,0x90};
static const uint8_t kRouteM[] = {1,1,1,1,1,1,0,0,0,0,1,1,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1};

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

// ── Crash guard for the wrap/route calls (a layout mismatch faults to SIGSEGV;
//    convert it to a skipped inject rather than taking down steamwebhelper). ───
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_inCall = 0;
static void CrashHandler(int sig) { if (g_inCall) siglongjmp(g_jmp, sig); raise(sig); }
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

// One pending 819 response: the 818's jobid + the app + the captured cmInterface.
struct Pending {
    uint64_t jobIdTarget;
    uint32_t appId;
    void*    cmInterface;
};
static std::queue<Pending> g_queue;
static std::mutex g_queueMutex;

bool Resolve(uintptr_t base, size_t size, SerializeBodyFn serialize) {
    g_base = base;
    g_serializeBody = serialize;
    void* wrap  = ScanSig(base, size, kWrapB,  kWrapM,  sizeof(kWrapB));
    void* route = ScanSig(base, size, kRouteB, kRouteM, sizeof(kRouteB));
    if (!wrap || !route) {
        LOG("[Stats] AchievementInject: signature scan incomplete (wrap=%p route=%p) -- legacy 818 serve disabled",
            wrap, route);
        return false;
    }
    g_wrapPacket = (WrapPacketFn)wrap;
    g_bRoute = (BRouteMsgFn)route;
    LOG("[Stats] AchievementInject resolved: WrapPacket=%p BRouteMsgToJob=%p", wrap, route);
    return true;
}

bool Ready() { return g_wrapPacket && g_bRoute && g_base && g_serializeBody; }

void ObserveOutbound(uint32_t emsg, void* msgObj, void* cmInterface) {
    if (!Ready() || emsg != EMSG_GET_USER_STATS || !msgObj || !cmInterface) return;

    uint64_t jobId = 0;
    void* bodyObj = nullptr;
    {
        // The outbound 818 header has no jobid yet (stamped at final serialize).
        // Read it from the sending coroutine instead: g_pJobCur is the
        // CAPIJobRequestUserStats, jobid at CJob+16 (ctor sub_2A5A170).
        CallGuard guard;
        if (sigsetjmp(g_jmp, 1) != 0) return;
        uintptr_t jobCur = *(uintptr_t*)(g_base + RVA_JOBCUR_GLOBAL);
        if (jobCur) jobId = *(uint64_t*)(jobCur + JOB_OFF_JOBID);
        bodyObj = *(void**)((uint8_t*)msgObj + 32);
    }
    if (!bodyObj) return;

    // game_id is field 1 (fixed64) of the body. Serialize + parse it.
    size_t blen = 0;
    const uint8_t* bbytes = g_serializeBody(bodyObj, &blen);
    if (!bbytes || blen == 0) return;
    auto fields = PB::Parse(bbytes, blen);
    auto* f1 = PB::FindField(fields, 1);
    uint32_t appId = f1 ? (uint32_t)(f1->varintVal & 0xFFFFFF) : 0;
    if (appId == 0 || !CloudIntercept::IsNamespaceApp(appId)) return;

    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_queue.push(Pending{jobId, appId, cmInterface});
    }
    LOG("[Stats] Observed legacy GetUserStats(818) app=%u jobid=%llu -> queued 819",
        appId, (unsigned long long)jobId);
}

// Build the raw CM wire bytes for a 819 response: [EMsg|protoflag][hdrLen][header]
// [body], matching the CProtoBuf packet framing the wrap function expects.
static std::vector<uint8_t> BuildWirePacket(uint64_t jobIdTarget,
                                            const std::vector<uint8_t>& body) {
    // Header: steamid, client_sessionid, jobid_target (the request's jobid_source).
    PB::Writer hdr;
    uint64_t steamId = (uint64_t)CloudIntercept::GetAccountId()
                     | (1ULL << 32) | (1ULL << 52) | (1ULL << 56);
    hdr.WriteFixed64(HDR_F_STEAMID, steamId);
    hdr.WriteFixed64(HDR_F_JOBID_TARGET, jobIdTarget);
    auto hdrBytes = hdr.Data();

    std::vector<uint8_t> pkt;
    pkt.reserve(4 + 4 + hdrBytes.size() + body.size());
    uint32_t emsg = EMSG_GET_USER_STATS_RESP | EMSG_PROTO_FLAG;
    pkt.push_back(emsg & 0xFF); pkt.push_back((emsg >> 8) & 0xFF);
    pkt.push_back((emsg >> 16) & 0xFF); pkt.push_back((emsg >> 24) & 0xFF);
    uint32_t hl = (uint32_t)hdrBytes.size();
    pkt.push_back(hl & 0xFF); pkt.push_back((hl >> 8) & 0xFF);
    pkt.push_back((hl >> 16) & 0xFF); pkt.push_back((hl >> 24) & 0xFF);
    pkt.insert(pkt.end(), hdrBytes.begin(), hdrBytes.end());
    pkt.insert(pkt.end(), body.begin(), body.end());
    return pkt;
}

// CNetPacket shell handed to WrapPacket (layout from CNetPacket::AddRef sub_2AEC230):
//   +0 ?, +4 data, +8 size, +12 refcount, +16 owned-copy buffer.
// We seed refcount=1 so WrapPacket's AddRef (-> 2) copies our wire bytes into a
// steam-owned buffer, removing any dependency on this stack data's lifetime.
struct RawPkt { uint32_t pad0; const uint8_t* data; uint32_t size; uint32_t refcount; uint32_t copyBuf; uint32_t pad[3]; };

static void RouteOne(const Pending& p) {
    // Build the 819 body from our store via the shared legacy handler. We hand it
    // a minimal request body (game_id + crc=0 to force a full send) so it resolves
    // the app and emits schema + stats + achievement_blocks.
    PB::Writer reqBody;
    reqBody.WriteFixed64(1, (uint64_t)p.appId);  // game_id
    reqBody.WriteVarint(2, 0);                    // crc_stats = 0 (force send)
    reqBody.WriteVarint(3, (uint64_t)(int64_t)-1);// schema_local_version = -1
    auto reqBytes = reqBody.Data();

    auto built = StatsHandlers::HandleLegacyGetUserStats(reqBytes.data(), reqBytes.size(), 0);
    if (!built.has_value() || built->empty()) {
        LOG("[Stats] 819 for app=%u: store had nothing to serve", p.appId);
        return;
    }

    auto wire = BuildWirePacket(p.jobIdTarget, *built);

    CallGuard guard;
    if (sigsetjmp(g_jmp, 1) != 0) {
        LOG("[Stats] 819 inject for app=%u crashed -- skipped", p.appId);
        return;
    }

    RawPkt raw = {};
    raw.data = wire.data();
    raw.size = (uint32_t)wire.size();
    raw.refcount = 1;   // AddRef -> 2 forces a steam-owned copy of the data

    void* wrapped = g_wrapPacket(&raw, 1);
    if (!wrapped) {
        LOG("[Stats] 819 inject app=%u: WrapPacket returned null", p.appId);
        return;
    }

    uint32_t engine = *(uint32_t*)(g_base + RVA_ENGINE_GLOBAL);
    int jobMgr = (int)(engine + ENGINE_OFF_JOBMGR);
    int connCtx = *(int*)((uint8_t*)p.cmInterface + CCM_OFF_CONNCTX);

    // route layout (from CCMInterface::RecvPkt asm): +0/+4 = -1, +8 = jobid_target
    // (QWORD, also carried in the packet header), +16 = emsg, +20 = realm(-3).
    uint8_t route[24] = {0};
    *(int32_t*)(route + 0)  = -1;
    *(int32_t*)(route + 4)  = -1;
    *(uint64_t*)(route + 8) = p.jobIdTarget;
    *(int32_t*)(route + 16) = (int32_t)EMSG_GET_USER_STATS_RESP;
    *(int32_t*)(route + 20) = -3;

    char ok = g_bRoute(jobMgr, connCtx, wrapped, route, -1);
    LOG("[Stats] 819 inject app=%u jobid=%llu -> BRouteMsgToJob=%d",
        p.appId, (unsigned long long)p.jobIdTarget, (int)ok);
}

void DrainOnNetThread() {
    if (!Ready()) return;
    std::vector<Pending> batch;
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        while (!g_queue.empty()) { batch.push_back(g_queue.front()); g_queue.pop(); }
    }
    for (auto& p : batch) RouteOne(p);
}

} // namespace AchievementInject
