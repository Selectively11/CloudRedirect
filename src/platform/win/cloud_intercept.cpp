#include "cloud_intercept.h"
#include "metadata_sync.h"
#include "rpc_handlers.h"
#include "stats_handlers.h"
#include "stats_store.h"
#include "app_state.h"
#include "protobuf.h"
#include "parental_bypass.h"
#include "steam_kv_injector.h"
#include "sc_resolver.h"
#include "sig_scanner.h"
#include "log.h"
#include "http_server.h"
#include "vdf.h"
#include "http_util.h"
#include "local_storage.h"
#include "cloud_storage.h"
#include "coop_yield.h"
#include "cloud_provider.h"
#include "cloud_provider_base.h" // g_uploadInFlightCapBytes
#include "pending_ops_journal.h"
#include "json.h"
#include "legacy_metadata_cleanup.h"
#include "file_util.h"
#include "miniz.h"
#include "miniz_zip.h"

// #define DEBUG_HEX_DUMP  // Enable to capture real Steam responses

#include <shlobj.h>
#include <psapi.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <queue>
#include <fstream>
#include <optional>
#include <chrono>
#include <limits>
#include <thread>

namespace AutoCloudScan { std::string GetAppName(const std::string& steamPath, uint32_t appId); }

namespace CloudIntercept {

static void ShutdownImpl();
static void InstallExitProcessHook();

static constexpr uint32_t PROTO_FLAG = 0x80000000;
static constexpr uint32_t EMSG_MASK = 0x7FFFFFFF;
static constexpr uint32_t EMSG_SERVICE_METHOD = 151;
static constexpr uint32_t EMSG_SERVICE_METHOD_RESP = 147;
static constexpr uint32_t EMSG_CLIENT_GET_USER_STATS_RESP = 819;  // schema-fetch response
static constexpr uint64_t JOBID_NONE = 0xFFFFFFFFFFFFFFFFULL;

static constexpr uint32_t HDR_STEAMID = 1;
static constexpr uint32_t HDR_SESSIONID = 2;
static constexpr uint32_t HDR_JOBID_SOURCE = 10;
static constexpr uint32_t HDR_JOBID_TARGET = 11;
static constexpr uint32_t HDR_TARGET_JOB_NAME = 12;
static constexpr uint32_t HDR_ERESULT = 13;

// Payload.dll RVAs (still needed for SteamTools integration)
static constexpr uintptr_t RVA_RECV_PKT_GLOBAL     = 0x1CAB48;
static constexpr uintptr_t RVA_CM_HANDLER_ORIG     = 0x1CAAF0;  // g_pfnOriginalCMServerHandler
static constexpr uintptr_t RVA_CM_VTABLE_SLOT      = 0x1CAB38;  // vtable slot where payload installed CMServerHandler_Hooked
static constexpr uintptr_t RVA_DEPOT_MANIFESTS     = 0x1C3868;  // g_pDepotManifests (heap ptr)
static constexpr uintptr_t RVA_DEPOT_MANIFEST_CNT  = 0x1C3870;  // g_nDepotManifestCount

static constexpr uint32_t EMSG_CLIENT_PICSPRODUCTINFO = 8903;

// CMsgClientGamesPlayed EMsg variants
static constexpr uint32_t EMSG_CLIENT_GAMES_PLAYED              = 742;
static constexpr uint32_t EMSG_CLIENT_GAMES_PLAYED_NO_DATABLOB  = 715;
static constexpr uint32_t EMSG_CLIENT_GAMES_PLAYED_WITH_DATABLOB = 5410;
// CMsgClientStoreUserStats2 -- sent when a game unlocks an achievement / sets a stat.
static constexpr uint32_t EMSG_CLIENT_STORE_USER_STATS2        = 5466;

// CMsgClientGamesPlayed protobuf field numbers
static constexpr uint32_t GP_FIELD_GAMES_PLAYED    = 1;   // repeated GamePlayed (length-delimited)
// CMsgClientGamesPlayed.GamePlayed field numbers
static constexpr uint32_t GP_FIELD_GAME_ID         = 2;   // fixed64
static constexpr uint32_t GP_FIELD_GAME_EXTRA_INFO = 7;   // string
static constexpr uint32_t GP_FIELD_OWNER_ID        = 12;  // uint32

// steamclient64.dll RVAs for manifest pinning inline detour
// IDA image base: 0x138000000
// sub_1384C4040 = CUserAppManager::BuildDepotDependency
// Signature: __int64 __fastcall(QWORD* a1, uint a2, int64 a3, int64 a4, int64 a5, int64 a6, DWORD* a7, BYTE* a8)
//   a1 (rcx) = CUserAppManager*
//   a2 (edx) = appId
//   a4 (r9)  = output depot vector (app's own depots)
//   a5 ([rsp+28h]) = output depot vector (DLC/shared depots)
// Depot vectors: *(QWORD*)vec = array base, *(int*)(vec+16) = count
// Each entry is 32 bytes: {uint32 depotId, uint32 appId, uint64 manifestId, ...}
static constexpr uintptr_t SC_RVA_BUILD_DEPOT_DEPENDENCY = 0x4B13A0;
static constexpr size_t SC_BDD_STOLEN_BYTES = 14;  // first 14 bytes of prologue

// CProtoBufMsg::BAsyncSend(uint32_t connectionHandle)
// Hooks this to inject game_extra_info into CMsgClientGamesPlayed before serialization.
static constexpr uintptr_t SC_RVA_BASYNC_SEND = 0xCF9590;
static constexpr size_t SC_BAS_STOLEN_BYTES = 15;   // 5+5+1+4 bytes of prologue
// CProtoBufMsg layout offsets
static constexpr uint32_t CPROTOBUFMSG_OFF_DESC   = 0x08;  // typed-body descriptor vtable*
static constexpr uint32_t CPROTOBUFMSG_OFF_CONN   = 0x1C;  // uint32_t connection handle
static constexpr uint32_t CPROTOBUFMSG_OFF_EMSG   = 0x20;  // uint32_t EMsg | PROTO_FLAG
static constexpr uint32_t CPROTOBUFMSG_OFF_BODY   = 0x30;  // protobuf body object*

// g_pJobCur (qword_1397E02C0): current CJob coroutine. CJobID at CJob+32.
// Only valid on BMainLoop/job thread (yield primitives assert g_pJobCur != NULL).
static constexpr uintptr_t SC_RVA_JOBCUR_GLOBAL = 0x17E9CC0;
static constexpr uint32_t  JOB_OFF_JOBID        = 32;

// CJob::BYieldIfTimeSlice (sub_138CE8130): yields if cooperative slice held >10ms.
//   bool fn(CJob* this, void* ctx, bool* outYielded); asserts this==g_pJobCur.
static constexpr uintptr_t SC_RVA_YIELD_IF_TIMESLICE = 0xCEF280;

// Schema-fetch injection: send EMsg 818 (schema_local_version=-1) on behalf of
// an owning SteamID; server replies with 819 -> UserGameStatsSchema_<appid>.bin.
// RVAs from CAPIJobRequestUserStats (sub_138A45010).
static constexpr uintptr_t SC_RVA_PBMSG_CTOR      = 0xCFC7D0;   // CProtoBufMsgBase::ctor(this, emsg, 0)
static constexpr uintptr_t SC_RVA_PBMSG_FINALIZE  = 0xCFF370;   // allocate typed body (sub_138CFF370)
static constexpr uintptr_t SC_RVA_PBMSG_CLEANUP   = 0xCFCA80;   // destroy msg
static constexpr uintptr_t SC_RVA_GETUSERSTATS_DESC = 0x16F8830; // CMsgClientGetUserStats body descriptor
// Typed vtable for CProtoBufMsg<CMsgClientGetUserStats>.
// Must be at msg[0] after base ctor; base vftable -> serialization crash.
static constexpr uintptr_t SC_RVA_GETUSERSTATS_VFTABLE = 0x1347988;
static constexpr uint32_t EMSG_CLIENT_GET_USER_STATS = 818;

// steamclient64.dll RVAs for CCMInterface discovery
// IDA image base: 0x138000000
// qword_1397D3628 = global CSteamEngine* pointer
static constexpr uintptr_t SC_RVA_GLOBAL_ENGINE     = 0x17D3628;
// CCMInterface vtable RVA (for validation)
static constexpr uintptr_t SC_RVA_CCMINTERFACE_VT   = 0x1279888;
// sub_138D022F0 = CNetPacket->CProtoBufNetPacket wrapper
static constexpr uintptr_t SC_RVA_WRAP_PACKET       = 0xD022F0;
// sub_138D0DBD0 = CJobMgr::BRouteMsgToJob
static constexpr uintptr_t SC_RVA_BROUTEMSG         = 0xD0DBD0;
// sub_1380EC300 = Release wrapped packet (CProtoBufNetPacket ref-count release)
static constexpr uintptr_t SC_RVA_RELEASE_WRAPPED   = 0x0EC300;

// CClientUnifiedServiceTransport vtable (RTTI resolves at runtime; RVA is fallback)
static constexpr uintptr_t SC_RVA_SERVICE_TRANSPORT_VT = 0x1256DF0;
// protobuf ParseFromArray, 3-arg (msgObj, data, int size)
static constexpr uintptr_t SC_RVA_PARSE_FROM_ARRAY  = 0xBD03F0;
// sub_138BD0800 = protobuf SerializeToArray (writes body to raw bytes)
static constexpr uintptr_t SC_RVA_SERIALIZE_TO_ARRAY = 0xBD0800;
// CUser playtime state helpers
static constexpr uintptr_t SC_RVA_GET_APP_MINUTES_PLAYED_DATA = 0x9C37A0;
static constexpr uintptr_t SC_RVA_FLUSH_APP_MINUTES_PLAYED = 0x9D3C40;
static constexpr uintptr_t SC_RVA_SET_APP_LAST_PLAYED_TIME = 0x9D6A70;
// Live playtime update: synthesized GetLastPlayedTimes response.
// Build 1784669098 RVAs:
static constexpr uintptr_t SC_RVA_PLAYTIME_WRITER    = 0x9CFDA0;
static constexpr uintptr_t SC_RVA_MSG_CTOR           = 0xCFC7D0;
static constexpr uintptr_t SC_RVA_MSG_INIT           = 0xCFF370;  // unused; same as PBMSG_FINALIZE
static constexpr uintptr_t SC_RVA_MSG_DTOR           = 0xCFCA80;
static constexpr uintptr_t SC_RVA_RESP_DESCRIPTOR    = 0x16D5590;
static constexpr uintptr_t SC_RVA_RESP_WRAPPER_VT    = 0x1334340;
// off_1396E8248: pointer to "Software\\Valve\\Steam\\LastPlayedTimesSyncTime"
static constexpr uintptr_t SC_RVA_REGKEY_SYNCTIME    = 0x16E8248;
// CUser member offsets used by the writer path
static constexpr uint32_t USER_OFF_REGISTRY          = 3272;   // CUser+0xCC8: registry obj (sync-time write)
// Inner CPlayer_GetLastPlayedTimes_Response message offsets
static constexpr uint32_t RESP_OFF_GAMES_COUNT       = 24;     // repeated games: element count
static constexpr uint32_t RESP_OFF_GAMES_ARRAY       = 32;     // repeated games: array base ptr
// CSteamEngine layout offsets
static constexpr uint32_t ENGINE_OFF_JOBMGR          = 592;    // CJobMgr embedded at CSteamEngine+592
static constexpr uint32_t ENGINE_OFF_GLOBAL_HANDLE   = 3144;  // uint32_t: global user handle
static constexpr uint32_t ENGINE_OFF_USER_MAP        = 3296;  // CUtlSortedVector: user map
// CCMInterface layout offsets
static constexpr uint32_t CCM_OFF_CONN_CONTEXT       = 1688;  // connection context pointer
// CUtlSortedVector layout (at engine + ENGINE_OFF_USER_MAP)
//   +0: QWORD array_base_ptr  (points to array of 16-byte entries)
//  +16: DWORD count
// Each entry: { DWORD handle, DWORD pad, QWORD CUser* }
// CBaseUser layout
static constexpr uint32_t USER_OFF_CCMINTERFACE     = 72;     // CCMInterface embedded at CBaseUser+0x48
// Account id in CUser. Resolved at runtime from UserGameStats_%u xref in SaveStatsToDisk.
// Fallback 570 = build 1782437068 (was 572 on earlier builds).
static uint32_t USER_OFF_ACCOUNTID = 570;

// Function pointer types for BRouteMsgToJob bypass (Approach D - legacy)
// sub_138D02530: wraps CNetPacket into CProtoBufNetPacket (parses protobuf header)
using WrapPacketFn = void*(__fastcall*)(CNetPacket* pkt, int addRef);
// sub_138D0EB50: routes a wrapped packet to the waiting job
using BRouteMsgToJobFn = char(__fastcall*)(void* jobMgr, void* connCtx,
                                           void* wrappedPkt, void* routeInfo, int validateFrom);
// sub_1380EB160: releases a wrapped packet (decrements refcount)
using ReleaseWrappedFn = void*(__fastcall*)(void* wrappedPkt);
// sub_138DCA830: refcount increment helper - takes ptr-to-ptr, reads inner ptr, does InterlockedIncrement64
using RefCountHelperFn = void*(__fastcall*)(volatile int64_t** ppCounter);

// Function pointer types for service-method vtable hook (Approach E)
// Slot 4 signature: CClientUnifiedServiceTransport::BYieldingSendMessageAndGetReply (direct)
//   rcx = this (CClientUnifiedServiceTransport*)
//   rdx = methodName (const char*, e.g. "Cloud.ClientBeginFileUpload#1")
//   r8  = request body (raw protobuf message object, NOT wrapped in CProtoBufMsg)
//   r9  = response body (raw protobuf message object, NOT wrapped in CProtoBufMsg)
//   [rsp+28h] = flags (int[68]: [0]=routing_appid, [1]=mode, [2]=error_code, [3]=eresult, [4..67]=error_message)
using ServiceMethodSlot4Fn = bool(__fastcall*)(void* thisptr, const char* methodName,
                                                void* requestBody, void* responseBody, int* flags);
// Slot 5 signature: CClientUnifiedServiceTransport::BYieldingSendMessageAndGetReply (wrapper)
//   rcx = this (CClientUnifiedServiceTransport*)
//   rdx = methodName (const char*, e.g. "Cloud.GetAppFileChangelist#1")
//   r8  = request CProtoBufMsg*
//   r9  = response CProtoBufMsg*
//   [rsp+28h] = flags (int64_t*, typically NULL)
using ServiceMethodSlot5Fn = bool(__fastcall*)(void* thisptr, const char* methodName,
                                                void* request, void* response, int64_t* flags);
// Slot 7 signature: notification direct - sends fire-and-forget notification
//   rcx = this (CClientUnifiedServiceTransport*)
//   rdx = methodName (const char*)
//   r8  = bodyObj (raw protobuf body object, NOT wrapped in CProtoBufMsg)
//   r9  = flags (int*, can be NULL) - {routing_appid, ?, ?, ?}
using NotificationSlot7Fn = bool(__fastcall*)(void* thisptr, const char* methodName,
                                               void* bodyObj, int* flags);
// Slot 8 signature: notification wrapper - extracts body from CProtoBufMsg, calls slot 7
//   rcx = this (CClientUnifiedServiceTransport*)
//   rdx = methodName (const char*)
//   r8  = request CProtoBufMsg* (body at +48, header at +40)
using NotificationSlot8Fn = bool(__fastcall*)(void* thisptr, const char* methodName,
                                               void* request);
// sub_138BD0210: ParseFromArray - fills a protobuf message object from raw bytes
//   rcx = protobuf message object (body at CProtoBufMsg+48)
//   rdx = raw data pointer
//   r8  = raw data size (as int)
using ParseFromArrayFn = char(__fastcall*)(void* msgBody, const char* data, int size);
// sub_138BD07E0: SerializeToArray -- writes protobuf message to a buffer
//   rcx = protobuf message object
//   rdx = output buffer pointer
//   r8  = buffer size (int)
//   returns end pointer on old Steam, flag on Steam >= 1778281814
using SerializeToArrayFn = uintptr_t(__fastcall*)(void* msgBody, void* outBuf, int size);

// Job routing info struct passed as 4th arg to BRouteMsgToJob
// Layout from RecvPkt assembly (naturally aligned, 24 bytes, no padding needed):
struct JobRouteInfo {
    int64_t  jobidSource;   // +0  always -1 for injected responses
    int64_t  jobidTarget;   // +8  target job to wake up
    int32_t  emsg;          // +16 message type (147 = k_EMsgServiceMethodResponse)
    int32_t  flags;         // +20 always -3
};
static_assert(sizeof(JobRouteInfo) == 24, "JobRouteInfo must be 24 bytes");
static_assert(offsetof(JobRouteInfo, jobidSource) == 0, "");
static_assert(offsetof(JobRouteInfo, jobidTarget) == 8, "");
static_assert(offsetof(JobRouteInfo, emsg) == 16, "");
static_assert(offsetof(JobRouteInfo, flags) == 20, "");

// RVA for the refcount helper: sub_138DE27C0
// This function takes rcx = pointer-to-pointer, reads *rcx to get a pointer,
// then does InterlockedIncrement64 on that second pointer.
// RecvPkt calls this with &unk_139797BD8 before calling BRouteMsgToJob.
static constexpr uintptr_t SC_RVA_REFCOUNT_HELPER   = 0xDC2D70;
// Global that holds the pointer-to-counter for the refcount helper
static constexpr uintptr_t SC_RVA_REFCOUNT_GLOBAL   = 0x17B7E38;
// sub_138D28CD0 = CUtlSortedVector::Find (looks up a CJob by jobId)
static constexpr uintptr_t SC_RVA_FIND_JOB          = 0xD0CDB0;

// SEH exception filter for crash diagnostics
static thread_local uintptr_t s_crashFaultAddr = 0;

// Forward declarations
void InstallServiceMethodHook();  // also declared in cloud_intercept.h (CR_InstallVtableHooks)
static bool IsSelfUnlockingLua(const std::string& filePath, uint32_t appId);
static bool __fastcall NotificationWrapperHook(void* thisptr, const char* methodName, void* request);
static bool __fastcall NotificationDirectHook(void* thisptr, const char* methodName, void* bodyObj, int* flags);
static int64_t __fastcall CMServerHandlerHook(int64_t a1, const uint8_t* data, uint64_t size);

static thread_local uintptr_t s_crashAccessAddr = 0;
static thread_local uintptr_t s_crashAccessType = 0;
static thread_local char s_crashModuleName[260] = {};
static LONG WINAPI CrashExcFilter(PEXCEPTION_POINTERS pExc) {
    if (pExc && pExc->ExceptionRecord) {
        s_crashFaultAddr = (uintptr_t)pExc->ExceptionRecord->ExceptionAddress;
        if (pExc->ExceptionRecord->NumberParameters >= 2) {
            s_crashAccessType = pExc->ExceptionRecord->ExceptionInformation[0]; // 0=read,1=write,8=DEP
            s_crashAccessAddr = pExc->ExceptionRecord->ExceptionInformation[1];
        } else {
            s_crashAccessType = 99;
            s_crashAccessAddr = 0;
        }
        // Identify the faulting module. Wide + UTF-8 narrow keeps non-ASCII
        // Steam install paths legible in the log.
        s_crashModuleName[0] = '\0';
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((void*)s_crashFaultAddr, &mbi, sizeof(mbi)) && mbi.AllocationBase) {
            wchar_t wbuf[MAX_PATH];
            DWORD wlen = GetModuleFileNameW((HMODULE)mbi.AllocationBase, wbuf, MAX_PATH);
            if (wlen > 0 && wlen < MAX_PATH) {
                // Fall back to the leaf name on overflow; UTF-8 of a wide
                // path can exceed our buffer for non-ASCII install paths.
                int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)wlen,
                                            s_crashModuleName,
                                            (int)sizeof(s_crashModuleName) - 1,
                                            nullptr, nullptr);
                if (n > 0) {
                    s_crashModuleName[n] = '\0';
                } else {
                    const wchar_t* leaf = wcsrchr(wbuf, L'\\');
                    leaf = leaf ? leaf + 1 : wbuf;
                    int leafN = WideCharToMultiByte(CP_UTF8, 0, leaf, -1,
                                                    s_crashModuleName,
                                                    (int)sizeof(s_crashModuleName),
                                                    nullptr, nullptr);
                    if (leafN <= 0) s_crashModuleName[0] = '\0';
                }
            }
        }
    }
    return EXCEPTION_EXECUTE_HANDLER;
}


static uintptr_t g_payloadBase = 0;
static uintptr_t g_steamClientBase = 0;           // steamclient64.dll base address

// Auto-resolved addresses from steamclient64.dll pattern scanning.
// Populated once in RunAutoResolver(). Zero = not resolved (use hardcoded fallback).
static ScResolver::ResolvedAddrs g_resolved = {};
static std::atomic<bool> g_resolverRan{false};

// Use resolved address if available, else 0 (subsystem must gate on this).
// No hardcoded fallback — a wrong RVA causes silent corruption or crashes.
#define SC_RESOLVE(field) (g_resolved.field)

static void RunAutoResolver() {
    if (g_resolverRan.exchange(true)) return;
    if (!g_steamClientBase) {
        HMODULE hSC = GetModuleHandleA("steamclient64.dll");
        if (!hSC) return;
        g_steamClientBase = (uintptr_t)hSC;
    }
    g_resolved = ScResolver::Resolve(g_steamClientBase);
    ScResolver::LogComparison(g_resolved, g_steamClientBase);

    SteamKvInjector::ResolvedKvAddrs kv;
    kv.globalEnginePtrPtr  = reinterpret_cast<void**>(g_resolved.globalEngine);
    kv.getAppInfo          = g_resolved.getAppInfo;
    kv.getSection          = g_resolved.getSection;
    kv.readConfigU64       = g_resolved.readConfigU64;
    kv.kvFindKey           = g_resolved.kvFindKey;
    kv.kvGetUint64         = g_resolved.kvGetUint64;
    kv.kvGetInt            = g_resolved.kvGetInt;
    kv.kvSetUint64         = g_resolved.kvSetUint64;
    kv.kvSetInt            = g_resolved.kvSetInt;
    kv.kvSetString         = g_resolved.kvSetString;
    kv.appInfoCacheOffset  = g_resolved.engineOffAppInfoCache;
    SteamKvInjector::Configure(kv);
}

static std::string g_steamPath;
static std::string g_manifestEndpoint;
static RecvPktFn g_originalRecvPkt = nullptr;       // trampoline to original RecvPkt (via inline detour)
static uint8_t* g_recvPktDetourSite = nullptr;      // address of hooked RecvPkt prologue (for shutdown restore)
static uint8_t  g_recvPktOrigBytes[15] = {};        // original bytes we overwrote
static uint8_t* g_recvPktTrampoline = nullptr;      // executable trampoline page
static std::atomic<void*> g_cmInterface{nullptr};  // real CCMInterface* (found via CSteamEngine)
static std::atomic<bool> g_shuttingDown{false};
static std::atomic<bool> g_cloudSaveOnly{false};    // third-party mode (no SteamTools DLL)
static std::atomic<bool> g_cmInterfaceFound{false}; // whether we've found the real CCMInterface
static std::thread g_luaSyncThread;                  // deferred lua sync (waits for accountId)
static std::thread g_startupMetadataThread;          // deferred startup playtime/stats restore
static std::atomic<bool> g_startupMetadataScheduled{false};

static std::mutex g_bgThreadsMutex;
static std::vector<std::thread> g_bgThreads;
static CR_NotifyFn g_notifyCallback = nullptr;

static void NotifyUser(int level, const char* title, const char* message) {
    if (g_notifyCallback) {
        g_notifyCallback(level, title, message);
    } else {
        UINT flags = MB_OK | MB_SETFOREGROUND;
        if (level == CR_NOTIFY_ERROR) flags |= MB_ICONERROR;
        else if (level == CR_NOTIFY_WARN) flags |= MB_ICONWARNING;
        else flags |= MB_ICONINFORMATION;
        MessageBoxA(nullptr, message, title, flags);
    }
}

static void ScheduleStartupMetadataSync() {
    // Manifest system fetches CN/manifest on-demand per app; no bulk startup sync.
    if (!CloudStorage::IsCloudActive()) return;
    LOG("[StartupSync] Cloud active; metadata will be fetched on-demand per app");

    // Reset stats cache on account switch (prevents cross-account inheritance).
    uint32_t accountId = GetAccountId();
    bool switched = StatsStore::ResetForAccountSwitch(accountId);

    // Re-run native imports now that accountId is known. Once per login.
    static std::atomic<bool> s_postLoginImportStarted{false};
    if (switched) s_postLoginImportStarted.store(false);
    if (!s_postLoginImportStarted.exchange(true)) {
        std::thread t([]() {
            if (g_shuttingDown.load(std::memory_order_acquire)) return;
            StatsStore::RetryNativeImportsAfterLogin();
        });
        std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
        if (g_shuttingDown.load(std::memory_order_acquire))
            t.detach();
        else
            g_bgThreads.push_back(std::move(t));
    }
}

#define g_syncLuas MetadataSync::syncLuas

static std::atomic<bool> g_parentalBypassPlaytime{false};
static std::atomic<bool> g_parentalIgnorePlaytime{false};
static std::atomic<uint64_t> g_detectedSteamVersion{0};

// Cloud-redirect master toggle (default ON). When OFF the DLL still applies manifest pinning + patches but skips HTTP/storage/interception.
static std::atomic<bool> g_cloudRedirectEnabled{true};

// Manifest pinning (depot -> manifest override)
// Config lives in Steam folder (per-system), NOT AppData (per-user).
static std::atomic<bool> g_manifestPinsEnabled{false};
static std::atomic<bool> g_autoComment{true};  // when true, ignore lua setManifestid lines
static std::atomic<bool> g_showNonSteamGame{true};  // show LUA games as "Playing non-Steam game" in friends
static std::unordered_set<uint32_t> g_pinnedApps;  // per-app overrides: always respect lua pins for these apps
static std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint64_t>> g_manifestPins;  // appId -> {depotId -> manifestId}

// Inline detour on steamclient64!sub_1384B72B0 (CUserAppManager::BuildDepotDependency)
// Post-call hook: call original via trampoline, then patch manifest IDs in output vectors.
using BuildDepotDependencyFn = __int64(__fastcall*)(__int64* a1, unsigned int a2, __int64 a3,
                                                     __int64 a4, __int64 a5, __int64 a6,
                                                     uint32_t* a7, uint8_t* a8);
static BuildDepotDependencyFn g_origBuildDepotDependency = nullptr;  // trampoline
static uint8_t* g_bddTrampoline = nullptr;                           // allocated trampoline memory
static uint8_t* g_bddOrigAddr = nullptr;                             // original function address

// BRouteMsgToJob bypass function pointers (resolved once from steamclient64.dll)
static WrapPacketFn g_wrapPacket = nullptr;
static BRouteMsgToJobFn g_bRouteMsgToJob = nullptr;
static ReleaseWrappedFn g_releaseWrapped = nullptr;
static RefCountHelperFn g_refCountHelper = nullptr;
static volatile int64_t** g_refCountGlobalPtr = nullptr;  // &unk_139771AD8

// Service-method vtable hook state (Approach E)
static ServiceMethodSlot4Fn g_originalSlot4 = nullptr;      // saved original slot 4 function
static ServiceMethodSlot5Fn g_originalSlot5 = nullptr;      // saved original slot 5 function
static NotificationSlot7Fn g_originalSlot7 = nullptr;       // saved original slot 7 function
static NotificationSlot8Fn g_originalSlot8 = nullptr;       // saved original slot 8 function
static ParseFromArrayFn g_parseFromArray = nullptr;          // sub_138BD0210
static SerializeToArrayFn g_serializeToArray = nullptr;      // sub_138BD07E0
static std::atomic<bool> g_vtableHookInstalled{false};
static std::atomic<bool> g_needsSeed{false};

// Schema-fetch injection primitives (resolved at hook install from steamclient64).
using PbMsgCtorFn     = void*(__fastcall*)(void* self, int emsg, int unk);
using PbMsgFinalizeFn = void(__fastcall*)(void* self);
using PbMsgCleanupFn  = void(__fastcall*)(void* self);
static PbMsgCtorFn     g_pbMsgCtor = nullptr;
static PbMsgFinalizeFn g_pbMsgFinalize = nullptr;
static PbMsgCleanupFn  g_pbMsgCleanup = nullptr;
static void*           g_getUserStatsDesc = nullptr;   // off_1396E4460 (resolved)
static void*           g_getUserStatsVtbl = nullptr;   // typed CProtoBufMsg vftable (resolved)
static std::atomic<uint32_t> g_liveConnHandle{0};    // generic CM conn from BAsyncSend
static std::atomic<uint32_t> g_statsConnHandle{0};   // CM conn from Steam's own 818 (preferred)
// Session fields copied from Steam's GetUserStats header onto injected 818s.
// CM drops requests missing steamid + client_sessionid.
// Header layout: +16 presence, +104 steamid, +112 sessionid, +156 realm, +208 jobid_source
static std::atomic<uint64_t> g_hdrSteamId{0};
static std::atomic<uint32_t> g_hdrSessionId{0};
static std::atomic<uint32_t> g_hdrRealm{0};
static std::atomic<bool>     g_hdrCaptured{false};
static uintptr_t g_serviceTransportVtableEa = 0;             // resolved via RTTI at install; 0 = unresolved, fall back to RVA

// CClientUnifiedServiceTransport vtable slot offsets (stable interface contract).
static constexpr size_t kSlot4Off = 0x20;
static constexpr size_t kSlot5Off = 0x28;
static constexpr size_t kSlot7Off = 0x38;
static constexpr size_t kSlot8Off = 0x40;

// Hook reference counter - incremented on entry to each hook, decremented on exit.
// Shutdown() spins until this reaches zero before restoring vtable pointers.
static std::atomic<int> g_hookRefCount{0};

struct HookGuard {
    HookGuard() { g_hookRefCount.fetch_add(1, std::memory_order_acquire); }
    ~HookGuard() { g_hookRefCount.fetch_sub(1, std::memory_order_release); }
    HookGuard(const HookGuard&) = delete;
    HookGuard& operator=(const HookGuard&) = delete;
};

// Re-entrancy probe: detects slot-5 RPC firing while CompleteBatch holds g_queueMutex.
static std::atomic<int>      g_reentCompleteInFlight{0};
static std::atomic<uint32_t> g_reentCompleteThreadId{0};

struct CompleteBatchInFlightMark {
    bool active = false;
    explicit CompleteBatchInFlightMark(bool on) : active(on) {
        if (active) {
            g_reentCompleteThreadId.store((uint32_t)GetCurrentThreadId(), std::memory_order_release);
            g_reentCompleteInFlight.fetch_add(1, std::memory_order_acq_rel);
        }
    }
    ~CompleteBatchInFlightMark() {
        if (active) g_reentCompleteInFlight.fetch_sub(1, std::memory_order_acq_rel);
    }
    CompleteBatchInFlightMark(const CompleteBatchInFlightMark&) = delete;
    CompleteBatchInFlightMark& operator=(const CompleteBatchInFlightMark&) = delete;
};

// namespace state (auto-detected from stplug-in directory)
static std::unordered_set<uint32_t> g_namespaceApps;
static std::mutex g_namespaceAppsMutex;

bool IsNamespaceApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    return g_namespaceApps.count(appId) > 0;
}

static bool HasNamespaceApps() {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    return !g_namespaceApps.empty();
}

static std::vector<uint32_t> GetNamespaceApps() {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    return std::vector<uint32_t>(g_namespaceApps.begin(), g_namespaceApps.end());
}

uint32_t GetAccountId();  // defined later
void RequestSchemaForApp(uint32_t appId, bool forceRefresh = false);  // defined later

// "Mark as private": reads PrivateApps_<accountId> from localconfig.vdf.
// Cached 5s to avoid re-reading on every GamesPlayed broadcast.
static std::mutex g_privateAppsMutex;
static std::unordered_set<uint32_t> g_privateApps;
static std::chrono::steady_clock::time_point g_privateAppsLoaded{};

static void RefreshPrivateAppsLocked() {
    g_privateApps.clear();
    uint32_t accountId = GetAccountId();
    if (!accountId || g_steamPath.empty()) return;

    std::string vdfPath = g_steamPath + "userdata\\" + std::to_string(accountId)
        + "\\config\\localconfig.vdf";
    auto vdfPathWide = FileUtil::Utf8ToPath(vdfPath).wstring();
    HANDLE hFile = CreateFileW(vdfPathWide.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    std::string content;
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
        content.resize(fileSize);
        DWORD bytesRead = 0;
        ReadFile(hFile, (LPVOID)content.data(), fileSize, &bytesRead, nullptr);
        content.resize(bytesRead);
    }
    CloseHandle(hFile);

    // Find:  "PrivateApps_<accountId>"   "[480,2499870,...]"
    std::string key = "\"PrivateApps_" + std::to_string(accountId) + "\"";
    size_t k = content.find(key);
    if (k == std::string::npos) return;
    size_t lb = content.find('[', k);
    size_t rb = (lb == std::string::npos) ? std::string::npos : content.find(']', lb);
    if (lb == std::string::npos || rb == std::string::npos) return;

    // Parse comma-separated appIds inside the brackets.
    size_t i = lb + 1;
    while (i < rb) {
        while (i < rb && !isdigit((unsigned char)content[i])) ++i;
        if (i >= rb) break;
        uint32_t id = (uint32_t)strtoul(content.c_str() + i, nullptr, 10);
        if (id) g_privateApps.insert(id);
        while (i < rb && isdigit((unsigned char)content[i])) ++i;
    }
}

bool IsPrivateApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_privateAppsMutex);
    auto now = std::chrono::steady_clock::now();
    if (g_privateAppsLoaded.time_since_epoch().count() == 0 ||
        now - g_privateAppsLoaded > std::chrono::seconds(5)) {
        RefreshPrivateAppsLocked();
        g_privateAppsLoaded = now;
    }
    return g_privateApps.count(appId) > 0;
}

void AddNamespaceApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    g_namespaceApps.insert(appId);
}

void RemoveNamespaceApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    g_namespaceApps.erase(appId);
}

// Replace the namespace-app set; reports add/remove counts for logging.
void SetNamespaceApps(const uint32_t* appIds, uint32_t count,
                      size_t* outAdded, size_t* outRemoved) {
    std::unordered_set<uint32_t> next;
    next.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (appIds[i] != 0) next.insert(appIds[i]);
    }
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    if (outAdded) {
        size_t added = 0;
        for (uint32_t id : next)
            if (g_namespaceApps.count(id) == 0) ++added;
        *outAdded = added;
    }
    if (outRemoved) {
        size_t removed = 0;
        for (uint32_t id : g_namespaceApps)
            if (next.count(id) == 0) ++removed;
        *outRemoved = removed;
    }
    g_namespaceApps = std::move(next);
}

static uintptr_t FindCurrentUser();

static uintptr_t FindCurrentUser() {
    if (!g_steamClientBase) {
        HMODULE hSC = GetModuleHandleA("steamclient64.dll");
        if (!hSC) return 0;
        g_steamClientBase = (uintptr_t)hSC;
    }

    uintptr_t engineGlobal = SC_RESOLVE(globalEngine);
    if (!engineGlobal) return 0;
    uintptr_t* pEngineGlobal = (uintptr_t*)engineGlobal;
    uintptr_t engine = 0;
    __try { engine = *pEngineGlobal; } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
    if (!engine) return 0;

    uint32_t globalHandle = 0;
    __try { globalHandle = *(uint32_t*)(engine + ENGINE_OFF_GLOBAL_HANDLE); }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
    if (globalHandle == 0) return 0;

    uintptr_t userMapBase = engine + ENGINE_OFF_USER_MAP;
    uintptr_t arrayPtr = 0;
    int32_t count = 0;
    __try {
        arrayPtr = *(uintptr_t*)(userMapBase);
        count = *(int32_t*)(userMapBase + 16);
    } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }

    if (!arrayPtr || count <= 0 || count > 64) return 0;

    uintptr_t userPtr = 0;
    __try {
        for (int32_t i = 0; i < count; i++) {
            uintptr_t entry = arrayPtr + (uintptr_t)i * 16;
            uint32_t handle = *(uint32_t*)entry;
            if (handle == globalHandle) {
                userPtr = *(uintptr_t*)(entry + 8);
                break;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }

    return userPtr;
}

// Scan for CUser accountId offset: find UserGameStats_%u string -> code xref ->
// backward scan for mov reg32,[reg+disp32] -> disp32 is the offset. 0 on failure.
static uint32_t ScanUserAccountIdOffset() {
    HMODULE hSC = GetModuleHandleA("steamclient64.dll");
    if (!hSC) return 0;
    uintptr_t base = (uintptr_t)hSC;

    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), hSC, &mi, sizeof(mi)))
        return 0;
    const uint8_t* img = (const uint8_t*)base;
    size_t imgSize = mi.SizeOfImage;

    // Step 1: find "UserGameStats_%u" in .rdata (may be mid-string; walk back to NUL).
    const char needle[] = "UserGameStats_%u";
    const size_t needleLen = sizeof(needle) - 1;  // exclude NUL
    uintptr_t matchAddr = 0;
    for (size_t i = 0; i + needleLen < imgSize; i++) {
        if (memcmp(img + i, needle, needleLen) == 0) {
            matchAddr = base + i;
            break;
        }
    }
    if (!matchAddr) {
        LOG("[Scan] UserGameStats string not found");
        return 0;
    }

    // Walk backward to the start of the containing C string (first NUL before match).
    uintptr_t strAddr = matchAddr;
    const uint8_t* matchPtr = img + (matchAddr - base);
    while (matchPtr > img && *(matchPtr - 1) != 0) {
        matchPtr--;
        strAddr--;
    }
    LOG("[Scan] UserGameStats needle at sc+0x%llX, containing string at sc+0x%llX: \"%.64s\"",
        (unsigned long long)(matchAddr - base), (unsigned long long)(strAddr - base),
        (const char*)(img + (strAddr - base)));

    // Step 2: find QWORD pointer to this string in .rdata/.data (off_XXXX entry).
    uintptr_t ptrAddr = 0;
    for (size_t i = 0; i + 8 <= imgSize; i += 8) {
        if (*(const uintptr_t*)(img + i) == strAddr) {
            ptrAddr = base + i;
            break;
        }
    }
    if (!ptrAddr) {
        LOG("[Scan] UserGameStats string pointer not found");
        return 0;
    }

    // Step 3: find RIP-relative xref: 48 8B 15 XX XX XX XX (mov rdx, [rip+disp32]).
    uintptr_t xrefAddr = 0;
    for (size_t i = 0; i + 7 < imgSize; i++) {
        if (img[i] == 0x48 && img[i+1] == 0x8B && img[i+2] == 0x15) {
            int32_t disp = *(const int32_t*)(img + i + 3);
            uintptr_t target = (base + i + 7) + disp;
            if (target == ptrAddr) {
                xrefAddr = base + i;
                break;
            }
        }
    }
    if (!xrefAddr) {
        LOG("[Scan] UserGameStats code xref not found");
        return 0;
    }

    // Step 4: walk backward for `mov r32, [reg+disp32]` (accountId load, disp in 256..4096).
    const uint8_t* scan = (const uint8_t*)xrefAddr;
    const uint8_t* scanStart = scan - 64;
    if (scanStart < img) scanStart = img;
    for (const uint8_t* p = scan - 3; p >= scanStart; p--) {
        // mov r32, [r64+disp32]: opcode 8B, ModR/M = XX_reg_101 (mod=10, rm=101=rbp/r13
        // won't appear here, rm varies). ModR/M mod=10 means [reg+disp32].
        // With REX.B (0x41): source is R8-R15.
        uint8_t op = *p;
        bool hasRex = (op >= 0x40 && op <= 0x4F);
        const uint8_t* modrm_p = hasRex ? p + 1 : p;
        if (*modrm_p != 0x8B) continue;
        uint8_t modrm = *(modrm_p + 1);
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm  = modrm & 7;
        if (mod != 2) continue;  // mod=10: [reg+disp32]
        // rm=4 means SIB byte follows (skip, more complex addressing)
        if (rm == 4) continue;
        int32_t offset;
        memcpy(&offset, modrm_p + 2, 4);
        if (offset >= 256 && offset <= 4096) {
            uint32_t result = (uint32_t)offset;
            LOG("[Scan] Resolved USER_OFF_ACCOUNTID = %u (0x%X) from code at sc+0x%llX",
                result, result, (unsigned long long)(p - img));
            return result;
        }
    }
    LOG("[Scan] Could not extract accountId offset from nearby instructions");
    return 0;
}

// Read account id from CUser when no RPC header is available yet. SEH-isolated.
static uint32_t ReadAccountIdFromUser() {
    uintptr_t user = FindCurrentUser();
    if (!user) return 0;
    uint32_t acct = 0;
    __try { acct = *(uint32_t*)(user + USER_OFF_ACCOUNTID); }
    __except(EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return acct;
}


// cave replacement buffer globals (still needed for passthrough SteamTools hook)


// SteamID extracted from first packet header
static std::atomic<uint64_t> g_steamId{0};
static std::atomic<int32_t> g_sessionId{0};
// True once g_steamId came from a real packet header (authoritative over CUser fallback).
static std::atomic<bool> g_steamIdFromHeader{false};

void SetAccountId(uint32_t accountId) {
    // SteamID: universe=1, type=1, instance=1
    uint64_t steamId = (uint64_t)accountId | (1ULL << 32) | (1ULL << 52) | (1ULL << 56);
    g_steamId.store(steamId, std::memory_order_relaxed);
    // Unblock disk reads immediately so GetPlaytime can serve from the
    // local cache before the cloud pull finishes.
    if (accountId != 0)
        StatsStore::ResetForAccountSwitch(accountId);
}

// recursion guard
thread_local bool g_proxySending = false;


static void SpyLogFields(const char* prefix, const uint8_t* data, uint32_t len, int depth = 0, int* totalFields = nullptr) {
    if (depth > 3) return;
    int localCount = 0;
    if (!totalFields) totalFields = &localCount;
    auto fields = PB::Parse(data, len);
    char indent[32];
    int n = depth * 2;
    if (n > 30) n = 30;
    memset(indent, ' ', n);
    indent[n] = '\0';
    for (auto& f : fields) {
        if (++(*totalFields) > 10000) {
            LOG("%s%s  ... (field limit reached, truncating)", prefix, indent);
            return;
        }
        if (f.wireType == PB::LengthDelimited) {
            auto sub = PB::Parse(f.data, f.dataLen);
            if (!sub.empty() && f.dataLen > 2) {
                LOG("%s%s  %sfield %u: SUBMSG (%u bytes) {", prefix, indent, indent, f.fieldNum, f.dataLen);
                SpyLogFields(prefix, f.data, f.dataLen, depth + 1, totalFields);
                LOG("%s%s  %s}", prefix, indent, indent);
            } else {
                bool printable = true;
                for (uint32_t i = 0; i < f.dataLen && i < 200; ++i) {
                    if (f.data[i] < 0x20 && f.data[i] != '\t' && f.data[i] != '\n' && f.data[i] != '\r') {
                        printable = false;
                        break;
                    }
                }
                if (printable && f.dataLen > 0) {
                    LOG("%s%s  field %u: STR(%u) = \"%.*s\"", prefix, indent,
                        f.fieldNum, f.dataLen, f.dataLen < 200 ? f.dataLen : 200, f.data);
                } else {
                    char hex[512];
                    uint32_t hlen = f.dataLen < 200 ? f.dataLen : 200;
                    for (uint32_t i = 0; i < hlen; ++i)
                        snprintf(hex + i * 2, 3, "%02x", f.data[i]);
                    hex[hlen * 2] = '\0';
                    LOG("%s%s  field %u: BYTES(%u) = %s%s", prefix, indent,
                        f.fieldNum, f.dataLen, hex, f.dataLen > 200 ? "..." : "");
                }
            }
        } else if (f.wireType == PB::Fixed64) {
            LOG("%s%s  field %u: FIXED64 = %llu (0x%llx)", prefix, indent,
                f.fieldNum, f.varintVal, f.varintVal);
        } else if (f.wireType == PB::Fixed32) {
            LOG("%s%s  field %u: FIXED32 = %u (0x%x)", prefix, indent,
                f.fieldNum, (uint32_t)f.varintVal, (uint32_t)f.varintVal);
        } else {
            LOG("%s%s  field %u: VARINT = %llu (0x%llx)", prefix, indent,
                f.fieldNum, f.varintVal, f.varintVal);
        }
    }
}

struct PacketView {
    uint32_t emsg;
    bool isProto;
    const uint8_t* headerData;
    uint32_t headerLen;
    const uint8_t* bodyData;
    uint32_t bodyLen;
    std::vector<PB::Field> header;
};

static bool ParsePacket(const uint8_t* data, uint32_t size, PacketView& pkt) {
    if (size < 8) return false;
    uint32_t emsgRaw;
    memcpy(&emsgRaw, data, 4);
    pkt.isProto = (emsgRaw & PROTO_FLAG) != 0;
    pkt.emsg = emsgRaw & EMSG_MASK;
    if (!pkt.isProto) return false;

    memcpy(&pkt.headerLen, data + 4, 4);
    if (8 + pkt.headerLen > size) return false;

    pkt.headerData = data + 8;
    pkt.bodyData = data + 8 + pkt.headerLen;
    pkt.bodyLen = size - 8 - pkt.headerLen;
    pkt.header = PB::Parse(pkt.headerData, pkt.headerLen);
    return true;
}

static uint64_t GetJobIdSource(const std::vector<PB::Field>& header) {
    auto* f = PB::FindField(header, HDR_JOBID_SOURCE);
    return f ? f->varintVal : JOBID_NONE;
}

// Coroutine_IsActive(): resolved by name from vstdlib_s64.dll. Returns true when the
// calling thread's coroutine depth > 1 (yield-safe). Fail-closed if unresolved.
typedef bool(__cdecl* CoroutineIsActiveFn)();
static std::atomic<CoroutineIsActiveFn> g_coroutineIsActive{nullptr};
static std::atomic<bool> g_coroutineIsActiveResolved{false};

static CoroutineIsActiveFn ResolveCoroutineIsActive() {
    if (g_coroutineIsActiveResolved.load(std::memory_order_acquire))
        return g_coroutineIsActive.load(std::memory_order_acquire);
    CoroutineIsActiveFn fn = nullptr;
    HMODULE vstd = GetModuleHandleW(L"vstdlib_s64.dll");
    if (vstd) {
        fn = reinterpret_cast<CoroutineIsActiveFn>(
            GetProcAddress(vstd, "Coroutine_IsActive"));
    }
    g_coroutineIsActive.store(fn, std::memory_order_release);
    g_coroutineIsActiveResolved.store(true, std::memory_order_release);
    LOG("[CoopYield] Coroutine_IsActive resolved: %p (vstdlib=%p)",
        (void*)fn, (void*)vstd);
    return fn;
}

// Safe wrapper: true only if the coroutine engine is resolved AND reports the
// current thread's coroutine is active (yieldable). SEH-isolated so a bad call
// can never escalate. Fails closed (returns false) on any uncertainty.
static bool CoroutineActiveNow() {
    CoroutineIsActiveFn fn = ResolveCoroutineIsActive();
    if (!fn) return false;
    bool active = false;
    __try {
        active = fn();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        active = false;
    }
    return active;
}

// Jobid of the running coroutine (correlates outbound 818 with injected 819).
// SEH-isolated: no C++ objects in scope.
static uint64_t ReadCurrentJobId() {
    uintptr_t addr = SC_RESOLVE(jobCurGlobal);
    if (!addr) return 0;
    uint64_t jobId = 0;
    __try {
        uintptr_t jobCur = *(uintptr_t*)addr;
        if (jobCur) jobId = *(uint64_t*)(jobCur + JOB_OFF_JOBID);
    } __except(EXCEPTION_EXECUTE_HANDLER) { jobId = 0; }
    return jobId;
}

// Read-only probe of g_pJobCur (non-NULL = on cooperative job fiber, yield legal).
static uintptr_t ReadCurrentJobPtr() {
    uintptr_t addr = SC_RESOLVE(jobCurGlobal);
    if (!addr) return 0;
    uintptr_t jobCur = 0;
    __try {
        jobCur = *(uintptr_t*)addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) { jobCur = 0; }
    return jobCur;
}

// CJob::BYieldIfTimeSlice signature (fastcall): (CJob* this, void* ctx, bool* out).
typedef bool(__fastcall* YieldIfTimeSliceFn)(void* job, void* ctx, bool* outYielded);

// Leaf SEH helper: invoke yield primitive. Separate for MSVC SEH/C++ unwinding split.
static bool InvokeYieldPrimitive(uintptr_t job) {
    auto fn = (YieldIfTimeSliceFn)SC_RESOLVE(yieldIfTimeSlice);
    if (!fn) return false;
    __try {
        fn((void*)job, nullptr, nullptr);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Cooperative yield hook. Skips if not on job thread (g_pJobCur==NULL) or coroutine
// inactive. Stale RVA fails closed (no yield, hook disabled).
static void CooperativeYieldCurrentJob() {
    if (!g_steamClientBase) return;
    uintptr_t job = ReadCurrentJobPtr();
    if (!job) return;  // not on the job thread (e.g. a worker) -> nothing to yield
    // Must verify coroutine active: yielding inactive corrupts stack (coroutine.cpp:434).
    if (!CoroutineActiveNow()) return;  // not at a legal yield point -> skip safely
    if (!InvokeYieldPrimitive(job)) {
        LOG("[CoopYield] yield primitive faulted; disabling cooperative yield");
        // DisableYieldHook (not Set): called from inside the hook itself.
        CoopYield::DisableYieldHook();
    }
}

static bool LooksLikeFunctionPrologue(const uint8_t* p);  // fwd decl (defined below)

// Register cooperative yield hook for UploadBatch (prevents pipe-stall on big saves).
// Prologue-gated: stale RVA disables yield gracefully. Separate function for MSVC C2712.
static void RegisterCooperativeYieldHook() {
    uintptr_t yieldAddr = SC_RESOLVE(yieldIfTimeSlice);
    if (!yieldAddr) {
        CoopYield::SetYieldHook(nullptr);
        LOG("[CoopYield] WARNING: YieldIfTimeSlice not resolved; "
            "cooperative yield DISABLED (uploads will use the blocking wait)");
        return;
    }
    auto yieldFn = reinterpret_cast<const uint8_t*>(yieldAddr);
    if (LooksLikeFunctionPrologue(yieldFn)) {
        CoopYield::SetYieldHook(&CooperativeYieldCurrentJob);
        LOG("[CoopYield] cooperative job-yield registered at %p", (void*)yieldAddr);
    } else {
        CoopYield::SetYieldHook(nullptr);
        LOG("[CoopYield] WARNING: yield primitive prologue check failed at %p; "
            "cooperative yield DISABLED (uploads will use the blocking wait)", (void*)yieldAddr);
    }
}

static std::vector<uint8_t> BuildPacket(uint32_t emsg, const PB::Writer& header, const PB::Writer& body) {
    uint32_t emsgRaw = emsg | PROTO_FLAG;
    uint32_t headerLen = (uint32_t)header.Size();
    std::vector<uint8_t> pkt;
    pkt.resize(8 + headerLen + body.Size());
    memcpy(pkt.data(), &emsgRaw, 4);
    memcpy(pkt.data() + 4, &headerLen, 4);
    memcpy(pkt.data() + 8, header.Data().data(), headerLen);
    memcpy(pkt.data() + 8 + headerLen, body.Data().data(), body.Size());
    return pkt;
}

// CCMInterface discovery: CSteamEngine* -> engine+3144 (handle) -> engine+3296
// (user map) -> matching CUser* -> CUser+72 (CCMInterface embedded).
static void* FindCCMInterface() {
    uintptr_t userPtr = FindCurrentUser();
    if (!userPtr) return nullptr;

    // CCMInterface is embedded at CBaseUser+72 (0x48)
    uintptr_t ccm = userPtr + USER_OFF_CCMINTERFACE;

    // Validate by checking vtable matches CCMInterface::vftable
    uintptr_t expectedVtable = SC_RESOLVE(ccmInterfaceVtable);
    if (!expectedVtable) return nullptr;
    uintptr_t actualVtable = 0;
    __try { actualVtable = *(uintptr_t*)ccm; } __except(EXCEPTION_EXECUTE_HANDLER) { return nullptr; }

    if (actualVtable != expectedVtable) {
        LOG("[CCM] Vtable mismatch at CUser+72: expected=%p actual=%p", 
            (void*)expectedVtable, (void*)actualVtable);
        return nullptr;
    }

    return (void*)ccm;
}

// Try to find CCMInterface if not yet found. Called from OnSendPkt on each invocation
// until successful. Once found, g_cmInterface is stable for the session.
static void TryFindCCMInterface() {
    if (g_cmInterfaceFound.load(std::memory_order_acquire)) return;

    void* ccm = FindCCMInterface();
    if (!ccm) return;

    // Claim first-finder atomically. Write pointer before flag (release ordering).
    bool expected = false;
    g_cmInterface.store(ccm, std::memory_order_release);
    if (!g_cmInterfaceFound.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        return; // another thread already found it
    }

    LOG("[CCM] Found real CCMInterface: %p", ccm);

    // Log details for debugging (wrapped in SEH - raw pointer dereferences for diagnostics only)
    __try {
        uintptr_t* pEngineGlobal = (uintptr_t*)SC_RESOLVE(globalEngine);
        uintptr_t engine = *pEngineGlobal;
        uint32_t handle = *(uint32_t*)(engine + ENGINE_OFF_GLOBAL_HANDLE);

        LOG("[CCM]   CSteamEngine: %p (global at sc+0x%X)", (void*)engine, SC_RVA_GLOBAL_ENGINE);
        LOG("[CCM]   Global user handle: %u", handle);
        LOG("[CCM]   Vtable: %p (RVA=0x%llX) -- MATCHES CCMInterface::vftable",
            (void*)(*(uintptr_t*)ccm), (uint64_t)SC_RVA_CCMINTERFACE_VT);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[CCM] WARNING: exception reading engine globals (code=0x%lX)", GetExceptionCode());
    }

    // Resolve BRouteMsgToJob bypass function pointers (computed from base + RVA, no dereferences)
    g_wrapPacket     = (WrapPacketFn)SC_RESOLVE(wrapPacket);
    g_bRouteMsgToJob = (BRouteMsgToJobFn)SC_RESOLVE(bRouteMsgToJob);
    g_releaseWrapped = (ReleaseWrappedFn)SC_RESOLVE(releaseWrapped);
    g_refCountHelper = (RefCountHelperFn)SC_RESOLVE(refCountHelper);
    g_refCountGlobalPtr = (volatile int64_t**)SC_RESOLVE(refCountGlobal);
    LOG("[CCM]   WrapPacket=%p BRouteMsgToJob=%p ReleaseWrapped=%p",
        g_wrapPacket, g_bRouteMsgToJob, g_releaseWrapped);

    // Additional diagnostic logging (dereferences pointers, wrap in SEH)
    __try {
        LOG("[CCM]   RefCountHelper=%p RefCountGlobal=%p (*=%p)",
            g_refCountHelper, g_refCountGlobalPtr,
            g_refCountGlobalPtr ? (void*)*g_refCountGlobalPtr : nullptr);
        uintptr_t engine = *(uintptr_t*)SC_RESOLVE(globalEngine);
        LOG("[CCM]   CJobMgr (engine+%u)=%p  ConnCtx (ccm+%u)=%p",
            ENGINE_OFF_JOBMGR, (void*)(engine + ENGINE_OFF_JOBMGR),
            CCM_OFF_CONN_CONTEXT, *(void**)((uintptr_t)ccm + CCM_OFF_CONN_CONTEXT));
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[CCM] WARNING: exception during extended diagnostics (code=0x%lX)", GetExceptionCode());
    }

    // Install service-method vtable hook (Approach E) now that we have steamclient base
    if (!g_vtableHookInstalled.load(std::memory_order_acquire) && HasNamespaceApps()) {
        InstallServiceMethodHook();
    }
}

// Approach D response injection: OnSendPkt enqueues; RecvPktMonitorHook drains on the network thread (valid Coroutine_Continue TLS).

struct QueuedInjection {
    uint8_t* pktBuf;       // VirtualAlloc'd packet data (kept in ring for deferred free)
    uint32_t pktSize;
    CNetPacket* pktStruct; // malloc'd CNetPacket
    uint64_t jobIdTarget;  // job to route the response to
    uint32_t emsg;         // EMsg type (147 service-method resp, 819 legacy user-stats resp)
    char methodName[128];
};

// Lock order: drop g_injectMutex before ProcessQueuedInjection (the call chain re-acquires via InjectResponse->enqueue).
static std::queue<QueuedInjection*> g_injectQueue;
static std::mutex g_injectMutex;
// Reentrancy guard: BRouteMsgToJob resumes a coroutine that may send another packet,
// re-entering OnSendPkt; the flag prevents recursion into the drain loop.
static thread_local bool t_drainingInjectQueue = false;

static void ProcessQueuedInjection(QueuedInjection* ctx); // defined below

// Live playtime-update queue. Writer touches CUser map, must run on net thread.
static std::queue<std::vector<uint8_t>> g_playtimeUpdateQueue;
static std::mutex g_playtimeUpdateMutex;
static void ApplyLastPlayedUpdate(const std::vector<uint8_t>& respBody); // defined below

// Enqueue a serialized playtime response body. Thread-safe.
static void QueueLastPlayedUpdate(const std::vector<uint8_t>& respBody) {
    if (respBody.empty()) return;
    std::lock_guard<std::mutex> lock(g_playtimeUpdateMutex);
    g_playtimeUpdateQueue.push(respBody);
}

// Drain queued playtime updates. Caller MUST be on Steam's network thread.
static void DrainPlaytimeUpdateQueueOnNetThread() {
    std::vector<std::vector<uint8_t>> batch;
    {
        std::lock_guard<std::mutex> lock(g_playtimeUpdateMutex);
        while (!g_playtimeUpdateQueue.empty()) {
            batch.push_back(std::move(g_playtimeUpdateQueue.front()));
            g_playtimeUpdateQueue.pop();
        }
    }
    for (auto& body : batch)
        ApplyLastPlayedUpdate(body);
}

// ── Schema-request queue ──────────────────────────────────────────────────
// BAsyncSend requires the network thread (pipe/coroutine TLS). Background threads
// enqueue (appId, owner) pairs; drained a few per net-thread tick.
struct SchemaSendItem { uint32_t appId; uint64_t owner; };
static std::queue<SchemaSendItem> g_schemaSendQueue;
static std::mutex g_schemaSendMutex;
static bool SendSchemaRequest(uint32_t appId, uint64_t ownerId, uint32_t connHandle); // fwd

// Compile-time kill-switch: set to 0 to completely disable proactive schema
// fetching (leaves the rest of the DLL intact). Kept as an emergency guard.
#define SCHEMA_FETCH_ENABLED 1

// Reentrancy guard: BAsyncSend re-enters the hook -> DrainSchemaQueue recursion.
static thread_local bool t_drainingSchemaQueue = false;

// Drain a small batch of queued schema requests on the calling network thread.
// Called from the recv/send hooks (which already run on the net thread).
static void DrainSchemaQueueOnNetThread() {
#if !SCHEMA_FETCH_ENABLED
    return;
#endif
    if (!MetadataSync::SchemaFetchEnabled()) return;
    if (t_drainingSchemaQueue) return;          // prevent reentrancy via BAsyncSend
    if (g_shuttingDown.load(std::memory_order_acquire)) return;
    if (!g_hdrCaptured.load(std::memory_order_relaxed)) return;  // need session fields
    // Prefer stats conn handle; fall back to generic live handle.
    uint32_t conn = g_statsConnHandle.load(std::memory_order_relaxed);
    if (conn == 0) conn = g_liveConnHandle.load(std::memory_order_relaxed);
    if (conn == 0) return;
    t_drainingSchemaQueue = true;
    constexpr int kMaxPerTick = 2;   // gentle: a couple of sends per net tick
    for (int i = 0; i < kMaxPerTick; ++i) {
        SchemaSendItem item;
        {
            std::lock_guard<std::mutex> lock(g_schemaSendMutex);
            if (g_schemaSendQueue.empty()) break;
            item = g_schemaSendQueue.front();
            g_schemaSendQueue.pop();
        }
        SendSchemaRequest(item.appId, item.owner, conn);
    }
    t_drainingSchemaQueue = false;
}

// Drain inject queue on network thread.
static void DrainInjectQueueOnNetThread() {
    if (t_drainingInjectQueue) return;
    t_drainingInjectQueue = true;
    static constexpr int kMaxDrainIterations = 16;
    for (int drainIter = 0; drainIter < kMaxDrainIterations; ++drainIter) {
        std::vector<QueuedInjection*> batch;
        {
            std::lock_guard<std::mutex> lock(g_injectMutex);
            while (!g_injectQueue.empty()) {
                batch.push_back(g_injectQueue.front());
                g_injectQueue.pop();
            }
        }
        if (batch.empty()) break;
        for (auto* inj : batch) {
            ProcessQueuedInjection(inj);
        }
        if (drainIter == kMaxDrainIterations - 1) {
            LOG("[INJECT] WARNING: drain loop hit %d iteration limit", kMaxDrainIterations);
        }
    }
    t_drainingInjectQueue = false;
}

// Process a single queued injection (called on the network thread from RecvPktMonitorHook)
static void ProcessQueuedInjection(QueuedInjection* ctx) {
    LOG("[INJECT] Processing queued inject: %s (pkt=%u bytes, jobid=%llu)",
        ctx->methodName, ctx->pktSize, ctx->jobIdTarget);

    if (!g_wrapPacket || !g_bRouteMsgToJob || !g_releaseWrapped) {
        LOG("[INJECT] FATAL: BRouteMsgToJob bypass not resolved");
        VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
        free(ctx->pktStruct);
        delete ctx;
        return;
    }

    // WrapPacket takes ownership via refcount; caller frees on failure.
    void* wrappedPkt = nullptr;
    __try {
        wrappedPkt = g_wrapPacket(ctx->pktStruct, 1);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[INJECT] EXCEPTION in WrapPacket: code=0x%08X", GetExceptionCode());
        VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
        free(ctx->pktStruct);
        delete ctx;
        return;
    }

    if (!wrappedPkt) {
        LOG("[INJECT] WrapPacket returned NULL -- packet validation failed");
        VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
        free(ctx->pktStruct);
        delete ctx;
        return;
    }

    // SEH-wrap vtable + slot reads on the Steam-internal wrapped packet.
    using GetEMsgFn = unsigned int(__fastcall*)(void* self);
    unsigned int wrappedEmsg = 0;
    __try {
        uintptr_t wrappedVtable = *(uintptr_t*)wrappedPkt;
        GetEMsgFn getEMsg = (GetEMsgFn)(*(uintptr_t*)(wrappedVtable + 0x40));
        wrappedEmsg = getEMsg(wrappedPkt);
        LOG("[INJECT]   wrappedPkt=%p GetEMsg()=%u (expected %u)",
            wrappedPkt, wrappedEmsg, (unsigned)EMSG_SERVICE_METHOD_RESP);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[INJECT]   EXCEPTION in GetEMsg: code=0x%08X", GetExceptionCode());
        __try { g_releaseWrapped(wrappedPkt); } __except(EXCEPTION_EXECUTE_HANDLER) {}
        VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
        delete ctx;
        return;
    }

    // Get CJobMgr and connection context (SEH-protected like FindCCMInterface)
    void* jobMgr = nullptr;
    void* connCtx = nullptr;
    __try {
        uintptr_t* pEngineGlobal = (uintptr_t*)SC_RESOLVE(globalEngine);
        uintptr_t engine = *pEngineGlobal;
        jobMgr = (void*)(engine + ENGINE_OFF_JOBMGR);
        connCtx = *(void**)((uintptr_t)g_cmInterface.load(std::memory_order_acquire) + CCM_OFF_CONN_CONTEXT);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[INJECT]   EXCEPTION reading engine/connCtx: code=0x%08X", GetExceptionCode());
        __try { g_releaseWrapped(wrappedPkt); } __except(EXCEPTION_EXECUTE_HANDLER) {}
        VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
        delete ctx;
        return;
    }

    // Build routing info (mirrors what RecvPkt builds on stack)
    JobRouteInfo route;
    route.jobidSource = -1;
    route.jobidTarget = (int64_t)ctx->jobIdTarget;
    route.emsg = (int32_t)ctx->emsg;
    route.flags = -3;

    LOG("[INJECT]   jobMgr=%p route: tgt=%llu emsg=%d flags=%d",
        jobMgr, (unsigned long long)ctx->jobIdTarget, route.emsg, route.flags);

    // RESPONSE routes by jobid_target; NOTIFICATION (JOBID_NONE) routes by name.
    // Skip pre-check for notifications to avoid dropping server pushes.
    bool isNotification = (ctx->jobIdTarget == JOBID_NONE);
    if (!isNotification) {
        // Pre-check: verify the waiting job still exists. BRouteMsgToJob silently
        // no-ops on a missing slot but returns 1 (false success), masking a
        // dropped response.
        using FindJobFn = int(__fastcall*)(void* slotMap, void* pJobId);
        FindJobFn findJob = (FindJobFn)SC_RESOLVE(findJob);
        int jobSlot = -1;
        bool findJobThrew = false;
        if (!findJob) {
            LOG("[INJECT]   FindJob not resolved, skipping pre-check");
            findJobThrew = true;  // treat as if threw -- skip the drop-on-miss logic
        } else {
            __try {
                void* slotMap = (void*)((uintptr_t)jobMgr + 0x200);
                jobSlot = findJob(slotMap, &route.jobidTarget);
                if (jobSlot >= 0) {
                    uintptr_t slotArr = *(uintptr_t*)((uintptr_t)jobMgr + 0x230);
                    void* cjobPtr = *(void**)(slotArr + (uintptr_t)jobSlot * 24 + 8);
                    uint32_t jobState = cjobPtr ? *(uint32_t*)((uintptr_t)cjobPtr + 0x84) : 999;
                    LOG("[INJECT]   FindJob slot=%d cjob=%p state=%u", jobSlot, cjobPtr, jobState);
                } else {
                    LOG("[INJECT]   FindJob: job not found (slot=%d) -- timed out, dropping inject for %s",
                        jobSlot, ctx->methodName);
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                LOG("[INJECT]   EXCEPTION in FindJob: code=0x%08X", GetExceptionCode());
                findJobThrew = true;
            }
        }
        if (jobSlot < 0 && !findJobThrew) {
            __try { g_releaseWrapped(wrappedPkt); } __except(EXCEPTION_EXECUTE_HANDLER) {}
            VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
            delete ctx;
            return;
        }
    } else {
        LOG("[INJECT]   notification %s: routing by target_job_name (no waiting job)", ctx->methodName);
    }

    // Increment refcount (matches RecvPkt at 0x13859D4CC)
    if (g_refCountHelper && g_refCountGlobalPtr) {
        __try {
            g_refCountHelper(g_refCountGlobalPtr);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[INJECT]   EXCEPTION in RefCountHelper: code=0x%08X", GetExceptionCode());
        }
    }

    // Call BRouteMsgToJob (on network thread - coroutine manager is valid here)
    char result = 0;
    s_crashFaultAddr = 0;
    s_crashAccessAddr = 0;
    __try {
        result = g_bRouteMsgToJob(jobMgr, connCtx, wrappedPkt, &route, -1);
        LOG("[INJECT] BRouteMsgToJob returned %d for %s", (int)result, ctx->methodName);
    } __except(CrashExcFilter(GetExceptionInformation())) {
        const char* accessTypeStr = s_crashAccessType == 0 ? "READ" :
                                     s_crashAccessType == 1 ? "WRITE" :
                                     s_crashAccessType == 8 ? "DEP" : "???";
        LOG("[INJECT] EXCEPTION in BRouteMsgToJob for %s: code=0x%08X %s at 0x%llX, crashIP=%p",
            ctx->methodName, GetExceptionCode(),
            accessTypeStr, (unsigned long long)s_crashAccessAddr,
            (void*)s_crashFaultAddr);
        LOG("[INJECT]   Crash module: %s", s_crashModuleName[0] ? s_crashModuleName : "(unknown)");
    }

    __try {
        g_releaseWrapped(wrappedPkt);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[INJECT] EXCEPTION in ReleaseWrapped: code=0x%08X", GetExceptionCode());
    }

    VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
    delete ctx;
}

// Free queued injections at shutdown without dispatching them; the
// receive thread is gone so BRouteMsgToJob is unsafe.
static void DrainInjectQueueOnShutdown() {
    std::vector<QueuedInjection*> leftovers;
    {
        std::lock_guard<std::mutex> lock(g_injectMutex);
        while (!g_injectQueue.empty()) {
            leftovers.push_back(g_injectQueue.front());
            g_injectQueue.pop();
        }
    }
    if (leftovers.empty()) return;
    LOG("Shutdown: dropping %zu undelivered injection(s)", leftovers.size());
    for (auto* ctx : leftovers) {
        if (ctx->pktBuf) VirtualFree(ctx->pktBuf, 0, MEM_RELEASE);
        if (ctx->pktStruct) free(ctx->pktStruct);
        delete ctx;
    }
}

static bool InjectResponse(uint64_t jobIdTarget, const std::string& methodName,
                           int32_t eresult, const PB::Writer& body) {
    if (!g_wrapPacket || !g_bRouteMsgToJob || !g_releaseWrapped || !g_cmInterface.load(std::memory_order_acquire)) {
        LOG("[INJECT] Cannot inject: wrapPacket=%p bRouteMsgToJob=%p releaseWrapped=%p cmInterface=%p",
            g_wrapPacket, g_bRouteMsgToJob, g_releaseWrapped, g_cmInterface.load(std::memory_order_relaxed));
        return false;
    }

    // build response header
    PB::Writer hdr;
    if (g_steamId.load()) hdr.WriteFixed64(HDR_STEAMID, g_steamId.load());
    if (g_sessionId.load()) hdr.WriteVarint(HDR_SESSIONID, (uint64_t)(uint32_t)g_sessionId.load());
    hdr.WriteVarint(HDR_ERESULT, (uint64_t)eresult);
    if (jobIdTarget != JOBID_NONE)
        hdr.WriteFixed64(HDR_JOBID_TARGET, jobIdTarget);
    hdr.WriteString(HDR_TARGET_JOB_NAME, methodName);

    auto pktData = BuildPacket(EMSG_SERVICE_METHOD_RESP, hdr, body);

    // VirtualAlloc for page-aligned packet buffer; CNetPacket holds the pointer past RecvPkt, so a ring buffer defers free.
    uint8_t* pktBuf = (uint8_t*)VirtualAlloc(nullptr, pktData.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pktBuf) {
        LOG("[INJECT] VirtualAlloc failed (%zu bytes)", pktData.size());
        return false;
    }
    memcpy(pktBuf, pktData.data(), pktData.size());

    // pktBuf lifetime is managed by ProcessQueuedInjection - freed after BRouteMsgToJob completes.

    // CNetPacket::Release pools rather than frees; m_cRef=1 keeps refcount > 0 forever and our malloc'd packet out of the pool (~64 B/inject leak).
    auto* fakePkt = (CNetPacket*)malloc(sizeof(CNetPacket));
    if (!fakePkt) {
        LOG("[INJECT] malloc failed for CNetPacket");
        VirtualFree(pktBuf, 0, MEM_RELEASE);
        return false;
    }
    memset(fakePkt, 0, sizeof(CNetPacket));
    fakePkt->pubData = pktBuf;
    fakePkt->cubData = (uint32_t)pktData.size();
    fakePkt->m_cRef = 1; // start at 1 to prevent pool recycling (see comment above)

    LOG("[INJECT] Deferring %s response: eresult=%d body=%zu bytes pkt=%zu bytes",
        methodName.c_str(), eresult, body.Size(), pktData.size());

    // Queue for the network thread to drain (BRouteMsgToJob requires net-thread TLS).
    auto* ctx = new QueuedInjection();
    ctx->pktBuf = pktBuf;
    ctx->pktSize = (uint32_t)pktData.size();
    ctx->pktStruct = fakePkt;
    ctx->jobIdTarget = jobIdTarget;
    ctx->emsg = EMSG_SERVICE_METHOD_RESP;
    strncpy(ctx->methodName, methodName.c_str(), sizeof(ctx->methodName) - 1);
    ctx->methodName[sizeof(ctx->methodName) - 1] = '\0';

    {
        std::lock_guard<std::mutex> lock(g_injectMutex);
        g_injectQueue.push(ctx);
        LOG("[INJECT] Queued for network thread injection (%zu pending)",
            g_injectQueue.size());
    }

    return true;
}

// Inject a raw EMsg 819 response to the waiting job (header: steamid + jobid_target only).
static bool InjectLegacyUserStatsResponse(uint64_t jobIdTarget, uint32_t appId,
                                          const std::vector<uint8_t>& body) {
    if (!g_wrapPacket || !g_bRouteMsgToJob || !g_releaseWrapped || !g_cmInterface.load(std::memory_order_acquire))
        return false;

    // 819 header: steamid + jobid_target (= outbound 818's jobid_source).
    PB::Writer hdr;
    if (g_steamId.load()) hdr.WriteFixed64(HDR_STEAMID, g_steamId.load());
    hdr.WriteFixed64(HDR_JOBID_TARGET, jobIdTarget);

    // BuildPacket frames with empty body; append pre-serialized 819 bytes after.
    PB::Writer emptyBody;
    auto pktData = BuildPacket(EMSG_CLIENT_GET_USER_STATS_RESP, hdr, emptyBody);
    pktData.insert(pktData.end(), body.begin(), body.end());

    uint8_t* pktBuf = (uint8_t*)VirtualAlloc(nullptr, pktData.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pktBuf) return false;
    memcpy(pktBuf, pktData.data(), pktData.size());

    auto* fakePkt = (CNetPacket*)malloc(sizeof(CNetPacket));
    if (!fakePkt) { VirtualFree(pktBuf, 0, MEM_RELEASE); return false; }
    memset(fakePkt, 0, sizeof(CNetPacket));
    fakePkt->pubData = pktBuf;
    fakePkt->cubData = (uint32_t)pktData.size();
    fakePkt->m_cRef = 1;

    auto* ctx = new QueuedInjection();
    ctx->pktBuf = pktBuf;
    ctx->pktSize = (uint32_t)pktData.size();
    ctx->pktStruct = fakePkt;
    ctx->jobIdTarget = jobIdTarget;
    ctx->emsg = EMSG_CLIENT_GET_USER_STATS_RESP;
    snprintf(ctx->methodName, sizeof(ctx->methodName), "ClientGetUserStatsResponse(app=%u)", appId);

    {
        std::lock_guard<std::mutex> lock(g_injectMutex);
        g_injectQueue.push(ctx);
    }
    LOG("[Stats] Queued legacy 819 for app=%u jobid=%llu (%zu bytes)",
        appId, (unsigned long long)jobIdTarget, pktData.size());
    return true;
}

// Feed synthesized GetLastPlayedTimes response to Steam's writer (sub_1389C7930).
// Direct-write: NotifyLastPlayedTimes#1 isn't in GMapJobTypesByName. Net thread only.
static void ApplyLastPlayedUpdate(const std::vector<uint8_t>& respBody) {
    if (!g_parseFromArray || respBody.empty()) return;

    uintptr_t pUser = FindCurrentUser();
    if (!pUser) {
        LOG("[Stats] ApplyLastPlayedUpdate: no current user");
        return;
    }

    // Stack CProtoBufMsg: [0]=vtable, [1]=descriptor, [6]=inner body (from init).
    uintptr_t wrapper[11] = {0};
    using MsgCtorFn = void(__fastcall*)(void* self, int a2, int a3);
    using MsgInitFn = void(__fastcall*)(void* self);
    using MsgDtorFn = void(__fastcall*)(void* self);
    using WriterFn  = uint32_t(__fastcall*)(uintptr_t pUser, uintptr_t gamesArray, int count);
    using RegWriteFn = void(__fastcall*)(void* reg, int type, const char* key, uint32_t val);

    uintptr_t ctorAddr = SC_RESOLVE(pbMsgCtor);
    uintptr_t initAddr = SC_RESOLVE(pbMsgFinalize);
    uintptr_t dtorAddr = SC_RESOLVE(pbMsgCleanup);
    uintptr_t writerAddr = SC_RESOLVE(playtimeWriter);
    uintptr_t wrapVt = SC_RESOLVE(respWrapperVtable);
    uintptr_t descAddr = SC_RESOLVE(respDescriptor);
    if (!ctorAddr || !initAddr || !dtorAddr || !writerAddr || !wrapVt || !descAddr) {
        LOG("[Stats] ApplyLastPlayedUpdate: skipped (playtime subsystem not resolved)");
        return;
    }
    auto msgCtor = (MsgCtorFn)ctorAddr;
    auto msgInit = (MsgInitFn)initAddr;
    auto msgDtor = (MsgDtorFn)dtorAddr;
    auto writer  = (WriterFn)writerAddr;

    __try {
        msgCtor(wrapper, 0, 0);
        wrapper[0] = wrapVt;
        wrapper[1] = descAddr;
        msgInit(wrapper);

        uintptr_t inner = wrapper[6]; // m_pProtoBufBody (the inner MessageLite)
        if (!inner) {
            LOG("[Stats] ApplyLastPlayedUpdate: inner body alloc failed");
            msgDtor(wrapper);
            return;
        }

        if (!g_parseFromArray((void*)inner, (const char*)respBody.data(), (int)respBody.size())) {
            LOG("[Stats] ApplyLastPlayedUpdate: ParseFromArray failed (%zu bytes)", respBody.size());
            msgDtor(wrapper);
            return;
        }

        // sub_1389DA1D0: v2 = *(inner+32); games = (v2 ? v2+8 : 0); count = *(inner+24)
        uintptr_t arrayBase = *(uintptr_t*)(inner + RESP_OFF_GAMES_ARRAY);
        int count = *(int*)(inner + RESP_OFF_GAMES_COUNT);
        uintptr_t games = arrayBase ? (arrayBase + 8) : 0;

        if (games && count > 0) {
            uint32_t syncTime = writer(pUser, games, count);
            // Persist LastPlayedTimesSyncTime (sub_1389DA1D0 tail).
            __try {
                uintptr_t reg = pUser + USER_OFF_REGISTRY;
                auto regWrite = (RegWriteFn)(*(uintptr_t*)(*(uintptr_t*)reg + 80));
                uintptr_t keyPtr = SC_RESOLVE(regKeySyncTime);
                if (keyPtr) {
                    const char* key = *(const char**)keyPtr;
                    regWrite((void*)reg, 3, key, syncTime);
                } else {
                    LOG("[Stats] RegKeySyncTime not resolved");
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                LOG("[Stats] ApplyLastPlayedUpdate: sync-time write threw (non-fatal)");
            }
            LOG("[Stats] ApplyLastPlayedUpdate: pushed %d game(s) to live client map", count);
        } else {
            LOG("[Stats] ApplyLastPlayedUpdate: no games parsed (count=%d)", count);
        }

        msgDtor(wrapper);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[Stats] ApplyLastPlayedUpdate: EXCEPTION code=0x%08X", GetExceptionCode());
    }
}

uint32_t GetAccountId() {
    uint64_t sid = g_steamId.load();
    if (sid != 0) return (uint32_t)(sid & 0xFFFFFFFF);

    // Fallback: read from CUser and seed g_steamId (individual/desktop SteamID64).
    uint32_t acct = ReadAccountIdFromUser();
    if (acct != 0) {
        uint64_t full = (uint64_t)acct | (1ULL << 32) | (1ULL << 52) | (1ULL << 56);
        uint64_t expected = 0;
        if (g_steamId.compare_exchange_strong(expected, full))
            LOG("[NS] Account id %u read from CUser (no packet scraped yet)", acct);
    }
    return acct;
}

const std::string& GetSteamPath() {
    return g_steamPath;
}

// Service-method vtable hook (Approach E): intercept Cloud RPCs via slot 4/5.
// CProtoBufMsg layout: +40 header*, +48 body*
// CMsgProtoBufHeader: +16 has_bits, +24 appid, +116 routing_appid, +216 eresult, +220 error_code

// Serialize a protobuf message body object to raw bytes
// SEH helpers (cannot use __try in functions with C++ objects)
static uint64_t SEH_ByteSize(void* bodyObj) {
    if (!bodyObj) return 0;
    __try {
        uintptr_t vtable = *(uintptr_t*)bodyObj;
        using ByteSizeFn = uint64_t(__fastcall*)(void* self);
        ByteSizeFn byteSize = (ByteSizeFn)(*(uintptr_t*)(vtable + 64));
        return byteSize(bodyObj);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION in ByteSize: code=0x%08X", GetExceptionCode());
        return 0;
    }
}

static ptrdiff_t SEH_SerializeToArray(void* bodyObj, uint8_t* buf, uint64_t expectedSize) {
    if (expectedSize > (uint64_t)INT_MAX) {
        LOG("[VtHook] SerializeToArray size %llu exceeds INT_MAX, rejecting", expectedSize);
        return -1;
    }

    __try {
        uintptr_t bufAddr = reinterpret_cast<uintptr_t>(buf);
        uintptr_t result = g_serializeToArray(bodyObj, buf, (int)expectedSize);
        if (!result) return -1;

        if (g_detectedSteamVersion.load(std::memory_order_relaxed) >= 1778281814ULL) {
            if ((result & 0xFF) != 0) return (ptrdiff_t)expectedSize;
            return -1;
        }

        if (result >= bufAddr && result <= bufAddr + expectedSize) {
            return static_cast<ptrdiff_t>(result - bufAddr);
        }

        if ((result & 0xFF) != 0) {
            return (ptrdiff_t)expectedSize;
        }

        if (result < bufAddr) {
            LOG("[VtHook] SerializeToArray returned invalid end pointer %p (buf=%p)",
                (void*)result, (void*)bufAddr);
            return -1;
        }

        LOG("[VtHook] SerializeToArray returned invalid end pointer %p (buf=%p)",
            (void*)result, (void*)bufAddr);
        return -1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION in SerializeToArray: code=0x%08X", GetExceptionCode());
        return -1;
    }
}

static std::vector<uint8_t> SerializeBodyToBytes(void* bodyObj) {
    if (!bodyObj || !g_serializeToArray) return {};

    uint64_t size = SEH_ByteSize(bodyObj);
    if (size == 0) return {};
    if (size > 16 * 1024 * 1024) {
        LOG("[VtHook] ByteSize returned %llu (too large), skipping", size);
        return {};
    }

    std::vector<uint8_t> buf((size_t)size);
    ptrdiff_t written = SEH_SerializeToArray(bodyObj, buf.data(), size);
    if (written < 0) {
        LOG("[VtHook] SerializeToArray failed (returned %lld)", (long long)written);
        return {};
    }
    // ByteSize is a conservative upper bound; actual serialized length is often smaller.
    if ((ptrdiff_t)size != written) {
        LOG("[VtHook] SerializeToArray wrote %lld bytes (ByteSize=%llu), resizing",
            (long long)written, size);
        buf.resize(static_cast<size_t>(written));
    }

    return buf;
}

// Parse raw protobuf bytes into a body object (SEH wrapper)
static char SEH_ParseFromArray(void* bodyObj, const uint8_t* data, int size) {
    __try {
        return g_parseFromArray(bodyObj, (const char*)data, size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION in ParseFromArray: code=0x%08X", GetExceptionCode());
        return 0;
    }
}

static bool ParseBytesToBody(void* bodyObj, const uint8_t* data, size_t size) {
    if (!bodyObj || !g_parseFromArray || !data || size == 0) return false;
    if (size > (size_t)INT_MAX) {
        LOG("[VtHook] ParseBytesToBody: size %zu exceeds INT_MAX, rejecting", size);
        return false;
    }
    return SEH_ParseFromArray(bodyObj, data, (int)size) != 0;
}

// SEH-safe header field writing
static bool SEH_WriteResponseHeader(void* respHeader, int32_t eresult = 1) {
    __try {
        *(uint32_t*)((uintptr_t)respHeader + 16) |= 0x20000000u;
        *(int32_t*)((uintptr_t)respHeader + 216) = eresult;

        *(uint32_t*)((uintptr_t)respHeader + 16) |= 0x40000000u;
        *(int32_t*)((uintptr_t)respHeader + 220) = 0;
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION writing response header: code=0x%08X", GetExceptionCode());
        return false;
    }
}

// Shared Cloud RPC dispatch - routes a method name to the appropriate handler.
// Returns std::nullopt if the method is not a recognized Cloud RPC we handle.
static std::optional<RpcResult> DispatchCloudRpc(
    const char* method, uint32_t appId, const std::vector<PB::Field>& reqBody) {
    if (strcmp(method, RPC_GET_CHANGELIST) == 0)       return HandleGetChangelist(appId, reqBody);
    if (strcmp(method, RPC_LAUNCH_INTENT) == 0)        return HandleLaunchIntent(appId, reqBody);
    if (strcmp(method, RPC_SUSPEND_SESSION) == 0)      return HandleSuspendSession(appId, reqBody);
    if (strcmp(method, RPC_RESUME_SESSION) == 0)       return HandleResumeSession(appId, reqBody);
    if (strcmp(method, RPC_QUOTA_USAGE) == 0)          return HandleQuotaUsage(appId, reqBody);
    if (strcmp(method, RPC_BEGIN_BATCH) == 0)           return HandleBeginBatch(appId, reqBody);
    if (strcmp(method, RPC_BEGIN_UPLOAD) == 0)          return HandleBeginFileUpload(appId, reqBody);
    if (strcmp(method, RPC_COMMIT_UPLOAD) == 0)        return HandleCommitFileUpload(appId, reqBody);
    if (strcmp(method, RPC_COMPLETE_BATCH) == 0)       return HandleCompleteBatch(appId, reqBody);
    if (strcmp(method, RPC_FILE_DOWNLOAD) == 0)        return HandleFileDownload(appId, reqBody);
    if (strcmp(method, RPC_DELETE_FILE) == 0)          return HandleDeleteFile(appId, reqBody);
    return std::nullopt;
}

// Vtable slot 4 hook: direct request/response (no CProtoBufMsg wrapper).
// ClientBeginFileUpload / ClientCommitFileUpload / ClientFileDownload all
// call slot 4 directly, so handling here avoids the slot-5 deferred queue.
// Flags layout (int[68]): [0]=routing_appid, [1]=mode, [2]=error_code, [3]=eresult, [4..67]=error_message
static bool __fastcall ServiceMethodDirectHook(void* thisptr, const char* methodName,
                                                  void* requestBody, void* responseBody, int* flags) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);

    // cloudSaveOnly: drain playtime updates here (no RecvPkt/SendPkt hooks).
    if (g_cloudSaveOnly.load(std::memory_order_relaxed))
        DrainPlaytimeUpdateQueueOnNetThread();

    if (!methodName) {
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    if (g_parentalBypassPlaytime.load() &&
        strcmp(methodName, "Parental.GetSignedParentalSettings#1") == 0) {
        bool result = g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
        if (result && responseBody) {
            auto respBytes = SerializeBodyToBytes(responseBody);
            auto respFields = PB::Parse(respBytes.data(), respBytes.size());
            const PB::Field* sf = PB::FindField(respFields, 1);
            if (sf && sf->wireType == PB::LengthDelimited && sf->data) {
                auto stripped = ParentalBypass::StripPlaytimeRestrictions(sf->data, sf->dataLen);
                PB::Writer newResp;
                newResp.WriteBytes(1, stripped.data(), stripped.size());
                for (const auto& f : respFields) {
                    if (f.fieldNum == 1) continue;
                    if (f.wireType == PB::Varint)        newResp.WriteVarint(f.fieldNum, f.varintVal);
                    else if (f.wireType == PB::Fixed64)  newResp.WriteFixed64(f.fieldNum, f.varintVal);
                    else if (f.wireType == PB::LengthDelimited) newResp.WriteBytes(f.fieldNum, f.data, f.dataLen);
                }
                if (ParseBytesToBody(responseBody, newResp.Data().data(), newResp.Size()))
                    LOG("[Parental] Stripped restrictions from GetSignedParentalSettings (slot4)");
            }
        }
        return result;
    }

    // Player.GetUserStats#1 (slot 4, raw bodies). Third-party uses raw schemaFetch flag.
    if (strcmp(methodName, StatsHandlers::RPC_GET_USER_STATS) == 0
        && (g_cloudSaveOnly.load(std::memory_order_relaxed)
            ? MetadataSync::schemaFetch.load(std::memory_order_relaxed)
            : MetadataSync::SchemaFetchEnabled())) {
        if (requestBody && responseBody && g_serializeToArray) {
            auto reqBytes = SerializeBodyToBytes(requestBody);
            auto reqFields = PB::Parse(reqBytes.data(), reqBytes.size());
            uint32_t appId = 0;
            if (auto* f = PB::FindField(reqFields, 2)) appId = (uint32_t)f->varintVal; // appid #2
            LOG("[Stats] slot4 GetUserStats seen: app=%u namespace=%d", appId, IsNamespaceApp(appId) ? 1 : 0);
            if (appId != 0 && IsNamespaceApp(appId)) {
                auto res = StatsHandlers::HandleGetUserStats(appId, reqFields);
                if (res.body.Size() > 0 &&
                    ParseBytesToBody(responseBody, res.body.Data().data(), res.body.Size())) {
                    if (flags) { flags[2] = 1; flags[3] = res.eresult; }
                    LOG("[Stats] GetUserStats app=%u handled locally via slot4 (%zu bytes)",
                        appId, res.body.Size());
                    return true;
                }
                LOG("[Stats] GetUserStats app=%u slot4 NOT handled (bodySize=%zu) -> passthrough",
                    appId, res.body.Size());
            }
        } else {
            LOG("[Stats] slot4 GetUserStats: missing req/resp/serializer -> passthrough");
        }
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    if (strncmp(methodName, "Cloud.", 6) != 0) {
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    // Only intercept the RPCs known to use slot 4 directly (zero-alloc check via strcmp)
    bool isSlot4Rpc = (strcmp(methodName, RPC_BEGIN_UPLOAD) == 0 || strcmp(methodName, RPC_COMMIT_UPLOAD) == 0 ||
                       strcmp(methodName, RPC_FILE_DOWNLOAD) == 0 || strcmp(methodName, RPC_DELETE_FILE) == 0);
    if (!isSlot4Rpc) {
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    // Serialize request body to raw protobuf bytes
    if (!requestBody || !g_serializeToArray) {
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    auto reqBytes = SerializeBodyToBytes(requestBody);
    if (reqBytes.empty()) {
        LOG("[Slot4] %s: failed to serialize request body, passing through", methodName);
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    // Parse the raw bytes to get fields
    auto innerFields = PB::Parse(reqBytes.data(), reqBytes.size());
    uint32_t appId = CloudRpcUtils::ExtractAppId(methodName, innerFields);
    if (appId == 0) {
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    // Check if this is a namespace app
    uint32_t realAppId = 0;
    bool isNamespace = false;

    if (IsNamespaceApp(appId)) {
        realAppId = appId;
        isNamespace = true;
    }

    if (!isNamespace) {
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    // FileDownload handled by DispatchCloudRpc below (calling original double-handles).

    // NAMESPACE APP: handle locally, synchronously
    auto slot4Start = std::chrono::steady_clock::now();
    LOG("[Slot4] INTERCEPT %s app=%u (%zu bytes) flags-before=[%d,%d,%d,%d]:",
        methodName, appId, reqBytes.size(),
        flags ? flags[0] : -1, flags ? flags[1] : -1,
        flags ? flags[2] : -1, flags ? flags[3] : -1);
#ifdef DEBUG_VERBOSE_LOGGING
    SpyLogFields("[Slot4-REQ]", reqBytes.data(), (uint32_t)reqBytes.size());
#endif

    // Capture SteamID from request header if not already cached.

    // Call the appropriate handler to build a response body
    auto dispatched = DispatchCloudRpc(methodName, realAppId, innerFields);
    if (!dispatched.has_value()) {
        LOG("[Slot4] Unhandled method %s, passing through", methodName);
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }
    auto& result = *dispatched;

    LOG("[Slot4] %s: response body %zu bytes, eresult=%d", methodName, result.body.Size(), result.eresult);

    // Write the response body into the response protobuf object
    if (responseBody && result.body.Size() > 0) {
        if (!ParseBytesToBody(responseBody, result.body.Data().data(), result.body.Size())) {
            LOG("[Slot4] %s: ParseFromArray failed for response body! Returning transport failure.", methodName);
            return false;
        }
    }

    // Flags: [0-1]=context, [2]=transport_ok, [3]=eresult, [4+]=error_msg
    if (flags) {
        flags[2] = 1;  // transport_success = true (MUST be 1, or caller returns k_EResultTimeout!)
        flags[3] = result.eresult;
        flags[4] = 0;  // error_message = "" (null terminator)
    }

    auto slot4Ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - slot4Start).count();
    LOG("[Slot4] %s handled in %lldms flags-after=[%d,%d,%d,%d]",
        methodName, (long long)slot4Ms,
        flags ? flags[0] : -1, flags ? flags[1] : -1,
        flags ? flags[2] : -1, flags ? flags[3] : -1);
    return true;
}

// ── Native Cloud spy ──────────────────────────────────────────────────────
// CR_SPY_APPID: log native cloud RPCs for a non-namespace app (read-only).
static uint32_t g_spyAppId = []() -> uint32_t {
    char buf[32] = {0};
    DWORD n = GetEnvironmentVariableA("CR_SPY_APPID", buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return 0;
    return (uint32_t)strtoul(buf, nullptr, 10);
}();

// Decode + log a Cloud.GetAppFileChangelist response: per-file path_prefix_index
// plus the path_prefixes table, which together reveal native's per-root entries.
static void SpyLogChangelistResponse(const char* tag, uint32_t appId,
                                     const uint8_t* data, size_t len) {
    auto fields = PB::Parse(data, len);
    uint64_t cn = 0; uint32_t isDelta = 0;
    std::vector<std::string> prefixes;
    struct SpyFile { std::string leaf; uint32_t prefixIdx; uint32_t persist; uint32_t platforms; uint64_t size; };
    std::vector<SpyFile> files;
    for (const auto& f : fields) {
        if (f.fieldNum == 1 && f.wireType == PB::Varint) cn = f.varintVal;
        else if (f.fieldNum == 3 && f.wireType == PB::Varint) isDelta = (uint32_t)f.varintVal;
        else if (f.fieldNum == 4 && f.wireType == PB::LengthDelimited)
            prefixes.emplace_back((const char*)f.data, f.dataLen);
        else if (f.fieldNum == 2 && f.wireType == PB::LengthDelimited) {
            auto sub = PB::Parse(f.data, f.dataLen);
            SpyFile sf{};
            for (const auto& g : sub) {
                if (g.fieldNum == 1 && g.wireType == PB::LengthDelimited)
                    sf.leaf.assign((const char*)g.data, g.dataLen);
                else if (g.fieldNum == 4 && g.wireType == PB::Varint) sf.size = g.varintVal;
                else if (g.fieldNum == 5 && g.wireType == PB::Varint) sf.persist = (uint32_t)g.varintVal;
                else if (g.fieldNum == 6 && g.wireType == PB::Varint) sf.platforms = (uint32_t)g.varintVal;
                else if (g.fieldNum == 7 && g.wireType == PB::Varint) sf.prefixIdx = (uint32_t)g.varintVal;
            }
            files.push_back(std::move(sf));
        }
    }
    LOG("[SPY-CL] %s app=%u CN=%llu is_delta=%u nfiles=%zu nprefixes=%zu",
        tag, appId, (unsigned long long)cn, isDelta, files.size(), prefixes.size());
    for (size_t i = 0; i < prefixes.size(); ++i)
        LOG("[SPY-CL]   prefix[%zu] = '%s'", i, prefixes[i].c_str());
    for (const auto& sf : files) {
        const char* pfx = sf.prefixIdx < prefixes.size() ? prefixes[sf.prefixIdx].c_str() : "<oob>";
        LOG("[SPY-CL]   file leaf='%s' prefixIdx=%u prefix='%s' persist=%u platforms=0x%X size=%llu",
            sf.leaf.c_str(), sf.prefixIdx, pfx, sf.persist, sf.platforms,
            (unsigned long long)sf.size);
    }
}

// The actual vtable hook function - replaces CClientUnifiedServiceTransport::vtable[5]
static bool __fastcall ServiceMethodHook(void* thisptr, const char* methodName,
                                           void* request, void* response, int64_t* flags) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    if (!methodName) {
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    if (g_parentalBypassPlaytime.load() &&
        strcmp(methodName, "Parental.GetSignedParentalSettings#1") == 0) {
        bool result = g_originalSlot5(thisptr, methodName, request, response, flags);
        if (result && response) {
            void* respBody = *(void**)((uintptr_t)response + 48);
            if (respBody) {
                auto respBytes = SerializeBodyToBytes(respBody);
                auto respFields = PB::Parse(respBytes.data(), respBytes.size());
                const PB::Field* sf = PB::FindField(respFields, 1);
                if (sf && sf->wireType == PB::LengthDelimited && sf->data) {
                    auto stripped = ParentalBypass::StripPlaytimeRestrictions(sf->data, sf->dataLen);
                    PB::Writer newResp;
                    newResp.WriteBytes(1, stripped.data(), stripped.size());
                    for (const auto& f : respFields) {
                        if (f.fieldNum == 1) continue;
                        if (f.wireType == PB::Varint)        newResp.WriteVarint(f.fieldNum, f.varintVal);
                        else if (f.wireType == PB::Fixed64)  newResp.WriteFixed64(f.fieldNum, f.varintVal);
                        else if (f.wireType == PB::LengthDelimited) newResp.WriteBytes(f.fieldNum, f.data, f.dataLen);
                    }
                    if (ParseBytesToBody(respBody, newResp.Data().data(), newResp.Size()))
                        LOG("[Parental] Stripped restrictions from GetSignedParentalSettings (slot5)");
                }
            }
        }
        return result;
    }

    // Native stats / playtime service RPCs.
    // Player.GetUserStats#1: answer namespace apps from our store for the achievement page.
    if (strcmp(methodName, StatsHandlers::RPC_GET_USER_STATS) == 0
        && (g_cloudSaveOnly.load(std::memory_order_relaxed)
            ? MetadataSync::schemaFetch.load(std::memory_order_relaxed)
            : MetadataSync::SchemaFetchEnabled())) {
        if (request && response) {
            void* reqBody = *(void**)((uintptr_t)request + 48);
            if (reqBody) {
                auto reqBytes = SerializeBodyToBytes(reqBody);
                auto reqFields = PB::Parse(reqBytes.data(), reqBytes.size());
                // appid = field 2 in CPlayer_GetUserStats_Request
                uint32_t appId = 0;
                if (auto* f = PB::FindField(reqFields, 2)) appId = (uint32_t)f->varintVal;
                LOG("[Stats] slot5 GetUserStats seen: app=%u namespace=%d", appId, IsNamespaceApp(appId) ? 1 : 0);
                if (appId != 0 && IsNamespaceApp(appId)) {
                    auto res = StatsHandlers::HandleGetUserStats(appId, reqFields);
                    void* respBody = *(void**)((uintptr_t)response + 48);
                    if (respBody && res.body.Size() > 0 &&
                        ParseBytesToBody(respBody, res.body.Data().data(), res.body.Size())) {
                        if (flags) *flags = 0;
                        LOG("[Stats] GetUserStats app=%u handled locally (%zu bytes)",
                            appId, res.body.Size());
                        return true;
                    }
                    LOG("[Stats] GetUserStats app=%u NOT handled (respBody=%p bodySize=%zu) -> passthrough",
                        appId, *(void**)((uintptr_t)response + 48), res.body.Size());
                }
            } else {
                LOG("[Stats] slot5 GetUserStats: null reqBody -> passthrough");
            }
        }
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Third-party: bypass StGate — playtime data should appear in library.
    if (strcmp(methodName, StatsHandlers::RPC_GET_LAST_PLAYED) == 0
        && (g_cloudSaveOnly.load(std::memory_order_relaxed)
            ? MetadataSync::syncPlaytime.load(std::memory_order_relaxed)
            : MetadataSync::PlaytimeEnabled())) {
        bool result = g_originalSlot5(thisptr, methodName, request, response, flags);
        LOG("[Stats] slot5 GetLastPlayedTimes seen: serverResult=%d", result ? 1 : 0);
        if (result && response) {
            void* respBody = *(void**)((uintptr_t)response + 48);
            if (respBody) {
                // Parse the request to honor min_last_played.
                std::vector<PB::Field> reqFields;
                if (request) {
                    void* reqBody = *(void**)((uintptr_t)request + 48);
                    if (reqBody) {
                        auto reqBytes = SerializeBodyToBytes(reqBody);
                        reqFields = PB::Parse(reqBytes.data(), reqBytes.size());
                    }
                }
                auto ours = StatsHandlers::HandleGetLastPlayedTimes(reqFields);
                if (ours.body.Size() > 0) {
                    // Append our games[] (field 1) to the server's response.
                    auto respBytes = SerializeBodyToBytes(respBody);
                    PB::Writer merged;
                    // keep all existing fields verbatim
                    auto existing = PB::Parse(respBytes.data(), respBytes.size());
                    for (const auto& f : existing) {
                        if (f.wireType == PB::Varint)            merged.WriteVarint(f.fieldNum, f.varintVal);
                        else if (f.wireType == PB::Fixed64)      merged.WriteFixed64(f.fieldNum, f.varintVal);
                        else if (f.wireType == PB::Fixed32)      merged.WriteFixed32(f.fieldNum, (uint32_t)f.varintVal);
                        else if (f.wireType == PB::LengthDelimited) merged.WriteBytes(f.fieldNum, f.data, f.dataLen);
                    }
                    // append our games (each game is a length-delimited field 1)
                    auto ourFields = PB::Parse(ours.body.Data().data(), ours.body.Size());
                    size_t added = 0;
                    for (const auto& f : ourFields) {
                        if (f.fieldNum == 1 && f.wireType == PB::LengthDelimited) {
                            merged.WriteBytes(1, f.data, f.dataLen);
                            ++added;
                        }
                    }
                    if (added > 0 &&
                        ParseBytesToBody(respBody, merged.Data().data(), merged.Size())) {
                        LOG("[Stats] GetLastPlayedTimes: appended %zu local game(s) to server response", added);
                    } else {
                        LOG("[Stats] GetLastPlayedTimes: nothing appended (added=%zu)", added);
                    }
                } else {
                    LOG("[Stats] GetLastPlayedTimes: store had no local games to append");
                }
            }
        }
        return result;
    }

    if (strncmp(methodName, "Cloud.", 6) != 0) {
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Check if it's a Cloud RPC we handle (zero-alloc check via strcmp)
    // Request/response RPCs only - notifications go through slots 7/8
    bool isCloudRpc = (strcmp(methodName, RPC_GET_CHANGELIST) == 0 || strcmp(methodName, RPC_BEGIN_BATCH) == 0 ||
                       strcmp(methodName, RPC_BEGIN_UPLOAD) == 0 || strcmp(methodName, RPC_COMMIT_UPLOAD) == 0 ||
                       strcmp(methodName, RPC_FILE_DOWNLOAD) == 0 || strcmp(methodName, RPC_DELETE_FILE) == 0 ||
                       strcmp(methodName, RPC_COMPLETE_BATCH) == 0 || strcmp(methodName, RPC_QUOTA_USAGE) == 0 ||
                       strcmp(methodName, RPC_LAUNCH_INTENT) == 0 || strcmp(methodName, RPC_SUSPEND_SESSION) == 0 ||
                       strcmp(methodName, RPC_RESUME_SESSION) == 0 ||
                       // Safety net: these are notifications that SHOULD go through slots 7/8,
                       // but add them here in case they somehow arrive via slot 5
                       strcmp(methodName, RPC_EXIT_SYNC) == 0 || strcmp(methodName, RPC_CONFLICT) == 0 ||
                       strcmp(methodName, RPC_TRANSFER_REPORT) == 0);
    if (!isCloudRpc) {
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    if (!request || !response) {
        LOG("[VtHook] %s: null request/response, passing through", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Extract the request body from CProtoBufMsg+48
    void* reqBody = *(void**)((uintptr_t)request + 48);
    if (!reqBody) {
        LOG("[VtHook] %s: request body is NULL, passing through", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Serialize request body to raw protobuf bytes
    auto reqBytes = SerializeBodyToBytes(reqBody);
    LOG("[VtHook] %s: request body %zu bytes", methodName, reqBytes.size());

    // Parse the raw bytes to get fields
    auto innerFields = PB::Parse(reqBytes.data(), reqBytes.size());

    // Extract appId from the request
    uint32_t appId = CloudRpcUtils::ExtractAppId(methodName, innerFields);
    if (appId == 0) {
        LOG("[VtHook] %s: no appId in request, passing through", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Check if this is a namespace app
    uint32_t realAppId = 0;
    bool isNamespace = false;

    if (IsNamespaceApp(appId)) {
        realAppId = appId;
        isNamespace = true;
    }

    if (!isNamespace) {
        // Not a namespace app - pass through to real Steam servers
        // Suppress log for high-frequency non-namespace apps (e.g. 2371090 = Steam Game Notes)
        if (appId != 2371090)
            LOG("[VtHook] %s app=%u: not namespace, passing through", methodName, appId);

        // Native Cloud spy (see g_spyAppId): capture native request + response.
        // Read-only.
        if (g_spyAppId != 0 && appId == g_spyAppId) {
            LOG("[SPY] %s app=%u native request (%zu bytes):", methodName, appId, reqBytes.size());
            SpyLogFields("[SPY-REQ]", reqBytes.data(), (uint32_t)reqBytes.size());
            bool spyResult = g_originalSlot5(thisptr, methodName, request, response, flags);
            // Inspect the response body only on success: a failed call may leave the
            // body slot without a constructed message.
            void* spyRespBody = spyResult ? *(void**)((uintptr_t)response + 48) : nullptr;
            if (spyRespBody) {
                auto respBytes = SerializeBodyToBytes(spyRespBody);
                LOG("[SPY] %s app=%u native response (%zu bytes, result=%d):",
                    methodName, appId, respBytes.size(), spyResult ? 1 : 0);
                if (strcmp(methodName, RPC_GET_CHANGELIST) == 0)
                    SpyLogChangelistResponse("native-response", appId,
                                             respBytes.data(), respBytes.size());
                else
                    SpyLogFields("[SPY-RESP]", respBytes.data(), (uint32_t)respBytes.size());
            }
            return spyResult;
        }

        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // FileDownload handled by DispatchCloudRpc below (calling original double-handles).

    // NAMESPACE APP: handle locally
    LOG("[VtHook] INTERCEPT %s app=%u (%zu bytes):", methodName, appId, reqBytes.size());
#ifdef DEBUG_VERBOSE_LOGGING
    SpyLogFields("[VtHook-REQ]", reqBytes.data(), (uint32_t)reqBytes.size());
#endif

    // Capture SteamID from the request header. Detects account switches.
    if (!g_steamIdFromHeader.load()) {
        void* reqHeader = *(void**)((uintptr_t)request + 40);
        if (reqHeader) {
            auto hdrBytes = SerializeBodyToBytes(reqHeader);
            if (!hdrBytes.empty()) {
                auto hdrFields = PB::Parse(hdrBytes.data(), hdrBytes.size());
                auto* sidField = PB::FindField(hdrFields, HDR_STEAMID);
                if (sidField) {
                    uint64_t newSid = sidField->varintVal;
                    uint64_t prevSid = g_steamId.exchange(newSid);
                    bool firstCapture = !g_steamIdFromHeader.exchange(true);
                    bool switched = !firstCapture && prevSid != 0 && prevSid != newSid;
                    if (firstCapture || switched) {
                        LOG("[VtHook] Captured SteamID: %llu (accountId=%u)%s", newSid, GetAccountId(),
                            switched ? " [ACCOUNT SWITCH]" : "");
                        HttpServer::SetAccountId(GetAccountId());
                        ScheduleStartupMetadataSync();
                    }
                }
                auto* sessField = PB::FindField(hdrFields, HDR_SESSIONID);
                if (sessField) {
                    g_sessionId.store((int32_t)sessField->varintVal);
                }
            }
        }
    }

    // Fiber-yield feasibility probe (read-only): log whether we're on the job fiber.
    bool isCompleteBatch = (strcmp(methodName, RPC_COMPLETE_BATCH) == 0);
    if (isCompleteBatch || strcmp(methodName, RPC_BEGIN_BATCH) == 0) {
        uintptr_t jobPtr = ReadCurrentJobPtr();
        bool coroActive = CoroutineActiveNow();
        LOG("[FiberProbe] %s app=%u: g_pJobCur=%p (on-fiber=%d) jobid=%llu coro-active=%d",
            methodName, appId, (void*)jobPtr, jobPtr != 0 ? 1 : 0, ReadCurrentJobId(),
            coroActive ? 1 : 0);
    }

    // Re-entrancy probe: detect slot-5 RPC during in-flight CompleteBatch.
    {
        int inFlight = g_reentCompleteInFlight.load(std::memory_order_acquire);
        if (inFlight > 0) {
            uint32_t curTid  = (uint32_t)GetCurrentThreadId();
            uint32_t cbTid   = g_reentCompleteThreadId.load(std::memory_order_acquire);
            LOG("[ReentProbe] %s app=%u began while %d CompleteBatch in-flight "
                "(this-tid=%u completebatch-tid=%u same-thread=%d)",
                methodName, appId, inFlight, curTid, cbTid, (curTid == cbTid) ? 1 : 0);
        }
    }

    // Mark CompleteBatch as in-flight for the duration of its dispatch (the slow
    // promote/drain wait), so concurrent slot-5 entries can detect overlap above.
    CompleteBatchInFlightMark cbMark(isCompleteBatch);

    auto slot5Start = std::chrono::steady_clock::now();

    // Call the appropriate handler to build a response body
    auto dispatched = DispatchCloudRpc(methodName, realAppId, innerFields);
    if (!dispatched.has_value()) {
        LOG("[VtHook] Unhandled method %s, passing through", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }
    auto& result = *dispatched;

    LOG("[VtHook] %s: response body %zu bytes, eresult=%d", methodName, result.body.Size(), result.eresult);

    // Validate response header BEFORE writing body to avoid corrupting the
    // response protobuf object on a failure path.
    void* respHeader = *(void**)((uintptr_t)response + 40);
    if (!respHeader) {
        LOG("[VtHook] %s: respHeader is NULL, cannot deliver response", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Write the response body into the response CProtoBufMsg
    void* respBody = *(void**)((uintptr_t)response + 48);
    if (!respBody) {
        LOG("[VtHook] %s: response body object is NULL, cannot write response!", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    if (result.body.Size() > 0) {
        if (!ParseBytesToBody(respBody, result.body.Data().data(), result.body.Size())) {
            LOG("[VtHook] %s: ParseFromArray failed for response body! Returning transport failure.", methodName);
            return false;
        }
    }

    // Write eresult into response header (CProtoBufMsg+40):
    //   has_bits |= 0x20000000 (eresult), |= 0x40000000 (error_message)
    //   header+216 = eresult, header+220 = error_code
    if (!SEH_WriteResponseHeader(respHeader, result.eresult)) {
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }
    LOG("[VtHook] Set response header: eresult=%d, error=0", result.eresult);

    // Populate flags output (caller reads in addition to the header).
    if (flags) {
        // flags layout (from slot 5):
        //   flags[0] = int32_t routing_appid
        //   flags[1] = int32_t (always 1, set in slot 5 constructor)
        //   flags[2] = int32_t error_code -> written to respHeader+220
        //   flags[3] = int32_t eresult -> written to respHeader+216
        //   flags[4..] = char[256] target_job_name
        int32_t* f32 = reinterpret_cast<int32_t*>(flags);
        f32[0] = 0;  // routing_appid (not relevant for our response)
        // f32[1] already set by caller (= 1)
        f32[2] = 0;  // error_code
        f32[3] = result.eresult;
    }

    auto slot5Ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - slot5Start).count();
    LOG("[VtHook] SUCCESS: %s app=%u handled in %lldms (response %zu bytes)",
        methodName, realAppId, (long long)slot5Ms, result.body.Size());
    return true;
}

// Notification hook helpers

// Cloud notification namespace check: appId is in body field 1; returns real appId, or 0 if not namespace.
static uint32_t CheckNotificationNamespaceApp(const char* methodName, void* bodyObj) {
    if (!bodyObj) return 0;

    auto bodyBytes = SerializeBodyToBytes(bodyObj);
    if (bodyBytes.empty()) {
        LOG("[VtHook-Notif] %s: body serialization empty", methodName);
        return 0;
    }

    auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
    // For Cloud notifications, appId is typically field 1
    auto* appField = PB::FindField(fields, 1);
    if (!appField) {
        LOG("[VtHook-Notif] %s: no field 1 (appId) in body", methodName);
        return 0;
    }

    uint32_t appId = (uint32_t)appField->varintVal;

    // Check if namespace app (same logic as ServiceMethodHook)
    if (IsNamespaceApp(appId)) {
        return appId;
    }

    return 0;
}

// Slot 8 hook - Notification wrapper (e.g. SignalAppExitSyncDone)
// request is a CProtoBufMsg* with body at +48, header at +40
static bool __fastcall NotificationWrapperHook(void* thisptr, const char* methodName, void* request) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalSlot8(thisptr, methodName, request);
    if (!methodName) {
        return g_originalSlot8(thisptr, methodName, request);
    }

    if (ParentalBypass::IsParentalNotification(methodName) && g_parentalBypassPlaytime.load()) {
        if (request) {
            void* bodyObj = *(void**)((uintptr_t)request + 48);
            if (bodyObj && strcmp(methodName, ParentalBypass::NOTIFY_SETTINGS_CHANGE) == 0) {
                auto bodyBytes = SerializeBodyToBytes(bodyObj);
                auto notifFields = PB::Parse(bodyBytes.data(), bodyBytes.size());
                const PB::Field* sf = PB::FindField(notifFields, ParentalBypass::NotifyFields::SERIALIZED_SETTINGS);
                if (sf && sf->wireType == PB::LengthDelimited && sf->data) {
                    auto stripped = ParentalBypass::StripPlaytimeRestrictions(sf->data, sf->dataLen);
                    PB::Writer newNotif;
                    newNotif.WriteBytes(ParentalBypass::NotifyFields::SERIALIZED_SETTINGS,
                                       stripped.data(), stripped.size());
                    for (const auto& f : notifFields) {
                        if (f.fieldNum == ParentalBypass::NotifyFields::SERIALIZED_SETTINGS) continue;
                        if (f.wireType == PB::Varint)        newNotif.WriteVarint(f.fieldNum, f.varintVal);
                        else if (f.wireType == PB::Fixed64)  newNotif.WriteFixed64(f.fieldNum, f.varintVal);
                        else if (f.wireType == PB::LengthDelimited) newNotif.WriteBytes(f.fieldNum, f.data, f.dataLen);
                    }
                    if (ParseBytesToBody(bodyObj, newNotif.Data().data(), newNotif.Size()))
                        LOG("[Parental] Stripped restrictions from NotifySettingsChange");
                }
            }
            if (ParentalBypass::ShouldSuppressNotification(methodName)) {
                LOG("[Parental] SUPPRESSED %s", methodName);
                return true;
            }
        }
        return g_originalSlot8(thisptr, methodName, request);
    }

    // Only intercept Cloud.* notifications
    if (strncmp(methodName, "Cloud.", 6) != 0) {
        return g_originalSlot8(thisptr, methodName, request);
    }

    if (!request) {
        LOG("[VtHook-Notif] %s: null request, passing through", methodName);
        return g_originalSlot8(thisptr, methodName, request);
    }

    // Extract body from CProtoBufMsg+48
    void* bodyObj = *(void**)((uintptr_t)request + 48);
    uint32_t realAppId = CheckNotificationNamespaceApp(methodName, bodyObj);

    if (realAppId == 0) {
        // Not a namespace app - pass through to real Steam
        LOG("[VtHook-Notif] %s: not namespace, passing through", methodName);
        return g_originalSlot8(thisptr, methodName, request);
    }

    // ExitSyncDone: let Steam's internal processing fire so it updates
    // remotecache.vdf with the CN from BeginAppUploadBatch. The notification
    // reaches Valve with a namespace app ID it has no record for -- harmless.
    if (strcmp(methodName, RPC_EXIT_SYNC) == 0) {
        auto bodyBytes = SerializeBodyToBytes(bodyObj);
        auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
        uint64_t clientId = 0;
        bool uploadsCompleted = false;
        bool uploadsRequired = false;
        if (auto* f = PB::FindField(fields, 2)) clientId = f->varintVal;
        if (auto* f = PB::FindField(fields, 3)) uploadsCompleted = f->varintVal != 0;
        if (auto* f = PB::FindField(fields, 4)) uploadsRequired = f->varintVal != 0;
        uint32_t accountId = GetAccountId();
        if (accountId != 0) {
            PendingOpsJournal::RecordExitSyncState(accountId, realAppId,
                uploadsCompleted, uploadsRequired, clientId);
            // ExitSyncDone is fire-and-forget (slot 64). Release session off-thread.
            std::thread([accountId, appId = realAppId, clientId] {
                CloudStorage::InflightSyncScope guard;
                if (!guard.entered) return;  // shutting down, skip session release
                CloudStorage::ReleaseCloudSession(accountId, appId, clientId);
            }).detach();
        }
        LOG("[VtHook-Notif] %s app=%u: letting Steam process internally", methodName, realAppId);
        return g_originalSlot8(thisptr, methodName, request);
    }

    // ConflictResolution: parse chose_local_files so HandleLaunchIntent
    // knows whether to skip pre-restore (user chose "keep local files").
    if (strcmp(methodName, RPC_CONFLICT) == 0 && bodyObj) {
        auto bodyBytes = SerializeBodyToBytes(bodyObj);
        auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
        bool choseLocal = false;
        if (auto* f = PB::FindField(fields, 2)) choseLocal = f->varintVal != 0;
        RecordConflictResolution(realAppId, choseLocal);
    }

    // Suppress other Cloud notifications for namespace apps
    LOG("[VtHook-Notif] SUPPRESSED %s app=%u (notification not sent to server)", methodName, realAppId);
    return true;  // Return success without actually sending
}

// Slot 7 hook - Notification direct (e.g. ConflictResolution, TransferReport)
// bodyObj is the raw protobuf body (NOT wrapped in CProtoBufMsg)
static bool __fastcall NotificationDirectHook(void* thisptr, const char* methodName, void* bodyObj, int* flags) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    if (!methodName) {
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    if (ParentalBypass::IsParentalNotification(methodName) && g_parentalBypassPlaytime.load()) {
        if (bodyObj && strcmp(methodName, ParentalBypass::NOTIFY_SETTINGS_CHANGE) == 0) {
            auto bodyBytes = SerializeBodyToBytes(bodyObj);
            auto notifFields = PB::Parse(bodyBytes.data(), bodyBytes.size());
            const PB::Field* sf = PB::FindField(notifFields, ParentalBypass::NotifyFields::SERIALIZED_SETTINGS);
            if (sf && sf->wireType == PB::LengthDelimited && sf->data) {
                auto stripped = ParentalBypass::StripPlaytimeRestrictions(sf->data, sf->dataLen);
                PB::Writer newNotif;
                newNotif.WriteBytes(ParentalBypass::NotifyFields::SERIALIZED_SETTINGS,
                                   stripped.data(), stripped.size());
                for (const auto& f : notifFields) {
                    if (f.fieldNum == ParentalBypass::NotifyFields::SERIALIZED_SETTINGS) continue;
                    if (f.wireType == PB::Varint)        newNotif.WriteVarint(f.fieldNum, f.varintVal);
                    else if (f.wireType == PB::Fixed64)  newNotif.WriteFixed64(f.fieldNum, f.varintVal);
                    else if (f.wireType == PB::LengthDelimited) newNotif.WriteBytes(f.fieldNum, f.data, f.dataLen);
                }
                if (ParseBytesToBody(bodyObj, newNotif.Data().data(), newNotif.Size()))
                    LOG("[Parental] Stripped restrictions from NotifySettingsChange (direct)");
            }
        }
        if (ParentalBypass::ShouldSuppressNotification(methodName)) {
            LOG("[Parental] SUPPRESSED %s (direct)", methodName);
            return true;
        }
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    // Only intercept Cloud.* notifications
    if (strncmp(methodName, "Cloud.", 6) != 0) {
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    uint32_t realAppId = CheckNotificationNamespaceApp(methodName, bodyObj);

    if (realAppId == 0) {
        // Not a namespace app - pass through to real Steam
        LOG("[VtHook-Notif] %s (direct): not namespace, passing through", methodName);
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    // ExitSyncDone: let Steam's internal processing fire so it updates
    // remotecache.vdf with the CN from BeginAppUploadBatch. The notification
    // reaches Valve with a namespace app ID it has no record for -- harmless.
    if (strcmp(methodName, RPC_EXIT_SYNC) == 0) {
        auto bodyBytes = SerializeBodyToBytes(bodyObj);
        auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
        uint64_t clientId = 0;
        bool uploadsCompleted = false;
        bool uploadsRequired = false;
        if (auto* f = PB::FindField(fields, 2)) clientId = f->varintVal;
        if (auto* f = PB::FindField(fields, 3)) uploadsCompleted = f->varintVal != 0;
        if (auto* f = PB::FindField(fields, 4)) uploadsRequired = f->varintVal != 0;
        uint32_t accountId = GetAccountId();
        if (accountId != 0) {
            PendingOpsJournal::RecordExitSyncState(accountId, realAppId,
                uploadsCompleted, uploadsRequired, clientId);
            // ReleaseCloudSession and stats/playtime upload handled by slot 8
            // (NotificationWrapperHook). Slot 7 is a cascade from the same
            // notification -- don't duplicate cloud I/O.
        }
        LOG("[VtHook-Notif] %s app=%u (direct): cascade from slot 8, passing through", methodName, realAppId);
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    // ConflictResolution: parse chose_local_files so HandleLaunchIntent
    // knows whether to skip pre-restore (user chose "keep local files").
    if (strcmp(methodName, RPC_CONFLICT) == 0) {
        auto bodyBytes = SerializeBodyToBytes(bodyObj);
        auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
        bool choseLocal = false;
        if (auto* f = PB::FindField(fields, 2)) choseLocal = f->varintVal != 0;
        RecordConflictResolution(realAppId, choseLocal);
    }

    // Suppress other Cloud notifications for namespace apps
    LOG("[VtHook-Notif] SUPPRESSED %s app=%u (direct notification not sent to server)", methodName, realAppId);
    return true;
}

// Conservative MSVC x64 prologue heuristic. False negative => refuse to patch (safe); false positive => crash.
static bool LooksLikeFunctionPrologue(const uint8_t* p) {
    if (!p) return false;
    uint8_t b[8] = {};
    __try {
        for (int i = 0; i < 8; ++i) b[i] = p[i];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if ((b[0] == 0x48 || b[0] == 0x4C) && b[1] == 0x89 && (b[2] == 0x5C || b[2] == 0x4C || b[2] == 0x54 || b[2] == 0x44) && b[3] == 0x24) return true;
    if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) return true;
    if (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC) return true;
    if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xDC) return true;
    if (b[0] == 0x48 && b[1] == 0x8B && (b[2] == 0xC4 || b[2] == 0xC2)) return true;
    if (b[0] == 0x40 && (b[1] == 0x53 || b[1] == 0x55 || b[1] == 0x56 || b[1] == 0x57)) return true;
    if (b[0] == 0x41 && (b[1] == 0x54 || b[1] == 0x55 || b[1] == 0x56 || b[1] == 0x57)) return true;
    if (b[0] == 0x53 || b[0] == 0x55 || b[0] == 0x56 || b[0] == 0x57) return true;
    if (b[0] == 0x48 && b[1] == 0x85 && b[2] == 0xC9) return true; // test rcx, rcx (null-guard on this)
    if (b[0] == 0xE9) return true;
    return false;
}

// MSVC-x64 RTTI walk: name(.data|.rdata) -> TD = name-0x10 -> COL in .rdata referencing TD -> vftable backref qword.
static uintptr_t ResolveServiceTransportVtableViaRtti(uintptr_t scBase) {
    if (!scBase) return 0;

    auto base = reinterpret_cast<uint8_t*>(scBase);
    auto dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto ntHdr = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return 0;

    uint8_t* rdataStart = nullptr; size_t rdataSize = 0;
    uint8_t* dataStart  = nullptr; size_t dataSize  = 0;
    auto sec = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".rdata", 6) == 0) {
            rdataStart = base + sec->VirtualAddress;
            rdataSize  = sec->Misc.VirtualSize;
        } else if (memcmp(sec->Name, ".data\0", 6) == 0) {
            dataStart = base + sec->VirtualAddress;
            dataSize  = sec->Misc.VirtualSize;
        }
    }
    if (!rdataStart || rdataSize == 0) {
        LOG("[VtHook-RTTI] .rdata not found");
        return 0;
    }

    static const char kName[] = ".?AVCClientUnifiedServiceTransport@@";
    const size_t kNameLen = sizeof(kName);
    auto findName = [&](uint8_t* sStart, size_t sSize) -> const uint8_t* {
        if (!sStart || sSize < kNameLen) return nullptr;
        const uint8_t* hit = nullptr;
        __try {
            const size_t scanEnd = sSize - kNameLen;
            for (size_t i = 0; i <= scanEnd; ++i) {
                if (sStart[i] == '.' && memcmp(sStart + i, kName, kNameLen) == 0) {
                    hit = sStart + i;
                    break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
        return hit;
    };
    const uint8_t* nameAddr = findName(dataStart, dataSize);
    if (!nameAddr) nameAddr = findName(rdataStart, rdataSize);
    if (!nameAddr) {
        LOG("[VtHook-RTTI] type descriptor name not found in .data or .rdata");
        return 0;
    }

    const uint8_t* tdAddr = nameAddr - 0x10;
    const uint32_t tdRva = static_cast<uint32_t>(tdAddr - base);

    const uint8_t* col = nullptr;
    __try {
        if (rdataSize >= 4) {
            for (size_t i = 0; i + 4 <= rdataSize; i += 4) {
                if (*reinterpret_cast<const uint32_t*>(rdataStart + i) != tdRva) continue;
                if (i < 0x0C) continue;
                const uint8_t* candidate = rdataStart + i - 0x0C;
                const uint32_t sig    = *reinterpret_cast<const uint32_t*>(candidate + 0x00);
                const uint32_t pSelf  = *reinterpret_cast<const uint32_t*>(candidate + 0x14);
                if (sig == 1 && pSelf == static_cast<uint32_t>(candidate - base)) {
                    col = candidate;
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    if (!col) {
        LOG("[VtHook-RTTI] COL referencing TD RVA 0x%X not found", tdRva);
        return 0;
    }

    const uint64_t colAbs = reinterpret_cast<uint64_t>(col);
    const uint8_t* vtable = nullptr;
    __try {
        if (rdataSize >= sizeof(uint64_t)) {
            for (size_t i = 0; i + sizeof(uint64_t) <= rdataSize; i += sizeof(void*)) {
                if (*reinterpret_cast<const uint64_t*>(rdataStart + i) == colAbs) {
                    if (i + 2 * sizeof(uint64_t) > rdataSize) break;
                    vtable = rdataStart + i + sizeof(uint64_t);
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    if (!vtable) {
        LOG("[VtHook-RTTI] vftable backref to COL %p not found", col);
        return 0;
    }

    const uintptr_t vtEa = reinterpret_cast<uintptr_t>(vtable);
    LOG("[VtHook-RTTI] resolved CClientUnifiedServiceTransport vftable @ %p (RVA 0x%llX)",
        (void*)vtEa, (uint64_t)(vtEa - scBase));
    return vtEa;
}

// One-shot warning when the vtable hook can't be installed; modal dialog on detached thread.
static std::atomic<bool> g_vtableHookFailureNotified{false};
static void RefuseVtableHook(const char* reasonFmt, ...) {
    char reason[512];
    va_list ap;
    va_start(ap, reasonFmt);
    vsnprintf(reason, sizeof(reason), reasonFmt, ap);
    va_end(ap);

    LOG("[VtHook] REFUSED: %s", reason);

    if (g_vtableHookFailureNotified.exchange(true)) return;

    uint64_t ver = g_detectedSteamVersion.load(std::memory_order_relaxed);
    char msg[1024];
    if (ver != 0) {
        snprintf(msg, sizeof(msg),
            "Your Steam client (version %llu) is newer than what "
            "CloudRedirect supports.\n\n"
            "Update CloudRedirect to match your Steam version.\n\n"
            "Cloud saves will not be redirected. STFixer patches will still apply.\n\n"
            "Reason: %s",
            ver, reason);
    } else {
        snprintf(msg, sizeof(msg),
            "CloudRedirect could not identify required addresses in "
            "steamclient64.dll.\n\n"
            "Update CloudRedirect to match your Steam version.\n\n"
            "Cloud saves will not be redirected. STFixer patches will still apply.\n\n"
            "Reason: %s",
            reason);
    }
    std::string msgStr(msg);
    std::thread t([msgStr]() {
        if (g_shuttingDown.load(std::memory_order_acquire)) return;
        MessageBoxA(nullptr, msgStr.c_str(),
            "CloudRedirect -- Incompatible Steam Update",
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
    });
    std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        t.detach();
    } else {
        g_bgThreads.push_back(std::move(t));
    }
}

// Lock-free body; caller must hold s_installMutex (declared in InstallServiceMethodHook).
static void InstallServiceMethodHookLocked();

static std::mutex& GetInstallMutex() {
    static std::mutex m;
    return m;
}

// Install the vtable hook on CClientUnifiedServiceTransport
void InstallServiceMethodHook() {
    // Serialize concurrent installers (network thread + lua-sync thread)
    // so a partial installer can't have its own hook read back as the original.
    std::lock_guard<std::mutex> installLock(GetInstallMutex());
    InstallServiceMethodHookLocked();
}

bool VtableHookInstalled() {
    return g_vtableHookInstalled.load(std::memory_order_acquire);
}

void SetNeedsSeed(bool v) {
    g_needsSeed.store(v, std::memory_order_release);
}

void TriggerDeferredSeed(const std::vector<uint32_t>& apps) {
    if (!g_needsSeed.exchange(false, std::memory_order_acq_rel)) return;
    // Set g_diskAccountId BEFORE the seed thread writes any stats files.
    // Otherwise SeedApps -> WriteAppStats uses the unscoped root path and
    // MigrateUnscopedFiles has to move them later when the first RPC arrives.
    uint32_t acct = GetAccountId();
    if (acct != 0)
        StatsStore::ResetForAccountSwitch(acct);
    LOG("[VtHook] Deferred seed: %zu app(s), account=%u", apps.size(), acct);
    std::thread seed([apps] {
        if (g_shuttingDown.load(std::memory_order_acquire)) return;
        StatsStore::SeedApps(apps);
    });
    std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
    if (g_shuttingDown.load(std::memory_order_acquire))
        seed.detach();
    else
        g_bgThreads.push_back(std::move(seed));
}

static void InstallServiceMethodHookLocked() {
    if (g_vtableHookInstalled.load(std::memory_order_acquire) || !g_steamClientBase) return;

    // Validate Parse/Serialize addresses before relying on them.
    auto candidateParse     = (ParseFromArrayFn)SC_RESOLVE(parseFromArray);
    auto candidateSerialize = (SerializeToArrayFn)SC_RESOLVE(serializeToArray);
    if (!candidateParse || !LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(candidateParse))) {
        RefuseVtableHook("ParseFromArray not resolved or failed prologue check");
        return;
    }
    if (!candidateSerialize || !LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(candidateSerialize))) {
        RefuseVtableHook("SerializeToArray not resolved or failed prologue check");
        return;
    }
    g_parseFromArray   = candidateParse;
    g_serializeToArray = candidateSerialize;

    LOG("[VtHook] ParseFromArray=%p SerializeToArray=%p",
        g_parseFromArray, g_serializeToArray);

    // Resolve schema-fetch injection primitives (best-effort; if resolution
    // fails we just disable schema-fetch, leaving the rest intact).
    {
        uintptr_t ctorAddr = SC_RESOLVE(pbMsgCtor);
        uintptr_t finAddr  = SC_RESOLVE(pbMsgFinalize);
        uintptr_t clnAddr  = SC_RESOLVE(pbMsgCleanup);
        uintptr_t descAddr = SC_RESOLVE(getUserStatsDesc);
        uintptr_t vtblAddr = SC_RESOLVE(getUserStatsVtable);
        if (ctorAddr && finAddr && clnAddr && descAddr && vtblAddr &&
            LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(ctorAddr)) &&
            LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(finAddr)) &&
            LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(clnAddr))) {
            g_pbMsgCtor        = (PbMsgCtorFn)ctorAddr;
            g_pbMsgFinalize    = (PbMsgFinalizeFn)finAddr;
            g_pbMsgCleanup     = (PbMsgCleanupFn)clnAddr;
            g_getUserStatsDesc = (void*)descAddr;
            g_getUserStatsVtbl = (void*)vtblAddr;
            LOG("[Schema] Fetch primitives resolved (ctor=%p desc=%p vtbl=%p)",
                (void*)ctorAddr, (void*)descAddr, (void*)vtblAddr);
        } else {
            LOG("[Schema] Fetch primitives not resolved -- schema auto-fetch disabled");
        }
    }

    // Prefer RTTI walk; fall back to RVA. Reject cached EA outside current image range.
    uintptr_t vtableEa = g_serviceTransportVtableEa;
    if (vtableEa) {
        bool inRange = false;
        __try {
            auto base = reinterpret_cast<uint8_t*>(g_steamClientBase);
            auto dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
                auto ntHdr = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHdr->e_lfanew);
                if (ntHdr->Signature == IMAGE_NT_SIGNATURE) {
                    const uintptr_t imgEnd = g_steamClientBase + ntHdr->OptionalHeader.SizeOfImage;
                    inRange = (vtableEa >= g_steamClientBase) && (vtableEa < imgEnd);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { inRange = false; }
        if (!inRange) {
            LOG("[VtHook] Cached vtable EA %p outside current steamclient range (base=%p), discarding",
                (void*)vtableEa, (void*)g_steamClientBase);
            vtableEa = 0;
            g_serviceTransportVtableEa = 0;
        }
    }
    if (!vtableEa) {
        vtableEa = ResolveServiceTransportVtableViaRtti(g_steamClientBase);
        if (vtableEa) {
            const uintptr_t slot0 = *reinterpret_cast<uintptr_t*>(vtableEa);
            if (!LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(slot0))) {
                LOG("[VtHook] RTTI resolved vtable %p but slot0=%p is not a function prologue, rejecting",
                    (void*)vtableEa, (void*)slot0);
                vtableEa = 0;
            }
        }
        if (!vtableEa) {
            const uintptr_t fallback = SC_RESOLVE(serviceTransportVtable);
            if (fallback) {
                uintptr_t slot0 = 0;
                __try { slot0 = *reinterpret_cast<uintptr_t*>(fallback); }
                __except (EXCEPTION_EXECUTE_HANDLER) { slot0 = 0; }
                if (slot0 && LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(slot0))) {
                    LOG("[VtHook] RTTI resolution failed, falling back to resolved RVA -> %p", (void*)fallback);
                    vtableEa = fallback;
                }
            }
            if (!vtableEa) {
                RefuseVtableHook("RTTI walk + resolver both failed -- Steam update?");
                return;
            }
        }
    }

    const uintptr_t vtableSlot4Addr = vtableEa + kSlot4Off;
    const uintptr_t vtableSlot5Addr = vtableEa + kSlot5Off;
    const uintptr_t vtableSlot7Addr = vtableEa + kSlot7Off;
    const uintptr_t vtableSlot8Addr = vtableEa + kSlot8Off;

    // Identity check: our hook prologues pass LooksLikeFunctionPrologue; reject explicitly.
    auto isOurHook = [](void* p) {
        return p == (void*)&ServiceMethodDirectHook
            || p == (void*)&ServiceMethodHook
            || p == (void*)&NotificationDirectHook
            || p == (void*)&NotificationWrapperHook;
    };

    // Read slot 4 (request/response direct)
    ServiceMethodSlot4Fn currentSlot4 = nullptr;
    __try {
        currentSlot4 = *(ServiceMethodSlot4Fn*)vtableSlot4Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 4: code=0x%08X", GetExceptionCode());
        return;
    }
    if (!currentSlot4 || isOurHook((void*)currentSlot4) ||
        !LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(currentSlot4))) {
        RefuseVtableHook("slot 4 (%p) at %p invalid (null/our-hook/non-prologue)",
            (void*)currentSlot4, (void*)vtableSlot4Addr);
        return;
    }
    g_originalSlot4 = currentSlot4;
    LOG("[VtHook] Original slot 4: %p (RVA=0x%llX)",
        (void*)currentSlot4, (uint64_t)((uintptr_t)currentSlot4 - g_steamClientBase));

    // Read slot 5 (request/response wrapper)
    ServiceMethodSlot5Fn currentSlot5 = nullptr;
    __try {
        currentSlot5 = *(ServiceMethodSlot5Fn*)vtableSlot5Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 5: code=0x%08X", GetExceptionCode());
        return;
    }
    if (!currentSlot5 || isOurHook((void*)currentSlot5) ||
        !LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(currentSlot5))) {
        RefuseVtableHook("slot 5 (%p) at %p invalid (null/our-hook/non-prologue)",
            (void*)currentSlot5, (void*)vtableSlot5Addr);
        return;
    }
    g_originalSlot5 = currentSlot5;
    LOG("[VtHook] Original slot 5: %p (RVA=0x%llX)",
        (void*)currentSlot5, (uint64_t)((uintptr_t)currentSlot5 - g_steamClientBase));

    // Read slot 7 (notification direct)
    NotificationSlot7Fn currentSlot7 = nullptr;
    __try {
        currentSlot7 = *(NotificationSlot7Fn*)vtableSlot7Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 7: code=0x%08X", GetExceptionCode());
        return;
    }
    if (!currentSlot7 || isOurHook((void*)currentSlot7) ||
        !LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(currentSlot7))) {
        RefuseVtableHook("slot 7 (%p) at %p invalid (null/our-hook/non-prologue)",
            (void*)currentSlot7, (void*)vtableSlot7Addr);
        return;
    }
    g_originalSlot7 = currentSlot7;
    LOG("[VtHook] Original slot 7: %p (RVA=0x%llX)",
        (void*)currentSlot7, (uint64_t)((uintptr_t)currentSlot7 - g_steamClientBase));

    // Read slot 8 (notification wrapper)
    NotificationSlot8Fn currentSlot8 = nullptr;
    __try {
        currentSlot8 = *(NotificationSlot8Fn*)vtableSlot8Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 8: code=0x%08X", GetExceptionCode());
        return;
    }
    if (!currentSlot8 || isOurHook((void*)currentSlot8) ||
        !LooksLikeFunctionPrologue(reinterpret_cast<const uint8_t*>(currentSlot8))) {
        RefuseVtableHook("slot 8 (%p) at %p invalid (null/our-hook/non-prologue)",
            (void*)currentSlot8, (void*)vtableSlot8Addr);
        return;
    }
    g_originalSlot8 = currentSlot8;
    LOG("[VtHook] Original slot 8: %p (RVA=0x%llX)",
        (void*)currentSlot8, (uint64_t)((uintptr_t)currentSlot8 - g_steamClientBase));

    // Patch all four slots in one writable window.
    uintptr_t regionStart = vtableSlot4Addr;
    size_t regionSize = (vtableSlot8Addr + sizeof(void*)) - vtableSlot4Addr;

    DWORD oldProt;
    if (!VirtualProtect((void*)regionStart, regionSize, PAGE_READWRITE, &oldProt)) {
        LOG("[VtHook] VirtualProtect failed (%u)", GetLastError());
        return;
    }

    *(ServiceMethodSlot4Fn*)vtableSlot4Addr = ServiceMethodDirectHook;
    *(ServiceMethodSlot5Fn*)vtableSlot5Addr = ServiceMethodHook;
    *(NotificationSlot7Fn*)vtableSlot7Addr = NotificationDirectHook;
    *(NotificationSlot8Fn*)vtableSlot8Addr = NotificationWrapperHook;

    VirtualProtect((void*)regionStart, regionSize, oldProt, &oldProt);

    // Verify all patches
    bool slot4Ok = (*(ServiceMethodSlot4Fn*)vtableSlot4Addr == ServiceMethodDirectHook);
    bool slot5Ok = (*(ServiceMethodSlot5Fn*)vtableSlot5Addr == ServiceMethodHook);
    bool slot7Ok = (*(NotificationSlot7Fn*)vtableSlot7Addr == NotificationDirectHook);
    bool slot8Ok = (*(NotificationSlot8Fn*)vtableSlot8Addr == NotificationWrapperHook);
    bool allOk = slot4Ok && slot5Ok && slot7Ok && slot8Ok;
    if (allOk) g_serviceTransportVtableEa = vtableEa; // commit only on success so shutdown's restore EA matches reality
    g_vtableHookInstalled.store(allOk, std::memory_order_release);

    LOG("[VtHook] Vtable slot 4 patched: %p -> %p (ok=%d)", (void*)currentSlot4, (void*)ServiceMethodDirectHook, slot4Ok);
    LOG("[VtHook] Vtable slot 5 patched: %p -> %p (ok=%d)", (void*)currentSlot5, (void*)ServiceMethodHook, slot5Ok);
    LOG("[VtHook] Vtable slot 7 patched: %p -> %p (ok=%d)", (void*)currentSlot7, (void*)NotificationDirectHook, slot7Ok);
    LOG("[VtHook] Vtable slot 8 patched: %p -> %p (ok=%d)", (void*)currentSlot8, (void*)NotificationWrapperHook, slot8Ok);

    if (g_vtableHookInstalled.load(std::memory_order_acquire)) {
        LOG("[VtHook] All hooks ACTIVE -- Cloud RPCs (slots 4/5/7/8) will be intercepted at vtable level");
    } else {
        LOG("[VtHook] WARNING: Some hooks failed! slot4=%d slot5=%d slot7=%d slot8=%d", slot4Ok, slot5Ok, slot7Ok, slot8Ok);
    }

    // Register the cooperative yield (kept in its own function: this one uses __try
    // and so cannot also host std::function object unwinding -- MSVC C2712).
    RegisterCooperativeYieldHook();
}

// SEH helper: read vector header (can't mix SEH with C++ object unwinding)
static bool ReadVecHeader(__int64 vec, uint8_t** outArrayBase, int* outCount) {
    __try {
        *outArrayBase = *reinterpret_cast<uint8_t**>(vec);
        *outCount = *reinterpret_cast<int*>(vec + 16);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// SEH helper: read/write depot entry (can't mix SEH with C++ object unwinding)
static bool PatchDepotEntry(uint8_t* entry, uint32_t* outDepotId,
                            uint64_t pinManifest, uint64_t* outOldManifest, bool* outPatched) {
    __try {
        *outDepotId = *reinterpret_cast<uint32_t*>(entry);
        uint64_t* pManifestId = reinterpret_cast<uint64_t*>(entry + 8);
        *outOldManifest = *pManifestId;
        if (pinManifest && *outOldManifest != pinManifest) {
            *pManifestId = pinManifest;
            *outPatched = true;
        } else {
            *outPatched = false;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Inline detour on CUserAppManager::BuildDepotDependency: call original
// then rewrite manifest IDs for pinned depots in the output vectors.
static void PatchDepotVector(__int64 vec, uint32_t appId,
                             const std::unordered_map<uint32_t, uint64_t>& depotPins,
                             const char* vecName) {
    if (!vec) return;

    // Reverse-engineered vector layout (pointer at +0, count at +16, 32-byte
    // entries). SEH-wrap every read and cap the bound for future-proofing.
    uint8_t* arrayBase = nullptr;
    int count = 0;
    if (!ReadVecHeader(vec, &arrayBase, &count)) {
        LOG("[ManifestPin] PatchDepotVector(%s): faulted reading vector header for app %u",
            vecName, appId);
        return;
    }

    constexpr int kMaxDepotsPerVec = 4096;
    if (!arrayBase || count <= 0) return;
    if (count > kMaxDepotsPerVec) {
        LOG("[ManifestPin] PatchDepotVector(%s): suspicious count=%d for app %u, skipping",
            vecName, count, appId);
        return;
    }

    for (int i = 0; i < count; i++) {
        uint8_t* entry = arrayBase + static_cast<size_t>(i) * 32;
        uint32_t depotId = 0;
        uint64_t oldManifest = 0;
        bool patched = false;

        // First read just the depot ID to look up the pin
        if (!PatchDepotEntry(entry, &depotId, 0, &oldManifest, &patched)) {
            LOG("[ManifestPin] PatchDepotVector(%s): faulted reading depot at index %d for app %u",
                vecName, i, appId);
            return;
        }

        auto pinIt = depotPins.find(depotId);
        if (pinIt != depotPins.end()) {
            uint64_t pinManifest = pinIt->second;
            if (!PatchDepotEntry(entry, &depotId, pinManifest, &oldManifest, &patched)) {
                LOG("[ManifestPin] PatchDepotVector(%s): faulted patching depot %u for app %u",
                    vecName, depotId, appId);
                return;
            }
            if (patched) {
                LOG("[ManifestPin] app %u depot %u (%s): manifest %llu -> %llu",
                    appId, depotId, vecName, oldManifest, pinManifest);
            }
        }
    }
}

static __int64 __fastcall BuildDepotDependencyHook(__int64* a1, unsigned int a2, __int64 a3,
                                                    __int64 a4, __int64 a5, __int64 a6,
                                                    uint32_t* a7, uint8_t* a8) {
    HookGuard guard;
    if (!g_origBuildDepotDependency) return 0;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_origBuildDepotDependency(a1, a2, a3, a4, a5, a6, a7, a8);

    __int64 result = g_origBuildDepotDependency(a1, a2, a3, a4, a5, a6, a7, a8);

    if (g_manifestPinsEnabled.load(std::memory_order_relaxed) && result) {
        auto appIt = g_manifestPins.find(a2);
        if (appIt != g_manifestPins.end()) {
            auto& depotPins = appIt->second;
            PatchDepotVector(a4, a2, depotPins, "primary");
            PatchDepotVector(a5, a2, depotPins, "secondary");
        }
    }

    return result;
}

static bool TryHandleSchemaResponse(const uint8_t* data, uint32_t size);  // fwd decl

// Inject the on-disk schema into an incoming 819 that lacks one, so Steam registers
// the achievement page for lua-unlocked games Valve won't serve stats for.
static void TryInjectSchemaInto819(CNetPacket* pkt) {
    if (!MetadataSync::SchemaFetchEnabled()) return;
    PacketView p;
    if (!ParsePacket(pkt->pubData, pkt->cubData, p)) return;

    auto bodyFields = PB::Parse(p.bodyData, p.bodyLen);
    const PB::Field* gameIdF = PB::FindField(bodyFields, 1);
    if (!gameIdF) return;
    uint32_t appId = (uint32_t)(gameIdF->varintVal & 0xFFFFFF);
    if (appId == 0 || !IsNamespaceApp(appId)) return;

    // Already has a schema -- nothing to do.
    const PB::Field* schemaF = PB::FindField(bodyFields, 4);
    if (schemaF && schemaF->wireType == PB::LengthDelimited && schemaF->dataLen > 0)
        return;

    // Load schema from disk.
    std::string schemaPath = g_steamPath + "appcache\\stats\\UserGameStatsSchema_"
        + std::to_string(appId) + ".bin";
    HANDLE hFile = CreateFileA(schemaPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return; }
    std::vector<uint8_t> schema(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, schema.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        CloseHandle(hFile);
        return;
    }
    CloseHandle(hFile);

    // Rebuild body with schema injected. Preserve all original fields except
    // eresult (force to OK) and schema (replace from disk).
    PB::Writer newBody;
    for (auto& f : bodyFields) {
        if (f.fieldNum == 2) continue; // eresult -- we force OK below
        if (f.fieldNum == 4) continue; // schema -- replaced from disk
        if (f.wireType == PB::Varint)
            newBody.WriteVarint(f.fieldNum, f.varintVal);
        else if (f.wireType == PB::Fixed64)
            newBody.WriteFixed64(f.fieldNum, f.varintVal);
        else if (f.wireType == PB::Fixed32)
            newBody.WriteFixed32(f.fieldNum, (uint32_t)f.varintVal);
        else if (f.wireType == PB::LengthDelimited)
            newBody.WriteBytes(f.fieldNum, f.data, f.dataLen);
    }
    newBody.WriteVarint(2, 1); // eresult = OK
    newBody.WriteBytes(4, schema.data(), schema.size());

    // Rebuild entire packet: [emsg(4)][hdrLen(4)][header][body]
    uint32_t emsgRaw = (EMSG_CLIENT_GET_USER_STATS_RESP | PROTO_FLAG);
    uint32_t headerLen = p.headerLen;
    size_t newPktSize = 8 + headerLen + newBody.Size();
    uint8_t* newBuf = (uint8_t*)VirtualAlloc(nullptr, newPktSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!newBuf) return;
    memcpy(newBuf, &emsgRaw, 4);
    memcpy(newBuf + 4, &headerLen, 4);
    memcpy(newBuf + 8, p.headerData, headerLen);
    memcpy(newBuf + 8 + headerLen, newBody.Data().data(), newBody.Size());

    // Swap the packet data. The old buffer is owned by Steam's allocator so we
    // can't free it -- just replace the pointer. The new buffer leaks (one per
    // 819 response for namespace apps, tiny -- ~40KB, once per app per session).
    pkt->pubData = newBuf;
    pkt->cubData = (uint32_t)newPktSize;

    LOG("[Schema] Injected disk schema (%u bytes) into 819 for namespace app %u",
        fileSize, appId);
}

// RecvPkt monitor hook (logging + Approach D injection drain)
static int64_t __fastcall RecvPktMonitorHook(void* thisptr, CNetPacket* pkt) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalRecvPkt(thisptr, pkt);
    // Drain on the network-recv thread (valid Coroutine_Continue TLS).
    DrainInjectQueueOnNetThread();
    DrainSchemaQueueOnNetThread();   // schema sends must run on the net thread
    DrainPlaytimeUpdateQueueOnNetThread(); // live playtime push (touches CUser map)

    if (!pkt || !pkt->pubData || pkt->cubData < 8)
        return g_originalRecvPkt(thisptr, pkt);

    uint32_t emsgRaw;
    memcpy(&emsgRaw, pkt->pubData, 4);
    uint32_t emsg = emsgRaw & EMSG_MASK;

    // Capture our injected schema-fetch responses (legacy EMsg 819).
    if (emsg == EMSG_CLIENT_GET_USER_STATS_RESP) {
        TryHandleSchemaResponse(pkt->pubData, pkt->cubData);
        // Inject schema from disk for namespace apps if Valve's 819 has none.
        TryInjectSchemaInto819(pkt);
        return g_originalRecvPkt(thisptr, pkt);   // let Steam process it too
    }

    if (emsg != EMSG_SERVICE_METHOD_RESP)
        return g_originalRecvPkt(thisptr, pkt);

    PacketView p;
    if (!ParsePacket(pkt->pubData, pkt->cubData, p))
        return g_originalRecvPkt(thisptr, pkt);

    // log Cloud.* responses for diagnostics
    auto methodName = PB::GetString(p.header, HDR_TARGET_JOB_NAME);
    if (!methodName.empty()) {
        std::string method(methodName);
        if (method.find("Cloud.") != std::string::npos) {
            auto* eresultField = PB::FindField(p.header, HDR_ERESULT);
            int32_t eresult = eresultField ? (int32_t)eresultField->varintVal : -1;
            // Suppress passthrough changelist responses (non-namespace apps spam these)
            if (method.find("GetAppFileChangelist") == std::string::npos)
                LOG("[RecvMon] %s eresult=%d body=%u bytes", method.c_str(), eresult, p.bodyLen);

            // Hex dump + protobuf parse for changelist responses (for comparing real vs ours)
#ifdef DEBUG_HEX_DUMP
            if (method.find("GetAppFileChangelist") != std::string::npos && p.bodyLen > 0) {
                // Log hex dump in chunks of 32 bytes per line
                for (uint32_t off = 0; off < p.bodyLen; off += 32) {
                    char hexLine[200];
                    int pos = 0;
                    uint32_t end = (off + 32 < p.bodyLen) ? off + 32 : p.bodyLen;
                    for (uint32_t i = off; i < end; i++) {
                        pos += snprintf(hexLine + pos, sizeof(hexLine) - pos, "%02X ", p.bodyData[i]);
                    }
                    LOG("[RecvMon-HEX] offset=%04X: %s", off, hexLine);
                }

                // Also parse and log individual protobuf fields
                auto respFields = PB::Parse(p.bodyData, p.bodyLen);
                for (auto& f : respFields) {
                    if (f.wireType == PB::WireType::Varint) {
                        LOG("[RecvMon-PB] field=%u type=varint val=%llu", f.fieldNum, f.varintVal);
                    } else if (f.wireType == PB::WireType::LengthDelimited) {
                        // Could be string, bytes, or submessage
                        if (f.fieldNum == 2) {
                            // file entry submessage - parse recursively
                            auto subFields = PB::Parse(f.data, f.dataLen);
                            std::string fileName;
                            for (auto& sf : subFields) {
                                if (sf.fieldNum == 1 && sf.wireType == PB::WireType::LengthDelimited) {
                                    fileName = std::string(reinterpret_cast<const char*>(sf.data), sf.dataLen);
                                }
                            }
                            LOG("[RecvMon-PB]  file_entry: name='%s'", fileName.c_str());
                            for (auto& sf : subFields) {
                                if (sf.wireType == PB::WireType::Varint) {
                                    LOG("[RecvMon-PB]    field=%u varint=%llu", sf.fieldNum, sf.varintVal);
                                } else if (sf.wireType == PB::WireType::LengthDelimited) {
                                    if (sf.fieldNum == 2) {
                                        // sha - log as hex
                                        char shaHex[50] = {};
                                        for (uint32_t i = 0; i < sf.dataLen && i < 20; i++)
                                            snprintf(shaHex + i*2, 3, "%02x", sf.data[i]);
                                        LOG("[RecvMon-PB]    field=2 sha=%s", shaHex);
                                    } else {
                                        LOG("[RecvMon-PB]    field=%u bytes len=%u", sf.fieldNum, sf.dataLen);
                                    }
                                } else if (sf.wireType == PB::WireType::Fixed32) {
                                    LOG("[RecvMon-PB]    field=%u fixed32=%u", sf.fieldNum, (uint32_t)sf.varintVal);
                                } else if (sf.wireType == PB::WireType::Fixed64) {
                                    LOG("[RecvMon-PB]    field=%u fixed64=%llu", sf.fieldNum, sf.varintVal);
                                }
                            }
                        } else if (f.fieldNum == 4) {
                            std::string prefix(reinterpret_cast<const char*>(f.data), f.dataLen);
                            LOG("[RecvMon-PB] field=4 path_prefix='%s'", prefix.c_str());
                        } else if (f.fieldNum == 5) {
                            std::string machine(reinterpret_cast<const char*>(f.data), f.dataLen);
                            LOG("[RecvMon-PB] field=5 machine_name='%s'", machine.c_str());
                        } else {
                            LOG("[RecvMon-PB] field=%u bytes len=%u", f.fieldNum, f.dataLen);
                        }
                    } else if (f.wireType == PB::WireType::Fixed32) {
                        LOG("[RecvMon-PB] field=%u fixed32=%u", f.fieldNum, (uint32_t)f.varintVal);
                    } else if (f.wireType == PB::WireType::Fixed64) {
                        LOG("[RecvMon-PB] field=%u fixed64=%llu", f.fieldNum, f.varintVal);
                    }
                }
            }
#endif
        }
    }

    return g_originalRecvPkt(thisptr, pkt);
}

// Lua file sync: stplug-in/*.lua via account-scope LuaArchive.zip + LuaManifest.json (appId=0).
// Union/grow-only: luas are only added or extracted, never deleted across machines.

static constexpr uint32_t LUA_SYNC_APPID = 0;

struct SyncState {
    uint64_t lastSyncTime = 0;
    std::unordered_set<std::string> files;
};

static std::string GetLuaSyncStatePath() {
    return g_steamPath + "config\\stplug-in\\.sync_state";
}

[[maybe_unused]] static SyncState ReadSyncState() {
    SyncState state;
    std::ifstream f(FileUtil::Utf8ToPath(GetLuaSyncStatePath()));
    if (!f.is_open()) return state;
    std::string line;
    // First line is the timestamp
    if (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        state.lastSyncTime = strtoull(line.c_str(), nullptr, 10);
    }
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (!line.empty()) state.files.insert(line);
    }
    return state;
}

static void WriteSyncState(uint64_t syncTime, const std::unordered_set<std::string>& files) {
    std::string path = GetLuaSyncStatePath();
    std::error_code ec;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(path).parent_path(), ec);
    // Atomic-write to avoid a half-truncated .sync_state on crash.
    std::string content;
    content += std::to_string(syncTime);
    content += '\n';
    for (auto& s : files) {
        content += s;
        content += '\n';
    }
    if (!FileUtil::AtomicWriteText(path, content)) {
        LOG("[LuaSync] Failed to write .sync_state");
    }
}

struct LuaFile {
    std::string filename;           // e.g. "1229490.lua"
    std::vector<uint8_t> content;
    uint64_t modTime;               // file modification time (unix seconds)
};

// Only allow plain "name.lua" filenames (no paths, no ..)
static bool IsValidLuaFilename(const std::string& name) {
    if (name.empty()) return false;
    if (name.find('/') != std::string::npos) return false;
    if (name.find('\\') != std::string::npos) return false;
    if (name.find("..") != std::string::npos) return false;
    if (name.find(':') != std::string::npos) return false;
    if (name.find('\n') != std::string::npos) return false;
    if (name.find('\r') != std::string::npos) return false;
    if (name.size() < 5) return false; // minimum: "X.lua"
    if (name.compare(name.size() - 4, 4, ".lua") != 0) return false;

    // Block Windows reserved device names (CON.lua, NUL.lua, etc.)
    std::string stem = name.substr(0, name.size() - 4);
    // Strip trailing dot for things like "CON..lua" edge cases
    while (!stem.empty() && stem.back() == '.') stem.pop_back();
    if (!stem.empty()) {
        static const char* reserved[] = {
            "CON","PRN","AUX","NUL",
            "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
            "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"
        };
        for (auto r : reserved) {
            if (_stricmp(stem.c_str(), r) == 0) return false;
        }
    }
    return true;
}

// Reject binary content (NUL bytes in the first 8KB)
static bool IsValidLuaContent(const uint8_t* data, size_t len) {
    size_t check = (len < 8192) ? len : 8192;
    return memchr(data, '\0', check) == nullptr;
}

static std::vector<LuaFile> ReadLocalLuaFiles() {
    std::vector<LuaFile> files;
    std::string dir = g_steamPath + "config\\stplug-in\\";
    // Wide enumeration; ANSI would return 8.3 short names for non-Latin-1
    // filenames and rotate them into different lua records every launch.
    auto dirWide = FileUtil::Utf8ToPath(dir).wstring();
    std::wstring pattern = dirWide + L"*.lua";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return files;
    do {
        std::string name = FileUtil::WideToUtf8(fd.cFileName);
        if (name.empty()) continue;
        std::string path = dir + name;
        std::ifstream f(FileUtil::Utf8ToPath(path), std::ios::binary | std::ios::ate);
        if (!f.is_open()) continue;
        auto size = f.tellg();
        if (size <= 0 || size > 10 * 1024 * 1024) continue; // 10 MB per-file limit
        LuaFile lf;
        lf.filename = name;
        lf.content.resize(static_cast<size_t>(size));
        f.seekg(0);
        f.read(reinterpret_cast<char*>(lf.content.data()), size);

        // Reject short reads to avoid uploading uninitialized tail bytes.
        if (f.fail() || static_cast<std::streamsize>(f.gcount()) != size) {
            LOG("[LuaSync] short read on %s (expected %lld, got %lld); skipping",
                name.c_str(), (long long)size, (long long)f.gcount());
            continue;
        }

        ULARGE_INTEGER uli;
        uli.LowPart = fd.ftLastWriteTime.dwLowDateTime;
        uli.HighPart = fd.ftLastWriteTime.dwHighDateTime;
        lf.modTime = (uli.QuadPart - 116444736000000000ULL) / 10000000ULL;
        files.push_back(std::move(lf));
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return files;
}

static std::vector<uint8_t> CreateLuaZip(const std::vector<LuaFile>& files) {
    mz_zip_archive zip{};
    if (!mz_zip_writer_init_heap(&zip, 0, 0)) {
        LOG("[LuaSync] Failed to init zip writer");
        return {};
    }
    for (auto& lf : files) {
        if (!mz_zip_writer_add_mem(&zip, lf.filename.c_str(),
                lf.content.data(), lf.content.size(), MZ_DEFAULT_COMPRESSION)) {
            LOG("[LuaSync] Failed to add %s to zip", lf.filename.c_str());
            mz_zip_writer_end(&zip);
            return {};
        }
    }
    void* buf = nullptr;
    size_t bufSize = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &buf, &bufSize)) {
        LOG("[LuaSync] Failed to get heap archive");
        mz_zip_writer_end(&zip);
        return {};
    }
    std::vector<uint8_t> result(static_cast<uint8_t*>(buf),
                                 static_cast<uint8_t*>(buf) + bufSize);
    mz_free(buf);
    mz_zip_writer_end(&zip);
    return result;
}

// Per-file manifest entry: mod time + optional deletion time
struct ManifestEntry {
    uint64_t mod = 0;
    uint64_t del = 0;   // 0 means not deleted; del > mod means deleted
    bool isDeleted() const { return del > mod; }
};

using CloudManifest = std::unordered_map<std::string, ManifestEntry>;

// Parse manifest JSON. Handles both new format ({ "f.lua": { "mod": N, "del": N } })
// and old format ({ "f.lua": N }) for migration.
static CloudManifest ParseManifest(const std::vector<uint8_t>& data) {
    CloudManifest manifest;
    if (data.empty()) return manifest;
    std::string mstr(reinterpret_cast<const char*>(data.data()), data.size());
    auto parsed = Json::Parse(mstr);
    if (parsed.type != Json::Type::Object) return manifest;
    for (auto& [key, val] : parsed.objVal) {
        ManifestEntry entry;
        if (val.type == Json::Type::Number) {
            // Old format: bare number is mod time
            entry.mod = static_cast<uint64_t>(val.numVal);
        } else if (val.type == Json::Type::Object) {
            if (val.has("mod")) {
                auto& m = val["mod"];
                if (m.type == Json::Type::Number)
                    entry.mod = static_cast<uint64_t>(m.numVal);
                else if (m.type == Json::Type::String)
                    entry.mod = strtoull(m.strVal.c_str(), nullptr, 10);
            }
            if (val.has("del")) {
                auto& d = val["del"];
                if (d.type == Json::Type::Number)
                    entry.del = static_cast<uint64_t>(d.numVal);
                else if (d.type == Json::Type::String)
                    entry.del = strtoull(d.strVal.c_str(), nullptr, 10);
            }
        }
        manifest[key] = entry;
    }
    return manifest;
}

static std::string SerializeManifest(const CloudManifest& manifest) {
    Json::Value root = Json::Object();
    for (auto& [filename, entry] : manifest) {
        Json::Value obj = Json::Object();
        obj.objVal["mod"] = Json::String(std::to_string(entry.mod));
        if (entry.del > 0)
            obj.objVal["del"] = Json::String(std::to_string(entry.del));
        root.objVal[filename] = obj;
    }
    return Json::Stringify(root);
}

static uint64_t NowUnix() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

static void SyncLuaFiles() {
    if (!CloudStorage::IsCloudActive()) {
        LOG("[LuaSync] Cloud not active, skipping lua sync");
        return;
    }
    uint32_t accountId = GetAccountId();
    if (!accountId) {
        LOG("[LuaSync] No account ID yet, skipping lua sync");
        return;
    }

    std::string luaDir = g_steamPath + "config\\stplug-in\\";
    uint64_t now = NowUnix();

    auto manifestData = CloudStorage::RetrieveBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json");
    auto cloudManifest = ParseManifest(manifestData);

    bool hasAlive = false;
    for (auto& [f, e] : cloudManifest) { if (!e.isDeleted()) { hasAlive = true; break; } }
    std::vector<uint8_t> archiveData;
    if (hasAlive)
        archiveData = CloudStorage::RetrieveBlob(accountId, LUA_SYNC_APPID, "LuaArchive.zip");

    // Parse archive into a map
    std::unordered_map<std::string, std::vector<uint8_t>> cloudFiles;
    if (!archiveData.empty()) {
        mz_zip_archive zip{};
        if (mz_zip_reader_init_mem(&zip, archiveData.data(), archiveData.size(), 0)) {
            mz_uint numFiles = mz_zip_reader_get_num_files(&zip);
            constexpr mz_uint MAX_ZIP_ENTRIES = 10000;
            if (numFiles > MAX_ZIP_ENTRIES) {
                LOG("[LuaSync] Archive has too many entries (%u), skipping", numFiles);
                mz_zip_reader_end(&zip);
            } else {
            size_t totalExtracted = 0;
            constexpr size_t MAX_TOTAL_SIZE = 100 * 1024 * 1024; // 100 MB aggregate
            for (mz_uint i = 0; i < numFiles; i++) {
                char fname[256];
                // Probe true name size first; miniz's silent post-clamp truncation could chop "../" and slip past IsValidLuaFilename.
                mz_uint nameLenPlusNul = mz_zip_reader_get_filename(&zip, i, nullptr, 0);
                if (nameLenPlusNul == 0) {
                    LOG("[LuaSync] Skipping zip entry %u: corrupt or missing CDH", i);
                    continue;
                }
                if (nameLenPlusNul > sizeof(fname)) {
                    LOG("[LuaSync] Skipping zip entry %u: overlength filename (%u bytes)",
                        i, nameLenPlusNul);
                    continue;
                }
                mz_zip_reader_get_filename(&zip, i, fname, sizeof(fname));
                if (!IsValidLuaFilename(fname)) {
                    LOG("[LuaSync] Skipping invalid zip entry: %s", fname);
                    continue;
                }
                // Check declared size before allocating
                mz_zip_archive_file_stat fstat;
                if (!mz_zip_reader_file_stat(&zip, i, &fstat)) continue;
                constexpr size_t MAX_LUA_SIZE = 10 * 1024 * 1024; // 10 MB
                if (fstat.m_uncomp_size > MAX_LUA_SIZE) {
                    LOG("[LuaSync] Skipping oversized zip entry: %s (%llu bytes)", fname, (unsigned long long)fstat.m_uncomp_size);
                    continue;
                }
                totalExtracted += static_cast<size_t>(fstat.m_uncomp_size);
                if (totalExtracted > MAX_TOTAL_SIZE) {
                    LOG("[LuaSync] Total extracted size exceeds %zuMB limit, stopping", MAX_TOTAL_SIZE / (1024*1024));
                    break;
                }
                size_t uncompSize = 0;
                void* p = mz_zip_reader_extract_to_heap(&zip, i, &uncompSize, 0);
                if (p) {
                    if (!IsValidLuaContent(static_cast<uint8_t*>(p), uncompSize)) {
                        LOG("[LuaSync] Skipping binary zip entry: %s", fname);
                        mz_free(p);
                        continue;
                    }
                    cloudFiles[fname] = std::vector<uint8_t>(
                        static_cast<uint8_t*>(p), static_cast<uint8_t*>(p) + uncompSize);
                    mz_free(p);
                }
            }
            mz_zip_reader_end(&zip);
            }
        } else {
            LOG("[LuaSync] Failed to open cloud archive: %s",
                mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
        }
    }

    auto localFiles = ReadLocalLuaFiles();
    std::unordered_map<std::string, uint64_t> localByName; // filename -> modTime
    for (auto& lf : localFiles) localByName[lf.filename] = lf.modTime;

    int extracted = 0, addedToCloud = 0;
    bool manifestChanged = false;

    // Extract cloud luas missing locally; never delete or tombstone.
    for (auto& [filename, entry] : cloudManifest) {
        if (!IsValidLuaFilename(filename)) {
            LOG("[LuaSync] Skipping invalid manifest entry: %s", filename.c_str());
            continue;
        }
        bool onDisk = localByName.count(filename) > 0;

        if (!onDisk) {
            auto it = cloudFiles.find(filename);
            if (it != cloudFiles.end()) {
                std::error_code ec;
                // Route via Utf8ToPath: create_directories on std::string narrows via ACP internally.
                std::filesystem::create_directories(FileUtil::Utf8ToPath(luaDir), ec);
                std::string destPath = luaDir + filename;
                // Atomic-write so a crash never leaves a partial lua.
                if (FileUtil::AtomicWriteBinary(destPath, it->second.data(), it->second.size())) {
                    localByName[filename] = entry.mod;
                    extracted++;
                    LOG("[LuaSync] Extracted new lua: %s (%zu bytes)", filename.c_str(), it->second.size());
                } else {
                    LOG("[LuaSync] Failed to extract lua %s", filename.c_str());
                }
            }
        }
    }

    if (extracted > 0) {
        localFiles = ReadLocalLuaFiles();
        localByName.clear();
        for (auto& lf : localFiles) localByName[lf.filename] = lf.modTime;

        {
            for (auto& lf : localFiles) {
                auto dot = lf.filename.rfind('.');
                if (dot != std::string::npos) {
                    uint32_t appId = (uint32_t)strtoul(lf.filename.substr(0, dot).c_str(), nullptr, 10);
                    if (appId) {
                        std::string luaPath = g_steamPath + "config\\stplug-in\\" + lf.filename;
                        if (IsSelfUnlockingLua(luaPath, appId))
                            AddNamespaceApp(appId);
                    }
                }
            }

            // If vtable hook wasn't installed during init (no namespace apps at the time),
            // install it now that we have namespace apps from cloud sync.
            if (!g_vtableHookInstalled.load(std::memory_order_acquire) &&
                g_cmInterfaceFound.load(std::memory_order_acquire) &&
                HasNamespaceApps()) {
                InstallServiceMethodHook();
            }
        }
    }

    // Propagate local additions up; never remove or tombstone entries.
    for (auto& [filename, modTime] : localByName) {
        auto it = cloudManifest.find(filename);
        if (it == cloudManifest.end()) {
            cloudManifest[filename] = { modTime, 0 };
            addedToCloud++;
            manifestChanged = true;
        }
    }

    bool needUpload = manifestChanged || extracted > 0;
    if (!needUpload && cloudManifest.empty() && !localFiles.empty()) {
        needUpload = true;
        LOG("[LuaSync] Cloud empty, seeding %zu lua files", localFiles.size());
        for (auto& lf : localFiles)
            cloudManifest[lf.filename] = { lf.modTime, 0 };
    }

    if (needUpload) {
        // Archive = union of cloud archive and local luas; local bytes win on collision.
        std::unordered_map<std::string, std::vector<uint8_t>> unionFiles = cloudFiles;
        for (auto& lf : localFiles)
            unionFiles[lf.filename] = lf.content;

        std::vector<LuaFile> archiveFiles;
        archiveFiles.reserve(unionFiles.size());
        for (auto& [filename, content] : unionFiles) {
            if (cloudManifest.count(filename) == 0) continue;
            LuaFile lf;
            lf.filename = filename;
            lf.content = content;
            lf.modTime = cloudManifest[filename].mod;
            archiveFiles.push_back(std::move(lf));
        }

        if (!archiveFiles.empty()) {
            auto zipData = CreateLuaZip(archiveFiles);
            if (!zipData.empty()) {
                CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID,
                    "LuaArchive.zip", zipData.data(), zipData.size());
                LOG("[LuaSync] Uploaded archive (union): %zu files, %zu bytes zip",
                    archiveFiles.size(), zipData.size());
            }
        }

        std::string manifestStr = SerializeManifest(cloudManifest);
        CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json",
            reinterpret_cast<const uint8_t*>(manifestStr.data()), manifestStr.size());
    }

    std::unordered_set<std::string> newFiles;
    for (auto& [filename, entry] : cloudManifest) {
        if (!entry.isDeleted()) newFiles.insert(filename);
    }
    WriteSyncState(now, newFiles);

    LOG("[LuaSync] Sync complete: %d extracted, %d added to cloud (union, grow-only)",
        extracted, addedToCloud);
}

// Shutdown upload: propagate local lua additions only; never tombstone (grow-only).
static void UploadLuaOnShutdown() {
    if (!CloudStorage::IsCloudActive()) return;
    uint32_t accountId = GetAccountId();
    if (!accountId) return;

    uint64_t now = NowUnix();

    auto manifestData = CloudStorage::RetrieveBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json");
    auto cloudManifest = ParseManifest(manifestData);

    bool hasCloudAlive = false;
    for (auto& [f, e] : cloudManifest) { if (!e.isDeleted()) { hasCloudAlive = true; break; } }
    std::unordered_map<std::string, std::vector<uint8_t>> cloudFiles;
    if (hasCloudAlive) {
        auto archiveData = CloudStorage::RetrieveBlob(accountId, LUA_SYNC_APPID, "LuaArchive.zip");
        if (!archiveData.empty()) {
            mz_zip_archive zip{};
            if (mz_zip_reader_init_mem(&zip, archiveData.data(), archiveData.size(), 0)) {
                mz_uint numFiles = mz_zip_reader_get_num_files(&zip);
                for (mz_uint i = 0; i < numFiles && numFiles <= 10000; i++) {
                    mz_uint nameLenPlusNul = mz_zip_reader_get_filename(&zip, i, nullptr, 0);
                    if (nameLenPlusNul == 0 || nameLenPlusNul > 256) continue;
                    char fname[256];
                    mz_zip_reader_get_filename(&zip, i, fname, sizeof(fname));
                    if (!IsValidLuaFilename(fname)) continue;
                    size_t uncompSize = 0;
                    void* p = mz_zip_reader_extract_to_heap(&zip, i, &uncompSize, 0);
                    if (p) {
                        if (IsValidLuaContent(static_cast<uint8_t*>(p), uncompSize))
                            cloudFiles[fname] = std::vector<uint8_t>(
                                static_cast<uint8_t*>(p), static_cast<uint8_t*>(p) + uncompSize);
                        mz_free(p);
                    }
                }
                mz_zip_reader_end(&zip);
            }
        }
    }

    auto localFiles = ReadLocalLuaFiles();
    std::unordered_map<std::string, uint64_t> localByName;
    for (auto& lf : localFiles) localByName[lf.filename] = lf.modTime;

    bool changed = false;

    // Add new local files to the manifest; never tombstone.
    for (auto& [filename, modTime] : localByName) {
        auto it = cloudManifest.find(filename);
        if (it == cloudManifest.end()) {
            cloudManifest[filename] = { modTime, 0 };
            changed = true;
        }
    }

    if (!changed && !cloudManifest.empty()) {
        LOG("[LuaSync] Shutdown: no changes to upload");
        std::unordered_set<std::string> newFiles;
        for (auto& [f, e] : cloudManifest) { if (!e.isDeleted()) newFiles.insert(f); }
        WriteSyncState(now, newFiles);
        return;
    }

    // Archive = union of cloud archive and local luas.
    std::unordered_map<std::string, std::vector<uint8_t>> unionFiles = cloudFiles;
    for (auto& lf : localFiles)
        unionFiles[lf.filename] = lf.content;

    std::vector<LuaFile> archiveFiles;
    archiveFiles.reserve(unionFiles.size());
    for (auto& [filename, content] : unionFiles) {
        auto it = cloudManifest.find(filename);
        if (it == cloudManifest.end() || it->second.isDeleted()) continue;
        LuaFile lf;
        lf.filename = filename;
        lf.content = content;
        lf.modTime = it->second.mod;
        archiveFiles.push_back(std::move(lf));
    }

    if (!archiveFiles.empty()) {
        auto zipData = CreateLuaZip(archiveFiles);
        if (!zipData.empty()) {
            CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID,
                "LuaArchive.zip", zipData.data(), zipData.size());
        }
    }

    std::string manifestStr = SerializeManifest(cloudManifest);
    CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json",
        reinterpret_cast<const uint8_t*>(manifestStr.data()), manifestStr.size());

    std::unordered_set<std::string> newFiles;
    for (auto& [f, e] : cloudManifest) { if (!e.isDeleted()) newFiles.insert(f); }
    WriteSyncState(now, newFiles);

    LOG("[LuaSync] Shutdown upload (union): %zu archived, %zu total manifest entries",
        archiveFiles.size(), cloudManifest.size());
}


static uint64_t ReadSteamVersion(const std::string& steamDir) {
    std::string manifest = steamDir + "package\\steam_client_win64.manifest";
    std::ifstream f(FileUtil::Utf8ToPath(manifest));
    if (!f) return 0;
    std::string line;
    while (std::getline(f, line)) {
        // trim leading whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        std::string_view sv(line.data() + start, line.size() - start);
        if (sv.substr(0, 9) != "\"version\"") continue;
        // format: "version"		"1777411435"
        auto last = sv.rfind('"');
        if (last == std::string_view::npos || last == 0) continue;
        auto secondLast = sv.rfind('"', last - 1);
        if (secondLast == std::string_view::npos) continue;
        auto val = sv.substr(secondLast + 1, last - secondLast - 1);
        uint64_t v = 0;
        for (char c : val) {
            if (c >= '0' && c <= '9') v = v * 10 + (c - '0');
            else return 0;
        }
        return v;
    }
    return 0;
}

// Self-unlocking lua: contains addappid(<own appId>), i.e. base game is lua-unlocked. DLC-only luas don't and are excluded.
static bool IsSelfUnlockingLua(const std::string& filePath, uint32_t appId) {
    std::ifstream ifs(FileUtil::Utf8ToPath(filePath));
    if (!ifs.is_open()) return false;

    // Build the two markers: "addappid(12345)" and "addappid(12345,"
    std::string markerExact = "addappid(" + std::to_string(appId) + ")";
    std::string markerArgs  = "addappid(" + std::to_string(appId) + ",";

    std::string line;
    while (std::getline(ifs, line)) {
        // Skip leading whitespace
        size_t start = 0;
        while (start < line.size() && (line[start] == ' ' || line[start] == '\t'))
            ++start;

        // Skip commented-out lines
        if (start + 1 < line.size() && line[start] == '-' && line[start + 1] == '-')
            continue;

        std::string_view sv(line.data() + start, line.size() - start);
        if (sv.starts_with(markerExact) || sv.starts_with(markerArgs))
            return true;
    }

    return false;
}


// DLL auto-update: check GitHub for a newer cloud_redirect.dll, replace on disk.

static bool ParseVersion(const std::string& s, int out[3]) {
    // "2.0.3" or "v2.0.3" ΓåÆ {2, 0, 3}
    const char* p = s.c_str();
    if (*p == 'v' || *p == 'V') ++p;
    return sscanf(p, "%d.%d.%d", &out[0], &out[1], &out[2]) == 3;
}

static bool IsNewerVersion(const int remote[3], const int local[3]) {
    for (int i = 0; i < 3; i++) {
        if (remote[i] > local[i]) return true;
        if (remote[i] < local[i]) return false;
    }
    return false;
}

static bool IsPrereleaseTag(const std::string& tag) {
    static const char* suffixes[] = { "-test", "-pre", "-rc", "-beta", "-alpha" };
    for (auto suf : suffixes) {
        if (tag.find(suf) != std::string::npos)
            return true;
    }
    return false;
}

static std::string GetDllPath() {
    wchar_t wpath[MAX_PATH];
    HMODULE hMod = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&GetDllPath), &hMod);
    DWORD n = GetModuleFileNameW(hMod, wpath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    return FileUtil::WideToUtf8(wpath, n);
}

// SHA-256 of a file on disk, lowercase hex.
static std::string ComputeFileSHA256(const std::string& path) {
    HANDLE hFile = CreateFileW(FileUtil::Utf8ToPath(path).c_str(),
        GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE buf[8192];
            DWORD bytesRead;
            bool ok = true;
            while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
                if (!CryptHashData(hHash, buf, bytesRead, 0)) { ok = false; break; }
            }
            if (ok) {
                BYTE hash[32];
                DWORD hashLen = 32;
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    static const char hex[] = "0123456789abcdef";
                    result.reserve(64);
                    for (DWORD i = 0; i < hashLen; i++) {
                        result += hex[hash[i] >> 4];
                        result += hex[hash[i] & 0xF];
                    }
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return result;
}

static void TryAutoUpdateDll() {
    LOG("[AutoUpdate] Checking for DLL update (local version: %s)...", CR_RELEASE_VERSION);

    // Fetch releases from GitHub
    HINTERNET hSession = WinHttpOpen(L"CloudRedirect-AutoUpdate/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        LOG("[AutoUpdate] WinHttpOpen failed: %u", GetLastError());
        return;
    }
    WinHttpSetTimeouts(hSession, 5000, 5000, 10000, 10000);

    HINTERNET hConn = WinHttpConnect(hSession, L"api.github.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) {
        LOG("[AutoUpdate] WinHttpConnect failed: %u", GetLastError());
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET",
        L"/repos/Selectively11/CloudRedirect/releases",
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) {
        LOG("[AutoUpdate] WinHttpOpenRequest failed: %u", GetLastError());
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSession);
        return;
    }

    WinHttpAddRequestHeaders(hReq, L"Accept: application/vnd.github+json", (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD);

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) {
        LOG("[AutoUpdate] GitHub API request failed: %u", GetLastError());
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD statusCode = 0, codeLen = sizeof(statusCode);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &codeLen, WINHTTP_NO_HEADER_INDEX);

    if (statusCode != 200) {
        LOG("[AutoUpdate] GitHub API returned HTTP %u", statusCode);
        WinHttpCloseHandle(hReq);
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSession);
        return;
    }

    std::string body;
    DWORD avail, got;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        if (body.size() + avail > 2 * 1024 * 1024) break; // 2MB cap
        size_t off = body.size();
        body.resize(off + avail);
        got = 0;
        WinHttpReadData(hReq, &body[off], avail, &got);
        body.resize(off + got);
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);

    // Parse releases
    auto releases = Json::Parse(body);
    if (releases.type != Json::Type::Array || releases.size() == 0) {
        LOG("[AutoUpdate] No releases found or parse error");
        WinHttpCloseHandle(hSession);
        return;
    }

    // Find first non-prerelease, non-draft release with DLL asset
    std::string bestTag;
    std::string dllDownloadUrl;
    std::string sha256DownloadUrl;

    for (size_t i = 0; i < releases.size(); i++) {
        auto& rel = releases[i];
        if (rel["prerelease"].type == Json::Type::Bool && rel["prerelease"].boolean())
            continue;
        if (rel["draft"].type == Json::Type::Bool && rel["draft"].boolean())
            continue;
        std::string tag = rel["tag_name"].str();
        if (tag.empty()) continue;
        if (IsPrereleaseTag(tag)) continue;

        int ver[3] = {};
        if (!ParseVersion(tag, ver)) continue;

        auto& assets = rel["assets"];
        if (assets.type != Json::Type::Array) continue;

        std::string dllUrl, hashUrl;
        for (size_t j = 0; j < assets.size(); j++) {
            std::string name = assets[j]["name"].str();
            if (name == "cloud_redirect.dll")
                dllUrl = assets[j]["browser_download_url"].str();
            else if (name == "cloud_redirect.dll.sha256")
                hashUrl = assets[j]["browser_download_url"].str();
        }
        if (dllUrl.empty()) continue;

        bestTag = tag;
        dllDownloadUrl = dllUrl;
        sha256DownloadUrl = hashUrl;
        break;
    }

    if (bestTag.empty()) {
        LOG("[AutoUpdate] No suitable release found with cloud_redirect.dll asset");
        WinHttpCloseHandle(hSession);
        return;
    }

    LOG("[AutoUpdate] Latest release: %s", bestTag.c_str());

    // Only update to a newer version.
    int localVer[3] = {}, remoteVer[3] = {};
    if (ParseVersion(CR_RELEASE_VERSION, localVer) && ParseVersion(bestTag, remoteVer)) {
        if (!IsNewerVersion(remoteVer, localVer)) {
            LOG("[AutoUpdate] DLL is up to date (version match: %s)", CR_RELEASE_VERSION);
            WinHttpCloseHandle(hSession);
            return;
        }
    }

    // Compare local DLL hash against published hash; skip download if unchanged.
    std::string dllPath = GetDllPath();
    if (!sha256DownloadUrl.empty() && !dllPath.empty()) {
        std::string localHash = ComputeFileSHA256(dllPath);
        if (!localHash.empty()) {
            LOG("[AutoUpdate] Local DLL SHA-256: %s", localHash.c_str());

            // Fetch published hash file
            auto fetchSmallFile = [&](const std::string& fullUrl) -> std::string {
                size_t schemeEnd = fullUrl.find("://");
                if (schemeEnd == std::string::npos) return {};
                size_t hostStart = schemeEnd + 3;
                size_t pathStart = fullUrl.find('/', hostStart);
                std::string host = (pathStart != std::string::npos)
                    ? fullUrl.substr(hostStart, pathStart - hostStart) : fullUrl.substr(hostStart);
                std::string path = (pathStart != std::string::npos) ? fullUrl.substr(pathStart) : "/";

                auto wHost = HttpUtil::Widen(host);
                auto wPath = HttpUtil::Widen(path);
                HINTERNET hC = WinHttpConnect(hSession, wHost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
                if (!hC) return {};
                HINTERNET hR = WinHttpOpenRequest(hC, L"GET", wPath.c_str(),
                    nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (!hR) { WinHttpCloseHandle(hC); return {}; }
                DWORD pol = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
                WinHttpSetOption(hR, WINHTTP_OPTION_REDIRECT_POLICY, &pol, sizeof(pol));

                BOOL s = WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
                if (s) s = WinHttpReceiveResponse(hR, nullptr);
                std::string result;
                if (s) {
                    DWORD code = 0, cl = sizeof(code);
                    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &cl, WINHTTP_NO_HEADER_INDEX);
                    if (code == 200) {
                        DWORD a, g;
                        while (WinHttpQueryDataAvailable(hR, &a) && a > 0) {
                            if (result.size() + a > 4096) break;
                            size_t o = result.size();
                            result.resize(o + a);
                            g = 0;
                            WinHttpReadData(hR, &result[o], a, &g);
                            result.resize(o + g);
                        }
                    }
                }
                WinHttpCloseHandle(hR);
                WinHttpCloseHandle(hC);
                return result;
            };

            std::string remoteHash = fetchSmallFile(sha256DownloadUrl);
            // Trim
            while (!remoteHash.empty() && (remoteHash.back() == '\n' || remoteHash.back() == '\r' || remoteHash.back() == ' '))
                remoteHash.pop_back();

            if (remoteHash.size() == 64) {
                LOG("[AutoUpdate] Remote DLL SHA-256: %s", remoteHash.c_str());
                if (localHash == remoteHash) {
                    LOG("[AutoUpdate] DLL is up to date (hash match)");
                    WinHttpCloseHandle(hSession);
                    return;
                }
                LOG("[AutoUpdate] Hash mismatch, update needed");
            } else {
                LOG("[AutoUpdate] Could not fetch remote hash (%zu bytes), falling back to download",
                    remoteHash.size());
            }
        }
    }

    // Download the DLL (follows redirects).

    auto downloadDll = [&](const std::string& fullUrl) -> std::string {
        size_t schemeEnd = fullUrl.find("://");
        if (schemeEnd == std::string::npos) return {};
        size_t hostStart = schemeEnd + 3;
        size_t pathStart = fullUrl.find('/', hostStart);
        std::string host = (pathStart != std::string::npos)
            ? fullUrl.substr(hostStart, pathStart - hostStart) : fullUrl.substr(hostStart);
        std::string path = (pathStart != std::string::npos) ? fullUrl.substr(pathStart) : "/";

        auto wHost = HttpUtil::Widen(host);
        auto wPath = HttpUtil::Widen(path);

        HINTERNET hDlConn = WinHttpConnect(hSession, wHost.c_str(),
            INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hDlConn) return {};

        HINTERNET hDlReq = WinHttpOpenRequest(hDlConn, L"GET", wPath.c_str(),
            nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hDlReq) { WinHttpCloseHandle(hDlConn); return {}; }

        DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
        WinHttpSetOption(hDlReq, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy));
        WinHttpSetTimeouts(hDlReq, 5000, 5000, 60000, 60000);

        ok = WinHttpSendRequest(hDlReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
        if (ok) ok = WinHttpReceiveResponse(hDlReq, nullptr);

        std::string dlBody;
        if (ok) {
            DWORD dlStatus = 0, dlCodeLen = sizeof(dlStatus);
            WinHttpQueryHeaders(hDlReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &dlStatus, &dlCodeLen, WINHTTP_NO_HEADER_INDEX);
            if (dlStatus == 200) {
                DWORD a2, g2;
                while (WinHttpQueryDataAvailable(hDlReq, &a2) && a2 > 0) {
                    if (dlBody.size() + a2 > 10 * 1024 * 1024) { dlBody.clear(); break; } // 10MB cap
                    size_t o2 = dlBody.size();
                    dlBody.resize(o2 + a2);
                    g2 = 0;
                    WinHttpReadData(hDlReq, &dlBody[o2], a2, &g2);
                    dlBody.resize(o2 + g2);
                }
            } else {
                LOG("[AutoUpdate] Download returned HTTP %u", dlStatus);
            }
        }

        WinHttpCloseHandle(hDlReq);
        WinHttpCloseHandle(hDlConn);
        return dlBody;
    };

    std::string dllBytes = downloadDll(dllDownloadUrl);
    if (dllBytes.size() < 1024) {
        LOG("[AutoUpdate] Downloaded DLL too small (%zu bytes), aborting", dllBytes.size());
        WinHttpCloseHandle(hSession);
        return;
    }

    if (dllBytes[0] != 'M' || dllBytes[1] != 'Z') {
        LOG("[AutoUpdate] Downloaded file is not a valid PE, aborting");
        WinHttpCloseHandle(hSession);
        return;
    }

    LOG("[AutoUpdate] Downloaded %zu bytes", dllBytes.size());
    WinHttpCloseHandle(hSession);

    // Replace DLL on disk
    if (dllPath.empty()) {
        dllPath = GetDllPath();
        if (dllPath.empty()) {
            LOG("[AutoUpdate] Cannot determine DLL path, aborting");
            return;
        }
    }

    std::string newPath = dllPath + ".new";
    std::string oldPath = dllPath + ".old";

    if (!FileUtil::AtomicWriteBinary(newPath, dllBytes.data(), dllBytes.size())) {
        LOG("[AutoUpdate] Failed to write %s", newPath.c_str());
        return;
    }

    // Swap: current -> .old, .new -> current
    auto wDllPath = FileUtil::Utf8ToPath(dllPath);
    auto wNewPath = FileUtil::Utf8ToPath(newPath);
    auto wOldPath = FileUtil::Utf8ToPath(oldPath);

    DeleteFileW(wOldPath.c_str());

    if (!MoveFileW(wDllPath.c_str(), wOldPath.c_str())) {
        LOG("[AutoUpdate] Failed to rename DLL to .old: %u", GetLastError());
        DeleteFileW(wNewPath.c_str());
        return;
    }

    if (!MoveFileW(wNewPath.c_str(), wDllPath.c_str())) {
        LOG("[AutoUpdate] Failed to rename .new to DLL: %u, rolling back", GetLastError());
        MoveFileW(wOldPath.c_str(), wDllPath.c_str()); // rollback
        return;
    }

    LOG("[AutoUpdate] DLL updated: %s -> %s (takes effect on next Steam launch)",
        CR_RELEASE_VERSION, bestTag.c_str());

    std::string msg = "CloudRedirect DLL updated to " + bestTag +
        ".\n\nRestart Steam to use the new version.";
    NotifyUser(CR_NOTIFY_INFO, "CloudRedirect -- DLL Updated", msg.c_str());
}

void Init(const std::string& steamPath, bool cloudSaveOnly, CR_NotifyFn notifyCallback) {
    g_notifyCallback = notifyCallback;
    g_cloudSaveOnly.store(cloudSaveOnly, std::memory_order_relaxed);
    g_steamPath = steamPath;
    if (!g_steamPath.empty() && g_steamPath.back() != '\\')
        g_steamPath += '\\';

    // Read Steam version for diagnostics and auto-update.
    uint64_t detectedVersion = ReadSteamVersion(g_steamPath);
    g_detectedSteamVersion.store(detectedVersion, std::memory_order_relaxed);
    if (detectedVersion != 0)
        LOG("Steam version: %llu", detectedVersion);
    else
        LOG("Steam version: UNKNOWN (manifest unreadable)");

    // Run auto-resolver: resolves steamclient64 function/global addresses via
    // pattern scanning, RTTI walks, and string xrefs. Must run before any hooks
    // or function-pointer resolution. Falls back to hardcoded RVAs on failure.
    RunAutoResolver();

    // Resolve CUser::accountId offset from steamclient64 (fallback: 570).
    {
        uint32_t scannedOff = ScanUserAccountIdOffset();
        if (scannedOff != 0)
            USER_OFF_ACCOUNTID = scannedOff;
        else
            LOG("[Scan] USER_OFF_ACCOUNTID: using fallback %u", USER_OFF_ACCOUNTID);
    }

    // Auto-detect namespace apps from {steamPath}\config\stplug-in\*.lua, restricted to self-unlocking luas (base-game addappid for own id).
    std::string pluginDir = g_steamPath + "config\\stplug-in\\*";
    std::string pluginBase = g_steamPath + "config\\stplug-in\\";
    int totalLuas = 0, selfUnlocking = 0;
    // Wide enumeration; FindFirstFileA fails on non-ASCII g_steamPath.
    auto pluginDirWide = FileUtil::Utf8ToPath(pluginDir).wstring();
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pluginDirWide.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string name = FileUtil::WideToUtf8(fd.cFileName);
            if (name.empty()) continue;
            if (name.size() > 4 && name.compare(name.size() - 4, 4, ".lua") == 0) {
                std::string stem = name.substr(0, name.size() - 4);
                bool allDigits = !stem.empty();
                for (char c : stem) {
                    if (c < '0' || c > '9') { allDigits = false; break; }
                }
                if (allDigits) {
                    uint32_t appId = (uint32_t)strtoul(stem.c_str(), nullptr, 10);
                    if (appId > 0) {
                        totalLuas++;
                        std::string luaPath = pluginBase + name;
                        if (IsSelfUnlockingLua(luaPath, appId)) {
                            AddNamespaceApp(appId);
                            selfUnlocking++;
                        }
                    }
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    } else {
        LOG("[NS] Failed to scan stplug-in directory: %s (err=%u)",
            pluginDir.c_str(), GetLastError());
    }

    if (HasNamespaceApps()) {
        LOG("[NS] Namespace mode ENABLED: %d self-unlocking of %d total lua(s)", selfUnlocking, totalLuas);
    } else {
        LOG("[NS] No self-unlocking Lua files found (%d total luas) -- DLL will only log Cloud RPCs", totalLuas);
    }

    // Steam-side config (per-system, controls DLL feature toggles).
    // Read this early so we know whether to init cloud features.
    std::string cloudRoot = g_steamPath + "cloud_redirect\\";
    {
        std::string pinConfigPath = cloudRoot + "config.json";
        std::ifstream pinFile(FileUtil::Utf8ToPath(pinConfigPath));
        if (pinFile) {
            std::string pinStr((std::istreambuf_iterator<char>(pinFile)), {});
            pinFile.close();
            auto pinCfg = Json::Parse(pinStr);

            // cloud_redirect defaults to true for backward compat with existing users
            if (pinCfg["cloud_redirect"].type == Json::Type::Bool)
                g_cloudRedirectEnabled = pinCfg["cloud_redirect"].boolean();

            if (!cloudSaveOnly) {

            if (pinCfg["manifest_pinning"].type == Json::Type::Bool)
                g_manifestPinsEnabled = pinCfg["manifest_pinning"].boolean();
            if (pinCfg["auto_comment"].type == Json::Type::Bool)
                g_autoComment = pinCfg["auto_comment"].boolean();
            // show_non_steam_game is per-user, so it lives in the AppData config (read below).

            size_t totalPins = 0;

            // Load pinned_apps list (per-app overrides)
            auto& pinnedArr = pinCfg["pinned_apps"];
            if (pinnedArr.type == Json::Type::Array) {
                for (auto& val : pinnedArr.arrVal) {
                    uint32_t appId = 0;
                    if (val.type == Json::Type::Number)
                        appId = (uint32_t)val.integer();
                    else if (val.type == Json::Type::String)
                        appId = (uint32_t)strtoul(val.str().c_str(), nullptr, 10);
                    if (appId != 0)
                        g_pinnedApps.insert(appId);
                }
                LOG("[ManifestPin] Loaded %zu pinned app(s)", g_pinnedApps.size());
            }

            // Load lua setManifestid pins (when auto_comment=false or app
            // is in pinned_apps). Wide enumeration for non-ASCII paths.
            if (g_manifestPinsEnabled.load()) {
                std::string luaDir = g_steamPath + "config\\stplug-in\\";
                auto luaDirWide = FileUtil::Utf8ToPath(luaDir).wstring();
                std::wstring pattern = luaDirWide + L"*.lua";
                WIN32_FIND_DATAW fd;
                HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        // strtoul on narrowed cFileName: pure-digit prefixes are single-byte in both encodings.
                        std::string nameUtf8 = FileUtil::WideToUtf8(fd.cFileName);
                        uint32_t fileAppId = (uint32_t)strtoul(nameUtf8.c_str(), nullptr, 10);
                        if (fileAppId == 0) continue;

                        bool shouldLoad = !g_autoComment.load() || g_pinnedApps.count(fileAppId);
                        if (!shouldLoad) continue;

                        std::string luaPath = luaDir + nameUtf8;
                        std::ifstream luaFile(FileUtil::Utf8ToPath(luaPath));
                        if (!luaFile) continue;
                        std::string line;
                        while (std::getline(luaFile, line)) {
                            size_t start = line.find_first_not_of(" \t");
                            if (start == std::string::npos) continue;
                            if (line.size() > start + 1 && line[start] == '-' && line[start+1] == '-') continue;

                            std::string lower = line;
                            for (auto& c : lower) c = (char)tolower((unsigned char)c);
                            size_t pos = lower.find("setmanifestid(");
                            if (pos == std::string::npos) continue;
                            pos += 14;

                            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) pos++;
                            uint32_t depotId = (uint32_t)strtoul(line.c_str() + pos, nullptr, 10);
                            if (depotId == 0) continue;

                            size_t q1 = line.find('"', pos);
                            if (q1 == std::string::npos) continue;
                            size_t q2 = line.find('"', q1 + 1);
                            if (q2 == std::string::npos) continue;
                            std::string manifestStr = line.substr(q1 + 1, q2 - q1 - 1);
                            uint64_t manifestId = strtoull(manifestStr.c_str(), nullptr, 10);
                            if (manifestId == 0) continue;

                            g_manifestPins[fileAppId][depotId] = manifestId;
                            totalPins++;
                            LOG("[ManifestPin] Lua pin: app %u depot %u -> manifest %llu (from %s)",
                                fileAppId, depotId, manifestId, nameUtf8.c_str());
                        }
                    } while (FindNextFileW(hFind, &fd));
                    FindClose(hFind);
                }
            }

            if (totalPins > 0)
                LOG("[ManifestPin] Loaded %zu pin(s) across %zu app(s)", totalPins, g_manifestPins.size());
            if (g_manifestPinsEnabled.load() && totalPins == 0) {
                LOG("[ManifestPin] Enabled but no valid pins configured");
                g_manifestPinsEnabled = false;
            }
            LOG("[ManifestPin] manifest_pinning=%d, auto_comment=%d",
                g_manifestPinsEnabled.load(), g_autoComment.load());

            } // !cloudSaveOnly (manifest pinning)
        } else {
            if (!cloudSaveOnly)
                LOG("[ManifestPin] No pin config at %s", pinConfigPath.c_str());
        }
    }

    LOG("cloud_redirect=%d", g_cloudRedirectEnabled.load());

    if (!g_cloudRedirectEnabled.load()) {
        LOG("Cloud redirection disabled, skipping cloud init");
        LOG("CloudIntercept initialized (manifest pinning only), steam=%s", g_steamPath.c_str());
        return;
    }

    // migrate legacy blobs/ directory to storage/ (one-time, introduced build 6-7)
    {
        std::string oldRoot = g_steamPath + "cloud_redirect\\blobs\\";
        std::string newRoot = g_steamPath + "cloud_redirect\\storage\\";
        std::error_code ec;
        auto oldRootPath = FileUtil::Utf8ToPath(oldRoot);
        if (std::filesystem::is_directory(oldRootPath, ec)) {
            int migrated = 0, skipped = 0;
            std::string oldRootPrefix = FileUtil::MakePathPrefix(FileUtil::PathToUtf8(oldRootPath));
            std::filesystem::recursive_directory_iterator it(oldRootPath, ec);
            const std::filesystem::recursive_directory_iterator end;
            while (!ec && it != end) {
                const auto& entry = *it;
                std::error_code regEc;
                if (entry.is_regular_file(regEc)) {
                    std::string entryUtf8 = FileUtil::PathToUtf8(entry.path());
                    FileUtil::NormalizeSlashesInPlace(entryUtf8);
                    std::string relStr;
                    if (FileUtil::RelativeUtf8Path(entryUtf8, oldRootPrefix, &relStr)) {
                        auto dest = FileUtil::Utf8ToPath(newRoot) / FileUtil::Utf8ToPath(relStr);
                        std::error_code existsEc;
                        if (std::filesystem::exists(dest, existsEc)) {
                            skipped++;
                        } else {
                            std::error_code mkEc;
                            std::filesystem::create_directories(dest.parent_path(), mkEc);
                            std::error_code mvEc;
                            std::filesystem::rename(entry.path(), dest, mvEc);
                            if (!mvEc) migrated++;
                        }
                    }
                }
                std::error_code stepEc;
                it.increment(stepEc);
                if (stepEc) break;
            }
            std::error_code rmEc;
            std::filesystem::remove_all(oldRootPath, rmEc);
            if (migrated > 0 || skipped > 0)
                LOG("[NS] Migrated legacy blobs/ -> storage/: %d files moved, %d already existed (skipped)", migrated, skipped);
        }
    }

    // Scrub Playtime.bin/UserGameStats.bin relics left by older DLL builds
    // in Steam's userdata remote/. Current DLL never writes there.
    LegacyMetadataCleanup::PruneSteamUserdata(g_steamPath);

    // Scrub <root>/.cloudredirect/{Playtime,UserGameStats}.bin in AutoCloud user-profile roots; ladder mirrors local_storage.cpp:GetAutoCloudFileList.
    try {
        auto getEnvUtf8 = [](const wchar_t* name) -> std::string {
            wchar_t wbuf[MAX_PATH];
            constexpr DWORD bufLen = (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]));
            DWORD n = GetEnvironmentVariableW(name, wbuf, bufLen);
            if (n == 0 || n >= bufLen) return {};
            return FileUtil::WideToUtf8(wbuf, (size_t)n);
        };
        auto knownFolderUtf8 = [](const KNOWNFOLDERID& id) -> std::string {
            PWSTR wide = nullptr;
            HRESULT hr = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &wide);
            if (FAILED(hr) || !wide) {
                if (wide) CoTaskMemFree(wide);
                return {};
            }
            // try/catch so CoTaskMemFree runs even if WideToUtf8 throws.
            std::string out;
            try {
                out = FileUtil::WideToUtf8(wide);
            } catch (...) {
                CoTaskMemFree(wide);
                throw;
            }
            CoTaskMemFree(wide);
            return out;
        };
        auto withTrailingSlash = [](std::string s) -> std::string {
            if (!s.empty() && s.back() != '\\' && s.back() != '/') s += '\\';
            return s;
        };

        std::vector<std::string> autoCloudRoots;

        // LocalLow: knownfolder primary, `%LOCALAPPDATA%\..\LocalLow` fallback.
        {
            std::string p = knownFolderUtf8(FOLDERID_LocalAppDataLow);
            if (p.empty()) {
                std::string la = getEnvUtf8(L"LOCALAPPDATA");
                if (!la.empty()) p = la + "\\..\\LocalLow";
            }
            if (!p.empty()) autoCloudRoots.push_back(withTrailingSlash(std::move(p)));
        }
        // LocalAppData: env-var only (matches AutoCloud).
        {
            std::string p = getEnvUtf8(L"LOCALAPPDATA");
            if (!p.empty()) autoCloudRoots.push_back(withTrailingSlash(std::move(p)));
        }
        // RoamingAppData: env-var only (matches AutoCloud).
        {
            std::string p = getEnvUtf8(L"APPDATA");
            if (!p.empty()) autoCloudRoots.push_back(withTrailingSlash(std::move(p)));
        }
        // Documents: knownfolder primary, `%USERPROFILE%\Documents` fallback.
        {
            std::string p = knownFolderUtf8(FOLDERID_Documents);
            if (p.empty()) {
                std::string up = getEnvUtf8(L"USERPROFILE");
                if (!up.empty()) p = up + "\\Documents";
            }
            if (!p.empty()) autoCloudRoots.push_back(withTrailingSlash(std::move(p)));
        }
        // Saved Games: knownfolder primary, `%USERPROFILE%\Saved Games` fallback.
        {
            std::string p = knownFolderUtf8(FOLDERID_SavedGames);
            if (p.empty()) {
                std::string up = getEnvUtf8(L"USERPROFILE");
                if (!up.empty()) p = up + "\\Saved Games";
            }
            if (!p.empty()) autoCloudRoots.push_back(withTrailingSlash(std::move(p)));
        }

        LegacyMetadataCleanup::PruneAutoCloudPollutionRoots(autoCloudRoots);
    } catch (const std::exception& ex) {
        // Helper swallows; only resolution lambdas can throw out (bad_alloc). Don't take down DLL init for a cleanup pass.
        LOG("[NS] PruneAutoCloud setup failed: %s", ex.what());
    } catch (...) {
        LOG("[NS] PruneAutoCloud setup failed: unknown exception");
    }

    // start local HTTP server for upload/download
    std::string blobRoot = g_steamPath + "cloud_redirect\\storage\\";
    if (HttpServer::Start(blobRoot)) {
        LOG("[NS] HTTP server started on port %u, blob root: %s",
            HttpServer::GetPort(), blobRoot.c_str());
    } else {
        LOG("[NS] WARNING: HTTP server failed to start!");
    }

    // init local storage for metadata tracking
    std::string storageRoot = g_steamPath + "cloud_redirect\\storage\\";
    LocalStorage::Init(storageRoot);
    LocalMetadataStore::Init(storageRoot);
    PendingOpsJournal::Init(storageRoot);

    // init CloudStorage manager - read config to determine cloud provider
    std::unique_ptr<ICloudProvider> provider;

    // Config lives in %AppData%/CloudRedirect/config.json (per-user)
    std::string configPath;
    {
        // Wide-API: SHGetFolderPathA mangles non-ASCII usernames, falling back to
        // local-only mode even when a cloud provider is configured.
        PWSTR wideAppData = nullptr;
        HRESULT hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, nullptr, &wideAppData);
        if (SUCCEEDED(hr) && wideAppData) {
            configPath = FileUtil::WideToUtf8(wideAppData) + "\\CloudRedirect\\config.json";
            CoTaskMemFree(wideAppData);
        } else {
            if (wideAppData) CoTaskMemFree(wideAppData);
            configPath = cloudRoot + "config.json";
            LOG("[NS] WARNING: Could not resolve %%APPDATA%%, falling back to steam folder for config");
        }
    }
    // Read manifest endpoint from settings.json (same directory as config.json).
    {
        std::string settingsDir = configPath.substr(0, configPath.rfind('\\') + 1);
        std::string settingsPath = settingsDir + "settings.json";
        std::ifstream sf(FileUtil::Utf8ToPath(settingsPath));
        if (sf) {
            std::string sStr((std::istreambuf_iterator<char>(sf)), {});
            sf.close();
            auto sj = Json::Parse(sStr);
            if (sj["manifest_endpoint"].type == Json::Type::String)
                g_manifestEndpoint = sj["manifest_endpoint"].str();
            if (!g_manifestEndpoint.empty())
                LOG("[ManifestEP] Configured: %s", g_manifestEndpoint.c_str());
        }
    }

    std::ifstream configFile(FileUtil::Utf8ToPath(configPath));
    if (configFile) {
        std::string configStr((std::istreambuf_iterator<char>(configFile)), {});
        configFile.close();
        auto cfg = Json::Parse(configStr);
        std::string providerName = cfg["provider"].str();
        std::string tokenPath = cfg["token_path"].str();

        if (!providerName.empty() && providerName != "local") {
            provider = CreateCloudProvider(providerName);
            if (provider) {
                std::string initPath = tokenPath;
                std::string syncPath = cfg["sync_path"].str();
                if (providerName == "folder" && !syncPath.empty()) {
                    initPath = syncPath;
                }

                if (!initPath.empty() && provider->Init(initPath)) {
                    LOG("[NS] Cloud provider '%s' initialized (path: %s)",
                        provider->Name(), initPath.c_str());
                    if (!provider->IsAuthenticated()) {
                        LOG("[NS] WARNING: %s is configured but not authenticated -- saves will only be stored locally",
                            provider->Name());
                        std::string name = provider->Name();
                        std::string notifMsg = name + " is configured but you haven't signed in yet.\n\n"
                            "Your saves will be stored locally but will NOT sync to the cloud.\n\n"
                            "Open the CloudRedirect app and sign in on the Cloud Provider page.";
                        std::thread t([notifMsg]() {
                            NotifyUser(CR_NOTIFY_WARN,
                                "CloudRedirect - Cloud Provider Not Authenticated",
                                notifMsg.c_str());
                        });
                        std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
                        g_bgThreads.push_back(std::move(t));
                    }
                } else {
                    LOG("[NS] WARNING: Cloud provider '%s' init failed (path='%s'), falling back to local-only",
                        providerName.c_str(), initPath.c_str());
                    provider.reset();
                }
            } else {
                LOG("[NS] WARNING: Unknown cloud provider '%s', falling back to local-only",
                    providerName.c_str());
            }
        } else {
            LOG("[NS] Config: provider='%s' -- local-only mode", providerName.c_str());
        }

        auto& maxUploadVal = cfg["max_upload_mb"];
        if (maxUploadVal.type == Json::Type::Number) {
            int mb = static_cast<int>(maxUploadVal.integer());
            HttpServer::SetMaxUploadMB(mb);
        }

        // Concurrency cap, not a speed knob (see g_uploadInFlightCapBytes). Clamp
        // 24..64 MB; out-of-range/absent keeps the 24 MB default.
        if (cfg["upload_inflight_mb"].type == Json::Type::Number) {
            int mb = static_cast<int>(cfg["upload_inflight_mb"].integer());
            if (mb >= 24 && mb <= 64)
                g_uploadInFlightCapBytes.store((uint64_t)mb << 20,
                    std::memory_order_relaxed);
        }

        // Lua sync requires SteamTools.
        if (MetadataSync::steamToolsPresent.load(std::memory_order_relaxed)) {
            if (cfg["sync_luas"].type == Json::Type::Bool)
                MetadataSync::syncLuas = cfg["sync_luas"].boolean();
        }
        // Native stats/playtime sync gates. Absent -> keep default (OFF, WIP).
        // When off, the matching native path does not interfere with Steam at all.
        if (cfg["sync_achievements"].type == Json::Type::Bool)
            MetadataSync::syncAchievements = cfg["sync_achievements"].boolean();
        if (cfg["sync_playtime"].type == Json::Type::Bool)
            MetadataSync::syncPlaytime = cfg["sync_playtime"].boolean();
        // Schema fetch (default on).
        if (cfg["schema_fetch"].type == Json::Type::Bool)
            MetadataSync::schemaFetch = cfg["schema_fetch"].boolean();
        LOG("[Stats] Sync gates: achievements=%d, playtime=%d, schemaFetch=%d, "
            "steamTools=%d, stGateOpen=%d",
            MetadataSync::syncAchievements.load() ? 1 : 0,
            MetadataSync::syncPlaytime.load() ? 1 : 0,
            MetadataSync::schemaFetch.load() ? 1 : 0,
            MetadataSync::steamToolsPresent.load() ? 1 : 0,
            MetadataSync::StGateOpen() ? 1 : 0);
        if (!cloudSaveOnly) {
            // Per-user toggle: defaults to true (set at declaration) when absent.
            if (cfg["show_non_steam_game"].type == Json::Type::Bool)
                g_showNonSteamGame = cfg["show_non_steam_game"].boolean();
            if (cfg["parental_bypass_playtime"].type == Json::Type::Bool)
                g_parentalBypassPlaytime = cfg["parental_bypass_playtime"].boolean();
            if (cfg["parental_ignore_playtime"].type == Json::Type::Bool)
                g_parentalIgnorePlaytime = cfg["parental_ignore_playtime"].boolean();
            LOG("[NS] Parental: bypass=%d, ignore_playtime=%d",
                g_parentalBypassPlaytime.load(), g_parentalIgnorePlaytime.load());

            if (g_parentalBypassPlaytime.load() || g_parentalIgnorePlaytime.load()) {
                ParentalBypass::PatchParentalSignatureCheck();
                ParentalBypass::InstallParentalSettingsHook(g_parentalBypassPlaytime.load());
            }
            if (g_parentalIgnorePlaytime.load()) {
                ParentalBypass::PatchPlaytimeEnforcement();
            }

        } // !cloudSaveOnly (parental)

        bool autoUpdate = cfg["auto_update_dll"].type == Json::Type::Bool
            ? cfg["auto_update_dll"].boolean()
            : !MetadataSync::steamToolsPresent.load(std::memory_order_relaxed);
        if (autoUpdate) {
            std::thread t(TryAutoUpdateDll);
            std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
            g_bgThreads.push_back(std::move(t));
            LOG("[NS] DLL auto-update enabled, checking in background");
        }
    } else {
        LOG("[NS] No config.json at %s -- local-only mode", configPath.c_str());
    }

    CloudStorage::Init(cloudRoot, std::move(provider));
    g_startupMetadataScheduled.store(false);

    // Native stats / playtime store (cloud-backed). Must come after CloudStorage.
    // Stats sync as one account-wide blob at <accountId>/0/stats.json (appId ->
    // stats JSON), not one blob per app (a Drive round-trip per app at startup).
    StatsStore::SetCloudProvider(
        // pullAll: one download of the account blob, split into per-app entries.
        [](std::unordered_map<uint32_t, std::string>& out) -> bool {
            uint32_t accountId = GetAccountId();
            if (accountId == 0) return false;
            std::vector<uint8_t> data;
            if (!CloudStorage::DownloadCloudMetadataWithLegacyFallback(
                    accountId, CloudIntercept::kAccountScopeAppId, "stats.json",
                    nullptr, data) || data.empty())
                return true;  // no account blob yet -> empty (not a failure)
            Json::Value root = Json::Parse(
                std::string(reinterpret_cast<const char*>(data.data()), data.size()));
            if (root.type != Json::Type::Object) return true;
            for (const auto& [appIdStr, appVal] : root.objVal) {
                uint32_t appId = (uint32_t)strtoul(appIdStr.c_str(), nullptr, 10);
                if (appId == 0) continue;
                out[appId] = Json::Stringify(appVal);
            }
            return true;
        },
        // pushAll: RMW-merge our snapshot onto the live blob (don't clobber
        // another device) and upload once; skip if nothing changed.
        [](const std::unordered_map<uint32_t, std::string>& all) {
            // This runs on a detached worker (off Steam's net thread). Register
            // with the in-flight drain so CloudStorage::Shutdown waits for the
            // provider read below before tearing g_provider down (UAF guard).
            CloudStorage::InflightSyncScope guard;
            if (!guard.entered) return;

            uint32_t accountId = GetAccountId();
            if (accountId == 0) return;

            // Read the current account blob as the merge base.
            Json::Value root = Json::Object();
            std::vector<uint8_t> cur;
            if (CloudStorage::DownloadCloudMetadataWithLegacyFallback(
                    accountId, CloudIntercept::kAccountScopeAppId, "stats.json",
                    nullptr, cur) && !cur.empty()) {
                Json::Value parsed = Json::Parse(
                    std::string(reinterpret_cast<const char*>(cur.data()), cur.size()));
                if (parsed.type == Json::Type::Object) root = std::move(parsed);
            }

            // Consume apps that were intentionally reset -- these must replace
            // (not merge) the cloud entry so old achievements can't resurrect.
            auto resetApps = StatsStore::ConsumeResetApps();

            // Fold each app onto the live cloud entry (monotonic merge, not replace).
            bool changed = false;
            for (const auto& [appId, json] : all) {
                if (appId == 0) continue;
                std::string key = std::to_string(appId);
                std::string mergedEntry;
                if (resetApps.count(appId)) {
                    mergedEntry = json;
                } else {
                    std::string baseEntry = root.has(key)
                        ? Json::Stringify(root.objVal[key]) : std::string();
                    mergedEntry = StatsStore::MergeAppStatsJson(baseEntry, json);
                }
                Json::Value appVal = Json::Parse(mergedEntry);
                if (!root.has(key) || !Json::DeepEqual(root.objVal[key], appVal)) {
                    root.objVal[key] = std::move(appVal);
                    changed = true;
                }
            }
            if (!changed) return;  // nothing to write

            std::string merged = Json::Stringify(root);
            CloudStorage::UploadCloudMetadataTextAsync(
                accountId, CloudIntercept::kAccountScopeAppId, "stats.json", merged);
        },
        // pullLegacy: read one app's old per-app blob for migration into the account blob.
        [](uint32_t appId) -> std::string {
            CloudStorage::InflightSyncScope guard;
            if (!guard.entered) return std::string();
            uint32_t accountId = GetAccountId();
            if (accountId == 0) return std::string();
            std::vector<uint8_t> data;
            if (CloudStorage::DownloadCloudMetadataWithLegacyFallback(
                    accountId, appId, "stats.json", nullptr, data) && !data.empty())
                return std::string(reinterpret_cast<const char*>(data.data()), data.size());
            return std::string();
        },
        // pullLegacyPlaytime: read one app's first-format Playtime/<appId>.bin from cloud.
        [](uint32_t appId) -> std::string {
            CloudStorage::InflightSyncScope guard;
            if (!guard.entered) return std::string();
            uint32_t accountId = GetAccountId();
            if (accountId == 0) return std::string();
            std::vector<uint8_t> data;
            if (CloudStorage::DownloadLegacyPlaytimeBlob(accountId, appId, data))
                return std::string(reinterpret_cast<const char*>(data.data()), data.size());
            return std::string();
        });
    // Restrict all playtime/stats tracking to namespace/lua apps only -- real
    // owned games must never have their playtime recorded or synced.
    StatsHandlers::SetNamespacePredicate([](uint32_t appId) { return IsNamespaceApp(appId); });
    // Resolve current accountId lazily so the store can import Steam's native
    // UserGameStats blobs (appcache\stats\UserGameStats_<accountId>_<appId>.bin).
    StatsStore::SetAccountIdProvider([]() -> uint32_t { return GetAccountId(); });
    StatsStore::SetNamespacePredicate([](uint32_t appId) { return IsNamespaceApp(appId); });
    // On import, refresh schema from Steam (forceRefresh detects new achievements;
    // deduped per app per session by g_schemaFetchAttempted).
    StatsStore::SetSchemaMissingCallback([](uint32_t appId) {
        std::thread([appId] { RequestSchemaForApp(appId, true); }).detach();
    });
    StatsStore::Init(cloudRoot, g_steamPath);
    StatsHandlers::Init();
    // Seed on bg thread only if a stats feature is enabled (blocks on cloud reads).
    // Third-party: check raw config flags since StGateOpen() is false.
    bool shouldSeed = cloudSaveOnly
        ? (MetadataSync::syncAchievements.load(std::memory_order_relaxed) ||
           MetadataSync::syncPlaytime.load(std::memory_order_relaxed))
        : (MetadataSync::AchievementsEnabled() || MetadataSync::PlaytimeEnabled());
    if (shouldSeed) {
        if (cloudSaveOnly) {
            // Third-party: apps aren't registered yet (CR_SetApps comes after Init).
            // Defer seeding — CR_SetApps calls TriggerDeferredSeed once apps arrive.
            CloudIntercept::SetNeedsSeed(true);
        } else {
            std::thread seed([] {
                if (g_shuttingDown.load(std::memory_order_acquire)) return;
                StatsStore::SeedApps(GetNamespaceApps());
            });
            std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
            if (g_shuttingDown.load(std::memory_order_acquire))
                seed.detach();
            else
                g_bgThreads.push_back(std::move(seed));
        }
    }

    // Poll cloud for remote playtime advances; enqueue for net-thread to apply.
    {
        std::thread poller([] {
            for (;;) {
                for (int i = 0; i < 60 && !g_shuttingDown.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                if (g_shuttingDown.load()) return;
                // Pure playtime feature: skip the cloud pull + live push when off.
                // Third-party (cloudSaveOnly): StGateOpen is false (no SteamTools DLL),
                // so PlaytimeEnabled() is always false -- check raw config instead.
                bool canPoll = g_cloudSaveOnly.load(std::memory_order_relaxed)
                    ? MetadataSync::syncPlaytime.load(std::memory_order_relaxed)
                    : MetadataSync::PlaytimeEnabled();
                if (!canPoll) continue;
                auto changed = StatsStore::RefreshFromCloud(GetNamespaceApps());
                if (changed.empty()) continue;
                PB::Writer body = StatsHandlers::BuildLastPlayedNotificationBody(changed);
                if (body.Size() > 0)
                    QueueLastPlayedUpdate(body.Data());
            }
        });
        std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
        if (g_shuttingDown.load(std::memory_order_acquire))
            poller.detach();
        else
            g_bgThreads.push_back(std::move(poller));
    }

    SteamKvInjector::Init();


    if (g_syncLuas) {
        g_luaSyncThread = std::thread([] {
            for (int i = 0; i < 300 && !g_shuttingDown.load(); i++) {
                if (GetAccountId() != 0) break;
                Sleep(1000);
            }
            if (g_shuttingDown.load() || GetAccountId() == 0) return;
            SyncLuaFiles();
        });
    }

    LOG("CloudIntercept initialized (local server mode), steam=%s", g_steamPath.c_str());

    // Cooperative Shutdown via ExitProcess IAT hook (atexit and
    // DLL_PROCESS_DETACH both run too late to safely drain workers).
    InstallExitProcessHook();
}

// InstallRecvPktDetour: inline-hook CCMConnection::RecvPkt via sig-scan.
// Finds the function by scanning for the VProf string reference.
static constexpr size_t DETOUR_PATCH_SIZE = 14;   // FF 25 00 00 00 00 <8-byte addr>
static constexpr size_t TRAMPOLINE_COPY  = 15;    // first 3 instructions of RecvPkt prologue

void InstallRecvPktDetour() {
    HMODULE hSC = GetModuleHandleA("steamclient64.dll");
    if (!hSC) { LOG("[RecvPkt] steamclient64.dll not loaded"); return; }
    uintptr_t scBase = (uintptr_t)hSC;

    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), hSC, &mi, sizeof(mi))) {
        LOG("[RecvPkt] GetModuleInformation failed"); return;
    }

    // Scan for "CCMConnection::RecvPkt() multi" in .rdata
    const char* needle = "CCMConnection::RecvPkt() multi";
    size_t needleLen = strlen(needle);
    const uint8_t* base = (const uint8_t*)scBase;
    const uint8_t* end = base + mi.SizeOfImage - needleLen;
    const uint8_t* strAddr = nullptr;
    for (const uint8_t* p = base; p < end; ++p) {
        if (memcmp(p, needle, needleLen) == 0) { strAddr = p; break; }
    }
    if (!strAddr) { LOG("[RecvPkt] VProf string not found"); return; }
    LOG("[RecvPkt] VProf string at %p (RVA 0x%llX)", strAddr, (uint64_t)(strAddr - base));

    // Find LEA rcx, [rip+disp] (48 8D 0D xx xx xx xx) targeting this string.
    // Search .text only (first ~80% of image is typically .text).
    const uint8_t* textEnd = base + mi.SizeOfImage;
    const uint8_t* leaRef = nullptr;
    for (const uint8_t* p = base + 0x1000; p < textEnd - 7; ++p) {
        if (p[0] == 0x48 && p[1] == 0x8D && p[2] == 0x0D) {
            int32_t disp;
            memcpy(&disp, p + 3, 4);
            if ((p + 7 + disp) == strAddr) { leaRef = p; break; }
        }
    }
    if (!leaRef) { LOG("[RecvPkt] LEA reference to VProf string not found"); return; }
    LOG("[RecvPkt] LEA ref at %p (RVA 0x%llX)", leaRef, (uint64_t)(leaRef - base));

    // Walk backward to find the function prologue (48 89 5C 24 08).
    uint8_t* funcStart = nullptr;
    for (const uint8_t* p = leaRef; p > leaRef - 0x200 && p > base + 0x1000; --p) {
        if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24 && p[4] == 0x08) {
            funcStart = (uint8_t*)p;
            break;
        }
    }
    if (!funcStart) { LOG("[RecvPkt] could not locate function prologue"); return; }
    LOG("[RecvPkt] CCMConnection::RecvPkt at %p (RVA 0x%llX)", funcStart, (uint64_t)(funcStart - base));

    // Allocate executable trampoline.
    g_recvPktTrampoline = (uint8_t*)VirtualAlloc(nullptr, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_recvPktTrampoline) { LOG("[RecvPkt] VirtualAlloc trampoline failed"); return; }

    // Copy original prologue bytes (15 bytes = 3 full instructions).
    memcpy(g_recvPktOrigBytes, funcStart, TRAMPOLINE_COPY);
    memcpy(g_recvPktTrampoline, funcStart, TRAMPOLINE_COPY);

    // Append JMP [rip+0] <original+15> to trampoline.
    g_recvPktTrampoline[TRAMPOLINE_COPY + 0] = 0xFF;
    g_recvPktTrampoline[TRAMPOLINE_COPY + 1] = 0x25;
    memset(g_recvPktTrampoline + TRAMPOLINE_COPY + 2, 0, 4);  // disp = 0
    uintptr_t resumeAddr = (uintptr_t)funcStart + TRAMPOLINE_COPY;
    memcpy(g_recvPktTrampoline + TRAMPOLINE_COPY + 6, &resumeAddr, 8);
    g_originalRecvPkt = (RecvPktFn)g_recvPktTrampoline;

    // Patch original with JMP [rip+0] <hook>.
    DWORD oldProt;
    if (!VirtualProtect(funcStart, TRAMPOLINE_COPY, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LOG("[RecvPkt] VirtualProtect failed (%u)", GetLastError());
        VirtualFree(g_recvPktTrampoline, 0, MEM_RELEASE);
        g_recvPktTrampoline = nullptr;
        g_originalRecvPkt = nullptr;
        return;
    }
    funcStart[0] = 0xFF;
    funcStart[1] = 0x25;
    memset(funcStart + 2, 0, 4);   // disp = 0
    uintptr_t hookAddr = (uintptr_t)RecvPktMonitorHook;
    memcpy(funcStart + 6, &hookAddr, 8);
    funcStart[14] = 0x90;          // NOP the 15th byte
    FlushInstructionCache(GetCurrentProcess(), funcStart, TRAMPOLINE_COPY);
    VirtualProtect(funcStart, TRAMPOLINE_COPY, oldProt, &oldProt);
    g_recvPktDetourSite = funcStart;

    LOG("[RecvPkt] Detour installed: hook=%p trampoline=%p original=%p",
        RecvPktMonitorHook, g_recvPktTrampoline, funcStart);
}

void InstallManifestPinHook() {
    if (!g_manifestPinsEnabled.load(std::memory_order_relaxed)) {
        LOG("[ManifestPin] Pins not enabled, skipping hook");
        return;
    }

    HMODULE hSteamClient = GetModuleHandleA("steamclient64.dll");
    if (!hSteamClient) {
        LOG("[ManifestPin] steamclient64.dll not loaded");
        return;
    }

    uintptr_t bddAddr = SC_RESOLVE(buildDepotDependency);
    if (!bddAddr) {
        LOG("[ManifestPin] BuildDepotDependency not resolved -- skipping hook");
        return;
    }
    g_bddOrigAddr = reinterpret_cast<uint8_t*>(bddAddr);
    LOG("[ManifestPin] Target: steamclient64!BuildDepotDependency at %p", g_bddOrigAddr);

    // Verify the prologue bytes match what we expect from IDA:
    // 48 8B C4             mov rax, rsp
    // 4C 89 48 20          mov [rax+20h], r9
    // 89 50 10             mov [rax+10h], edx
    // 48 89 48 08          mov [rax+8], rcx
    static const uint8_t expectedPrologue[SC_BDD_STOLEN_BYTES] = {
        0x48, 0x8B, 0xC4,              // mov rax, rsp
        0x4C, 0x89, 0x48, 0x20,        // mov [rax+20h], r9
        0x89, 0x50, 0x10,              // mov [rax+10h], edx
        0x48, 0x89, 0x48, 0x08         // mov [rax+8], rcx
    };
    if (memcmp(g_bddOrigAddr, expectedPrologue, SC_BDD_STOLEN_BYTES) != 0) {
        LOG("[ManifestPin] Prologue mismatch! Steam may have updated. Aborting hook.");
        LOG("[ManifestPin] Expected: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            expectedPrologue[0], expectedPrologue[1], expectedPrologue[2], expectedPrologue[3],
            expectedPrologue[4], expectedPrologue[5], expectedPrologue[6], expectedPrologue[7],
            expectedPrologue[8], expectedPrologue[9], expectedPrologue[10], expectedPrologue[11],
            expectedPrologue[12], expectedPrologue[13]);
        LOG("[ManifestPin] Got:      %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            g_bddOrigAddr[0], g_bddOrigAddr[1], g_bddOrigAddr[2], g_bddOrigAddr[3],
            g_bddOrigAddr[4], g_bddOrigAddr[5], g_bddOrigAddr[6], g_bddOrigAddr[7],
            g_bddOrigAddr[8], g_bddOrigAddr[9], g_bddOrigAddr[10], g_bddOrigAddr[11],
            g_bddOrigAddr[12], g_bddOrigAddr[13]);
        g_bddOrigAddr = nullptr;
        return;
    }

    // Allocate executable memory for the trampoline (stolen bytes + jmp back).
    // Total trampoline size: 14 (stolen) + 14 (jmp [rip+0] + 8-byte addr) = 28 bytes
    static constexpr size_t TRAMPOLINE_SIZE = SC_BDD_STOLEN_BYTES + 14;
    g_bddTrampoline = reinterpret_cast<uint8_t*>(
        VirtualAlloc(nullptr, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!g_bddTrampoline) {
        LOG("[ManifestPin] VirtualAlloc for trampoline failed (%u)", GetLastError());
        g_bddOrigAddr = nullptr;
        return;
    }

    // Build trampoline: stolen prologue bytes + absolute jump back to original+14
    memcpy(g_bddTrampoline, g_bddOrigAddr, SC_BDD_STOLEN_BYTES);
    uint8_t* jumpBack = g_bddTrampoline + SC_BDD_STOLEN_BYTES;
    jumpBack[0] = 0xFF;  // jmp [rip+0]
    jumpBack[1] = 0x25;
    jumpBack[2] = 0x00;
    jumpBack[3] = 0x00;
    jumpBack[4] = 0x00;
    jumpBack[5] = 0x00;
    uintptr_t returnAddr = reinterpret_cast<uintptr_t>(g_bddOrigAddr) + SC_BDD_STOLEN_BYTES;
    memcpy(jumpBack + 6, &returnAddr, 8);

    g_origBuildDepotDependency = reinterpret_cast<BuildDepotDependencyFn>(g_bddTrampoline);
    LOG("[ManifestPin] Trampoline at %p, returns to %p", g_bddTrampoline, (void*)returnAddr);

    // Overwrite the original function's first 14 bytes with a jump to our hook.
    // ff 25 00 00 00 00 [8-byte absolute address of BuildDepotDependencyHook]
    DWORD oldProt;
    if (!VirtualProtect(g_bddOrigAddr, SC_BDD_STOLEN_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LOG("[ManifestPin] VirtualProtect on target failed (%u)", GetLastError());
        VirtualFree(g_bddTrampoline, 0, MEM_RELEASE);
        g_bddTrampoline = nullptr;
        g_origBuildDepotDependency = nullptr;
        g_bddOrigAddr = nullptr;
        return;
    }

    uint8_t detour[SC_BDD_STOLEN_BYTES];
    detour[0] = 0xFF;  // jmp [rip+0]
    detour[1] = 0x25;
    detour[2] = 0x00;
    detour[3] = 0x00;
    detour[4] = 0x00;
    detour[5] = 0x00;
    uintptr_t hookAddr = reinterpret_cast<uintptr_t>(&BuildDepotDependencyHook);
    memcpy(detour + 6, &hookAddr, 8);
    memcpy(g_bddOrigAddr, detour, SC_BDD_STOLEN_BYTES);

    FlushInstructionCache(GetCurrentProcess(), g_bddOrigAddr, SC_BDD_STOLEN_BYTES);
    VirtualProtect(g_bddOrigAddr, SC_BDD_STOLEN_BYTES, oldProt, &oldProt);

    LOG("[ManifestPin] Inline detour installed at %p -> BuildDepotDependencyHook %p",
        g_bddOrigAddr, (void*)hookAddr);
}

// Release-state patch state
static uint8_t* g_releaseStateAddr = nullptr;
static uint8_t  g_releaseStateOrig[6] = {};
static std::atomic<bool> g_releaseStatePatched{false};

void InstallReleaseStateNop() {
    // Patch GetEffectiveReleaseState to always return 4 (RELEASED).
    HMODULE hSC = GetModuleHandleA("steamclient64.dll");
    if (!hSC) return;

    uintptr_t base = reinterpret_cast<uintptr_t>(hSC);

    // Find "ReleaseStateOverride\0" in .rdata to locate the function.
    static const uint8_t needle[] = "ReleaseStateOverride";
    char mask[21]; memset(mask, 'x', 20); mask[20] = '\0';

    uintptr_t strAddr = 0;
    {
        uintptr_t searchFrom = SigScanner::GetRdataBase();
        size_t remaining = SigScanner::GetRdataSize();
        while (remaining > 20) {
            uintptr_t hit = SigScanner::FindPatternInRange(searchFrom, remaining, needle, mask, 20);
            if (!hit) break;
            // Must be exactly "ReleaseStateOverride\0" (not "...Countries")
            if (*(uint8_t*)(hit + 20) == '\0') {
                strAddr = hit;
                break;
            }
            size_t advance = (hit - searchFrom) + 1;
            searchFrom = hit + 1;
            remaining -= advance;
        }
    }
    if (!strAddr) {
        LOG("[RelState] 'ReleaseStateOverride' string not found in .rdata");
        return;
    }

    uintptr_t textBase = SigScanner::GetTextBase();
    size_t textSize = SigScanner::GetTextSize();

    // Find LEA xref to the string to get the thunk that populates the global.
    uintptr_t thunkLeaAddr = 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(textBase);
        for (size_t i = 0; i + 7 <= textSize; ++i) {
            if ((p[i] == 0x48 || p[i] == 0x4C) && p[i+1] == 0x8D) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 3);
                uintptr_t target = textBase + i + 7 + disp;
                if (target == strAddr) {
                    thunkLeaAddr = textBase + i;
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!thunkLeaAddr) {
        LOG("[RelState] LEA xref to 'ReleaseStateOverride' not found");
        return;
    }

    // The LEA after the string ref loads the override global's address.
    uintptr_t globalAddr = 0;
    __try {
        const auto* q = reinterpret_cast<const uint8_t*>(thunkLeaAddr + 7);
        if ((q[0] == 0x48 || q[0] == 0x4C) && q[1] == 0x8D) {
            int32_t disp = *reinterpret_cast<const int32_t*>(q + 3);
            globalAddr = (thunkLeaAddr + 7) + 7 + disp;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!globalAddr) {
        LOG("[RelState] Could not extract override global address");
        return;
    }

    // Find the MOV that reads this global -- that's inside GetEffectiveReleaseState.
    uintptr_t funcAddr = 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(textBase);
        for (size_t i = 0; i + 6 <= textSize; ++i) {
            // 8B 15 xx xx xx xx  = mov edx, [rip+disp32]
            if (p[i] == 0x8B && p[i+1] == 0x15) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 2);
                uintptr_t target = textBase + i + 6 + disp;
                if (target == globalAddr) {
                    // Walk backward to function prologue
                    uintptr_t ea = textBase + i;
                    for (int j = 0; j < 128; ++j) {
                        if (SigScanner::LooksLikeFunctionStart(ea - j)) {
                            funcAddr = ea - j;
                            break;
                        }
                    }
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!funcAddr) {
        LOG("[RelState] GetEffectiveReleaseState not found");
        return;
    }

    g_releaseStateAddr = reinterpret_cast<uint8_t*>(funcAddr);
    memcpy(g_releaseStateOrig, g_releaseStateAddr, 6);
    LOG("[RelState] GetEffectiveReleaseState at sc+0x%llX, prologue: %02X %02X %02X %02X %02X %02X",
        (unsigned long long)(funcAddr - base),
        g_releaseStateOrig[0], g_releaseStateOrig[1], g_releaseStateOrig[2],
        g_releaseStateOrig[3], g_releaseStateOrig[4], g_releaseStateOrig[5]);

    DWORD oldProt;
    if (!VirtualProtect(g_releaseStateAddr, 6, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LOG("[RelState] VirtualProtect failed (%u)", GetLastError());
        g_releaseStateAddr = nullptr;
        return;
    }

    // mov eax, 4; ret
    g_releaseStateAddr[0] = 0xB8;
    g_releaseStateAddr[1] = 0x04;
    g_releaseStateAddr[2] = 0x00;
    g_releaseStateAddr[3] = 0x00;
    g_releaseStateAddr[4] = 0x00;
    g_releaseStateAddr[5] = 0xC3;

    VirtualProtect(g_releaseStateAddr, 6, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_releaseStateAddr, 6);

    g_releaseStatePatched.store(true, std::memory_order_release);
    LOG("[RelState] Patched to return ERELEASESTATE_RELEASED (4)");
}

// ── Manifest endpoint override (runtime code patch) ────────────────────

static void* g_manifestStringsPage = nullptr;
static uint8_t* g_manifestUrlLeaAddr = nullptr;
static uint8_t  g_manifestUrlLeaOrig[4] = {};
static uint8_t* g_manifestP8bAddr = nullptr;
static uint8_t  g_manifestP8bOrig[51] = {};
static std::atomic<bool> g_manifestEndpointPatched{false};

static const uint8_t kP8bSig[] = {
    0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x33, 0xC9,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0xD8,
    0x4C, 0x8B, 0xC0,
    0xBA, 0x27, 0x27, 0x00, 0x00,
};
static const uint8_t kP8bMask[] = {
    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF,
    0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

void InstallManifestEndpointOverride() {
    if (g_manifestEndpoint.empty()) {
        LOG("[ManifestEP] No endpoint configured, skipping");
        return;
    }
    if (!g_payloadBase) {
        LOG("[ManifestEP] Payload base unknown, skipping");
        return;
    }

    // Hardcoded section layout (page 0 not mapped, no PE header access).
    static constexpr uintptr_t kTextRva   = 0x1000;
    static constexpr size_t    kTextSize  = 0x178000;
    static constexpr uintptr_t kRdataRva  = 0x179000;
    static constexpr size_t    kRdataSize = 0x54000;

    uintptr_t textBase = g_payloadBase + kTextRva;
    size_t textSize = kTextSize;
    uintptr_t rdataBase = g_payloadBase + kRdataRva;
    size_t rdataSize = kRdataSize;

    __try {
        volatile uint8_t probe = *reinterpret_cast<uint8_t*>(textBase);
        (void)probe;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("[ManifestEP] .text base not readable at %p", (void*)textBase);
        return;
    }

    uintptr_t p8bAddr = 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(textBase);
        for (size_t i = 0; i + sizeof(kP8bSig) <= textSize; ++i) {
            bool match = true;
            for (size_t j = 0; j < sizeof(kP8bSig); ++j) {
                if ((p[i + j] & kP8bMask[j]) != (kP8bSig[j] & kP8bMask[j])) {
                    match = false; break;
                }
            }
            if (match) { p8bAddr = textBase + i; break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (!p8bAddr) {
        LOG("[ManifestEP] P8b signature not found in payload .text"); return;
    }
    LOG("[ManifestEP] P8b at %p (payload+0x%llX)",
        (void*)p8bAddr, (unsigned long long)(p8bAddr - g_payloadBase));

    // URL lea rdx,[rip+xx] is 355 bytes before P8b (function+108 vs +463).
    uintptr_t urlLeaAddr = p8bAddr - 355;
    __try {
        if (*(uint8_t*)urlLeaAddr != 0x48 || *(uint8_t*)(urlLeaAddr + 1) != 0x8D ||
            *(uint8_t*)(urlLeaAddr + 2) != 0x15) {
            LOG("[ManifestEP] URL lea not found at expected offset (got %02X %02X %02X)",
                *(uint8_t*)urlLeaAddr, *(uint8_t*)(urlLeaAddr + 1), *(uint8_t*)(urlLeaAddr + 2));
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("[ManifestEP] Access violation reading URL lea at %p", (void*)urlLeaAddr);
        return;
    }

    int32_t origUrlDisp = *(int32_t*)(urlLeaAddr + 3);
    uintptr_t origUrlTarget = urlLeaAddr + 7 + origUrlDisp;
    if (origUrlTarget < rdataBase || origUrlTarget >= rdataBase + rdataSize) {
        LOG("[ManifestEP] URL lea target %p outside expected .rdata range, proceeding anyway",
            (void*)origUrlTarget);
    }
    const char* origUrl = nullptr;
    __try {
        origUrl = reinterpret_cast<const char*>(origUrlTarget);
        if (strncmp(origUrl, "http", 4) != 0) {
            LOG("[ManifestEP] URL lea target doesn't start with 'http': %.32s", origUrl);
            return;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG("[ManifestEP] Access violation reading URL target at %p", (void*)origUrlTarget);
        return;
    }
    LOG("[ManifestEP] Original URL: %.64s", origUrl);

    // Allocate a page within ±2GB for RIP-relative addressing.
    uintptr_t allocHint = g_payloadBase;
    g_manifestStringsPage = nullptr;
    for (int attempt = 0; attempt < 256 && !g_manifestStringsPage; ++attempt) {
        uintptr_t tryAddr = allocHint + (uintptr_t)attempt * 0x10000;
        g_manifestStringsPage = VirtualAlloc((void*)tryAddr, 4096,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!g_manifestStringsPage) {
        for (int attempt = 1; attempt < 256 && !g_manifestStringsPage; ++attempt) {
            uintptr_t tryAddr = allocHint - (uintptr_t)attempt * 0x10000;
            if (tryAddr < 0x10000) break;
            g_manifestStringsPage = VirtualAlloc((void*)tryAddr, 4096,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
    }
    if (!g_manifestStringsPage) {
        LOG("[ManifestEP] VirtualAlloc failed for string page"); return;
    }

    char* urlSlot = (char*)g_manifestStringsPage;
    char* uaSlot = (char*)g_manifestStringsPage + 512;
    strncpy(urlSlot, g_manifestEndpoint.c_str(), 255);
    urlSlot[255] = '\0';
    strncpy(uaSlot, "OpenSteamTool/1.0", 63);
    uaSlot[63] = '\0';

    int64_t urlDispCheck = (int64_t)(uintptr_t)urlSlot - (int64_t)(urlLeaAddr + 7);
    if (urlDispCheck < INT32_MIN || urlDispCheck > INT32_MAX) {
        LOG("[ManifestEP] URL displacement out of range (%lld)", urlDispCheck);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    int32_t urlDisp = (int32_t)urlDispCheck;

    // Resolve setopt target from unpatched P8b+25: mov rcx,rdi; call setopt
    uint8_t* afterSig = (uint8_t*)(p8bAddr + 25);
    if (afterSig[0] != 0x48 || afterSig[1] != 0x8B || afterSig[2] != 0xCF) {
        LOG("[ManifestEP] Expected 'mov rcx,rdi' at P8b+25, got %02X %02X %02X",
            afterSig[0], afterSig[1], afterSig[2]);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    if (afterSig[3] != 0xE8) {
        LOG("[ManifestEP] Expected 'call' at P8b+28, got %02X", afterSig[3]);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    int32_t origSetoptRel = *(int32_t*)(afterSig + 4);
    uintptr_t setoptTarget = (uintptr_t)(afterSig + 8) + origSetoptRel;

    int64_t uaDispCheck = (int64_t)(uintptr_t)uaSlot - (int64_t)(p8bAddr + 7);
    if (uaDispCheck < INT32_MIN || uaDispCheck > INT32_MAX) {
        LOG("[ManifestEP] UA displacement out of range (%lld)", uaDispCheck);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    int32_t uaDisp = (int32_t)uaDispCheck;

    int64_t setoptNewRel = (int64_t)setoptTarget - (int64_t)(p8bAddr + 20);
    if (setoptNewRel < INT32_MIN || setoptNewRel > INT32_MAX) {
        LOG("[ManifestEP] setopt call displacement out of range (%lld)", setoptNewRel);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }

    // Resolve perform target from P8b+33: mov rcx,rdi; call perform
    uint8_t* performSite = (uint8_t*)(p8bAddr + 33);
    if (performSite[0] != 0x48 || performSite[1] != 0x8B || performSite[2] != 0xCF) {
        LOG("[ManifestEP] Expected 'mov rcx,rdi' at P8b+33, got %02X %02X %02X",
            performSite[0], performSite[1], performSite[2]);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    if (performSite[3] != 0xE8) {
        LOG("[ManifestEP] Expected 'call' at P8b+36, got %02X", performSite[3]);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    int32_t origPerformRel = *(int32_t*)(performSite + 4);
    uintptr_t performTarget = (uintptr_t)(p8bAddr + 41) + origPerformRel;

    int64_t performNewRel = (int64_t)performTarget - (int64_t)(p8bAddr + 28);
    if (performNewRel < INT32_MIN || performNewRel > INT32_MAX) {
        LOG("[ManifestEP] perform call displacement out of range (%lld)", performNewRel);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }

    // 51-byte replacement: lea r8→UA, setopt(USERAGENT), perform, mov esi eax, NOPs
    uint8_t p8bRepl[51];
    p8bRepl[0] = 0x4C; p8bRepl[1] = 0x8D; p8bRepl[2] = 0x05;
    memcpy(p8bRepl + 3, &uaDisp, 4);
    p8bRepl[7] = 0xBA; p8bRepl[8] = 0x22; p8bRepl[9] = 0x27;
    p8bRepl[10] = 0x00; p8bRepl[11] = 0x00;
    p8bRepl[12] = 0x48; p8bRepl[13] = 0x8B; p8bRepl[14] = 0xCF;
    p8bRepl[15] = 0xE8;
    int32_t setoptRel32 = (int32_t)setoptNewRel;
    memcpy(p8bRepl + 16, &setoptRel32, 4);
    p8bRepl[20] = 0x48; p8bRepl[21] = 0x8B; p8bRepl[22] = 0xCF;
    p8bRepl[23] = 0xE8;
    int32_t performRel32 = (int32_t)performNewRel;
    memcpy(p8bRepl + 24, &performRel32, 4);
    p8bRepl[28] = 0x8B; p8bRepl[29] = 0xF0;
    memset(p8bRepl + 30, 0x90, 21);

    g_manifestUrlLeaAddr = (uint8_t*)(urlLeaAddr + 3);
    memcpy(g_manifestUrlLeaOrig, g_manifestUrlLeaAddr, 4);
    DWORD oldProt;
    if (!VirtualProtect(g_manifestUrlLeaAddr, 4, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LOG("[ManifestEP] VirtualProtect failed for URL lea (%u)", GetLastError());
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    memcpy(g_manifestUrlLeaAddr, &urlDisp, 4);
    VirtualProtect(g_manifestUrlLeaAddr, 4, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_manifestUrlLeaAddr, 4);

    g_manifestP8bAddr = (uint8_t*)p8bAddr;
    memcpy(g_manifestP8bOrig, g_manifestP8bAddr, 51);
    if (!VirtualProtect(g_manifestP8bAddr, 51, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LOG("[ManifestEP] VirtualProtect failed for P8b rewrite (%u)", GetLastError());
        DWORD tmp;
        VirtualProtect(g_manifestUrlLeaAddr, 4, PAGE_EXECUTE_READWRITE, &tmp);
        memcpy(g_manifestUrlLeaAddr, g_manifestUrlLeaOrig, 4);
        VirtualProtect(g_manifestUrlLeaAddr, 4, tmp, &tmp);
        FlushInstructionCache(GetCurrentProcess(), g_manifestUrlLeaAddr, 4);
        VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
        g_manifestStringsPage = nullptr;
        return;
    }
    memcpy(g_manifestP8bAddr, p8bRepl, 51);
    VirtualProtect(g_manifestP8bAddr, 51, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_manifestP8bAddr, 51);

    g_manifestEndpointPatched.store(true, std::memory_order_release);
    LOG("[ManifestEP] Redirected to %s (UA: OpenSteamTool/1.0)", g_manifestEndpoint.c_str());
}

// ── BAsyncSend inline detour (GamesPlayed rewriting) ───────────────────
// Intercept BAsyncSend to inject game_extra_info into CMsgClientGamesPlayed.

using BAsyncSendFn = uint8_t(__fastcall*)(void* pMsg, uint32_t connHandle);

static uint8_t* g_basOrigAddr = nullptr;         // original BAsyncSend address
static uint8_t  g_basTrampoline[64] = {};         // trampoline: stolen prologue + jmp back
static BAsyncSendFn g_basOriginal = nullptr;      // trampoline as callable

// Forward declaration - defined later in file
static std::vector<uint8_t> RewriteGamesPlayed(const uint8_t* body, uint32_t bodyLen);

// Rewrite the GamesPlayed body in-place on the live protobuf object.
static void RewriteGamesPlayedBody(void* bodyObj) {
    auto bodyBytes = SerializeBodyToBytes(bodyObj);
    if (bodyBytes.empty()) return;

    auto newBody = RewriteGamesPlayed(bodyBytes.data(), (uint32_t)bodyBytes.size());
    if (newBody.empty()) return;

    ParseBytesToBody(bodyObj, newBody.data(), newBody.size());
}

static void SweepNamespaceSchemas();  // fwd decl

// Schedule schema sweep once after startup settles (injecting during startup hangs client).
static std::atomic<bool> g_schemaSweepScheduled{false};
static void MaybeScheduleSchemaSweep() {
    // Experimental opt-in: only fetch schemas when the user enabled it.
    if (!MetadataSync::SchemaFetchEnabled()) return;
    if (g_schemaSweepScheduled.exchange(true)) return;   // once per session
    std::thread t([] {
        constexpr int kStartupSettleMs = 15000;          // wait for startup to settle
        for (int waited = 0; waited < kStartupSettleMs; waited += 500) {
            if (g_shuttingDown.load(std::memory_order_acquire)) return;
            Sleep(500);
        }
        if (g_shuttingDown.load(std::memory_order_acquire)) return;
        SweepNamespaceSchemas();
    });
    std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
    if (g_shuttingDown.load(std::memory_order_acquire))
        t.detach();
    else
        g_bgThreads.push_back(std::move(t));
}

static uint8_t __fastcall BAsyncSendHook(void* pMsg, uint32_t connHandle) {
    // Capture CM connection handle for schema-fetch injection.
    if (connHandle && pMsg) {
        // Prefer the conn from Steam's own GetUserStats (818 -> 819 reply path).
        uint32_t hookEmsg = *(uint32_t*)((uintptr_t)pMsg + CPROTOBUFMSG_OFF_EMSG) & EMSG_MASK;
        if (hookEmsg == EMSG_CLIENT_GET_USER_STATS) {
            if (g_statsConnHandle.exchange(connHandle, std::memory_order_relaxed) != connHandle)
                LOG("[Schema] captured CM conn=%u from Steam's own GetUserStats", connHandle);
        }
        // Capture session fields from any outgoing message for injected 818s.
        if (!g_hdrCaptured.load(std::memory_order_relaxed)) {
            void* ownHdr = *(void**)((uintptr_t)pMsg + 0x28);
            if (ownHdr) {
                uint8_t* hb = (uint8_t*)ownHdr;
                uint64_t sid = *(uint64_t*)(hb + 104);
                uint32_t ses = *(uint32_t*)(hb + 112);
                uint32_t rlm = *(uint32_t*)(hb + 156);
                if (sid != 0 && ses != 0) {
                    g_hdrSteamId.store(sid, std::memory_order_relaxed);
                    g_hdrSessionId.store(ses, std::memory_order_relaxed);
                    g_hdrRealm.store(rlm, std::memory_order_relaxed);
                    g_hdrCaptured.store(true, std::memory_order_relaxed);
                    LOG("[Schema] captured header session: steamid=0x%llX sessionid=%u realm=%u (from emsg=%u)",
                        (unsigned long long)sid, ses, rlm, hookEmsg);
                }
            }
        }
        // Still keep a generic fallback handle if we never see an 818.
        g_liveConnHandle.store(connHandle, std::memory_order_relaxed);
        MaybeScheduleSchemaSweep();
    }
    if (HasNamespaceApps() && pMsg && g_serializeToArray && g_parseFromArray) {
        uint32_t emsgRaw = *(uint32_t*)((uintptr_t)pMsg + CPROTOBUFMSG_OFF_EMSG);
        uint32_t emsg = emsgRaw & EMSG_MASK;

        if (emsg == EMSG_CLIENT_GAMES_PLAYED ||
            emsg == EMSG_CLIENT_GAMES_PLAYED_NO_DATABLOB ||
            emsg == EMSG_CLIENT_GAMES_PLAYED_WITH_DATABLOB) {

            void* bodyObj = *(void**)((uintptr_t)pMsg + CPROTOBUFMSG_OFF_BODY);
            if (bodyObj) {
                // Observe games-played for playtime session tracking (gated by sync_playtime).
                if (MetadataSync::PlaytimeEnabled()) {
                    auto observeBytes = SerializeBodyToBytes(bodyObj);
                    if (!observeBytes.empty()) {
                        LOG("[Stats] GamesPlayed observed (emsg=%u, %zu bytes) -> session tracking",
                            emsg, observeBytes.size());
                        StatsHandlers::ObserveGamesPlayed(observeBytes.data(), observeBytes.size());
                    }
                }
                // Non-Steam-game spoof (hard-gated to ST clients).
                if (g_showNonSteamGame.load(std::memory_order_relaxed) &&
                    MetadataSync::StGateOpen())
                    RewriteGamesPlayedBody(bodyObj);
            }
        }
        else if (emsg == EMSG_CLIENT_STORE_USER_STATS2 &&
                 MetadataSync::AchievementsEnabled()) {
            // Client sends on achievement/stat unlock. Re-read native blob to sync new unlocks.
            void* bodyObj = *(void**)((uintptr_t)pMsg + CPROTOBUFMSG_OFF_BODY);
            if (bodyObj) {
                auto observeBytes = SerializeBodyToBytes(bodyObj);
                if (!observeBytes.empty()) {
                    LOG("[Stats] StoreUserStats2 observed (emsg=%u, %zu bytes) -> capturing unlocks",
                        emsg, observeBytes.size());
                    StatsHandlers::ObserveStoreUserStats(observeBytes.data(), observeBytes.size());
                }
            }
        }
        else if (emsg == EMSG_CLIENT_GET_USER_STATS &&
                 MetadataSync::AchievementsEnabled()) {
            // Namespace apps: inject our 819 and suppress 818 to prevent CM clobbering.
            void* bodyObj = *(void**)((uintptr_t)pMsg + CPROTOBUFMSG_OFF_BODY);
            if (bodyObj) {
                auto reqBytes = SerializeBodyToBytes(bodyObj);
                if (!reqBytes.empty()) {
                    auto fields = PB::Parse(reqBytes.data(), reqBytes.size());
                    auto* f1 = PB::FindField(fields, 1);   // game_id (fixed64)
                    uint32_t appId = f1 ? (uint32_t)(f1->varintVal & 0xFFFFFF) : 0;
                    if (appId != 0 && IsNamespaceApp(appId)) {
                        uint64_t jobId = ReadCurrentJobId();
                        auto built = StatsHandlers::HandleLegacyGetUserStats(
                            reqBytes.data(), reqBytes.size(), g_steamId.load());
                        if (built.has_value() && !built->empty()) {
                            LOG("[Stats] GetUserStats(818) app=%u jobid=%llu -> serving 819 (blocking send)",
                                appId, (unsigned long long)jobId);
                            InjectLegacyUserStatsResponse(jobId, appId, *built);
                            // Don't forward to Valve -- we are the sole server.
                            return 1;
                        } else {
                            LOG("[Stats] GetUserStats(818) app=%u: store had nothing to serve, passing through", appId);
                        }
                    }
                }
            }
        }
    }

    return g_basOriginal(pMsg, connHandle);
}

// ── Achievement-schema auto-fetch ──────────────────────────────────────
// Send 818 (schema_local_version=-1) on behalf of game owners (CM requires ownership).
// Discovery: category 22 check -> recent reviewers -> fallback accounts.

// Fallback SteamID64s, used only if review-owner discovery yields no candidates.
static const uint64_t kFallbackOwnerIds[] = {
    76561197978902089ull, 76561198028121353ull, 76561198017975643ull,
    76561198001678750ull, 76561198355953202ull, 76561197993544755ull,
};

// Per-app schema fetch state. Tracks which owners we've tried and manages the
// review-owner discovery + retry pipeline.
struct SchemaFetchState {
    std::vector<uint64_t> owners;       // owners queued to try (review + fallback)
    size_t nextOwnerIdx = 0;            // next owner in `owners` to enqueue
    uint32_t responsesReceived = 0;     // 819 responses received (with or without schema)
    uint32_t requestsSent = 0;          // requests dispatched so far
    bool reviewFetched = false;         // true once we've tried the review API
    bool resolved = false;              // true once schema written to disk
};

static std::mutex g_schemaFetchMutex;
static std::unordered_set<uint32_t> g_schemaFetchAttempted;
static std::unordered_map<uint32_t, SchemaFetchState> g_schemaFetchStates;

// Cache of apps checked for achievement support. true = supports, false = does not.
static std::unordered_map<uint32_t, bool> g_achievementSupportCache;

// Persistent skip-list (cr_schema_skip.txt). Re-probed after kSchemaSkipRetrySecs.
static std::mutex g_schemaSkipMutex;
static std::unordered_map<uint32_t, uint64_t> g_schemaSkip;   // appId -> unix epoch when skip-listed
static std::atomic<bool> g_schemaSkipLoaded{false};

// Re-probe after 14 days (games may add achievements later).
static constexpr uint64_t kSchemaSkipRetrySecs = 14ull * 24 * 60 * 60;

static uint64_t NowEpochSecs() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

static std::string SchemaSkipPath() {
    return g_steamPath + "cloud_redirect\\cr_schema_skip.txt";
}

// Rewrite skip file from in-memory map. Caller must hold g_schemaSkipMutex.
static void RewriteSchemaSkipFileLocked() {
    std::string out;
    out.reserve(g_schemaSkip.size() * 20);
    for (const auto& kv : g_schemaSkip)
        out += std::to_string(kv.first) + "," + std::to_string(kv.second) + "\r\n";
    HANDLE h = CreateFileA(SchemaSkipPath().c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, out.data(), (DWORD)out.size(), &w, nullptr);
    CloseHandle(h);
}

static void LoadSchemaSkipList() {
    if (g_schemaSkipLoaded.exchange(true)) return;
    HANDLE h = CreateFileA(SchemaSkipPath().c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string buf;
    char chunk[4096];
    DWORD got = 0;
    // Cap read at 4MB to prevent corruption from ballooning RAM.
    constexpr size_t kMaxSkipFileBytes = 4 * 1024 * 1024;
    while (ReadFile(h, chunk, sizeof(chunk), &got, nullptr) && got > 0) {
        buf.append(chunk, got);
        if (buf.size() >= kMaxSkipFileBytes) break;
    }
    CloseHandle(h);
    std::lock_guard<std::mutex> lock(g_schemaSkipMutex);
    size_t pos = 0;
    bool sawDuplicate = false;
    while (pos < buf.size()) {
        size_t nl = buf.find('\n', pos);
        std::string line = buf.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        // Lines are "appId,epoch"; tolerate a bare "appId" (epoch=0 -> retry soon).
        size_t comma = line.find(',');
        try {
            uint32_t id = (uint32_t)std::stoul(line.substr(0, comma));
            uint64_t ts = (comma == std::string::npos) ? 0 : std::stoull(line.substr(comma + 1));
            if (id) {
                if (!g_schemaSkip.emplace(id, ts).second) { g_schemaSkip[id] = ts; sawDuplicate = true; }
            }
        } catch (...) {}
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    // Compact away accumulated append-duplicates so the file can't grow forever.
    if (sawDuplicate) RewriteSchemaSkipFileLocked();
}

static bool IsSchemaSkipped(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_schemaSkipMutex);
    return g_schemaSkip.count(appId) != 0;
}

// True if a skip-listed app is due for a re-probe (skip-listed long enough ago).
static bool SchemaSkipDueForRetry(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_schemaSkipMutex);
    auto it = g_schemaSkip.find(appId);
    if (it == g_schemaSkip.end()) return true;
    return NowEpochSecs() >= it->second + kSchemaSkipRetrySecs;
}

// Skip-list an app. Compacted on next load (last line wins).
static void AddSchemaSkip(uint32_t appId) {
    uint64_t now = NowEpochSecs();
    {
        std::lock_guard<std::mutex> lock(g_schemaSkipMutex);
        g_schemaSkip[appId] = now;
    }
    HANDLE h = CreateFileA(SchemaSkipPath().c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, nullptr, FILE_END);
    std::string line = std::to_string(appId) + "," + std::to_string(now) + "\r\n";
    DWORD w = 0;
    WriteFile(h, line.data(), (DWORD)line.size(), &w, nullptr);
    CloseHandle(h);
}

// True if Store API confirms achievements (category 22). Fail-open on HTTP errors.
static bool AppSupportsAchievements(uint32_t appId) {
    {
        std::lock_guard<std::mutex> lock(g_schemaFetchMutex);
        auto it = g_achievementSupportCache.find(appId);
        if (it != g_achievementSupportCache.end()) return it->second;
    }

    wchar_t path[256];
    swprintf_s(path, L"/api/appdetails?appids=%u&filters=categories", appId);

    HINTERNET hSession = WinHttpOpen(L"CloudRedirect/2.2",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return true;  // fail-open
    WinHttpSetTimeouts(hSession, 2000, 2000, 3000, 3000);

    HINTERNET hConn = WinHttpConnect(hSession, L"store.steampowered.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return true; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return true; }

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return true;  // fail-open
    }

    DWORD statusCode = 0, codeLen = sizeof(statusCode);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &codeLen, WINHTTP_NO_HEADER_INDEX);
    if (statusCode != 200) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return true;  // fail-open
    }

    std::string body;
    DWORD avail, got;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        if (body.size() + avail > 64 * 1024) break;
        size_t off = body.size();
        body.resize(off + avail);
        got = 0;
        WinHttpReadData(hReq, &body[off], avail, &got);
        body.resize(off + got);
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);

    // Look for "success":false (unlisted/removed apps)
    if (body.find("\"success\":false") != std::string::npos) {
        // Can't determine -- fail-open (might be region-locked but still have achievements)
        return true;
    }

    // Category 22 = "Steam Achievements". Search for "id":22 in the categories array.
    bool supports = (body.find("\"id\":22") != std::string::npos);
    {
        std::lock_guard<std::mutex> lock(g_schemaFetchMutex);
        g_achievementSupportCache[appId] = supports;
    }
    if (!supports) {
        LOG("[Schema] app %u: no achievement support (category 22 absent), skipping", appId);
    }
    return supports;
}

// Fetch review-owner SteamIDs from appreviews API. Must NOT run on the network thread.
static std::vector<uint64_t> FetchReviewOwnerIds(uint32_t appId) {
    std::vector<uint64_t> ids;
    wchar_t path[256];
    swprintf_s(path, L"/appreviews/%u?json=1&filter=recent&language=all"
               L"&purchase_type=all&num_per_page=20", appId);

    HINTERNET hSession = WinHttpOpen(L"CloudRedirect/2.2",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return ids;
    WinHttpSetTimeouts(hSession, 3000, 3000, 5000, 5000);

    HINTERNET hConn = WinHttpConnect(hSession, L"store.steampowered.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return ids; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return ids; }

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return ids;
    }

    DWORD statusCode = 0, codeLen = sizeof(statusCode);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &codeLen, WINHTTP_NO_HEADER_INDEX);
    if (statusCode != 200) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return ids;
    }

    std::string body;
    DWORD avail, got;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        if (body.size() + avail > 256 * 1024) break;
        size_t off = body.size();
        body.resize(off + avail);
        got = 0;
        WinHttpReadData(hReq, &body[off], avail, &got);
        body.resize(off + got);
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);

    // Parse "steamid":"<digits>" from the JSON response
    constexpr uint64_t kSteamId64Base = 76561197960265728ull;
    size_t pos = 0;
    while ((pos = body.find("\"steamid\"", pos)) != std::string::npos) {
        pos = body.find(':', pos);
        if (pos == std::string::npos) break;
        ++pos;
        while (pos < body.size() && (body[pos] == ' ' || body[pos] == '"')) ++pos;
        size_t start = pos;
        while (pos < body.size() && body[pos] >= '0' && body[pos] <= '9') ++pos;
        if (start == pos) continue;
        uint64_t sid = strtoull(body.c_str() + start, nullptr, 10);
        if (sid >= kSteamId64Base) {
            bool dup = false;
            for (uint64_t existing : ids) if (existing == sid) { dup = true; break; }
            if (!dup) ids.push_back(sid);
        }
    }
    return ids;
}

// Check if a SteamID has public stats for an app (community XML endpoint).
static bool HasPublicStats(uint32_t appId, uint64_t steamId) {
    wchar_t path[256];
    swprintf_s(path, L"/profiles/%llu/stats/%u/?xml=1",
               (unsigned long long)steamId, appId);

    HINTERNET hSession = WinHttpOpen(L"CloudRedirect/2.2",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    WinHttpSetTimeouts(hSession, 2000, 2000, 3000, 3000);

    HINTERNET hConn = WinHttpConnect(hSession, L"steamcommunity.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return false; }

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return false;
    }

    // Read just enough to check for public stats markers
    std::string body;
    DWORD avail, got;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        if (body.size() + avail > 32 * 1024) break;
        size_t off = body.size();
        body.resize(off + avail);
        got = 0;
        WinHttpReadData(hReq, &body[off], avail, &got);
        body.resize(off + got);
    }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);

    return body.find("<playerstats>") != std::string::npos &&
           body.find("<privacyState>public</privacyState>") != std::string::npos;
}



// Build and send one CMsgClientGetUserStats for (appId, ownerId). Returns false
// if injection primitives aren't ready or send failed to dispatch.
static bool SendSchemaRequest(uint32_t appId, uint64_t ownerId, uint32_t connHandle) {
    if (!g_pbMsgCtor || !g_pbMsgFinalize || !g_pbMsgCleanup ||
        !g_getUserStatsDesc || !g_getUserStatsVtbl || !g_parseFromArray)
        return false;

    // Replicate CProtoBufMsg<CMsgClientGetUserStats> construction (sub_138A44F70).
    // Typed vftable mandatory: base vftable -> malformed wire -> crash.
    alignas(16) uint8_t msg[128] = {0};
    g_pbMsgCtor(msg, (int)EMSG_CLIENT_GET_USER_STATS, 0);     // base ctor: emsg=818
    *(void**)(msg + 0) = g_getUserStatsVtbl;                  // install typed vftable
    *(void**)(msg + CPROTOBUFMSG_OFF_DESC) = g_getUserStatsDesc; // typed-body descriptor
    g_pbMsgFinalize(msg);                                      // allocate body at +0x30

    void* body = *(void**)(msg + CPROTOBUFMSG_OFF_BODY);
    if (!body) { g_pbMsgCleanup(msg); return false; }

    // Header requirements:
    //  1. +192 = -1 (expiry sentinel): 0 asserts at msgprotobuf.cpp:980 -> crash.
    //  2. Session fields (steamid, sessionid, realm, jobid_source): CM drops without.
    // Offsets: +104 steamid, +112 sessionid, +156 realm, +208 jobid_source
    static std::atomic<uint64_t> s_jobIdCounter{0x5C00000000000001ull};
    if (void* hdr = *(void**)(msg + 0x28)) {
        uint8_t* h = (uint8_t*)hdr;
        *(int32_t*)(h + 192) = -1;                         // expiry = -1 (no deadline)
        *(uint32_t*)(h + 16) &= ~0x4000000u;               // clear "no reply expected"
        if (g_hdrCaptured.load(std::memory_order_relaxed)) {
            uint64_t jobId = s_jobIdCounter.fetch_add(1, std::memory_order_relaxed);
            *(uint64_t*)(h + 104) = g_hdrSteamId.load(std::memory_order_relaxed);  // steamid
            *(uint32_t*)(h + 112) = g_hdrSessionId.load(std::memory_order_relaxed);// client_sessionid
            *(uint32_t*)(h + 156) = g_hdrRealm.load(std::memory_order_relaxed);    // realm
            *(uint64_t*)(h + 208) = jobId;                 // jobid_source (unique)
            *(uint32_t*)(h + 16) |= (0x40u | 0x80u | 0x8000000u | 0x80000000u);    // presence bits
        }
    }

    // Build CMsgClientGetUserStats body:
    //   game_id#1 fixed64, crc_stats#2 varint, schema_local_version#3 int32(-1), steam_id_for_user#4 fixed64
    PB::Writer w;
    w.WriteFixed64(1, (uint64_t)appId);          // game_id (low 24 bits = appid)
    w.WriteVarint(2, 0);                          // crc_stats = 0
    // schema_local_version = -1: must be sign-extended 64-bit varint (not 0xFFFFFFFF).
    w.WriteVarint(3, (uint64_t)(int64_t)(-1));    // schema_local_version = -1 (send latest)
    w.WriteFixed64(4, ownerId);                   // steam_id_for_user = owner

    bool ok = ParseBytesToBody(body, w.Data().data(), w.Size());
    if (!ok) { g_pbMsgCleanup(msg); return false; }

    *(uint32_t*)(msg + CPROTOBUFMSG_OFF_CONN) = connHandle;

    // The 819 response is correlated by game_id (appid); see TryHandleSchemaResponse.
    auto basend = reinterpret_cast<BAsyncSendFn>(g_basOriginal);
    uint8_t sent = basend ? basend(msg, connHandle) : 0;

    g_pbMsgCleanup(msg);
    return sent != 0;
}

// Handle incoming 819 for our schema requests. Correlated by game_id (appid).
// Writes UserGameStatsSchema_<appId>.bin + per-user stats template if schema present.
static bool TryHandleSchemaResponse(const uint8_t* data, uint32_t size) {
    PacketView p;
    if (!ParsePacket(data, size, p)) return false;

    // Match the response to an app we asked about via game_id (field 1, fixed64).
    auto bodyFields = PB::Parse(p.bodyData, p.bodyLen);
    const PB::Field* gameIdF = PB::FindField(bodyFields, 1);
    if (!gameIdF) return false;
    uint32_t appId = (uint32_t)(gameIdF->varintVal & 0xFFFFFF);
    if (appId == 0) return false;

    {
        std::lock_guard<std::mutex> lock(g_schemaFetchMutex);
        if (g_schemaFetchAttempted.find(appId) == g_schemaFetchAttempted.end())
            return false;   // not an app we asked about
    }

    // Body = CMsgClientGetUserStatsResponse: eresult#2 int32, schema#4 bytes.
    int32_t eresult = 2;
    if (auto* er = PB::FindField(bodyFields, 2)) eresult = (int32_t)er->varintVal;
    const PB::Field* schemaF = PB::FindField(bodyFields, 4);

    bool hasSchema = (eresult == 1 && schemaF &&
                      schemaF->wireType == PB::LengthDelimited && schemaF->dataLen > 0);
    if (!hasSchema) {
        // All queued owners exhausted without schema -> skip-list the app.
        bool exhausted = false;
        {
            std::lock_guard<std::mutex> lock(g_schemaFetchMutex);
            auto it = g_schemaFetchStates.find(appId);
            if (it != g_schemaFetchStates.end() && !it->second.resolved) {
                if (it->second.responsesReceived < it->second.requestsSent)
                    it->second.responsesReceived++;
                // Mark resolved to prevent late-duplicate 819 re-skip-listing.
                exhausted = it->second.requestsSent > 0 &&
                            it->second.responsesReceived >= it->second.requestsSent;
                if (exhausted) it->second.resolved = true;
            }
        }
        if (exhausted) AddSchemaSkip(appId);
        return true;
    }

    std::string schemaPath = g_steamPath + "appcache\\stats\\UserGameStatsSchema_"
        + std::to_string(appId) + ".bin";
    // Skip if same size on disk; overwrite if size changed.
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(schemaPath.c_str(), GetFileExInfoStandard, &fad)) {
        if (fad.nFileSizeLow == schemaF->dataLen && fad.nFileSizeHigh == 0) return true;
        LOG("[Schema] app %u: schema changed (%u -> %u bytes), updating",
            appId, fad.nFileSizeLow, schemaF->dataLen);
    }

    HANDLE h = CreateFileA(schemaPath.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(h, schemaF->data, schemaF->dataLen, &written, nullptr);
        CloseHandle(h);
        LOG("[Schema] app %u: wrote schema (%u bytes) from server response",
            appId, schemaF->dataLen);
        // Mark resolved so the exhaustion path can't skip-list this app.
        {
            std::lock_guard<std::mutex> lock(g_schemaFetchMutex);
            auto it = g_schemaFetchStates.find(appId);
            if (it != g_schemaFetchStates.end()) it->second.resolved = true;
        }
        // Evict stale skip entry now that schema is present.
        {
            std::lock_guard<std::mutex> lock(g_schemaSkipMutex);
            if (g_schemaSkip.erase(appId)) RewriteSchemaSkipFileLocked();
        }


        // Per-user stats file needed for Steam to load stats (create if absent).
        uint32_t acctId = GetAccountId();
        if (acctId != 0) {
            static const uint8_t kUserStatsTemplate[38] = {
                0x00,0x63,0x61,0x63,0x68,0x65,0x00,0x02,0x63,0x72,0x63,0x00,0x00,0x00,
                0x00,0x00,0x02,0x50,0x65,0x6e,0x64,0x69,0x6e,0x67,0x43,0x68,0x61,0x6e,
                0x67,0x65,0x73,0x00,0x00,0x00,0x00,0x00,0x08,0x08
            };
            std::string statsPath = g_steamPath + "appcache\\stats\\UserGameStats_"
                + std::to_string(acctId) + "_" + std::to_string(appId) + ".bin";
            if (GetFileAttributesA(statsPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                HANDLE hs = CreateFileA(statsPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hs != INVALID_HANDLE_VALUE) {
                    DWORD w2 = 0;
                    WriteFile(hs, kUserStatsTemplate, sizeof(kUserStatsTemplate), &w2, nullptr);
                    CloseHandle(hs);
                    LOG("[Schema] app %u: wrote per-user stats template (acct %u)", appId, acctId);
                }
            }
        }
    } else {
        LOG("[Schema] app %u: failed to open %s for write (err=%u)",
            appId, schemaPath.c_str(), GetLastError());
    }
    return true;
}

// Fetch one app's schema. Background thread only (HTTP). Sends queued for net thread.
void RequestSchemaForApp(uint32_t appId, bool forceRefresh) {
#if !SCHEMA_FETCH_ENABLED
    (void)appId; (void)forceRefresh; return;
#endif
    if (!MetadataSync::SchemaFetchEnabled()) return;
    if (appId == 0) return;
    if (g_shuttingDown.load(std::memory_order_acquire)) return;
    if (g_liveConnHandle.load(std::memory_order_relaxed) == 0) return;

    {
        std::lock_guard<std::mutex> lock(g_schemaFetchMutex);
        if (!g_schemaFetchAttempted.insert(appId).second) return;  // once per session per app
    }

    std::string schemaPath = g_steamPath + "appcache\\stats\\UserGameStatsSchema_"
        + std::to_string(appId) + ".bin";
    if (!forceRefresh) {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        bool gotAttr = GetFileAttributesExA(schemaPath.c_str(), GetFileExInfoStandard, &fad);
        uint64_t fsize = gotAttr ? ((uint64_t)fad.nFileSizeHigh << 32 | fad.nFileSizeLow) : 0;
        if (gotAttr && fsize > 0) {
            LOG("[Schema] RequestSchemaForApp %u: already on disk (%llu bytes), skipping",
                appId, (unsigned long long)fsize);
            return;
        }
        LOG("[Schema] RequestSchemaForApp %u: needs fetch (exists=%d size=%llu)",
            appId, (int)gotAttr, (unsigned long long)fsize);
    }

    // NOTE: the Store API category-22 check was removed because newly released
    // games can have achievements before Steam updates the store metadata.

    // Phase 1: discover owners from recent reviews + verify public stats
    std::vector<uint64_t> owners = FetchReviewOwnerIds(appId);
    std::vector<uint64_t> verified;
    for (uint64_t sid : owners) {
        if (g_shuttingDown.load(std::memory_order_acquire)) return;
        if (HasPublicStats(appId, sid)) {
            verified.push_back(sid);
            if (verified.size() >= 3) break;  // 3 verified owners is plenty
        }
    }

    // Phase 2: if review discovery found nothing, append fallback owners
    bool usingFallback = verified.empty();
    if (usingFallback) {
        for (uint64_t id : kFallbackOwnerIds)
            verified.push_back(id);
    }

    if (verified.empty()) return;

    // Store fetch state for response tracking
    {
        std::lock_guard<std::mutex> lock(g_schemaFetchMutex);
        auto& state = g_schemaFetchStates[appId];
        state.owners = verified;
        state.nextOwnerIdx = 0;
        state.requestsSent = (uint32_t)verified.size();
        state.responsesReceived = 0;
    }

    // Cap queue at 256 to avoid saturating the shared CM conn.
    constexpr size_t kSchemaSendQueueMax = 256;
    {
        std::lock_guard<std::mutex> lock(g_schemaSendMutex);
        for (uint64_t owner : verified) {
            if (g_schemaSendQueue.size() >= kSchemaSendQueueMax) break;
            g_schemaSendQueue.push({appId, owner});
        }
    }
    LOG("[Schema] app %u: queued %zu request(s) via %s",
        appId, verified.size(), usingFallback ? "fallback" : "review-owner discovery");
}

// One-time proactive sweep: request schemas for namespace apps missing on disk.
// Fired once a live CM connection handle is captured.
static std::atomic<bool> g_schemaSweepDone{false};
static void SweepNamespaceSchemas() {
#if !SCHEMA_FETCH_ENABLED
    return;                                             // kill-switch: see SCHEMA_FETCH_ENABLED
#endif
    if (g_schemaSweepDone.exchange(true)) return;       // once per session
    if (g_liveConnHandle.load(std::memory_order_relaxed) == 0) {
        g_schemaSweepDone.store(false);                 // retry on a later call
        return;
    }

    std::vector<uint32_t> apps;
    {
        std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
        apps.assign(g_namespaceApps.begin(), g_namespaceApps.end());
    }
    if (apps.empty()) return;

    LOG("[Schema] Proactive sweep: checking %zu namespace app(s) for missing schemas", apps.size());

    // Runs on caller's thread so shutdown can join.
    LoadSchemaSkipList();
    std::vector<uint32_t> needed;
    for (uint32_t appId : apps) {
        std::string schemaPath = g_steamPath + "appcache\\stats\\UserGameStatsSchema_"
            + std::to_string(appId) + ".bin";
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        bool gotAttr = GetFileAttributesExA(schemaPath.c_str(), GetFileExInfoStandard, &fad);
        uint64_t fsize = gotAttr ? ((uint64_t)fad.nFileSizeHigh << 32 | fad.nFileSizeLow) : 0;
        if (gotAttr && fsize > 0) {
            LOG("[Schema] Sweep: app %u schema present (%llu bytes), skipping",
                appId, (unsigned long long)fsize);
            continue;
        }
        // Skip known schema-less apps; re-probe on cooldown expiry.
        if (IsSchemaSkipped(appId) && !SchemaSkipDueForRetry(appId)) continue;
        LOG("[Schema] Sweep: app %u schema missing/empty (exists=%d size=%llu)",
            appId, (int)gotAttr, (unsigned long long)fsize);
        needed.push_back(appId);
    }
    if (needed.empty()) {
        LOG("[Schema] Proactive sweep: all schemas present on disk");
        return;
    }
    LOG("[Schema] Proactive sweep: %zu app(s) need schemas, fetching with %d workers",
        needed.size(), 4);

    // Fan out across worker threads (I/O-bound HTTP per app).
    constexpr int kWorkers = 4;
    std::atomic<size_t> idx{0};
    std::atomic<int> totalRequested{0};
    std::vector<std::thread> workers;
    for (int w = 0; w < kWorkers; ++w) {
        workers.emplace_back([&needed, &idx, &totalRequested] {
            while (true) {
                if (g_shuttingDown.load(std::memory_order_acquire)) break;
                size_t i = idx.fetch_add(1, std::memory_order_relaxed);
                if (i >= needed.size()) break;
                RequestSchemaForApp(needed[i]);
                totalRequested.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& t : workers) t.join();
    LOG("[Schema] Proactive sweep complete: enqueued schemas for %d app(s)",
        totalRequested.load(std::memory_order_relaxed));
}

void InstallGamesPlayedHook() {
    if (!HasNamespaceApps()) return;
    // Always install: playtime tracking + non-Steam-game spoof (gated per-call).

    HMODULE hSteamClient = GetModuleHandleA("steamclient64.dll");
    if (!hSteamClient) {
        LOG("[GamesPlayed] steamclient64.dll not loaded");
        return;
    }

    uintptr_t basAddr = SC_RESOLVE(bAsyncSend);
    if (!basAddr) {
        LOG("[GamesPlayed] BAsyncSend not resolved -- skipping hook");
        return;
    }
    g_basOrigAddr = reinterpret_cast<uint8_t*>(basAddr);

    LOG("[GamesPlayed] BAsyncSend at %p", g_basOrigAddr);

    // Verify prologue matches expected bytes
    static const uint8_t expectedPrologue[SC_BAS_STOLEN_BYTES] = {
        0x48, 0x89, 0x5C, 0x24, 0x10,   // mov [rsp+10h], rbx
        0x48, 0x89, 0x74, 0x24, 0x18,   // mov [rsp+18h], rsi
        0x57,                             // push rdi
        0x48, 0x83, 0xEC, 0x50           // sub rsp, 50h
    };

    if (memcmp(g_basOrigAddr, expectedPrologue, SC_BAS_STOLEN_BYTES) != 0) {
        LOG("[GamesPlayed] Prologue mismatch at BAsyncSend -- skipping hook");
        g_basOrigAddr = nullptr;
        return;
    }

    // Build trampoline: stolen bytes + jmp back to original+15
    DWORD oldTrampolineProt;
    VirtualProtect(g_basTrampoline, sizeof(g_basTrampoline), PAGE_EXECUTE_READWRITE, &oldTrampolineProt);

    memcpy(g_basTrampoline, g_basOrigAddr, SC_BAS_STOLEN_BYTES);
    uint8_t* jumpBack = g_basTrampoline + SC_BAS_STOLEN_BYTES;
    // jmp [rip+0]; <8-byte addr>
    jumpBack[0] = 0xFF;
    jumpBack[1] = 0x25;
    jumpBack[2] = 0x00;
    jumpBack[3] = 0x00;
    jumpBack[4] = 0x00;
    jumpBack[5] = 0x00;
    uintptr_t returnAddr = reinterpret_cast<uintptr_t>(g_basOrigAddr) + SC_BAS_STOLEN_BYTES;
    memcpy(jumpBack + 6, &returnAddr, 8);

    g_basOriginal = reinterpret_cast<BAsyncSendFn>(reinterpret_cast<uintptr_t>(g_basTrampoline));

    // Patch original function with jmp to our hook
    DWORD oldProt;
    if (!VirtualProtect(g_basOrigAddr, SC_BAS_STOLEN_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) {
        LOG("[GamesPlayed] VirtualProtect failed (%u)", GetLastError());
        g_basOrigAddr = nullptr;
        return;
    }

    // Build detour: jmp [rip+0]; <8-byte hookAddr>; nop (15 bytes = 14+1)
    uint8_t detour[SC_BAS_STOLEN_BYTES];
    detour[0] = 0xFF;
    detour[1] = 0x25;
    detour[2] = 0x00;
    detour[3] = 0x00;
    detour[4] = 0x00;
    detour[5] = 0x00;
    uintptr_t hookAddr = reinterpret_cast<uintptr_t>(&BAsyncSendHook);
    memcpy(detour + 6, &hookAddr, 8);
    detour[14] = 0x90; // nop for the 15th byte
    memcpy(g_basOrigAddr, detour, SC_BAS_STOLEN_BYTES);

    FlushInstructionCache(GetCurrentProcess(), g_basOrigAddr, SC_BAS_STOLEN_BYTES);
    VirtualProtect(g_basOrigAddr, SC_BAS_STOLEN_BYTES, oldProt, &oldProt);

    LOG("[GamesPlayed] Inline detour installed at %p -> BAsyncSendHook %p",
        g_basOrigAddr, (void*)hookAddr);
}

void SetSendPktAddr(void* recvPktGlobalAddr) {
    if (!recvPktGlobalAddr) {
        LOG("[NS] SetSendPktAddr: recvPktGlobalAddr is null");
        return;
    }

    g_payloadBase = (uintptr_t)recvPktGlobalAddr - RVA_RECV_PKT_GLOBAL;
    LOG("[NS] payload_base=%p", (void*)g_payloadBase);
}

// ── GamesPlayed rewriting ──────────────────────────────────────────────
// Inject game_extra_info so friends see namespace app titles.

static std::mutex g_gameNameCacheMtx;
static std::unordered_map<uint32_t, std::string> g_gameNameCache;

static const std::string& LookupGameName(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_gameNameCacheMtx);
    auto it = g_gameNameCache.find(appId);
    if (it != g_gameNameCache.end()) return it->second;

    std::string name = AutoCloudScan::GetAppName(g_steamPath, appId);
    if (name.empty())
        name = "App " + std::to_string(appId);
    auto [ins, _] = g_gameNameCache.emplace(appId, std::move(name));
    return ins->second;
}

// Inject game_extra_info for namespace apps. Returns empty if no changes needed.
static std::vector<uint8_t> RewriteGamesPlayed(const uint8_t* body, uint32_t bodyLen) {
    auto outerFields = PB::Parse(body, bodyLen);
    bool needsRewrite = false;

    // First pass: check if any entry needs rewriting
    for (const auto& f : outerFields) {
        if (f.fieldNum != GP_FIELD_GAMES_PLAYED || f.wireType != PB::LengthDelimited)
            continue;
        auto inner = PB::Parse(f.data, f.dataLen);
        // Extract game_id (fixed64, field 2)
        const auto* gameIdField = PB::FindField(inner, GP_FIELD_GAME_ID);
        if (!gameIdField) continue;
        uint32_t appId = (uint32_t)(gameIdField->varintVal & 0x00FFFFFF); // low 24 bits = appId in CGameID
        if (appId == 0) continue;
        if (!IsNamespaceApp(appId)) continue;
        if (IsPrivateApp(appId)) continue;  // respect "mark as private"
        auto existing = PB::GetString(inner, GP_FIELD_GAME_EXTRA_INFO);
        if (!existing.empty()) continue;
        needsRewrite = true;
        break;
    }

    if (!needsRewrite) return {};

    // Second pass: rebuild body with game_extra_info injected
    PB::Writer newBody;
    for (const auto& f : outerFields) {
        if (f.fieldNum != GP_FIELD_GAMES_PLAYED || f.wireType != PB::LengthDelimited) {
            if (f.wireType == PB::Varint)
                newBody.WriteVarint(f.fieldNum, f.varintVal);
            else if (f.wireType == PB::Fixed64)
                newBody.WriteFixed64(f.fieldNum, f.varintVal);
            else if (f.wireType == PB::LengthDelimited)
                newBody.WriteBytes(f.fieldNum, f.data, f.dataLen);
            else if (f.wireType == PB::Fixed32)
                newBody.WriteFixed32(f.fieldNum, (uint32_t)f.varintVal);
            continue;
        }

        auto inner = PB::Parse(f.data, f.dataLen);
        const auto* gameIdField = PB::FindField(inner, GP_FIELD_GAME_ID);
        uint32_t appId = gameIdField ? (uint32_t)(gameIdField->varintVal & 0x00FFFFFF) : 0;
        bool isNs = appId > 0 && IsNamespaceApp(appId);
        auto existingInfo = PB::GetString(inner, GP_FIELD_GAME_EXTRA_INFO);

        if (isNs && existingInfo.empty() && !IsPrivateApp(appId)) {
            // Rebuild as non-Steam shortcut (CGameID type=2). Privacy enforced by
            // IsPrivateApp() since friends server has no per-shortcut privacy.
            const std::string& name = LookupGameName(appId);

            // Build a shortcut-style CGameID: type=2, appId=0, modId=hash
            // CGameID layout: bits 0-23 = appId, bits 24-31 = type, bits 32-63 = modId
            // Hash the game name to produce a stable modId (like Steam does for shortcuts)
            uint32_t modId = 0;
            for (char c : name) modId = modId * 31 + (uint8_t)c;
            modId |= 0x80000000; // set high bit like Steam shortcut hashes
            uint64_t shortcutGameId = ((uint64_t)modId << 32) | (2ULL << 24); // type=2, appId=0

            PB::Writer sub;
            for (const auto& sf : inner) {
                if (sf.fieldNum == GP_FIELD_GAME_ID) continue;         // replace with shortcut
                if (sf.fieldNum == GP_FIELD_GAME_EXTRA_INFO) continue; // replace with title
                if (sf.fieldNum == GP_FIELD_OWNER_ID) continue;        // clear
                if (sf.wireType == PB::Varint)
                    sub.WriteVarint(sf.fieldNum, sf.varintVal);
                else if (sf.wireType == PB::Fixed64)
                    sub.WriteFixed64(sf.fieldNum, sf.varintVal);
                else if (sf.wireType == PB::LengthDelimited)
                    sub.WriteBytes(sf.fieldNum, sf.data, sf.dataLen);
                else if (sf.wireType == PB::Fixed32)
                    sub.WriteFixed32(sf.fieldNum, (uint32_t)sf.varintVal);
            }
            sub.WriteFixed64(GP_FIELD_GAME_ID, shortcutGameId);
            sub.WriteString(GP_FIELD_GAME_EXTRA_INFO, name);
            sub.WriteVarint(GP_FIELD_OWNER_ID, 0);
            newBody.WriteSubmessage(GP_FIELD_GAMES_PLAYED, sub);
            LOG("[GamesPlayed] Injected game_extra_info for app %u: \"%s\"", appId, name.c_str());
        } else {
            if (isNs && existingInfo.empty() && IsPrivateApp(appId))
                LOG("[GamesPlayed] App %u is marked private -- not injecting (respecting privacy)", appId);
            newBody.WriteBytes(f.fieldNum, f.data, f.dataLen);
        }
    }

    return {newBody.Data().begin(), newBody.Data().end()};
}

// OnSendPkt — vtable hook handles namespace Cloud RPCs; this is the fallback path.
bool OnSendPkt(void* thisptr, const uint8_t* data, uint32_t size) {

    if (!g_cloudRedirectEnabled.load(std::memory_order_relaxed)) return false;
    if (g_proxySending) return false;
    if (g_shuttingDown.load(std::memory_order_acquire)) return false;

    // Drain queues on outbound too: inbound alone can't keep up during idle stalls.
    DrainInjectQueueOnNetThread();
    DrainSchemaQueueOnNetThread();   // schema sends must run on the net thread
    DrainPlaytimeUpdateQueueOnNetThread(); // live playtime push (touches CUser map)

    // Discover CCMInterface + install vtable hook if not yet found.
    TryFindCCMInterface();

    PacketView pkt;
    if (!ParsePacket(data, size, pkt)) return false;

    if (pkt.emsg != EMSG_SERVICE_METHOD) return false;

    auto methodSv = PB::GetString(pkt.header, HDR_TARGET_JOB_NAME);
    if (methodSv.empty()) return false;

    // Fast early-out: only care about Cloud.* methods (zero-alloc via string_view)
    bool isCloudMethod = (methodSv.size() >= 6 && methodSv.substr(0, 6) == "Cloud.");

    uint64_t jobSrc = GetJobIdSource(pkt.header);

    // Capture SteamID + session from packet header. Detects account switches.
    {
        auto* sidField = PB::FindField(pkt.header, HDR_STEAMID);
        if (sidField) {
            uint64_t newSid = sidField->varintVal;
            uint64_t prevSid = g_steamId.exchange(newSid);
            bool firstCapture = !g_steamIdFromHeader.exchange(true);
            bool switched = !firstCapture && prevSid != 0 && prevSid != newSid;
            if (firstCapture || switched) {
                LOG("[NS] Captured SteamID: %llu (accountId=%u)%s", newSid, GetAccountId(),
                    switched ? " [ACCOUNT SWITCH]" : "");
                HttpServer::SetAccountId(GetAccountId());
                ScheduleStartupMetadataSync();
            }
        }
        if (g_sessionId.load() == 0) {
            auto* sessField = PB::FindField(pkt.header, HDR_SESSIONID);
            if (sessField) {
                g_sessionId.store((int32_t)sessField->varintVal);
            }
        }
    }

    // With slots 4+5 hooked, namespace Cloud RPCs should not reach SendPkt;
    // log and fall through to Approach D as a safety net if they do.
    // Notifications (ExitSyncDone, ConflictResolution) are suppressed by slots
    // 7/8 for namespace apps, so they should not reach here either.
    static std::atomic<int> g_approachDFallbackCount{0};
    if (g_vtableHookInstalled.load(std::memory_order_acquire)) {
        if (isCloudMethod) {
            auto innerFields = PB::Parse(pkt.bodyData, pkt.bodyLen);
            // Need null-terminated string for CloudRpcUtils::ExtractAppId and LOG
            std::string method(methodSv);
            uint32_t appId = CloudRpcUtils::ExtractAppId(method.c_str(), innerFields);

            // Check if this is a namespace app that needs local handling
            bool isNs = IsNamespaceApp(appId);

            if (isNs) {
                bool isPassthroughNotif = (method == RPC_EXIT_SYNC || method == RPC_CONFLICT);
                if (!isPassthroughNotif) {
                    int count = ++g_approachDFallbackCount;
                    LOG("[SendPkt] WARNING: %s app=%u (%u bytes) escaped vtable hooks! "
                        "Using Approach D fallback (occurrence #%d)",
                        method.c_str(), appId, pkt.bodyLen, count);
                }
            } else {
                if (appId != 2371090)
                    LOG("[SendPkt] %s app=%u (%u bytes) -- vtable hook active, passing through",
                        method.c_str(), appId, pkt.bodyLen);
                return false;
            }
        } else {
            return false;  // non-Cloud RPC, let it through
        }
    }

    // Approach D: handle namespace Cloud RPCs locally
    // This path is only reached when vtable hooks are not active, or a namespace RPC escaped.
    // Non-Cloud RPCs: early-out before allocating std::string
    if (!isCloudMethod) return false;

    // Constructing std::string here is acceptable since this is a rare fallback path.
    std::string method(methodSv);

    // log SyncStats (never intercepted)
    if (method == RPC_SYNC_STATS) {
        LOG("[SyncStats] body (%u bytes):", pkt.bodyLen);
#ifdef DEBUG_VERBOSE_LOGGING
        SpyLogFields("[SyncStats]", pkt.bodyData, pkt.bodyLen);
#endif
        return false;
    }

    // log transfer reports (never intercepted)
    if (method == RPC_TRANSFER_REPORT) {
        LOG("[TransferReport] body (%u bytes):", pkt.bodyLen);
#ifdef DEBUG_VERBOSE_LOGGING
        SpyLogFields("[TransferReport]", pkt.bodyData, pkt.bodyLen);
#endif
        return false;
    }

    // ExitSyncDone is a notification (no response expected)
    if (method == RPC_EXIT_SYNC) {
        LOG("[NS] ExitSyncDone notification");
#ifdef DEBUG_VERBOSE_LOGGING
        SpyLogFields("[ExitSync]", pkt.bodyData, pkt.bodyLen);
#endif
        return false;
    }

    // ConflictResolution is a notification (no response expected)
    if (method == RPC_CONFLICT) {
        auto conflictFields = PB::Parse(pkt.bodyData, pkt.bodyLen);
        uint32_t conflictAppId = CloudRpcUtils::ExtractAppId(method.c_str(), conflictFields);
        bool choseLocal = false;
        if (auto* f = PB::FindField(conflictFields, 2)) choseLocal = f->varintVal != 0;
        if (conflictAppId && IsNamespaceApp(conflictAppId))
            RecordConflictResolution(conflictAppId, choseLocal);
        LOG("[NS] ConflictResolution notification app=%u choseLocal=%d", conflictAppId, choseLocal);
#ifdef DEBUG_VERBOSE_LOGGING
        SpyLogFields("[Conflict]", pkt.bodyData, pkt.bodyLen);
#endif
        return false;
    }

    auto innerFields = PB::Parse(pkt.bodyData, pkt.bodyLen);
    uint32_t appId = CloudRpcUtils::ExtractAppId(method.c_str(), innerFields);
    if (appId == 0) return false;

    // check if this is a Cloud RPC we handle
    bool isCloudRpc = (method == RPC_GET_CHANGELIST || method == RPC_BEGIN_BATCH ||
                       method == RPC_BEGIN_UPLOAD || method == RPC_COMMIT_UPLOAD ||
                       method == RPC_FILE_DOWNLOAD || method == RPC_DELETE_FILE ||
                       method == RPC_COMPLETE_BATCH || method == RPC_QUOTA_USAGE ||
                       method == RPC_LAUNCH_INTENT || method == RPC_SUSPEND_SESSION ||
                       method == RPC_RESUME_SESSION);
    if (!isCloudRpc) return false;

    // detect namespace app: either direct appid match, or SteamTools rewrote to proxy
    uint32_t realAppId = 0;
    bool isNamespace = false;

    if (IsNamespaceApp(appId)) {
        realAppId = appId;
        isNamespace = true;
    }

    if (!isNamespace) {
        // not a namespace app - log and pass through
        if (method.find("Cloud.") != std::string::npos) {
            LOG("[PassThru] %s app=%u (%u bytes)", method.c_str(), appId, pkt.bodyLen);
        }
        return false;
    }

    // NAMESPACE APP: handle locally, fabricate response (Approach D fallback)
    LOG("[NS-D] INTERCEPT %s app=%u (%u bytes):", method.c_str(), appId, pkt.bodyLen);
#ifdef DEBUG_VERBOSE_LOGGING
    SpyLogFields("[NS-REQ]", pkt.bodyData, pkt.bodyLen);
#endif

    auto dispatched = DispatchCloudRpc(method.c_str(), realAppId, innerFields);
    if (!dispatched.has_value()) {
        LOG("[NS-D] Unhandled method %s, passing through", method.c_str());
        return false;
    }
    auto& result = *dispatched;

    // inject fabricated response via queue (old Approach D)
    if (!InjectResponse(jobSrc, method, result.eresult, result.body)) {
        LOG("[NS-D] Failed to inject response for %s, falling through", method.c_str());
        return false;
    }

    return true;
}

// Bounded join used at shutdown so a wedged worker can't keep Steam alive.
// Timeout detaches; the OS reaps at process exit.
static bool JoinThreadWithTimeout(std::thread& t, DWORD timeoutMs, const char* name) {
    if (!t.joinable()) return true;
    HANDLE h = static_cast<HANDLE>(t.native_handle());
    DWORD wait = WaitForSingleObject(h, timeoutMs);
    if (wait == WAIT_OBJECT_0) {
        t.join();
        return true;
    }
    LOG("Shutdown: %s did not finish within %u ms (wait=%u) -- detaching to unblock shutdown",
        name, timeoutMs, wait);
    t.detach();
    return false;
}

// IAT rewrite of every module's kernel32!ExitProcess slot; wrapper runs
// cooperative Shutdown then chains the original.
using ExitProcessFn = VOID(WINAPI*)(UINT);
static ExitProcessFn g_originalExitProcess = nullptr;
static std::vector<void**> g_patchedExitProcessIatSlots;

static VOID WINAPI ExitProcessHook(UINT uExitCode) {
    // Re-entry guard: Shutdown() invoking ExitProcess on this thread would
    // recurse into call_once and hang.
    static thread_local bool tls_inShutdown = false;
    if (tls_inShutdown) {
        LOG("ExitProcessHook: re-entry on shutdown thread (code=%u) -- chaining original directly", uExitCode);
        if (g_originalExitProcess) g_originalExitProcess(uExitCode);
        TerminateProcess(GetCurrentProcess(), uExitCode);
        for (;;) Sleep(INFINITE);
    }
    tls_inShutdown = true;
    LOG("ExitProcessHook: caller invoked ExitProcess(%u) -- running cooperative Shutdown", uExitCode);
    Shutdown();
    if (g_originalExitProcess) {
        g_originalExitProcess(uExitCode);
    } else {
        TerminateProcess(GetCurrentProcess(), uExitCode);
    }
    for (;;) Sleep(INFINITE);
}

static bool PatchModuleExitProcessIat(HMODULE hMod, void* originalAddr, void* hookAddr) {
    if (!hMod) return false;
    auto base = reinterpret_cast<uint8_t*>(hMod);
    auto dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto ntHdr = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return false;
    auto& importDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return false;

    auto importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
    bool patchedAny = false;
    for (; importDesc->Name != 0; ++importDesc) {
        // Match by resolved address so api-ms-win-core-* forwarders count.
        auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + importDesc->FirstThunk);
        for (; thunk->u1.Function != 0; ++thunk) {
            if (reinterpret_cast<void*>(thunk->u1.Function) != originalAddr) continue;
            void** slot = reinterpret_cast<void**>(&thunk->u1.Function);
            DWORD oldProt;
            if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProt)) continue;
            *slot = hookAddr;
            VirtualProtect(slot, sizeof(void*), oldProt, &oldProt);
            g_patchedExitProcessIatSlots.push_back(slot);
            patchedAny = true;
        }
    }
    return patchedAny;
}

static void InstallExitProcessHook() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) {
        LOG("InstallExitProcessHook: kernel32.dll not loaded (impossible) -- skipping");
        return;
    }
    auto origAddr = reinterpret_cast<void*>(GetProcAddress(hKernel, "ExitProcess"));
    if (!origAddr) {
        LOG("InstallExitProcessHook: GetProcAddress(ExitProcess) returned NULL -- skipping");
        return;
    }
    g_originalExitProcess = reinterpret_cast<ExitProcessFn>(origAddr);
    void* hookAddr = reinterpret_cast<void*>(&ExitProcessHook);

    // Walk every loaded module and patch its ExitProcess IAT slot.
    HMODULE mods[1024];
    DWORD cbNeeded = 0;
    HANDLE hProc = GetCurrentProcess();
    if (!EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded)) {
        LOG("InstallExitProcessHook: EnumProcessModules failed (%u)", GetLastError());
        return;
    }
    DWORD modCount = cbNeeded / sizeof(HMODULE);
    if (modCount > 1024) modCount = 1024;
    int patchedModules = 0;
    for (DWORD i = 0; i < modCount; ++i) {
        // Skip kernel32 itself (its IAT entry, if any, would create a self-loop).
        if (mods[i] == hKernel) continue;
        if (PatchModuleExitProcessIat(mods[i], origAddr, hookAddr)) {
            ++patchedModules;
        }
    }
    LOG("InstallExitProcessHook: patched %d module IAT slot(s) for ExitProcess (orig=%p hook=%p)",
        patchedModules, origAddr, hookAddr);
}

void DrainPlaytimeUpdates() {
    DrainPlaytimeUpdateQueueOnNetThread();
}

// Shutdown entry points: ExitProcess IAT hook (production) and DllMain
// DLL_PROCESS_DETACH with reserved==NULL. once_flag makes it idempotent.
void Shutdown() {
    static std::once_flag s_shutdownOnce;
    std::call_once(s_shutdownOnce, [] {
        ShutdownImpl();
        // Close the log last so teardown errors reach disk.
        Log::Shutdown();
    });
}

static void ShutdownImpl() {
    g_shuttingDown.store(true);

    // Drain in-flight hook calls (HookGuard refcount) before restoring any
    // patched slot, including the recv-pkt slot which has its own install path.
    bool hookDrainTimedOut = false;
    {
        int spinCount = 0;
        while (g_hookRefCount.load(std::memory_order_acquire) > 0) {
            Sleep(1);
            if (++spinCount > 5000) { // 5 seconds max
                LOG("Shutdown: timed out waiting for %d in-flight hooks", g_hookRefCount.load());
                LOG("Shutdown: CRITICAL - cannot restore vtable with hooks in-flight, aborting restore");
                g_vtableHookInstalled.store(false, std::memory_order_release);
                hookDrainTimedOut = true;
                break;
            }
        }
    }

    // Flush stats/playtime to cloud (hooks drained, store is safe).
    StatsHandlers::Shutdown();

    // Restore vtable pointers; skip if steamclient64 unloaded or hook drain timed out.
    if (!hookDrainTimedOut && g_vtableHookInstalled.load(std::memory_order_acquire) && g_steamClientBase) {
        HMODULE currentSC = GetModuleHandleA("steamclient64.dll");
        if (!currentSC) {
            LOG("Shutdown: steamclient64.dll already unloaded, skipping vtable restore");
            g_vtableHookInstalled.store(false, std::memory_order_release);
            // steamclient gone: cached EAs point into unmapped memory; clear so a
            // subsequent re-init re-resolves against the new module image.
            g_serviceTransportVtableEa = 0;
            g_originalSlot4 = nullptr;
            g_originalSlot5 = nullptr;
            g_originalSlot7 = nullptr;
            g_originalSlot8 = nullptr;
            g_parseFromArray = nullptr;
            g_serializeToArray = nullptr;
            g_steamClientBase = 0;
        } else if ((uintptr_t)currentSC != g_steamClientBase) {
            LOG("Shutdown: steamclient64.dll base changed (%p -> %p), skipping vtable restore",
                (void*)g_steamClientBase, (void*)currentSC);
            g_vtableHookInstalled.store(false, std::memory_order_release);
            // Module rebased: every cached absolute pointer is wrong for the new base.
            g_serviceTransportVtableEa = 0;
            g_originalSlot4 = nullptr;
            g_originalSlot5 = nullptr;
            g_originalSlot7 = nullptr;
            g_originalSlot8 = nullptr;
            g_parseFromArray = nullptr;
            g_serializeToArray = nullptr;
            g_steamClientBase = (uintptr_t)currentSC;
        } else {
            // Restore against installed vtable EA; fall back to resolved RVA.
            const uintptr_t vtableEa = g_serviceTransportVtableEa
                                       ? g_serviceTransportVtableEa
                                       : (SC_RESOLVE(serviceTransportVtable));
            if (!vtableEa) {
                LOG("Shutdown: vtable EA not available, cannot restore slots");
                g_vtableHookInstalled.store(false, std::memory_order_release);
            } else {
            const uintptr_t vtableSlot4Addr = vtableEa + kSlot4Off;
            const uintptr_t vtableSlot5Addr = vtableEa + kSlot5Off;
            const uintptr_t vtableSlot7Addr = vtableEa + kSlot7Off;
            const uintptr_t vtableSlot8Addr = vtableEa + kSlot8Off;
            const uintptr_t regionStart = vtableSlot4Addr;
            const size_t regionSize = (vtableSlot8Addr + sizeof(void*)) - vtableSlot4Addr;

            DWORD oldProt;
            if (VirtualProtect((void*)regionStart, regionSize, PAGE_READWRITE, &oldProt)) {
                if (g_originalSlot4) *(ServiceMethodSlot4Fn*)vtableSlot4Addr = g_originalSlot4;
                if (g_originalSlot5) *(ServiceMethodSlot5Fn*)vtableSlot5Addr = g_originalSlot5;
                if (g_originalSlot7) *(NotificationSlot7Fn*)vtableSlot7Addr = g_originalSlot7;
                if (g_originalSlot8) *(NotificationSlot8Fn*)vtableSlot8Addr = g_originalSlot8;
                VirtualProtect((void*)regionStart, regionSize, oldProt, &oldProt);
                g_vtableHookInstalled.store(false, std::memory_order_release);
                LOG("Shutdown: restored vtable slots 4/5/7/8");
            } else {
                LOG("Shutdown: VirtualProtect failed restoring vtable (%u)", GetLastError());
            }
            }  // else (vtableEa valid)
        }
    }

    // Restore RecvPkt inline detour (write back original prologue bytes).
    if (g_recvPktDetourSite) {
        DWORD oldProt;
        if (VirtualProtect(g_recvPktDetourSite, TRAMPOLINE_COPY, PAGE_EXECUTE_READWRITE, &oldProt)) {
            memcpy(g_recvPktDetourSite, g_recvPktOrigBytes, TRAMPOLINE_COPY);
            FlushInstructionCache(GetCurrentProcess(), g_recvPktDetourSite, TRAMPOLINE_COPY);
            VirtualProtect(g_recvPktDetourSite, TRAMPOLINE_COPY, oldProt, &oldProt);
            LOG("Shutdown: restored RecvPkt detour at %p", g_recvPktDetourSite);
        }
        g_recvPktDetourSite = nullptr;
        // Trampoline page deliberately leaked (another thread may be mid-trampoline).
    }

    // Drop pre-shutdown inject queue entries (RecvPktMonitorHook bails now).
    DrainInjectQueueOnShutdown();

    // Restore BuildDepotDependency detour; trampoline page is leaked deliberately (mid-trampoline thread would AV); ExitProcess reclaims it.
    if (g_bddOrigAddr && g_bddTrampoline) {
        // If steamclient64 already unloaded, the prologue is gone with it.
        HMODULE currentSC = GetModuleHandleA("steamclient64.dll");
        if (!currentSC) {
            LOG("Shutdown: steamclient64.dll already unloaded, skipping BuildDepotDependency restore");
        } else {
            DWORD oldProt;
            if (VirtualProtect(g_bddOrigAddr, SC_BDD_STOLEN_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) {
                memcpy(g_bddOrigAddr, g_bddTrampoline, SC_BDD_STOLEN_BYTES);
                FlushInstructionCache(GetCurrentProcess(), g_bddOrigAddr, SC_BDD_STOLEN_BYTES);
                VirtualProtect(g_bddOrigAddr, SC_BDD_STOLEN_BYTES, oldProt, &oldProt);
                LOG("Shutdown: restored BuildDepotDependency prologue (trampoline page intentionally leaked, reclaimed on ExitProcess)");
            } else {
                LOG("Shutdown: VirtualProtect failed restoring BuildDepotDependency prologue (%u)", GetLastError());
            }
        }
        g_bddTrampoline = nullptr;
        g_origBuildDepotDependency = nullptr;
        g_bddOrigAddr = nullptr;
    }

    // Restore BAsyncSend detour
    if (g_basOrigAddr) {
        HMODULE currentSC = GetModuleHandleA("steamclient64.dll");
        if (currentSC) {
            DWORD oldProt;
            if (VirtualProtect(g_basOrigAddr, SC_BAS_STOLEN_BYTES, PAGE_EXECUTE_READWRITE, &oldProt)) {
                memcpy(g_basOrigAddr, g_basTrampoline, SC_BAS_STOLEN_BYTES);
                FlushInstructionCache(GetCurrentProcess(), g_basOrigAddr, SC_BAS_STOLEN_BYTES);
                VirtualProtect(g_basOrigAddr, SC_BAS_STOLEN_BYTES, oldProt, &oldProt);
            }
        }
        g_basOriginal = nullptr;
        g_basOrigAddr = nullptr;
    }

    if (g_manifestEndpointPatched.load(std::memory_order_acquire)) {
        DWORD oldProt;
        if (g_manifestP8bAddr &&
            VirtualProtect(g_manifestP8bAddr, 51, PAGE_EXECUTE_READWRITE, &oldProt)) {
            memcpy(g_manifestP8bAddr, g_manifestP8bOrig, 51);
            VirtualProtect(g_manifestP8bAddr, 51, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), g_manifestP8bAddr, 51);
        }
        if (g_manifestUrlLeaAddr &&
            VirtualProtect(g_manifestUrlLeaAddr, 4, PAGE_EXECUTE_READWRITE, &oldProt)) {
            memcpy(g_manifestUrlLeaAddr, g_manifestUrlLeaOrig, 4);
            VirtualProtect(g_manifestUrlLeaAddr, 4, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), g_manifestUrlLeaAddr, 4);
        }
        if (g_manifestStringsPage) {
            VirtualFree(g_manifestStringsPage, 0, MEM_RELEASE);
            g_manifestStringsPage = nullptr;
        }
        g_manifestEndpointPatched.store(false, std::memory_order_release);
    }

    // Restore GetEffectiveReleaseState prologue
    if (g_releaseStateAddr && g_releaseStatePatched.load(std::memory_order_acquire)) {
        HMODULE currentSC = GetModuleHandleA("steamclient64.dll");
        if (currentSC) {
            DWORD oldProt;
            if (VirtualProtect(g_releaseStateAddr, 6, PAGE_EXECUTE_READWRITE, &oldProt)) {
                memcpy(g_releaseStateAddr, g_releaseStateOrig, 6);
                FlushInstructionCache(GetCurrentProcess(), g_releaseStateAddr, 6);
                VirtualProtect(g_releaseStateAddr, 6, oldProt, &oldProt);
                LOG("Shutdown: restored GetEffectiveReleaseState prologue");
            }
        }
        g_releaseStatePatched.store(false, std::memory_order_release);
        g_releaseStateAddr = nullptr;
    }

    // Both threads poll g_shuttingDown; 5s is generous. Stuck network I/O
    // detaches and is reaped by the OS.
    JoinThreadWithTimeout(g_luaSyncThread, 5000, "g_luaSyncThread");
    JoinThreadWithTimeout(g_startupMetadataThread, 5000, "g_startupMetadataThread");

    // Background threads (exit-sync uploads, MessageBox) don't poll
    // g_shuttingDown mid-flight; bounded-join to keep shutdown responsive.
    {
        std::vector<std::thread> threads;
        {
            std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
            if (!g_shuttingDown.load(std::memory_order_acquire)) {
                LOG("Shutdown: BUG - g_shuttingDown not set before bg thread join");
            }
            threads = std::move(g_bgThreads);
            g_bgThreads.clear();
        }
        // Move out before joining so spawners that race in don't deadlock
        // on g_bgThreadsMutex; they re-check g_shuttingDown and detach.
        size_t total = threads.size();
        size_t joined = 0, detached = 0, skipped = 0;
        for (auto& t : threads) {
            if (!t.joinable()) { ++skipped; continue; }
            if (JoinThreadWithTimeout(t, 3000, "g_bgThreads[bg]")) ++joined;
            else ++detached;
        }
        if (total > 0) {
            LOG("Shutdown: bg threads joined=%zu detached=%zu skipped=%zu (total=%zu)",
                joined, detached, skipped, total);
        }
    }

    // Upload current lua state before cloud provider shuts down
    if (g_syncLuas) UploadLuaOnShutdown();

    ShutdownRpcHandlers();

    // Wait for all pending cloud uploads (including lua) to finish
    CloudWorkQueue::DrainQueue();

    HttpServer::Stop();
    CloudStorage::Shutdown();
    LOG("CloudIntercept shutdown complete");
}

} // namespace CloudIntercept
