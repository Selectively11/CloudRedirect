#include "cloud_intercept.h"
#include "rpc_handlers.h"
#include "protobuf.h"
#include "log.h"
#include "http_server.h"
#include "vdf.h"
#include "http_util.h"
#include "local_storage.h"
#include "cloud_storage.h"
#include "cloud_provider.h"
#include "json.h"
#include "legacy_metadata_cleanup.h"
#include "file_util.h"
#include "miniz.h"
#include "miniz_zip.h"
#include <shlobj.h>
#include <psapi.h>
#include <unordered_map>
#include <unordered_set>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <queue>
#include <fstream>
#include <optional>
#include <chrono>
#include <limits>

namespace CloudIntercept {

static void ShutdownImpl();
static void InstallExitProcessHook();

static constexpr uint32_t PROTO_FLAG = 0x80000000;
static constexpr uint32_t EMSG_MASK = 0x7FFFFFFF;
static constexpr uint32_t EMSG_SERVICE_METHOD = 151;
static constexpr uint32_t EMSG_SERVICE_METHOD_RESP = 147;
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

// steamclient64.dll RVAs for manifest pinning inline detour
// IDA image base: 0x138000000
// sub_1384B72B0 = CUserAppManager::BuildDepotDependency
// Signature: __int64 __fastcall(QWORD* a1, uint a2, int64 a3, int64 a4, int64 a5, int64 a6, DWORD* a7, BYTE* a8)
//   a1 (rcx) = CUserAppManager*
//   a2 (edx) = appId
//   a4 (r9)  = output depot vector (app's own depots)
//   a5 ([rsp+28h]) = output depot vector (DLC/shared depots)
// Depot vectors: *(QWORD*)vec = array base, *(int*)(vec+16) = count
// Each entry is 32 bytes: {uint32 depotId, uint32 appId, uint64 manifestId, ...}
static constexpr uintptr_t SC_RVA_BUILD_DEPOT_DEPENDENCY = 0x4B72B0;
static constexpr size_t SC_BDD_STOLEN_BYTES = 14;  // first 14 bytes of prologue

// steamclient64.dll RVAs for CCMInterface discovery
// IDA image base: 0x138000000
// qword_139781D38 = global CSteamEngine* pointer
static constexpr uintptr_t SC_RVA_GLOBAL_ENGINE     = 0x1781D38;
// CCMInterface vtable RVA (for validation)
static constexpr uintptr_t SC_RVA_CCMINTERFACE_VT   = 0x1271FB8;
// sub_138D02530 = CNetPacket→CProtoBufNetPacket wrapper
static constexpr uintptr_t SC_RVA_WRAP_PACKET       = 0xD02530;
// sub_138D0EB50 = CJobMgr::BRouteMsgToJob
static constexpr uintptr_t SC_RVA_BROUTEMSG         = 0xD0EB50;
// sub_1380EB160 = Release wrapped packet (CProtoBufNetPacket ref-count release)
static constexpr uintptr_t SC_RVA_RELEASE_WRAPPED   = 0x0EB160;

// steamclient64.dll RVAs for service-method vtable hook (Approach E)
// CClientUnifiedServiceTransport vtable (IDA addr 0x13924F910)
static constexpr uintptr_t SC_RVA_SERVICE_TRANSPORT_VT = 0x124F910;
// Slot 4 (offset +0x20) = request/response direct function (BYieldingSendMessageAndGetReply)
static constexpr uintptr_t SC_RVA_SERVICE_TRANSPORT_SLOT4 = 0x124F930;
// Slot 5 (offset +0x28) = request/response wrapper function we hook
static constexpr uintptr_t SC_RVA_SERVICE_TRANSPORT_SLOT5 = 0x124F938;
// Slot 7 (offset +0x38) = notification direct function
static constexpr uintptr_t SC_RVA_SERVICE_TRANSPORT_SLOT7 = 0x124F948;
// Slot 8 (offset +0x40) = notification wrapper function
static constexpr uintptr_t SC_RVA_SERVICE_TRANSPORT_SLOT8 = 0x124F950;
// sub_138BD0210 = protobuf ParseFromArray (fills body from raw bytes)
static constexpr uintptr_t SC_RVA_PARSE_FROM_ARRAY  = 0xBD0210;
// sub_138BD07E0 = protobuf SerializeToArray (writes body to raw bytes)
static constexpr uintptr_t SC_RVA_SERIALIZE_TO_ARRAY = 0xBD07E0;
// CUser playtime state helpers
static constexpr uintptr_t SC_RVA_GET_APP_MINUTES_PLAYED_DATA = 0x9BF480;
static constexpr uintptr_t SC_RVA_FLUSH_APP_MINUTES_PLAYED = 0x9CF7E0;
static constexpr uintptr_t SC_RVA_SET_APP_LAST_PLAYED_TIME = 0x9D2640;
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

// Function pointer types for BRouteMsgToJob bypass (Approach D -- legacy)
// sub_138D02530: wraps CNetPacket into CProtoBufNetPacket (parses protobuf header)
using WrapPacketFn = void*(__fastcall*)(CNetPacket* pkt, int addRef);
// sub_138D0EB50: routes a wrapped packet to the waiting job
using BRouteMsgToJobFn = char(__fastcall*)(void* jobMgr, void* connCtx,
                                           void* wrappedPkt, void* routeInfo, int validateFrom);
// sub_1380EB160: releases a wrapped packet (decrements refcount)
using ReleaseWrappedFn = void*(__fastcall*)(void* wrappedPkt);
// sub_138DCA830: refcount increment helper -- takes ptr-to-ptr, reads inner ptr, does InterlockedIncrement64
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
// Slot 7 signature: notification direct -- sends fire-and-forget notification
//   rcx = this (CClientUnifiedServiceTransport*)
//   rdx = methodName (const char*)
//   r8  = bodyObj (raw protobuf body object, NOT wrapped in CProtoBufMsg)
//   r9  = flags (int*, can be NULL) -- {routing_appid, ?, ?, ?}
using NotificationSlot7Fn = bool(__fastcall*)(void* thisptr, const char* methodName,
                                               void* bodyObj, int* flags);
// Slot 8 signature: notification wrapper -- extracts body from CProtoBufMsg, calls slot 7
//   rcx = this (CClientUnifiedServiceTransport*)
//   rdx = methodName (const char*)
//   r8  = request CProtoBufMsg* (body at +48, header at +40)
using NotificationSlot8Fn = bool(__fastcall*)(void* thisptr, const char* methodName,
                                               void* request);
// sub_138BD0210: ParseFromArray -- fills a protobuf message object from raw bytes
//   rcx = protobuf message object (body at CProtoBufMsg+48)
//   rdx = raw data pointer
//   r8  = raw data size (as int)
using ParseFromArrayFn = char(__fastcall*)(void* msgBody, const char* data, int size);
// sub_138BD07E0: SerializeToArray -- writes protobuf message to a buffer
//   rcx = protobuf message object (body at CProtoBufMsg+48)
//   rdx = output buffer pointer
//   returns pointer past last written byte
using SerializeToArrayFn = void*(__fastcall*)(void* msgBody, void* outBuf);
using GetAppMinutesPlayedDataFn = unsigned int*(__fastcall*)(int64_t userPtr, unsigned int appId, char create);
using FlushAppMinutesPlayedFn = int64_t(__fastcall*)(int64_t userPtr, unsigned int appId, unsigned int* record);
using SetAppLastPlayedTimeFn = void(__fastcall*)(int64_t userPtr, unsigned int appId, unsigned int lastPlayed);

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

// RVA for the refcount helper: sub_138DCA830
// This function takes rcx = pointer-to-pointer, reads *rcx to get a pointer,
// then does InterlockedIncrement64 on that second pointer.
// RecvPkt calls this with &unk_139771AD8 before calling BRouteMsgToJob.
static constexpr uintptr_t SC_RVA_REFCOUNT_HELPER   = 0xDCA830;
// Global that holds the pointer-to-counter for the refcount helper
static constexpr uintptr_t SC_RVA_REFCOUNT_GLOBAL   = 0x1771AD8;
// sub_138D11470 = CUtlSortedVector::Find (looks up a CJob by jobId)
static constexpr uintptr_t SC_RVA_FIND_JOB          = 0xD11470;

// SEH exception filter for crash diagnostics
static thread_local uintptr_t s_crashFaultAddr = 0;

// Forward declarations
static void InstallServiceMethodHook();
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
static std::string g_steamPath;
static RecvPktFn g_originalRecvPkt = nullptr;
static void** g_recvPktSlot = nullptr;            // address of the patched RecvPkt vtable slot, for shutdown restore
static void* g_cmInterface = nullptr;             // real CCMInterface* (found via CSteamEngine)
static std::atomic<bool> g_shuttingDown{false};
static std::atomic<bool> g_cmInterfaceFound{false}; // whether we've found the real CCMInterface
static std::thread g_luaSyncThread;                  // deferred lua sync (waits for accountId)
static std::thread g_startupMetadataThread;          // deferred startup playtime/stats restore
static std::atomic<bool> g_startupMetadataScheduled{false};

// Background threads spawned by notification hooks (exit-sync uploads, MessageBox, etc.)
static std::mutex g_bgThreadsMutex;
static std::vector<std::thread> g_bgThreads;

static void ScheduleStartupMetadataSync() {
    if (!CloudStorage::IsCloudActive()) return;

    bool expected = false;
    if (!g_startupMetadataScheduled.compare_exchange_strong(expected, true)) return;

    if (g_startupMetadataThread.joinable()) g_startupMetadataThread.join();
    g_startupMetadataThread = std::thread([] {
        uint32_t accountId = GetAccountId();
        if (g_shuttingDown.load() || accountId == 0) return;

        LOG("[StartupSync] Restoring cloud metadata for account %u", accountId);
        auto appIds = CloudStorage::SyncAllFromCloud(accountId);
        for (uint32_t appId : appIds) {
            if (g_shuttingDown.load()) break;
            RestoreAppMetadata(accountId, appId);
        }
        LOG("[StartupSync] Restored metadata for %zu apps", appIds.size());
    });
}

// Sync toggles (all default OFF, read from config.json at init)
static std::atomic<bool> g_syncAchievements{false};
static std::atomic<bool> g_syncPlaytime{false};
static std::atomic<bool> g_syncLuas{false};

// Cloud-redirect master toggle (default ON). When OFF the DLL still applies manifest pinning + patches but skips HTTP/storage/interception.
static std::atomic<bool> g_cloudRedirectEnabled{true};

// Manifest pinning (depot -> manifest override)
// Config lives in Steam folder (per-system), NOT AppData (per-user).
static std::atomic<bool> g_manifestPinsEnabled{false};
static std::atomic<bool> g_autoComment{true};  // when true, ignore lua setManifestid lines
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

// Hook reference counter -- incremented on entry to each hook, decremented on exit.
// Shutdown() spins until this reaches zero before restoring vtable pointers.
static std::atomic<int> g_hookRefCount{0};

// RAII guard for g_hookRefCount
struct HookGuard {
    HookGuard() { g_hookRefCount.fetch_add(1, std::memory_order_acquire); }
    ~HookGuard() { g_hookRefCount.fetch_sub(1, std::memory_order_release); }
    HookGuard(const HookGuard&) = delete;
    HookGuard& operator=(const HookGuard&) = delete;
};

// namespace state (auto-detected from stplug-in directory)
static std::unordered_set<uint32_t> g_namespaceApps;
static std::mutex g_namespaceAppsMutex;

static bool IsNamespaceApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    return g_namespaceApps.count(appId) > 0;
}

static bool HasNamespaceApps() {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    return !g_namespaceApps.empty();
}

static void AddNamespaceApp(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_namespaceAppsMutex);
    g_namespaceApps.insert(appId);
}

// per-app launch timestamp for internal playtime tracking
static std::mutex g_launchTimeMutex;
static std::unordered_map<uint32_t, time_t> g_launchTimes;
static std::unordered_map<uint32_t, uint64_t> g_launchVdfPlaytime;
static std::unordered_map<uint32_t, uint64_t> g_launchVdfPlaytime2wks;

static uint32_t ClampToUint32(uint64_t value) {
    return value > (std::numeric_limits<uint32_t>::max)()
        ? (std::numeric_limits<uint32_t>::max)()
        : static_cast<uint32_t>(value);
}

static uintptr_t FindCurrentUser();

static uintptr_t ResolveCurrentUserForRestore(const char* featureTag, uint32_t appId) {
    if (!g_steamClientBase) {
        HMODULE hSC = GetModuleHandleA("steamclient64.dll");
        if (!hSC) {
            LOG("[%s] In-memory restore skipped for app %u: steamclient64.dll not loaded", featureTag, appId);
            return 0;
        }
        g_steamClientBase = (uintptr_t)hSC;
    }

    uintptr_t userPtr = 0;
    for (int attempt = 0; attempt < 20 && !userPtr && !g_shuttingDown.load(); ++attempt) {
        userPtr = FindCurrentUser();
        if (!userPtr) Sleep(100);
    }
    if (!userPtr) {
        LOG("[%s] In-memory restore skipped for app %u: current CUser not available", featureTag, appId);
    }
    return userPtr;
}

static uintptr_t FindCurrentUser() {
    if (!g_steamClientBase) {
        HMODULE hSC = GetModuleHandleA("steamclient64.dll");
        if (!hSC) return 0;
        g_steamClientBase = (uintptr_t)hSC;
    }

    uintptr_t* pEngineGlobal = (uintptr_t*)(g_steamClientBase + SC_RVA_GLOBAL_ENGINE);
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

void RecordLaunchTime(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_launchTimeMutex);
    g_launchTimes[appId] = time(nullptr);

    // Snapshot VDF playtime at launch while the file is stable
    uint64_t vdfPT = 0;
    uint64_t vdfPT2wks = 0;
    uint32_t accountId = GetAccountId();
    if (accountId) {
        std::string vdfPath = g_steamPath + "userdata\\" + std::to_string(accountId)
            + "\\config\\localconfig.vdf";
        // Wide-API: CreateFileA's ACP narrowing breaks non-ASCII profile paths (Cyrillic/CJK), which would silently skip the playtime baseline.
        auto vdfPathWide = FileUtil::Utf8ToPath(vdfPath).wstring();
        HANDLE hFile = CreateFileW(vdfPathWide.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, nullptr);
            std::string vdfContent;
            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                vdfContent.resize(fileSize);
                DWORD bytesRead = 0;
                ReadFile(hFile, (LPVOID)vdfContent.data(), fileSize, &bytesRead, nullptr);
                vdfContent.resize(bytesRead);
            }
            CloseHandle(hFile);

            std::string appIdStr = std::to_string(appId);
            const char* sections[] = { "UserLocalConfigStore", "Software", "Valve", "Steam", "Apps", appIdStr.c_str() };
            VdfUtil::ForEachFieldInSection(vdfContent, sections, 6,
                [&](const VdfUtil::FieldInfo& fi) {
                    if (fi.key == "Playtime")
                        vdfPT = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                    else if (fi.key == "Playtime2wks")
                        vdfPT2wks = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                    return true;
                });
        }
    }
    g_launchVdfPlaytime[appId] = vdfPT;
    g_launchVdfPlaytime2wks[appId] = vdfPT2wks;
    LOG("[Playtime] Recorded launch time for app %u (vdfBaseline=%llu min, vdf2wks=%llu min)",
        appId, vdfPT, vdfPT2wks);
}

struct LaunchInfo { time_t launchTime; uint64_t vdfBaseline; uint64_t vdfBaseline2wks; };
static LaunchInfo PopLaunchInfo(uint32_t appId) {
    std::lock_guard<std::mutex> lock(g_launchTimeMutex);
    LaunchInfo info = {0, 0, 0};
    auto it = g_launchTimes.find(appId);
    if (it != g_launchTimes.end()) {
        info.launchTime = it->second;
        g_launchTimes.erase(it);
    }
    auto it2 = g_launchVdfPlaytime.find(appId);
    if (it2 != g_launchVdfPlaytime.end()) {
        info.vdfBaseline = it2->second;
        g_launchVdfPlaytime.erase(it2);
    }
    auto it3 = g_launchVdfPlaytime2wks.find(appId);
    if (it3 != g_launchVdfPlaytime2wks.end()) {
        info.vdfBaseline2wks = it3->second;
        g_launchVdfPlaytime2wks.erase(it3);
    }
    return info;
}

bool RestorePlaytimeState(uint32_t appId, uint64_t playtime, uint64_t playtime2wks) {
    if (!playtime && !playtime2wks) return false;

    uintptr_t userPtr = ResolveCurrentUserForRestore("Playtime", appId);
    if (!userPtr) return false;

    auto getData = (GetAppMinutesPlayedDataFn)(g_steamClientBase + SC_RVA_GET_APP_MINUTES_PLAYED_DATA);
    auto flushData = (FlushAppMinutesPlayedFn)(g_steamClientBase + SC_RVA_FLUSH_APP_MINUTES_PLAYED);

    unsigned int* record = nullptr;
    __try {
        record = getData((int64_t)userPtr, appId, 1);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[Playtime] In-memory restore exception creating record for app %u: code=0x%08lX",
            appId, GetExceptionCode());
        return false;
    }
    if (!record) {
        LOG("[Playtime] In-memory restore failed for app %u: no playtime record", appId);
        return false;
    }

    uint32_t total32 = ClampToUint32(playtime);
    uint32_t twoWks32 = ClampToUint32(playtime2wks ? playtime2wks : playtime);
    uint32_t oldTotal = 0;
    uint32_t oldTwoWks = 0;

    __try {
        oldTotal = record[1];
        oldTwoWks = record[2];
        if (oldTotal > total32) total32 = oldTotal;
        if (oldTwoWks > twoWks32) twoWks32 = oldTwoWks;
        record[1] = total32;
        record[2] = twoWks32;
        record[3] = 0;
        record[4] = 0;
        record[5] = 0;
        record[6] = 0;
        flushData((int64_t)userPtr, appId, record);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[Playtime] In-memory restore exception applying record for app %u: code=0x%08lX",
            appId, GetExceptionCode());
        return false;
    }

    LOG("[Playtime] Seeded in-memory playtime for app %u: total %u->%u, 2wks %u->%u",
        appId, oldTotal, total32, oldTwoWks, twoWks32);
    return true;
}

bool RestoreLastPlayedState(uint32_t appId, uint64_t lastPlayed) {
    if (!lastPlayed) return false;

    uintptr_t userPtr = ResolveCurrentUserForRestore("Playtime", appId);
    if (!userPtr) return false;

    auto setLastPlayed = (SetAppLastPlayedTimeFn)(g_steamClientBase + SC_RVA_SET_APP_LAST_PLAYED_TIME);

    uint32_t lastPlayed32 = ClampToUint32(lastPlayed);
    __try {
        setLastPlayed((int64_t)userPtr, appId, lastPlayed32);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[Playtime] In-memory LastPlayed restore exception for app %u: code=0x%08lX",
            appId, GetExceptionCode());
        return false;
    }

    LOG("[Playtime] Seeded in-memory LastPlayed for app %u: %u", appId, lastPlayed32);
    return true;
}

// cave replacement buffer globals (still needed for passthrough SteamTools hook)


// SteamID extracted from first packet header
static std::atomic<uint64_t> g_steamId{0};
static std::atomic<int32_t> g_sessionId{0};

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

// CCMInterface discovery via CSteamEngine global
//
// Traversal: qword_139781D38 (global CSteamEngine*)
//   → engine+3144 (uint32 global user handle)
//   → engine+3296 (CUtlSortedVector user map)
//     → array[i] where handle matches → CUser*
//   → CUser+72 (CCMInterface embedded in CBaseUser)
static void* FindCCMInterface() {
    uintptr_t userPtr = FindCurrentUser();
    if (!userPtr) return nullptr;

    // CCMInterface is embedded at CBaseUser+72 (0x48)
    uintptr_t ccm = userPtr + USER_OFF_CCMINTERFACE;

    // Validate by checking vtable matches CCMInterface::vftable
    uintptr_t expectedVtable = g_steamClientBase + SC_RVA_CCMINTERFACE_VT;
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

    // Atomically claim the "first finder" role -- only one thread proceeds.
    // This prevents double vtable patching which would overwrite the saved
    // original slot pointers with our hook addresses, causing crash on restore.
    bool expected = false;
    if (!g_cmInterfaceFound.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        return; // another thread already found it
    }

    g_cmInterface = ccm;

    LOG("[CCM] Found real CCMInterface: %p", ccm);

    // Log details for debugging (wrapped in SEH -- raw pointer dereferences for diagnostics only)
    __try {
        uintptr_t* pEngineGlobal = (uintptr_t*)(g_steamClientBase + SC_RVA_GLOBAL_ENGINE);
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
    g_wrapPacket     = (WrapPacketFn)(g_steamClientBase + SC_RVA_WRAP_PACKET);
    g_bRouteMsgToJob = (BRouteMsgToJobFn)(g_steamClientBase + SC_RVA_BROUTEMSG);
    g_releaseWrapped = (ReleaseWrappedFn)(g_steamClientBase + SC_RVA_RELEASE_WRAPPED);
    g_refCountHelper = (RefCountHelperFn)(g_steamClientBase + SC_RVA_REFCOUNT_HELPER);
    g_refCountGlobalPtr = (volatile int64_t**)(g_steamClientBase + SC_RVA_REFCOUNT_GLOBAL);
    LOG("[CCM]   WrapPacket=%p BRouteMsgToJob=%p ReleaseWrapped=%p",
        g_wrapPacket, g_bRouteMsgToJob, g_releaseWrapped);

    // Additional diagnostic logging (dereferences pointers, wrap in SEH)
    __try {
        LOG("[CCM]   RefCountHelper=%p RefCountGlobal=%p (*=%p)",
            g_refCountHelper, g_refCountGlobalPtr,
            g_refCountGlobalPtr ? (void*)*g_refCountGlobalPtr : nullptr);
        uintptr_t engine = *(uintptr_t*)(g_steamClientBase + SC_RVA_GLOBAL_ENGINE);
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
    uint32_t emsg;         // EMsg type (147 = response, 152 = send-to-client)
    char methodName[128];
};

// Lock order: drop g_injectMutex before ProcessQueuedInjection (the call chain re-acquires via InjectResponse->enqueue).
static std::queue<QueuedInjection*> g_injectQueue;
static std::mutex g_injectMutex;

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

    // Wrap CNetPacket into CProtoBufNetPacket.
    // WrapPacket takes ownership of pktStruct via refcount on success;
    // caller frees pktStruct on failure.
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
        uintptr_t* pEngineGlobal = (uintptr_t*)(g_steamClientBase + SC_RVA_GLOBAL_ENGINE);
        uintptr_t engine = *pEngineGlobal;
        jobMgr = (void*)(engine + ENGINE_OFF_JOBMGR);
        connCtx = *(void**)((uintptr_t)g_cmInterface + CCM_OFF_CONN_CONTEXT);
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

    // Pre-check: verify job still exists and is in yielding state
    using FindJobFn = int(__fastcall*)(void* slotMap, void* pJobId);
    FindJobFn findJob = (FindJobFn)(g_steamClientBase + SC_RVA_FIND_JOB);
    int jobSlot = -1;
    __try {
        void* slotMap = (void*)((uintptr_t)jobMgr + 0x200);
        jobSlot = findJob(slotMap, &route.jobidTarget);
        if (jobSlot >= 0) {
            uintptr_t slotArr = *(uintptr_t*)((uintptr_t)jobMgr + 0x230);
            void* cjobPtr = *(void**)(slotArr + (uintptr_t)jobSlot * 24 + 8);
            uint32_t jobState = cjobPtr ? *(uint32_t*)((uintptr_t)cjobPtr + 0x84) : 999;
            LOG("[INJECT]   FindJob slot=%d cjob=%p state=%u", jobSlot, cjobPtr, jobState);
        } else {
            LOG("[INJECT]   FindJob: job not found (slot=%d) -- may have timed out", jobSlot);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[INJECT]   EXCEPTION in FindJob: code=0x%08X", GetExceptionCode());
    }

    // Increment refcount (matches RecvPkt at 0x13859D4CC)
    if (g_refCountHelper && g_refCountGlobalPtr) {
        __try {
            g_refCountHelper(g_refCountGlobalPtr);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[INJECT]   EXCEPTION in RefCountHelper: code=0x%08X", GetExceptionCode());
        }
    }

    // Call BRouteMsgToJob (on network thread -- coroutine manager is valid here)
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
    if (!g_wrapPacket || !g_bRouteMsgToJob || !g_releaseWrapped || !g_cmInterface) {
        LOG("[INJECT] Cannot inject: wrapPacket=%p bRouteMsgToJob=%p releaseWrapped=%p cmInterface=%p",
            g_wrapPacket, g_bRouteMsgToJob, g_releaseWrapped, g_cmInterface);
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

    // pktBuf lifetime is managed by ProcessQueuedInjection -- freed after BRouteMsgToJob completes.

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

    // Queue for the network thread to drain: BRouteMsgToJob requires the
    // network thread's coroutine manager, and the job hasn't yielded yet.
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



uint32_t GetAccountId() {
    return (uint32_t)(g_steamId.load() & 0xFFFFFFFF);
}

const std::string& GetSteamPath() {
    return g_steamPath;
}

bool SyncAchievementsEnabled() { return g_syncAchievements; }
bool SyncPlaytimeEnabled() { return g_syncPlaytime; }
bool SyncLuasEnabled() { return g_syncLuas; }

// Service-method vtable hook (Approach E)
//
// Hooks slot 4/5 of CClientUnifiedServiceTransport's vtable to intercept
// Cloud RPCs inside the sync job's own coroutine context.
// For namespace apps: serialize request, call handler, deserialize response.
// For non-namespace apps: passthrough to original function.
//
// CProtoBufMsg layout:
//   +40: CMsgProtoBufHeader* (header, 248 bytes)
//   +48: body protobuf message object
//
// CMsgProtoBufHeader relevant fields:
//   +16: has_bits, +24: appid, +116: routing_appid, +216: eresult, +220: error_code

// Serialize a protobuf message body object to raw bytes
// SEH helpers (cannot use __try in functions with C++ objects)
static uint64_t SEH_ByteSize(void* bodyObj) {
    uintptr_t vtable = *(uintptr_t*)bodyObj;
    using ByteSizeFn = uint64_t(__fastcall*)(void* self);
    ByteSizeFn byteSize = (ByteSizeFn)(*(uintptr_t*)(vtable + 64));
    uint64_t size = 0;
    __try {
        size = byteSize(bodyObj);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION in ByteSize: code=0x%08X", GetExceptionCode());
        return 0;
    }
    return size;
}

static ptrdiff_t SEH_SerializeToArray(void* bodyObj, uint8_t* buf, uint64_t expectedSize) {
    __try {
        void* end = g_serializeToArray(bodyObj, buf);
        return (uint8_t*)end - buf;
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
    if (written < 0) return {};
    if (written != (ptrdiff_t)size) {
        LOG("[VtHook] SerializeToArray wrote %lld bytes, expected %llu", (long long)written, size);
        buf.resize((size_t)written);
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
static bool SEH_WriteResponseHeader(void* respHeader) {
    __try {
        // Set eresult = 1 (k_EResultOK)
        *(uint32_t*)((uintptr_t)respHeader + 16) |= 0x20000000u;
        *(int32_t*)((uintptr_t)respHeader + 216) = 1;  // eresult = OK

        // Set the error_message related field (slot 5 does this too)
        *(uint32_t*)((uintptr_t)respHeader + 16) |= 0x40000000u;
        *(int32_t*)((uintptr_t)respHeader + 220) = 0;  // no error
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION writing response header: code=0x%08X", GetExceptionCode());
        return false;
    }
}

// Shared Cloud RPC dispatch -- routes a method name to the appropriate handler.
// Returns std::nullopt if the method is not a recognized Cloud RPC we handle.
static std::optional<PB::Writer> DispatchCloudRpc(
    const char* method, uint32_t appId, const std::vector<PB::Field>& reqBody) {
    if (strcmp(method, RPC_GET_CHANGELIST) == 0)       return HandleGetChangelist(appId, reqBody);
    if (strcmp(method, RPC_LAUNCH_INTENT) == 0)        return HandleLaunchIntent(appId, reqBody);
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
    if (!methodName) {
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }

    // Fast check: only intercept Cloud.* methods
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
    uint32_t appId = ExtractAppId(methodName, innerFields);
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

    // NAMESPACE APP: handle locally, synchronously
    LOG("[Slot4] INTERCEPT %s app=%u (%zu bytes):", methodName, appId, reqBytes.size());
#ifdef DEBUG_VERBOSE_LOGGING
    SpyLogFields("[Slot4-REQ]", reqBytes.data(), (uint32_t)reqBytes.size());
#endif

    // Capture SteamID if not yet captured (from SendPkt or slot 5 -- but just in case)
    // (SteamID should already be captured from earlier RPCs)

    // Call the appropriate handler to build a response body
    PB::Writer responseBodyPB;

    auto dispatched = DispatchCloudRpc(methodName, realAppId, innerFields);
    if (!dispatched.has_value()) {
        LOG("[Slot4] Unhandled method %s, passing through", methodName);
        return g_originalSlot4(thisptr, methodName, requestBody, responseBody, flags);
    }
    responseBodyPB = std::move(*dispatched);

    LOG("[Slot4] %s: response body %zu bytes", methodName, responseBodyPB.Size());

    // Write the response body into the response protobuf object
    if (responseBody && responseBodyPB.Size() > 0) {
        if (!ParseBytesToBody(responseBody, responseBodyPB.Data().data(), responseBodyPB.Size())) {
            // ParseBytesToBody may have partially modified the response object.
            // Passing through to g_originalSlot4 with a corrupted response is unsafe.
            LOG("[Slot4] %s: ParseFromArray failed for response body! Returning transport failure.", methodName);
            return false;
        }
    }

    // Flags layout (from IDA decompilation of sub_138914710 / sub_138914A30):
    //   [0-1]: __int64 (routing/request context, leave untouched)
    //   [2]:   int  -- transport success flag (1 = OK, 0 = transport failure → triggers k_EResultTimeout=16)
    //   [3]:   int  -- eresult from response header (1 = k_EResultOK)
    //   [4+]:  char[] -- error message string (null-terminated)
    if (flags) {
        flags[2] = 1;  // transport_success = true (MUST be 1, or caller returns k_EResultTimeout!)
        flags[3] = 1;  // eresult = k_EResultOK
        flags[4] = 0;  // error_message = "" (null terminator)
    }

    LOG("[Slot4] %s handled synchronously", methodName);
    return true;
}

// The actual vtable hook function -- replaces CClientUnifiedServiceTransport::vtable[5]
static bool __fastcall ServiceMethodHook(void* thisptr, const char* methodName,
                                           void* request, void* response, int64_t* flags) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    if (!methodName) {
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Fast check: only intercept Cloud.* methods
    if (strncmp(methodName, "Cloud.", 6) != 0) {
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // Check if it's a Cloud RPC we handle (zero-alloc check via strcmp)
    // Request/response RPCs only -- notifications go through slots 7/8
    bool isCloudRpc = (strcmp(methodName, RPC_GET_CHANGELIST) == 0 || strcmp(methodName, RPC_BEGIN_BATCH) == 0 ||
                       strcmp(methodName, RPC_BEGIN_UPLOAD) == 0 || strcmp(methodName, RPC_COMMIT_UPLOAD) == 0 ||
                       strcmp(methodName, RPC_FILE_DOWNLOAD) == 0 || strcmp(methodName, RPC_DELETE_FILE) == 0 ||
                       strcmp(methodName, RPC_COMPLETE_BATCH) == 0 || strcmp(methodName, RPC_QUOTA_USAGE) == 0 ||
                       strcmp(methodName, RPC_LAUNCH_INTENT) == 0 ||
                       // Safety net: these are notifications that SHOULD go through slots 7/8,
                       // but add them here in case they somehow arrive via slot 5
                       strcmp(methodName, RPC_EXIT_SYNC) == 0 || strcmp(methodName, RPC_CONFLICT) == 0 ||
                       strcmp(methodName, RPC_TRANSFER_REPORT) == 0);
    if (!isCloudRpc) {
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
    uint32_t appId = ExtractAppId(methodName, innerFields);
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
        // Not a namespace app -- pass through to real Steam servers
        LOG("[VtHook] %s app=%u: not namespace, passing through", methodName, appId);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    // NAMESPACE APP: handle locally
    LOG("[VtHook] INTERCEPT %s app=%u (%zu bytes):", methodName, appId, reqBytes.size());
#ifdef DEBUG_VERBOSE_LOGGING
    SpyLogFields("[VtHook-REQ]", reqBytes.data(), (uint32_t)reqBytes.size());
#endif

    // Capture SteamID from request header if not yet captured
    if (g_steamId.load() == 0) {
        void* reqHeader = *(void**)((uintptr_t)request + 40);
        if (reqHeader) {
            // CMsgProtoBufHeader: serialize-and-parse to extract steamid.
            auto hdrBytes = SerializeBodyToBytes(reqHeader);
            if (!hdrBytes.empty()) {
                auto hdrFields = PB::Parse(hdrBytes.data(), hdrBytes.size());
                auto* sidField = PB::FindField(hdrFields, HDR_STEAMID);
                if (sidField) {
                    g_steamId.store(sidField->varintVal);
                    LOG("[VtHook] Captured SteamID: %llu (accountId=%u)", g_steamId.load(), GetAccountId());
                    HttpServer::SetAccountId(GetAccountId());
                    ScheduleStartupMetadataSync();
                }
                auto* sessField = PB::FindField(hdrFields, HDR_SESSIONID);
                if (sessField) {
                    g_sessionId.store((int32_t)sessField->varintVal);
                }
            }
        }
    }

    // Call the appropriate handler to build a response body
    PB::Writer responseBody;

    auto dispatched = DispatchCloudRpc(methodName, realAppId, innerFields);
    if (!dispatched.has_value()) {
        LOG("[VtHook] Unhandled method %s, passing through", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }
    responseBody = std::move(*dispatched);

    LOG("[VtHook] %s: response body %zu bytes", methodName, responseBody.Size());

    // Write the response body into the response CProtoBufMsg
    void* respBody = *(void**)((uintptr_t)response + 48);
    if (!respBody) {
        LOG("[VtHook] %s: response body object is NULL, cannot write response!", methodName);
        return g_originalSlot5(thisptr, methodName, request, response, flags);
    }

    if (responseBody.Size() > 0) {
        if (!ParseBytesToBody(respBody, responseBody.Data().data(), responseBody.Size())) {
            // ParseBytesToBody may have partially modified the response object.
            // Passing through to g_originalSlot5 with a corrupted response is unsafe.
            LOG("[VtHook] %s: ParseFromArray failed for response body! Returning transport failure.", methodName);
            return false;
        }
    }

    // Set eresult=1 in the response header (CProtoBufMsg+40):
    //   has_bits |= 0x20000000 (eresult), |= 2 (target_job_name), |= 0x40000000 (error_message)
    //   header+216 = eresult, header+220 = error_code
    void* respHeader = *(void**)((uintptr_t)response + 40);
    if (respHeader) {
        if (!SEH_WriteResponseHeader(respHeader)) {
            return g_originalSlot5(thisptr, methodName, request, response, flags);
        }
        LOG("[VtHook] Set response header: eresult=1, error=0");
    } else {
        // Body already written; passing through would corrupt the real
        // network response. Return transport failure instead.
        LOG("[VtHook] %s: respHeader is NULL after writing body -- returning transport failure", methodName);
        return false;
    }

    // Populate flags output (caller reads in addition to the header).
    if (flags) {
        // flags layout (from slot 5):
        //   flags[0] = int32_t routing_appid (slot 5 reads *(reqHeader+116) and writes to flags[0])
        //   flags[1] = int32_t (always 1, set in slot 5 constructor)
        //   flags[2] = int32_t error_code → written to respHeader+220
        //   flags[3] = int32_t eresult → written to respHeader+216
        //   flags[4..] = char[256] target_job_name
        // flags is int64_t* but actual layout is int32_t[68].
        // Use int32_t* cast to avoid zeroing adjacent fields.
        int32_t* f32 = reinterpret_cast<int32_t*>(flags);
        f32[0] = 0;  // routing_appid (not relevant for our response)
        // f32[1] already set by caller (= 1)
        f32[2] = 0;  // error_code
        f32[3] = 1;  // eresult = OK
    }

    LOG("[VtHook] SUCCESS: %s app=%u handled locally (response %zu bytes)",
        methodName, realAppId, responseBody.Size());
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

// On namespace-app exit: read appcache/stats/UserGameStats_{account}_{app}.bin and store as a cross-machine restore blob.
static void UploadStatsOnExit(uint32_t appId) {
    if (!CloudStorage::IsCloudActive()) return;

    uint32_t accountId = GetAccountId();
    if (!accountId) return;

    std::string statsFile = g_steamPath + "appcache\\stats\\UserGameStats_"
        + std::to_string(accountId) + "_" + std::to_string(appId) + ".bin";

    // Wide-API: CreateFileA narrows via ACP and fails for non-ASCII Steam
    // install roots, silently skipping stats upload for affected users.
    auto statsFileWide = FileUtil::Utf8ToPath(statsFile).wstring();
    HANDLE hFile = CreateFileW(statsFileWide.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG("[Stats] No stats file for app %u, skipping upload", appId);
        return;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > 50 * 1024 * 1024) {
        LOG("[Stats] Stats file empty or too large for app %u (%lld bytes), skipping upload",
            appId, fileSize.QuadPart);
        CloseHandle(hFile);
        return;
    }

    std::vector<uint8_t> data(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead = 0;
    BOOL readOk = ReadFile(hFile, data.data(), static_cast<DWORD>(data.size()), &bytesRead, nullptr);
    CloseHandle(hFile);

    if (!readOk || bytesRead != data.size()) {
        LOG("[Stats] Failed to read stats file for app %u", appId);
        return;
    }

    // Account-scoped sentinel (appId=0): keeps blob out of per-app namespace so Steam never resolves it under an AutoCloud root. See cloud_metadata_paths.h.
    bool ok = CloudStorage::StoreBlob(accountId, kAccountScopeAppId,
        AccountStatsFilename(appId), data.data(), data.size());
    LOG("[Stats] Uploaded stats for app %u (%zu bytes, ok=%d)", appId, data.size(), ok);

    if (ok) {
        CloudStorage::DeleteBlob(accountId, appId, kLegacyStatsMetadataPath,
                                 /*keepTombstoneOnSuccess=*/true);
    }
}

// Upload playtime on namespace-app exit. Internal launch->exit delta + launch-time VDF baseline (exit-side VDF is unreliable -- Steam may not have written it yet).
static void UploadPlaytimeOnExit(uint32_t appId) {
    if (!CloudStorage::IsCloudActive()) return;

    uint32_t accountId = GetAccountId();
    if (!accountId) return;

    auto info = PopLaunchInfo(appId);
    time_t now = time(nullptr);

    uint64_t trackedMinutes = 0;
    uint64_t trackedLastPlayed = (uint64_t)now;

    if (info.launchTime > 0 && now > info.launchTime) {
        trackedMinutes = (uint64_t)(now - info.launchTime) / 60;
        LOG("[Playtime] Internal tracking for app %u: %llu minutes (baseline=%llu)", appId, trackedMinutes, info.vdfBaseline);
    } else {
        LOG("[Playtime] No internal launch time for app %u, relying on VDF", appId);
    }

    // Read Steam's cumulative playtime from localconfig.vdf (if available).
    // Use Win32 API with shared access since Steam may have the file open.
    uint64_t vdfLastPlayed = 0, vdfPlaytime = 0, vdfPlaytime2wks = 0;
    {
        std::string vdfPath = g_steamPath + "userdata\\" + std::to_string(accountId)
            + "\\config\\localconfig.vdf";
        // Wide-API parity with the launch-time reader above; see UploadStatsOnExit.
        auto vdfPathWide = FileUtil::Utf8ToPath(vdfPath).wstring();
        HANDLE hFile = CreateFileW(vdfPathWide.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, nullptr);
            std::string vdfContent;
            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                vdfContent.resize(fileSize);
                DWORD bytesRead = 0;
                ReadFile(hFile, (LPVOID)vdfContent.data(), fileSize, &bytesRead, nullptr);
                vdfContent.resize(bytesRead);
            }
            CloseHandle(hFile);

            std::string appIdStr = std::to_string(appId);
            const char* sections[] = { "UserLocalConfigStore", "Software", "Valve", "Steam", "Apps", appIdStr.c_str() };
            bool sectionFound = VdfUtil::ForEachFieldInSection(vdfContent, sections, 6,
                [&](const VdfUtil::FieldInfo& fi) {
                    if (fi.key == "LastPlayed")
                        vdfLastPlayed = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                    else if (fi.key == "Playtime")
                        vdfPlaytime = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                    else if (fi.key == "Playtime2wks")
                        vdfPlaytime2wks = strtoull(std::string(fi.value).c_str(), nullptr, 10);
                    return true;
                });
            LOG("[Playtime] VDF for app %u: found=%d Playtime=%llu Playtime2wks=%llu LastPlayed=%llu (read %lu bytes)",
                appId, sectionFound, vdfPlaytime, vdfPlaytime2wks, vdfLastPlayed, (unsigned long)vdfContent.size());
        } else {
            LOG("[Playtime] Cannot open localconfig.vdf for app %u (err=%lu, path=%s)",
                appId, GetLastError(), vdfPath.c_str());
        }
    }

    // Use the launch-time VDF baseline if exit-side read came back empty.
    // Steam may not have flushed playtime to disk yet at exit time.
    if (vdfPlaytime == 0 && info.vdfBaseline > 0) {
        vdfPlaytime = info.vdfBaseline;
        LOG("[Playtime] Using launch-time VDF baseline for app %u: %llu min", appId, vdfPlaytime);
    }
    if (vdfPlaytime2wks == 0 && info.vdfBaseline2wks > 0) {
        vdfPlaytime2wks = info.vdfBaseline2wks;
        LOG("[Playtime] Using launch-time 2wks VDF baseline for app %u: %llu min", appId, vdfPlaytime2wks);
    }

    uint64_t lastPlayed = (trackedLastPlayed > vdfLastPlayed) ? trackedLastPlayed : vdfLastPlayed;

    // Merge with existing blob; CheckBlobExists distinguishes Missing (merge with empty) from Error (abort) -- RetrieveBlob alone would silently overwrite on transient failure.
    uint64_t cloudLastPlayed = 0, cloudPlaytime = 0, cloudPlaytime2wks = 0;
    auto acctScopeStatus = CloudStorage::CheckBlobExists(
        accountId, kAccountScopeAppId, AccountPlaytimeFilename(appId));
    if (acctScopeStatus == ICloudProvider::ExistsStatus::Error) {
        LOG("[Playtime] account-scope existence check returned Error for app %u; "
            "aborting upload to avoid stale-merge rollback", appId);
        return;
    }
    std::vector<uint8_t> ptData;
    if (acctScopeStatus == ICloudProvider::ExistsStatus::Exists) {
        ptData = CloudStorage::RetrieveBlob(accountId, kAccountScopeAppId,
                                             AccountPlaytimeFilename(appId));
        // Empty after Exists means the download itself failed; abort
        // matches the Error path above (our writer never emits empty).
        if (ptData.empty()) {
            LOG("[Playtime] account-scope retrieve returned empty after Exists for app %u; "
                "aborting upload to avoid stale-merge rollback", appId);
            return;
        }
    }
    if (!ptData.empty()) {
        std::string blob(reinterpret_cast<const char*>(ptData.data()), ptData.size());
        auto parsed = Json::Parse(blob);
        if (parsed.type == Json::Type::Object) {
            if (parsed.has("LastPlayed"))
                cloudLastPlayed = (parsed["LastPlayed"].type == Json::Type::Number)
                    ? (parsed["LastPlayed"].number() > 0 ? (uint64_t)parsed["LastPlayed"].number() : 0)
                    : strtoull(parsed["LastPlayed"].str().c_str(), nullptr, 10);
            if (parsed.has("Playtime"))
                cloudPlaytime = (parsed["Playtime"].type == Json::Type::Number)
                    ? (parsed["Playtime"].number() > 0 ? (uint64_t)parsed["Playtime"].number() : 0)
                    : strtoull(parsed["Playtime"].str().c_str(), nullptr, 10);
            if (parsed.has("Playtime2wks"))
                cloudPlaytime2wks = (parsed["Playtime2wks"].type == Json::Type::Number)
                    ? (parsed["Playtime2wks"].number() > 0 ? (uint64_t)parsed["Playtime2wks"].number() : 0)
                    : strtoull(parsed["Playtime2wks"].str().c_str(), nullptr, 10);
        } else {
            std::istringstream blobStream(blob);
            std::string blobLine;
            while (std::getline(blobStream, blobLine)) {
                size_t tab = blobLine.find('\t');
                if (tab == std::string::npos) continue;
                std::string key = blobLine.substr(0, tab);
                std::string val = blobLine.substr(tab + 1);
                if (key == "LastPlayed") cloudLastPlayed = strtoull(val.c_str(), nullptr, 10);
                else if (key == "Playtime") cloudPlaytime = strtoull(val.c_str(), nullptr, 10);
                else if (key == "Playtime2wks") cloudPlaytime2wks = strtoull(val.c_str(), nullptr, 10);
            }
        }
    }
    if (cloudPlaytime2wks == 0 && cloudPlaytime > 0)
        cloudPlaytime2wks = cloudPlaytime;

    // Playtime merge: baseline + session, but never less than VDF or cloud
    uint64_t mergedPlaytime = cloudPlaytime + trackedMinutes;
    if (vdfPlaytime > mergedPlaytime)
        mergedPlaytime = vdfPlaytime;
    if (info.vdfBaseline + trackedMinutes > mergedPlaytime)
        mergedPlaytime = info.vdfBaseline + trackedMinutes;
    uint64_t mergedPlaytime2wks = cloudPlaytime2wks + trackedMinutes;
    if (vdfPlaytime2wks > mergedPlaytime2wks)
        mergedPlaytime2wks = vdfPlaytime2wks;
    if (info.vdfBaseline2wks + trackedMinutes > mergedPlaytime2wks)
        mergedPlaytime2wks = info.vdfBaseline2wks + trackedMinutes;
    uint64_t mergedLastPlayed = (lastPlayed > cloudLastPlayed) ? lastPlayed : cloudLastPlayed;

    if (mergedPlaytime == 0 && mergedPlaytime2wks == 0 && mergedLastPlayed == 0) {
        LOG("[Playtime] No playtime data for app %u (no tracking, no VDF, no cloud)", appId);
        return;
    }

    Json::Value obj = Json::Object();
    obj.objVal["LastPlayed"] = Json::String(std::to_string(mergedLastPlayed));
    obj.objVal["Playtime"] = Json::String(std::to_string(mergedPlaytime));
    obj.objVal["Playtime2wks"] = Json::String(std::to_string(mergedPlaytime2wks));
    std::string blobStr = Json::Stringify(obj);

    // Account-scoped sentinel (appId=0): keeps blob out of per-app namespace so Steam never resolves it under an AutoCloud root. See cloud_metadata_paths.h.
    bool ok = CloudStorage::StoreBlob(accountId, kAccountScopeAppId,
        AccountPlaytimeFilename(appId),
        reinterpret_cast<const uint8_t*>(blobStr.data()), blobStr.size());
    LOG("[Playtime] Uploaded playtime for app %u (session=%llu min, baseline=%llu min, baseline2wks=%llu min, vdf=%llu min, vdf2wks=%llu min, cloud=%llu min, cloud2wks=%llu min, total=%llu min, 2wks=%llu min, LastPlayed=%llu, ok=%d)",
        appId, trackedMinutes, info.vdfBaseline, info.vdfBaseline2wks, vdfPlaytime, vdfPlaytime2wks,
        cloudPlaytime, cloudPlaytime2wks, mergedPlaytime, mergedPlaytime2wks, mergedLastPlayed, ok);

    if (ok) {
        CloudStorage::DeleteBlob(accountId, appId, kLegacyPlaytimeMetadataPath,
                                 /*keepTombstoneOnSuccess=*/true);
    }
}

// Slot 8 hook -- Notification wrapper (e.g. SignalAppExitSyncDone)
// request is a CProtoBufMsg* with body at +48, header at +40
static bool __fastcall NotificationWrapperHook(void* thisptr, const char* methodName, void* request) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalSlot8(thisptr, methodName, request);
    if (!methodName) {
        return g_originalSlot8(thisptr, methodName, request);
    }

    // Only intercept Cloud.* notifications
    if (strncmp(methodName, "Cloud.", 6) != 0) {
        return g_originalSlot8(thisptr, methodName, request);
    }

    // Extract body from CProtoBufMsg+48
    void* bodyObj = *(void**)((uintptr_t)request + 48);
    uint32_t realAppId = CheckNotificationNamespaceApp(methodName, bodyObj);

    if (realAppId == 0) {
        // Not a namespace app -- pass through to real Steam
        LOG("[VtHook-Notif] %s: not namespace, passing through", methodName);
        return g_originalSlot8(thisptr, methodName, request);
    }

    // On ExitSyncDone, upload stats and playtime to cloud before suppressing
    if (strcmp(methodName, RPC_EXIT_SYNC) == 0) {
        uint32_t capturedAppId = realAppId;
        std::thread t([capturedAppId] {
            if (g_syncAchievements) UploadStatsOnExit(capturedAppId);
            if (g_syncPlaytime) UploadPlaytimeOnExit(capturedAppId);
        });
        // Re-check shutdown under the same lock used to splice out the
        // vector, so we never push into an already-drained list.
        std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
        if (g_shuttingDown.load(std::memory_order_acquire)) {
            t.detach(); // OS reaps at process exit
        } else {
            g_bgThreads.push_back(std::move(t));
        }
    }

    // Namespace app - suppress the notification (don't send to Steam servers)
    LOG("[VtHook-Notif] SUPPRESSED %s app=%u (notification not sent to server)", methodName, realAppId);
    return true;  // Return success without actually sending
}

// Slot 7 hook -- Notification direct (e.g. ConflictResolution, TransferReport)
// bodyObj is the raw protobuf body (NOT wrapped in CProtoBufMsg)
static bool __fastcall NotificationDirectHook(void* thisptr, const char* methodName, void* bodyObj, int* flags) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    if (!methodName) {
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    // Only intercept Cloud.* notifications
    if (strncmp(methodName, "Cloud.", 6) != 0) {
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    uint32_t realAppId = CheckNotificationNamespaceApp(methodName, bodyObj);

    if (realAppId == 0) {
        // Not a namespace app -- pass through to real Steam
        LOG("[VtHook-Notif] %s (direct): not namespace, passing through", methodName);
        return g_originalSlot7(thisptr, methodName, bodyObj, flags);
    }

    // On ExitSyncDone, upload stats and playtime to cloud before suppressing
    if (strcmp(methodName, RPC_EXIT_SYNC) == 0) {
        uint32_t capturedAppId = realAppId;
        std::thread t([capturedAppId] {
            if (g_syncAchievements) UploadStatsOnExit(capturedAppId);
            if (g_syncPlaytime) UploadPlaytimeOnExit(capturedAppId);
        });
        // See NotificationHook (slot 8) above -- same shutdown-window race.
        std::lock_guard<std::mutex> lock(g_bgThreadsMutex);
        if (g_shuttingDown.load(std::memory_order_acquire)) {
            t.detach();
        } else {
            g_bgThreads.push_back(std::move(t));
        }
    }

    // Namespace app - suppress the notification
    LOG("[VtHook-Notif] SUPPRESSED %s app=%u (direct notification not sent to server)", methodName, realAppId);
    return true;
}

// Install the vtable hook on CClientUnifiedServiceTransport
static void InstallServiceMethodHook() {
    if (g_vtableHookInstalled.load(std::memory_order_acquire) || !g_steamClientBase) return;

    // Resolve function pointers
    g_parseFromArray = (ParseFromArrayFn)(g_steamClientBase + SC_RVA_PARSE_FROM_ARRAY);
    g_serializeToArray = (SerializeToArrayFn)(g_steamClientBase + SC_RVA_SERIALIZE_TO_ARRAY);

    LOG("[VtHook] ParseFromArray=%p SerializeToArray=%p",
        g_parseFromArray, g_serializeToArray);

    // Read slot 4 (request/response direct)
    uintptr_t vtableSlot4Addr = g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT4;

    ServiceMethodSlot4Fn currentSlot4 = nullptr;
    __try {
        currentSlot4 = *(ServiceMethodSlot4Fn*)vtableSlot4Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 4: code=0x%08X", GetExceptionCode());
        return;
    }

    if (!currentSlot4) {
        LOG("[VtHook] Vtable slot 4 is NULL at %p", (void*)vtableSlot4Addr);
        return;
    }

    g_originalSlot4 = currentSlot4;
    LOG("[VtHook] Original slot 4: %p (RVA=0x%llX)",
        (void*)currentSlot4, (uint64_t)((uintptr_t)currentSlot4 - g_steamClientBase));

    // Patch slot 5 (request/response wrapper)
    uintptr_t vtableSlot5Addr = g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT5;

    ServiceMethodSlot5Fn currentSlot5 = nullptr;
    __try {
        currentSlot5 = *(ServiceMethodSlot5Fn*)vtableSlot5Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 5: code=0x%08X", GetExceptionCode());
        return;
    }

    if (!currentSlot5) {
        LOG("[VtHook] Vtable slot 5 is NULL at %p", (void*)vtableSlot5Addr);
        return;
    }

    g_originalSlot5 = currentSlot5;
    LOG("[VtHook] Original slot 5: %p (RVA=0x%llX)",
        (void*)currentSlot5, (uint64_t)((uintptr_t)currentSlot5 - g_steamClientBase));

    // Patch slot 7 (notification direct)
    uintptr_t vtableSlot7Addr = g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT7;

    NotificationSlot7Fn currentSlot7 = nullptr;
    __try {
        currentSlot7 = *(NotificationSlot7Fn*)vtableSlot7Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 7: code=0x%08X", GetExceptionCode());
        return;
    }

    if (!currentSlot7) {
        LOG("[VtHook] Vtable slot 7 is NULL at %p", (void*)vtableSlot7Addr);
        return;
    }

    g_originalSlot7 = currentSlot7;
    LOG("[VtHook] Original slot 7: %p (RVA=0x%llX)",
        (void*)currentSlot7, (uint64_t)((uintptr_t)currentSlot7 - g_steamClientBase));

    // Patch slot 8 (notification wrapper)
    uintptr_t vtableSlot8Addr = g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT8;

    NotificationSlot8Fn currentSlot8 = nullptr;
    __try {
        currentSlot8 = *(NotificationSlot8Fn*)vtableSlot8Addr;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[VtHook] EXCEPTION reading slot 8: code=0x%08X", GetExceptionCode());
        return;
    }

    if (!currentSlot8) {
        LOG("[VtHook] Vtable slot 8 is NULL at %p", (void*)vtableSlot8Addr);
        return;
    }

    g_originalSlot8 = currentSlot8;
    LOG("[VtHook] Original slot 8: %p (RVA=0x%llX)",
        (void*)currentSlot8, (uint64_t)((uintptr_t)currentSlot8 - g_steamClientBase));

    // Make vtable region writable and patch all four slots
    // Slots 4, 5, 7, 8 span from slot 4 (offset 0x20) to slot 8 (offset 0x40 + 8)
    // Total region: slot 4 addr to slot 8 addr + sizeof(void*) 
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
    g_vtableHookInstalled.store(slot4Ok && slot5Ok && slot7Ok && slot8Ok, std::memory_order_release);

    LOG("[VtHook] Vtable slot 4 patched: %p -> %p (ok=%d)", (void*)currentSlot4, (void*)ServiceMethodDirectHook, slot4Ok);
    LOG("[VtHook] Vtable slot 5 patched: %p -> %p (ok=%d)", (void*)currentSlot5, (void*)ServiceMethodHook, slot5Ok);
    LOG("[VtHook] Vtable slot 7 patched: %p -> %p (ok=%d)", (void*)currentSlot7, (void*)NotificationDirectHook, slot7Ok);
    LOG("[VtHook] Vtable slot 8 patched: %p -> %p (ok=%d)", (void*)currentSlot8, (void*)NotificationWrapperHook, slot8Ok);

    if (g_vtableHookInstalled.load(std::memory_order_acquire)) {
        LOG("[VtHook] All hooks ACTIVE -- Cloud RPCs (slots 4/5/7/8) will be intercepted at vtable level");
    } else {
        LOG("[VtHook] WARNING: Some hooks failed! slot4=%d slot5=%d slot7=%d slot8=%d", slot4Ok, slot5Ok, slot7Ok, slot8Ok);
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
    __try {
        arrayBase = *reinterpret_cast<uint8_t**>(vec);
        count = *reinterpret_cast<int*>(vec + 16);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
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

    __try {
        for (int i = 0; i < count; i++) {
            uint8_t* entry = arrayBase + static_cast<size_t>(i) * 32;
            uint32_t depotId = *reinterpret_cast<uint32_t*>(entry);
            auto pinIt = depotPins.find(depotId);
            if (pinIt != depotPins.end()) {
                uint64_t* pManifestId = reinterpret_cast<uint64_t*>(entry + 8);
                uint64_t oldManifest = *pManifestId;
                if (oldManifest != pinIt->second) {
                    *pManifestId = pinIt->second;
                    LOG("[ManifestPin] app %u depot %u (%s): manifest %llu -> %llu",
                        appId, depotId, vecName, oldManifest, pinIt->second);
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG("[ManifestPin] PatchDepotVector(%s): faulted iterating entries for app %u (count=%d)",
            vecName, appId, count);
    }
}

static __int64 __fastcall BuildDepotDependencyHook(__int64* a1, unsigned int a2, __int64 a3,
                                                    __int64 a4, __int64 a5, __int64 a6,
                                                    uint32_t* a7, uint8_t* a8) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire) || !g_origBuildDepotDependency)
        return g_origBuildDepotDependency ? g_origBuildDepotDependency(a1, a2, a3, a4, a5, a6, a7, a8) : 0;

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

// RecvPkt monitor hook (logging + Approach D injection drain)
static int64_t __fastcall RecvPktMonitorHook(void* thisptr, CNetPacket* pkt) {
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire))
        return g_originalRecvPkt(thisptr, pkt);
    // Network-recv thread is the only one that can BRouteMsgToJob the original coroutines. Snapshot under g_injectMutex, process unlocked (resumed coroutine may re-enter InjectResponse).
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
            LOG("[RecvMon] WARNING: injection drain loop hit %d iteration limit", kMaxDrainIterations);
        }
    }

    if (!pkt || !pkt->pubData || pkt->cubData < 8)
        return g_originalRecvPkt(thisptr, pkt);

    uint32_t emsgRaw;
    memcpy(&emsgRaw, pkt->pubData, 4);
    uint32_t emsg = emsgRaw & EMSG_MASK;

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
                            // file entry submessage -- parse recursively
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
                                        // sha -- log as hex
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
// Manifest entry: { "file.lua": { "mod": ts, "del": ts } }; del > mod = deleted (timestamps prevent ping-pong).
// .sync_state: line 1 = lastSyncTime, remaining lines = files this machine knows about.

static constexpr uint32_t LUA_SYNC_APPID = 0;

struct SyncState {
    uint64_t lastSyncTime = 0;
    std::unordered_set<std::string> files;
};

static std::string GetLuaSyncStatePath() {
    return g_steamPath + "config\\stplug-in\\.sync_state";
}

static SyncState ReadSyncState() {
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

    // 1. Download + parse cloud manifest
    auto manifestData = CloudStorage::RetrieveBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json");
    auto cloudManifest = ParseManifest(manifestData);

    // 2. Download cloud archive if there are alive entries
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

    // 3. Read local sync state
    auto syncState = ReadSyncState();
    uint64_t lastSync = syncState.lastSyncTime;

    // 4. Read local lua files
    auto localFiles = ReadLocalLuaFiles();
    std::unordered_map<std::string, uint64_t> localByName; // filename -> modTime
    for (auto& lf : localFiles) localByName[lf.filename] = lf.modTime;

    int extracted = 0, deletedLocally = 0, addedToCloud = 0, markedDeleted = 0;
    bool manifestChanged = false;

    // 5. Process cloud manifest entries
    for (auto& [filename, entry] : cloudManifest) {
        if (!IsValidLuaFilename(filename)) {
            LOG("[LuaSync] Skipping invalid manifest entry: %s", filename.c_str());
            continue;
        }
        bool onDisk = localByName.count(filename) > 0;
        bool inSyncState = syncState.files.count(filename) > 0;

        if (entry.isDeleted()) {
            // Cloud says deleted
            if (onDisk && lastSync > 0 && entry.del > lastSync) {
                // Deleted on another machine after our last sync -- delete locally
                std::string path = luaDir + filename;
                // Wide-API: DeleteFileA's ACP narrowing fails with ERROR_FILE_NOT_FOUND on non-ASCII installs, stranding the stale lua.
                auto pathWide = FileUtil::Utf8ToPath(path).wstring();
                if (DeleteFileW(pathWide.c_str())) {
                    deletedLocally++;
                    localByName.erase(filename);
                    LOG("[LuaSync] Deleted locally (remote deletion): %s", filename.c_str());
                }
            }
            // If not on disk or deletion is old, no action
        } else {
            // Cloud says alive
            if (!onDisk && !inSyncState) {
                // New file for this machine
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
            } else if (!onDisk && inSyncState) {
                // User deleted locally -- mark as deleted in cloud
                entry.del = now;
                markedDeleted++;
                manifestChanged = true;
                LOG("[LuaSync] User deleted %s, marking deleted in cloud", filename.c_str());
            }
        }
    }

    // 6. Re-read local files if we extracted or deleted anything
    if (extracted > 0 || deletedLocally > 0) {
        localFiles = ReadLocalLuaFiles();
        localByName.clear();
        for (auto& lf : localFiles) localByName[lf.filename] = lf.modTime;

        if (extracted > 0) {
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

    // 7. Add new local files to manifest
    for (auto& [filename, modTime] : localByName) {
        auto it = cloudManifest.find(filename);
        if (it == cloudManifest.end()) {
            cloudManifest[filename] = { modTime, 0 };
            addedToCloud++;
            manifestChanged = true;
        } else if (it->second.isDeleted()) {
            // File exists locally but cloud says deleted -- local wins (re-added)
            it->second.mod = modTime;
            it->second.del = 0;
            addedToCloud++;
            manifestChanged = true;
            LOG("[LuaSync] Re-added %s (was deleted in cloud)", filename.c_str());
        }
    }

    // 8. Upload if anything changed
    bool needUpload = manifestChanged || extracted > 0 || deletedLocally > 0;
    if (!needUpload && cloudManifest.empty() && !localFiles.empty()) {
        needUpload = true;
        LOG("[LuaSync] Cloud empty, seeding %zu lua files", localFiles.size());
        for (auto& lf : localFiles)
            cloudManifest[lf.filename] = { lf.modTime, 0 };
    }

    if (needUpload) {
        // Build archive from alive files only
        std::vector<LuaFile> aliveFiles;
        for (auto& lf : localFiles) {
            auto it = cloudManifest.find(lf.filename);
            if (it != cloudManifest.end() && !it->second.isDeleted())
                aliveFiles.push_back(lf);
        }

        if (!aliveFiles.empty()) {
            auto zipData = CreateLuaZip(aliveFiles);
            if (!zipData.empty()) {
                CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID,
                    "LuaArchive.zip", zipData.data(), zipData.size());
                LOG("[LuaSync] Uploaded archive: %zu files, %zu bytes zip",
                    aliveFiles.size(), zipData.size());
            }
        } else {
            CloudStorage::DeleteBlob(accountId, LUA_SYNC_APPID, "LuaArchive.zip");
        }

        std::string manifestStr = SerializeManifest(cloudManifest);
        CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json",
            reinterpret_cast<const uint8_t*>(manifestStr.data()), manifestStr.size());
    }

    // 9. Update sync state
    std::unordered_set<std::string> newFiles;
    for (auto& [filename, entry] : cloudManifest) {
        if (!entry.isDeleted()) newFiles.insert(filename);
    }
    WriteSyncState(now, newFiles);

    LOG("[LuaSync] Sync complete: %d extracted, %d deleted locally, %d added to cloud, %d marked deleted",
        extracted, deletedLocally, addedToCloud, markedDeleted);
}

// Shutdown upload: captures local changes (additions + deletions) to cloud.
// Downloads manifest first to detect local deletions and set timestamps.
static void UploadLuaOnShutdown() {
    if (!CloudStorage::IsCloudActive()) return;
    uint32_t accountId = GetAccountId();
    if (!accountId) return;

    uint64_t now = NowUnix();

    // Download current cloud manifest to compare against
    auto manifestData = CloudStorage::RetrieveBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json");
    auto cloudManifest = ParseManifest(manifestData);

    auto localFiles = ReadLocalLuaFiles();
    std::unordered_map<std::string, uint64_t> localByName;
    for (auto& lf : localFiles) localByName[lf.filename] = lf.modTime;

    bool changed = false;

    // Mark cloud-alive files that are no longer on disk as deleted
    for (auto& [filename, entry] : cloudManifest) {
        if (!entry.isDeleted() && localByName.count(filename) == 0) {
            entry.del = now;
            changed = true;
            LOG("[LuaSync] Shutdown: marking %s as deleted", filename.c_str());
        }
    }

    // Add new local files
    for (auto& [filename, modTime] : localByName) {
        auto it = cloudManifest.find(filename);
        if (it == cloudManifest.end()) {
            cloudManifest[filename] = { modTime, 0 };
            changed = true;
        } else if (it->second.isDeleted()) {
            it->second.mod = modTime;
            it->second.del = 0;
            changed = true;
        }
    }

    if (!changed && !cloudManifest.empty()) {
        LOG("[LuaSync] Shutdown: no changes to upload");
        // Still update sync state time
        std::unordered_set<std::string> newFiles;
        for (auto& [f, e] : cloudManifest) { if (!e.isDeleted()) newFiles.insert(f); }
        WriteSyncState(now, newFiles);
        return;
    }

    // Upload archive (alive files only)
    std::vector<LuaFile> aliveFiles;
    for (auto& lf : localFiles) {
        auto it = cloudManifest.find(lf.filename);
        if (it != cloudManifest.end() && !it->second.isDeleted())
            aliveFiles.push_back(lf);
    }

    if (!aliveFiles.empty()) {
        auto zipData = CreateLuaZip(aliveFiles);
        if (!zipData.empty()) {
            CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID,
                "LuaArchive.zip", zipData.data(), zipData.size());
        }
    }

    // Upload manifest (includes deletion markers)
    std::string manifestStr = SerializeManifest(cloudManifest);
    CloudStorage::StoreBlob(accountId, LUA_SYNC_APPID, "LuaManifest.json",
        reinterpret_cast<const uint8_t*>(manifestStr.data()), manifestStr.size());

    // Update sync state
    std::unordered_set<std::string> newFiles;
    for (auto& [f, e] : cloudManifest) { if (!e.isDeleted()) newFiles.insert(f); }
    WriteSyncState(now, newFiles);

    LOG("[LuaSync] Shutdown upload: %zu alive, %zu total manifest entries",
        localFiles.size(), cloudManifest.size());
}

// Expected Steam client version -- patches and RVAs are only valid for this build
static constexpr uint64_t EXPECTED_STEAM_VERSION = 1773426488ULL;

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
        // format: "version"		"1773426488"
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

// Stage cached UserGameStats into appcache/stats/ before Steam's one-shot startup load.
static void PreStageStatsFromLocalCache(const std::string& steamPath) {
    std::string storageRoot = steamPath + "cloud_redirect\\storage\\";
    std::string statsRoot = steamPath + "appcache\\stats\\";

    auto storageRootWide = FileUtil::Utf8ToPath(storageRoot).wstring();
    DWORD attrs = GetFileAttributesW(storageRootWide.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        return;

    auto statsRootWide = FileUtil::Utf8ToPath(statsRoot).wstring();
    if (GetFileAttributesW(statsRootWide.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::error_code ec;
        std::filesystem::create_directories(FileUtil::Utf8ToPath(statsRoot), ec);
    }

    int staged = 0;
    int skipped = 0;
    WIN32_FIND_DATAW acctFd;
    HANDLE hAcct = FindFirstFileW((storageRootWide + L"*").c_str(), &acctFd);
    if (hAcct == INVALID_HANDLE_VALUE) return;
    do {
        if (!(acctFd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        std::wstring acctName = acctFd.cFileName;
        if (acctName == L"." || acctName == L"..") continue;
        bool allDigits = !acctName.empty();
        for (wchar_t c : acctName) { if (c < L'0' || c > L'9') { allDigits = false; break; } }
        if (!allDigits) continue;

        std::wstring statsDir = storageRootWide + acctName + L"\\0\\UserGameStats\\";
        if (GetFileAttributesW(statsDir.c_str()) == INVALID_FILE_ATTRIBUTES) continue;

        WIN32_FIND_DATAW appFd;
        HANDLE hApp = FindFirstFileW((statsDir + L"*.bin").c_str(), &appFd);
        if (hApp == INVALID_HANDLE_VALUE) continue;
        do {
            if (appFd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring appBin = appFd.cFileName;
            if (appBin.size() < 5) continue;
            std::wstring appStem = appBin.substr(0, appBin.size() - 4);
            bool appDigits = !appStem.empty();
            for (wchar_t c : appStem) { if (c < L'0' || c > L'9') { appDigits = false; break; } }
            if (!appDigits) continue;

            std::wstring srcPath = statsDir + appBin;
            std::wstring dstPath = statsRootWide + L"UserGameStats_" + acctName + L"_" + appStem + L".bin";

            // Steam writes a 38 B empty stub for unloaded apps; skip anything bigger.
            WIN32_FILE_ATTRIBUTE_DATA dstAttr{};
            bool dstExists = GetFileAttributesExW(dstPath.c_str(),
                GetFileExInfoStandard, &dstAttr) != 0;
            if (dstExists) {
                ULARGE_INTEGER dstSize;
                dstSize.LowPart = dstAttr.nFileSizeLow;
                dstSize.HighPart = dstAttr.nFileSizeHigh;
                if (dstSize.QuadPart > 64) {
                    skipped++;
                    continue;
                }
            }

            if (CopyFileW(srcPath.c_str(), dstPath.c_str(), FALSE)) {
                staged++;
            } else {
                LOG("[PreStage] CopyFile failed: %ls -> %ls (err=%lu)",
                    srcPath.c_str(), dstPath.c_str(), GetLastError());
            }
        } while (FindNextFileW(hApp, &appFd));
        FindClose(hApp);
    } while (FindNextFileW(hAcct, &acctFd));
    FindClose(hAcct);

    if (staged > 0 || skipped > 0)
        LOG("[PreStage] Staged %d UserGameStats files from local cache (skipped %d non-empty)", staged, skipped);
}

void Init(const std::string& steamPath) {
    g_steamPath = steamPath;
    if (!g_steamPath.empty() && g_steamPath.back() != '\\')
        g_steamPath += '\\';

    // ── Steam version gate ──────────────────────────────────────────────
    uint64_t detectedVersion = ReadSteamVersion(g_steamPath);
    if (detectedVersion == 0) {
        LOG("FATAL: Could not read Steam version from manifest");

        MessageBoxA(nullptr,
            "CloudRedirect could not determine the installed Steam version.\n\n"
            "The manifest file may be missing or unreadable.\n\n"
            "CloudRedirect will NOT activate.",
            "CloudRedirect -- Version Unknown",
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return;
    } else if (detectedVersion != EXPECTED_STEAM_VERSION) {
        bool steamIsNewer = detectedVersion > EXPECTED_STEAM_VERSION;
        LOG("FATAL: Steam version mismatch! expected=%llu actual=%llu (%s)",
            EXPECTED_STEAM_VERSION, detectedVersion,
            steamIsNewer ? "Steam is newer" : "Steam is older");

        char msg[512];
        if (steamIsNewer) {
            snprintf(msg, sizeof(msg),
                "Your Steam client (version %llu) is newer than what "
                "CloudRedirect supports (version %llu).\n\n"
                "Update CloudRedirect to match your Steam version.\n\n"
                "CloudRedirect will NOT activate.",
                detectedVersion, EXPECTED_STEAM_VERSION);
        } else {
            snprintf(msg, sizeof(msg),
                "Your Steam client (version %llu) is older than what "
                "CloudRedirect expects (version %llu).\n\n"
                "Update Steam to match your CloudRedirect version.\n\n"
                "CloudRedirect will NOT activate.",
                detectedVersion, EXPECTED_STEAM_VERSION);
        }

        MessageBoxA(nullptr, msg, "CloudRedirect -- Version Mismatch",
                    MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return;  // abort initialization -- no hooks installed
    } else {
        LOG("Steam version: %llu (OK)", detectedVersion);
    }

    PreStageStatsFromLocalCache(g_steamPath);

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

            if (pinCfg["manifest_pinning"].type == Json::Type::Bool)
                g_manifestPinsEnabled = pinCfg["manifest_pinning"].boolean();
            if (pinCfg["auto_comment"].type == Json::Type::Bool)
                g_autoComment = pinCfg["auto_comment"].boolean();

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
        } else {
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
            // Manual increment with error_code; range-for throws on permission
            // errors and would kill Steam on the DLL init thread.
            std::filesystem::recursive_directory_iterator it(oldRootPath, ec);
            const std::filesystem::recursive_directory_iterator end;
            while (!ec && it != end) {
                const auto& entry = *it;
                std::error_code regEc;
                if (entry.is_regular_file(regEc)) {
                    std::error_code relEc;
                    auto rel = std::filesystem::relative(entry.path(), oldRootPath, relEc);
                    if (!relEc) {
                        auto dest = FileUtil::Utf8ToPath(newRoot) / rel;
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

    // init CloudStorage manager -- read config to determine cloud provider
    std::unique_ptr<ICloudProvider> provider;

    // Config lives in %AppData%/CloudRedirect/config.json (per-user)
    std::string configPath;
    {
        char appdata[MAX_PATH];
        if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) == S_OK) {
            configPath = std::string(appdata) + "\\CloudRedirect\\config.json";
        } else {
            configPath = cloudRoot + "config.json";
            LOG("[NS] WARNING: Could not resolve %%APPDATA%%, falling back to steam folder for config");
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
                        std::thread t([name]() {
                            MessageBoxA(nullptr,
                                (name + " is configured but you haven't signed in yet.\n\n"
                                 "Your saves will be stored locally but will NOT sync to the cloud.\n\n"
                                 "Open the CloudRedirect app and sign in on the Cloud Provider page.").c_str(),
                                "CloudRedirect - Cloud Provider Not Authenticated",
                                MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
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

        if (cfg["sync_achievements"].type == Json::Type::Bool)
            g_syncAchievements = cfg["sync_achievements"].boolean();
        if (cfg["sync_playtime"].type == Json::Type::Bool)
            g_syncPlaytime = cfg["sync_playtime"].boolean();
        if (cfg["sync_luas"].type == Json::Type::Bool)
            g_syncLuas = cfg["sync_luas"].boolean();
        LOG("[NS] Sync toggles: achievements=%d, playtime=%d, luas=%d",
            g_syncAchievements.load(), g_syncPlaytime.load(), g_syncLuas.load());
    } else {
        LOG("[NS] No config.json at %s -- local-only mode", configPath.c_str());
    }

    CloudStorage::Init(cloudRoot, std::move(provider));
    g_startupMetadataScheduled.store(false);

    // Launch deferred lua sync thread (waits for accountId to be captured).
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

// InstallRecvPktMonitor / SetSendPktAddr
void InstallRecvPktMonitor(void* savedOrigPtrAddr) {
    if (!savedOrigPtrAddr) {
        LOG("InstallRecvPktMonitor: saved original ptr addr is null");
        return;
    }
    auto* slot = reinterpret_cast<RecvPktFn*>(savedOrigPtrAddr);
    g_originalRecvPkt = *slot;
    LOG("InstallRecvPktMonitor: original RecvPkt at slot %p = %p", savedOrigPtrAddr, g_originalRecvPkt);

    DWORD oldProt;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProt)) {
        LOG("InstallRecvPktMonitor: VirtualProtect failed (%u)", GetLastError());
        return;
    }
    *slot = RecvPktMonitorHook;
    VirtualProtect(slot, sizeof(void*), oldProt, &oldProt);
    // Remember the slot only on success so shutdown never restores an
    // unpatched slot.
    g_recvPktSlot = reinterpret_cast<void**>(slot);
    RecvPktFn readback = *slot;
    LOG("InstallRecvPktMonitor: hooked -> %p (readback=%p, match=%d)",
        RecvPktMonitorHook, readback, readback == RecvPktMonitorHook);
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

    uintptr_t scBase = reinterpret_cast<uintptr_t>(hSteamClient);
    g_bddOrigAddr = reinterpret_cast<uint8_t*>(scBase + SC_RVA_BUILD_DEPOT_DEPENDENCY);
    LOG("[ManifestPin] Target: steamclient64!BuildDepotDependency at %p (base %p + 0x%X)",
        g_bddOrigAddr, hSteamClient, SC_RVA_BUILD_DEPOT_DEPENDENCY);

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

void SetSendPktAddr(void* recvPktGlobalAddr) {
    if (!recvPktGlobalAddr) {
        LOG("[NS] SetSendPktAddr: recvPktGlobalAddr is null");
        return;
    }

    g_payloadBase = (uintptr_t)recvPktGlobalAddr - RVA_RECV_PKT_GLOBAL;
    LOG("[NS] payload_base=%p", (void*)g_payloadBase);
}

// OnSendPkt
// When vtable hook (Approach E) is active: only handles CCMInterface discovery,
// SteamID capture, and logging. Namespace Cloud RPCs are intercepted by the vtable hook.
// When vtable hook is NOT active: falls back to Approach D (packet injection).
bool OnSendPkt(void* thisptr, const uint8_t* data, uint32_t size) {
    if (!g_cloudRedirectEnabled.load(std::memory_order_relaxed)) return false;
    if (g_proxySending) return false;
    // After Shutdown() the receive thread is gone; refuse new pushes so
    // queued buffers don't leak.
    if (g_shuttingDown.load(std::memory_order_acquire)) return false;

    // Try to discover the real CCMInterface via CSteamEngine global.
    // This also installs the vtable hook once CCMInterface is found.
    TryFindCCMInterface();

    PacketView pkt;
    if (!ParsePacket(data, size, pkt)) return false;
    if (pkt.emsg != EMSG_SERVICE_METHOD) return false;

    auto methodSv = PB::GetString(pkt.header, HDR_TARGET_JOB_NAME);
    if (methodSv.empty()) return false;

    // Fast early-out: only care about Cloud.* methods (zero-alloc via string_view)
    bool isCloudMethod = (methodSv.size() >= 6 && methodSv.substr(0, 6) == "Cloud.");

    uint64_t jobSrc = GetJobIdSource(pkt.header);

    // capture SteamID and SessionID from first packet
    if (g_steamId.load() == 0) {
        auto* sidField = PB::FindField(pkt.header, HDR_STEAMID);
        if (sidField) {
            g_steamId.store(sidField->varintVal);
            LOG("[NS] Captured SteamID: %llu (accountId=%u)", g_steamId.load(), GetAccountId());
            HttpServer::SetAccountId(GetAccountId());
            ScheduleStartupMetadataSync();
        }
        auto* sessField = PB::FindField(pkt.header, HDR_SESSIONID);
        if (sessField) {
            g_sessionId.store((int32_t)sessField->varintVal);
        }
    }

    // With slots 4+5 hooked, namespace Cloud RPCs should not reach SendPkt;
    // log and fall through to Approach D as a safety net if they do.
    static std::atomic<int> g_approachDFallbackCount{0};
    if (g_vtableHookInstalled.load(std::memory_order_acquire)) {
        if (isCloudMethod) {
            auto innerFields = PB::Parse(pkt.bodyData, pkt.bodyLen);
            // Need null-terminated string for ExtractAppId and LOG
            std::string method(methodSv);
            uint32_t appId = ExtractAppId(method.c_str(), innerFields);

            // Check if this is a namespace app that needs local handling
            bool isNs = IsNamespaceApp(appId);

            if (isNs) {
                // Namespace app Cloud RPC reached SendPkt despite slot 4+5 hooks -- unexpected!
                int count = ++g_approachDFallbackCount;
                LOG("[SendPkt] WARNING: %s app=%u (%u bytes) escaped vtable hooks! "
                    "Using Approach D fallback (occurrence #%d)",
                    method.c_str(), appId, pkt.bodyLen, count);
                // Fall through to Approach D below
            } else {
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
        LOG("[NS] ConflictResolution notification");
#ifdef DEBUG_VERBOSE_LOGGING
        SpyLogFields("[Conflict]", pkt.bodyData, pkt.bodyLen);
#endif
        return false;
    }

    auto innerFields = PB::Parse(pkt.bodyData, pkt.bodyLen);
    uint32_t appId = ExtractAppId(method.c_str(), innerFields);
    if (appId == 0) return false;

    // check if this is a Cloud RPC we handle
    bool isCloudRpc = (method == RPC_GET_CHANGELIST || method == RPC_BEGIN_BATCH ||
                       method == RPC_BEGIN_UPLOAD || method == RPC_COMMIT_UPLOAD ||
                       method == RPC_FILE_DOWNLOAD || method == RPC_DELETE_FILE ||
                       method == RPC_COMPLETE_BATCH || method == RPC_QUOTA_USAGE ||
                       method == RPC_LAUNCH_INTENT);
    if (!isCloudRpc) return false;

    // detect namespace app: either direct appid match, or SteamTools rewrote to proxy
    uint32_t realAppId = 0;
    bool isNamespace = false;

    if (IsNamespaceApp(appId)) {
        realAppId = appId;
        isNamespace = true;
    }

    if (!isNamespace) {
        // not a namespace app -- log and pass through
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

    PB::Writer responseBody;

    auto dispatched = DispatchCloudRpc(method.c_str(), realAppId, innerFields);
    if (!dispatched.has_value()) {
        LOG("[NS-D] Unhandled method %s, passing through", method.c_str());
        return false;
    }
    responseBody = std::move(*dispatched);

    // inject fabricated response via queue (old Approach D)
    if (!InjectResponse(jobSrc, method, 1 /*eresult=success*/, responseBody)) {
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
    int spinCount = 0;
    while (g_hookRefCount.load(std::memory_order_acquire) > 0) {
        Sleep(1);
        if (++spinCount > 5000) { // 5 seconds max
            LOG("Shutdown: timed out waiting for %d in-flight hooks", g_hookRefCount.load());
            break;
        }
    }

    // Restore vtable pointers before DLL unload, but skip if steamclient64
    // is gone (Steam's clean exit FreeLibrarys it before ExitProcess; the
    // cached base then points at unmapped memory and VirtualProtect 487s).
    if (g_vtableHookInstalled.load(std::memory_order_acquire) && g_steamClientBase) {
        HMODULE currentSC = GetModuleHandleA("steamclient64.dll");
        if (!currentSC) {
            LOG("Shutdown: steamclient64.dll already unloaded, skipping vtable restore");
            g_vtableHookInstalled.store(false, std::memory_order_release);
        } else if ((uintptr_t)currentSC != g_steamClientBase) {
            LOG("Shutdown: steamclient64.dll base changed (%p -> %p), skipping vtable restore",
                (void*)g_steamClientBase, (void*)currentSC);
            g_vtableHookInstalled.store(false, std::memory_order_release);
        } else {
            uintptr_t vtableSlot4Addr = g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT4;
            uintptr_t vtableSlot8Addr = g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT8;
            uintptr_t regionStart = vtableSlot4Addr;
            size_t regionSize = (vtableSlot8Addr + sizeof(void*)) - vtableSlot4Addr;

            DWORD oldProt;
            if (VirtualProtect((void*)regionStart, regionSize, PAGE_READWRITE, &oldProt)) {
                if (g_originalSlot4) *(ServiceMethodSlot4Fn*)vtableSlot4Addr = g_originalSlot4;
                if (g_originalSlot5) *(ServiceMethodSlot5Fn*)(g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT5) = g_originalSlot5;
                if (g_originalSlot7) *(NotificationSlot7Fn*)(g_steamClientBase + SC_RVA_SERVICE_TRANSPORT_SLOT7) = g_originalSlot7;
                if (g_originalSlot8) *(NotificationSlot8Fn*)vtableSlot8Addr = g_originalSlot8;
                VirtualProtect((void*)regionStart, regionSize, oldProt, &oldProt);
                g_vtableHookInstalled.store(false, std::memory_order_release);
                LOG("Shutdown: restored vtable slots 4/5/7/8");
            } else {
                LOG("Shutdown: VirtualProtect failed restoring vtable (%u)", GetLastError());
            }
        }
    }

    // Restore the RecvPkt vtable slot in clientservice.dll. InstallRecvPktMonitor
    // saved the slot address into g_recvPktSlot only on its success path, so a
    // failed install leaves g_recvPktSlot null and we skip cleanly.
    if (g_recvPktSlot && g_originalRecvPkt) {
        DWORD oldProt;
        if (VirtualProtect(g_recvPktSlot, sizeof(void*), PAGE_READWRITE, &oldProt)) {
            *g_recvPktSlot = reinterpret_cast<void*>(g_originalRecvPkt);
            VirtualProtect(g_recvPktSlot, sizeof(void*), oldProt, &oldProt);
            LOG("Shutdown: restored RecvPkt slot (%p -> %p)", g_recvPktSlot, g_originalRecvPkt);
        } else {
            LOG("Shutdown: VirtualProtect failed restoring RecvPkt slot (%u)", GetLastError());
        }
        g_recvPktSlot = nullptr;
    }

    // No new InjectResponse pushes can land after vtable restore + ref spin;
    // drop any pre-shutdown enqueues since RecvPktMonitorHook now bails.
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
    CloudStorage::DrainQueue();

    HttpServer::Stop();
    CloudStorage::Shutdown();
    LOG("CloudIntercept shutdown complete");
}

} // namespace CloudIntercept
