#include "cloud_hooks.h"
#include "cloud_intercept.h"
#include "stats_hooks.h"
#include "gamesplayed_hook.h"
#include "live_playtime.h"
#include "achievement_inject.h"
#include "stats_store.h"
#include "stats_handlers.h"
#include "metadata_sync.h"
#include "rpc_handlers.h"
#include "app_state.h"
#include "local_storage.h"
#include "pending_ops_journal.h"
#include "cloud_storage.h"
#include "cloud_provider.h"
#include "http_server.h"
#include "protobuf.h"
#include "json.h"
#include "log.h"

#include <cstring>
#include <climits>
#include <fstream>
#include <atomic>
#include <mutex>
#include <optional>
#include <setjmp.h>
#include <signal.h>
#include <thread>
#include <vector>
#include <unistd.h>

// 32-bit Linux cdecl: all args on stack
using BYieldingSend_t     = int(*)(void* pThis, const char* method, void* req, void* resp, int* flags);
using NotificationDirect_t = int(*)(void* pThis, const char* method, void* body, int* flags);
using SyncSend2_t         = int(*)(void* pThis, const char* method, void* buf, unsigned int bufLen, void* resp, int* flags);

static std::atomic<BYieldingSend_t>      g_origBYieldingSend{nullptr};
static std::atomic<NotificationDirect_t> g_origNotificationDirect{nullptr};
static std::atomic<SyncSend2_t>          g_origSyncSend2{nullptr};

static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_shuttingDown{false};
static std::atomic<int>  g_hookRefCount{0};

struct HookGuard {
    HookGuard() { g_hookRefCount.fetch_add(1, std::memory_order_acquire); }
    ~HookGuard() { g_hookRefCount.fetch_sub(1, std::memory_order_release); }
};

extern "C" void CR_SetCrashContext(const char* hook, const char* method, uint32_t appId);
extern "C" void CR_ClearCrashContext();

class CrashContextScope {
public:
    CrashContextScope(const char* hook, const char* method, uint32_t appId) {
        CR_SetCrashContext(hook, method, appId);
    }

    ~CrashContextScope() {
        CR_ClearCrashContext();
    }
};

// CProtoBufMsg vtable layout on 32-bit GCC Linux (google::protobuf::MessageLite):
//   slot[5]  (+20): Clear()
//   slot[9]  (+36): ByteSizeLong() -> int
//   slot[10] (+40): GetCachedSize() -> int
//
// Standalone functions found by signature scan:
//   SerializeToArray(msg, buffer) -> uint8_t* (end pointer)
//   ParseFromArray(msg, data, len) -> int (success)

using SerializeToArray_t = void*(*)(void* msg, void* buffer);
using ParseFromArray_t   = int(*)(void* msg, const void* data, int len);

static SerializeToArray_t g_serializeToArray = nullptr;
static ParseFromArray_t   g_parseFromArray   = nullptr;

static sigjmp_buf g_protoJmpBuf;
static volatile sig_atomic_t g_inProtoCall = 0;

static void ProtoCrashHandler(int sig) {
    if (g_inProtoCall) {
        siglongjmp(g_protoJmpBuf, sig);
    }
    raise(sig);
}

class ProtoCrashGuard {
public:
    ProtoCrashGuard() {
        struct sigaction sa = {};
        sa.sa_handler = ProtoCrashHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESETHAND;
        sigaction(SIGSEGV, &sa, &m_oldSegv);
        sigaction(SIGBUS, &sa, &m_oldBus);
        g_inProtoCall = 1;
    }

    ~ProtoCrashGuard() {
        g_inProtoCall = 0;
        sigaction(SIGSEGV, &m_oldSegv, nullptr);
        sigaction(SIGBUS, &m_oldBus, nullptr);
    }

private:
    struct sigaction m_oldSegv = {};
    struct sigaction m_oldBus = {};
};

// Signature patterns for runtime resolution
//
// SerializeToArray (33 bytes total):
//   55 89 e5 53 83 ec 10 8b 5d 08 8b 03 53 ff 50 28
//   push ebp; mov ebp,esp; push ebx; sub esp,0x10; mov ebx,[ebp+8]; mov eax,[ebx]; push ebx; call [eax+0x28]
//
// ParseFromArray (first 9 bytes before PIC thunk call):
//   55 89 e5 57 56 53 83 ec 0c
//   push ebp; mov ebp,esp; push edi; push esi; push ebx; sub esp,0xC
//   Then: e8 xx xx xx xx (call __x86.get_pc_thunk.bx)
//   Then: 81 c3 xx xx xx xx (add ebx, offset)
//   Then at +0x14: mov eax,[ebp+8]  => 8b 45 08
//   Then at +0x17: mov edx,[ebp+10h] => 8b 55 10
//   Then at +0x1a: mov esi,[ebp+0Ch] => 8b 75 0c
//   Then at +0x1d: test edx,edx      => 85 d2
//   Then at +0x1f: jns short          => 79 xx

static const uint8_t kSerializeSig[] = {
    0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x10,
    0x8B, 0x5D, 0x08, 0x8B, 0x03, 0x53, 0xFF, 0x50, 0x28
};

// ParseFromArray: match the prologue + arg loads after PIC fixup
// We match: 55 89 e5 57 56 53 83 ec 0c (prologue)
// Then skip the PIC thunk (e8 + 4 bytes + add ebx + 4 bytes = 11 bytes)
// Then match: 8b 45 08 8b 55 10 8b 75 0c 85 d2 79
static const uint8_t kParsePrologue[] = {
    0x55, 0x89, 0xE5, 0x57, 0x56, 0x53, 0x83, 0xEC, 0x0C
};
static const uint8_t kParseArgLoads[] = {
    0x8B, 0x45, 0x08, 0x8B, 0x55, 0x10, 0x8B, 0x75, 0x0C, 0x85, 0xD2, 0x79
};

static void* ScanForPattern(void* base, size_t size, const uint8_t* pattern, size_t patLen) {
    const uint8_t* p = (const uint8_t*)base;
    const uint8_t* end = p + size - patLen;
    for (; p <= end; ++p) {
        if (memcmp(p, pattern, patLen) == 0) return (void*)p;
    }
    return nullptr;
}

bool CloudHooks::ResolveProtobufHelpers(void* steamclientBase, size_t steamclientSize) {
    // Find SerializeToArray by its unique 16-byte signature
    void* serialize = ScanForPattern(steamclientBase, steamclientSize, kSerializeSig, sizeof(kSerializeSig));
    if (serialize) {
        g_serializeToArray = (SerializeToArray_t)serialize;
        LOG("[Hook] Found SerializeToArray at %p", serialize);
    } else {
        LOG("[Hook] ERROR: SerializeToArray not found by signature");
    }

    // Find ParseFromArray by prologue + arg loads at offset +0x14
    if (steamclientSize < 0x30) {
        LOG("[Hook] ERROR: steamclient too small (%zu bytes) for signature scan", steamclientSize);
        return false;
    }
    const uint8_t* p = (const uint8_t*)steamclientBase;
    const uint8_t* end = p + steamclientSize - 0x30;
    void* parseFound = nullptr;
    for (; p <= end; ++p) {
        if (memcmp(p, kParsePrologue, sizeof(kParsePrologue)) != 0) continue;
        // Check arg loads at offset +0x14 (after PIC thunk: e8 + 4 + add ebx + 4 = 11 bytes after prologue)
        // Prologue is 9 bytes, PIC fixup is 11 bytes => offset 20 = 0x14
        if (memcmp(p + 0x14, kParseArgLoads, sizeof(kParseArgLoads)) == 0) {
            parseFound = (void*)p;
            break;
        }
    }
    if (parseFound) {
        g_parseFromArray = (ParseFromArray_t)parseFound;
        LOG("[Hook] Found ParseFromArray at %p", parseFound);
    } else {
        LOG("[Hook] ERROR: ParseFromArray not found by signature");
    }

    return g_serializeToArray != nullptr && g_parseFromArray != nullptr;
}

static std::vector<uint8_t> SerializeMessage(void* msg) {
    if (!msg || !g_serializeToArray) return {};

    // vtable[9] = ByteSizeLong (offset +36 on 32-bit)
    uint32_t* vtable = *(uint32_t**)msg;
    if (!vtable || !vtable[9]) return {};
    using ByteSizeFn = int(__attribute__((cdecl)) *)(void*);
    ProtoCrashGuard guard;
    int sig = sigsetjmp(g_protoJmpBuf, 1);
    if (sig != 0) {
        LOG("[Hook] SerializeToArray helper crashed with signal %d", sig);
        return {};
    }

    int size = ((ByteSizeFn)vtable[9])(msg);
    if (size <= 0 || size > 64 * 1024 * 1024) return {};

    std::vector<uint8_t> buf(size);
    g_serializeToArray(msg, buf.data());
    return buf;
}

static bool ParseIntoMessage(void* msg, const uint8_t* data, size_t len) {
    if (!msg || !g_parseFromArray || !data || len == 0) return false;
    if (len > (size_t)INT_MAX) return false;
    ProtoCrashGuard guard;
    int sig = sigsetjmp(g_protoJmpBuf, 1);
    if (sig != 0) {
        LOG("[Hook] ParseFromArray helper crashed with signal %d while parsing %zu bytes", sig, len);
        return false;
    }
    return g_parseFromArray(msg, data, (int)len) != 0;
}

// Serialize a protobuf body object into a thread-local buffer for the
// GamesPlayed observer (runs on Steam's network thread).
static const uint8_t* SerializeBodyTL(void* bodyObj, size_t* outLen) {
    static thread_local std::vector<uint8_t> tlBuf;
    tlBuf = SerializeMessage(bodyObj);
    if (outLen) *outLen = tlBuf.size();
    return tlBuf.empty() ? nullptr : tlBuf.data();
}

void CloudHooks::InstallGamesPlayedObserver(uintptr_t steamclientBase, size_t steamclientSize) {
    if (!g_serializeToArray) {
        LOG("[GamesPlayed] serializer not resolved -- playtime tracking disabled");
        return;
    }
    GamesPlayedHook::SetSerializer(&SerializeBodyTL);
    GamesPlayedHook::Install(steamclientBase, steamclientSize);

    // Resolve the playtime writer/message helpers and install the CUser-capture
    // detour used to apply cross-device playtime updates live.
    if (LivePlaytime::Resolve(steamclientBase, steamclientSize, g_parseFromArray))
        LivePlaytime::InstallUserCapture();

    // Resolve the packet-wrap + job-routing functions used to serve the legacy
    // CMsgClientGetUserStats (818) achievement fetch with a 819 response.
    AchievementInject::Resolve(steamclientBase, steamclientSize, &SerializeBodyTL);
}

static std::optional<CloudIntercept::RpcResult> DispatchCloudRpc(
    const char* method, uint32_t appId, const std::vector<PB::Field>& reqBody) {
    using namespace CloudIntercept;
    if (strcmp(method, RPC_GET_CHANGELIST) == 0)    return HandleGetChangelist(appId, reqBody);
    if (strcmp(method, RPC_LAUNCH_INTENT) == 0)     return HandleLaunchIntent(appId, reqBody);
    if (strcmp(method, RPC_SUSPEND_SESSION) == 0)   return HandleSuspendSession(appId, reqBody);
    if (strcmp(method, RPC_RESUME_SESSION) == 0)    return HandleResumeSession(appId, reqBody);
    if (strcmp(method, RPC_QUOTA_USAGE) == 0)       return HandleQuotaUsage(appId, reqBody);
    if (strcmp(method, RPC_BEGIN_BATCH) == 0)       return HandleBeginBatch(appId, reqBody);
    if (strcmp(method, RPC_BEGIN_UPLOAD) == 0)      return HandleBeginFileUpload(appId, reqBody);
    if (strcmp(method, RPC_COMMIT_UPLOAD) == 0)     return HandleCommitFileUpload(appId, reqBody);
    if (strcmp(method, RPC_COMPLETE_BATCH) == 0)    return HandleCompleteBatch(appId, reqBody);
    if (strcmp(method, RPC_FILE_DOWNLOAD) == 0)     return HandleFileDownload(appId, reqBody);
    if (strcmp(method, RPC_DELETE_FILE) == 0)       return HandleDeleteFile(appId, reqBody);
    return std::nullopt;
}

static std::atomic<bool> g_initFailed{false};

static void EnsureInitialized() {
    if (g_initialized.load(std::memory_order_acquire)) return;
    if (g_initFailed.load(std::memory_order_acquire)) return;

    static std::once_flag s_initFlag;
    std::call_once(s_initFlag, []() {
        // Initialize the intercept layer (parses SLSsteam config, loginusers.vdf)
        CloudIntercept::InitLinux();

        const char* home = getenv("HOME");
        if (!home || home[0] == '\0') {
            LOG("[Linux] FATAL: HOME environment variable not set, cannot initialize storage");
            g_initFailed.store(true, std::memory_order_release);
            return;
        }
        std::string cloudRedirectRoot = std::string(home) + "/.config/CloudRedirect/";
        std::string storageRoot = cloudRedirectRoot + "storage";

        // Initialize CloudStorage with cloud provider from config.json
        std::unique_ptr<ICloudProvider> provider;
        std::string configPath = cloudRedirectRoot + "config.json";
        std::ifstream configFile(configPath);
        if (configFile) {
            std::string configStr((std::istreambuf_iterator<char>(configFile)), {});
            configFile.close();
            auto cfg = Json::Parse(configStr);
            std::string providerName = cfg["provider"].str();

            // Native stats/playtime sync gates. Absent -> keep default (ON).
            // When off, the matching native path does not interfere with Steam.
            if (cfg["sync_achievements"].type == Json::Type::Bool)
                MetadataSync::syncAchievements = cfg["sync_achievements"].boolean();
            if (cfg["sync_playtime"].type == Json::Type::Bool)
                MetadataSync::syncPlaytime = cfg["sync_playtime"].boolean();
            LOG("[Stats] Sync gates: achievements=%d, playtime=%d",
                MetadataSync::syncAchievements.load() ? 1 : 0,
                MetadataSync::syncPlaytime.load() ? 1 : 0);

            if (!providerName.empty() && providerName != "local") {
                provider = CreateCloudProvider(providerName);
                if (provider) {
                    std::string tokenPath = cloudRedirectRoot + "tokens_" + providerName + ".json";
                    if (provider->Init(tokenPath)) {
                        LOG("[Linux] Cloud provider '%s' initialized (tokens: %s)",
                            provider->Name(), tokenPath.c_str());
                        if (!provider->IsAuthenticated()) {
                            LOG("[Linux] WARNING: %s configured but not authenticated -- local-only until signed in",
                                provider->Name());
                            provider.reset();
                        }
                    } else {
                        LOG("[Linux] WARNING: Cloud provider '%s' init failed, falling back to local-only",
                            providerName.c_str());
                        provider.reset();
                    }
                } else {
                    LOG("[Linux] WARNING: Unknown cloud provider '%s', falling back to local-only",
                        providerName.c_str());
                }
            }
        } else {
            LOG("[Linux] No config.json at %s -- local-only mode", configPath.c_str());
        }

        CloudStorage::Init(cloudRedirectRoot, std::move(provider));
    
        LocalStorage::Init(storageRoot);
        LocalMetadataStore::Init(storageRoot);
        PendingOpsJournal::Init(storageRoot);
        HttpServer::Start(storageRoot, CloudIntercept::GetAccountId());

        // Native stats / playtime store (cloud-backed). Per-app stats blobs ride
        // each app's Steam Cloud sync, same as the CN/root-token metadata blobs.
        StatsStore::SetCloudProvider(
            [](uint32_t appId, std::string& outJson) -> bool {
                uint32_t accountId = CloudIntercept::GetAccountId();
                if (accountId == 0) return false;
                std::vector<uint8_t> data;
                if (!CloudStorage::DownloadCloudMetadataWithLegacyFallback(
                        accountId, appId, "stats.json", nullptr, data) || data.empty())
                    return false;
                outJson.assign(reinterpret_cast<const char*>(data.data()), data.size());
                return true;
            },
            [](uint32_t appId, const std::string& json) {
                uint32_t accountId = CloudIntercept::GetAccountId();
                if (accountId == 0) return;
                // Queued: serializes on the cloud work queue (safe from any thread).
                CloudStorage::UploadCloudMetadataTextAsync(accountId, appId, "stats.json", json);
            });
        // Track playtime/stats for namespace (lua) apps only -- real owned games
        // must never have their playtime recorded or synced.
        StatsHandlers::SetNamespacePredicate(
            [](uint32_t appId) { return CloudIntercept::IsNamespaceApp(appId); });
        StatsStore::SetNamespacePredicate(
            [](uint32_t appId) { return CloudIntercept::IsNamespaceApp(appId); });
        StatsStore::SetAccountIdProvider(
            []() -> uint32_t { return CloudIntercept::GetAccountId(); });
        StatsStore::Init(cloudRedirectRoot, CloudIntercept::GetSteamPath());
        StatsHandlers::Init();
        // Seed managed apps so playtime/achievements are available before the
        // user launches anything: pulls each app's cloud stats blob and imports
        // Steam's native data.
        StatsStore::SeedApps(CloudIntercept::GetNamespaceApps());

        // Re-pull the cloud every 60s for another device's playtime advances.
        // RefreshFromCloud merges to disk; advanced apps are queued for a live
        // update applied on the network thread (LivePlaytime::DrainOnNetThread).
        std::thread([] {
            for (;;) {
                for (int i = 0; i < 60 && !g_shuttingDown.load(std::memory_order_acquire); ++i)
                    sleep(1);
                if (g_shuttingDown.load(std::memory_order_acquire)) return;
                auto changed = StatsStore::RefreshFromCloud(CloudIntercept::GetNamespaceApps());
                if (!changed.empty() && LivePlaytime::Ready()) {
                    PB::Writer body = StatsHandlers::BuildLastPlayedNotificationBody(changed);
                    if (body.Size() > 0)
                        LivePlaytime::Queue(body.Data());
                }
            }
        }).detach();
        StatsHooks::SetProtobufHelpers(
            [](void* msg) { return SerializeMessage(msg); },
            [](void* msg, const uint8_t* data, size_t len) {
                return ParseIntoMessage(msg, data, len);
            });

        g_initialized.store(true, std::memory_order_release);
        
        LOG("[Linux] Storage initialized: root=%s, accountId=%u, namespaceApps=%d",
            storageRoot.c_str(), CloudIntercept::GetAccountId(), 
            CloudIntercept::HasNamespaceApps() ? 1 : 0);

        // Manifest system fetches CN/manifest on-demand; no bulk startup sync.
        if (CloudStorage::IsCloudActive()) {
            LOG("[StartupSync] Cloud active; metadata will be fetched on-demand per app");
        }
    });
}

void CloudHooks::SetOriginals(void* origSlot5, void* origSlot7, void* origSlot8) {
    g_origBYieldingSend.store(reinterpret_cast<BYieldingSend_t>(origSlot5), std::memory_order_release);
    g_origNotificationDirect.store(reinterpret_cast<NotificationDirect_t>(origSlot7), std::memory_order_release);
    g_origSyncSend2.store(reinterpret_cast<SyncSend2_t>(origSlot8), std::memory_order_release);
}

static bool IsCloudRpc(const char* methodName) {
    return methodName && strncmp(methodName, "Cloud.", 6) == 0;
}

// Hook: BYieldingSendMessageAndGetReply (slot 5)
//
// 32-bit cdecl: int(void* this, const char* method, void* req, void* resp, int* flags)
// This is the primary synchronous RPC path.

extern "C" int hook_BYieldingSend(void* pThis, const char* methodName, void* request, void* response, int* flags)
{
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        auto fn = g_origBYieldingSend.load(std::memory_order_acquire);
        return fn ? fn(pThis, methodName, request, response, flags) : 0;
    }
    CrashContextScope crashContext("BYieldingSend:entry", methodName, 0);
    auto origFn = g_origBYieldingSend.load(std::memory_order_acquire);
    
    // Spin-wait for originals (installed before hooks in correct order).
    for (int i = 0; !origFn && i < 1000; ++i) {
        usleep(100);
        origFn = g_origBYieldingSend.load(std::memory_order_acquire);
    }
    if (!origFn) return 0;

    // The playtime writer touches Steam's minutes-played map and posts callbacks,
    // so queued updates are drained here on the network thread, not on the poller.
    LivePlaytime::DrainOnNetThread();
    // Queued 819 achievement responses route to their waiting job here (needs the
    // network thread's coroutine TLS, same as any inbound CM packet).
    AchievementInject::DrainOnNetThread();

    // Native stats / playtime service methods (Player.*) ride this same path.
    // GetUserStats is answered from our store; GetLastPlayedTimes needs the real
    // server reply first, then we append our namespace apps' playtime.
    if (methodName && g_serializeToArray && g_parseFromArray) {
        if (strcmp(methodName, StatsHandlers::RPC_GET_USER_STATS) == 0) {
            EnsureInitialized();
            if (StatsHooks::TryHandleGetUserStats(methodName, request, response, flags))
                return 1;
            return origFn(pThis, methodName, request, response, flags);
        }
        if (strcmp(methodName, StatsHandlers::RPC_GET_LAST_PLAYED) == 0) {
            EnsureInitialized();
            int result = origFn(pThis, methodName, request, response, flags);
            if (result)
                StatsHooks::MergeLastPlayedTimes(methodName, request, response);
            return result;
        }
    }

    if (!IsCloudRpc(methodName) || !g_serializeToArray || !g_parseFromArray)
        return origFn(pThis, methodName, request, response, flags);

    EnsureInitialized();

    // Extract raw protobuf bytes
    auto reqBytes = SerializeMessage(request);
    if (reqBytes.empty()) {
        return origFn(pThis, methodName, request, response, flags);
    }

    auto reqFields = PB::Parse(reqBytes.data(), reqBytes.size());
    uint32_t appId = CloudRpcUtils::ExtractAppId(methodName, reqFields);
    if (appId == 0) {
        return origFn(pThis, methodName, request, response, flags);
    }
    CR_SetCrashContext("BYieldingSend:app", methodName, appId);

    if (!CloudIntercept::IsNamespaceApp(appId)) {
        return origFn(pThis, methodName, request, response, flags);
    }
    CR_SetCrashContext("BYieldingSend:namespace", methodName, appId);

    uint32_t accountId = CloudIntercept::GetAccountId();
    if (accountId == 0) {
        return origFn(pThis, methodName, request, response, flags);
    }

    LocalStorage::InitApp(accountId, appId);
    CR_SetCrashContext("BYieldingSend:metadata-init", methodName, appId);
    LocalMetadataStore::InitApp(accountId, appId);

    CR_SetCrashContext("BYieldingSend:dispatch", methodName, appId);
    auto dispatched = DispatchCloudRpc(methodName, appId, reqFields);
    if (!dispatched.has_value()) {
        return origFn(pThis, methodName, request, response, flags);
    }
    auto& result = *dispatched;

    LOG("[Hook] INTERCEPT BYieldingSend %s app=%u -> %zu bytes, eresult=%d",
        methodName, appId, result.body.Size(), result.eresult);

#ifdef DEBUG_HEX_DUMP
    {
        auto& d = result.body.Data();
        std::string hex;
        for (size_t i = 0; i < d.size() && i < 64; i++) {
            char tmp[4]; snprintf(tmp, sizeof(tmp), "%02X ", d[i]);
            hex += tmp;
        }
        LOG("[Hook]   response hex: %s", hex.c_str());
    }
#endif

    // Parse response bytes into the response protobuf object
    if (response && result.body.Size() > 0) {
        CR_SetCrashContext("BYieldingSend:parse-response", methodName, appId);
        if (!ParseIntoMessage(response, result.body.Data().data(), result.body.Size())) {
            LOG("[Hook] BYieldingSend %s: ParseFromArray failed for response! Falling through.",
                methodName);
            return origFn(pThis, methodName, request, response, flags);
        }
        LOG("[Hook]   ParseFromArray succeeded");
    }

    // Flags layout: [0]=routing, [1]=mode, [2]=transport_success, [3]=eresult
    if (flags) {
        flags[2] = 1;  // transport success
        flags[3] = result.eresult;
    }

    LOG("[Hook]   returning success for %s app=%u", methodName, appId);
    return 1;  // success
}

// Hook: NotificationDirect (slot 7)
//
// Suppress cloud notifications for namespace apps.

static uint32_t CheckNotificationNamespaceApp(const char* methodName, void* body) {
    if (!body || !g_serializeToArray) return 0;

    auto bodyBytes = SerializeMessage(body);
    if (bodyBytes.empty()) {
        LOG("[Hook-Notif] %s: body serialization empty", methodName);
        return 0;
    }

    auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
    // For Cloud notifications, appId is field 1
    auto* appField = PB::FindField(fields, 1);
    if (!appField) {
        LOG("[Hook-Notif] %s: no field 1 (appId) in body", methodName);
        return 0;
    }

    uint32_t appId = (uint32_t)appField->varintVal;
    if (CloudIntercept::IsNamespaceApp(appId)) {
        return appId;
    }
    return 0;
}

extern "C" int hook_NotificationDirect(void* pThis, const char* methodName, void* body, int* flags)
{
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        auto fn = g_origNotificationDirect.load(std::memory_order_acquire);
        return fn ? fn(pThis, methodName, body, flags) : 0;
    }
    CrashContextScope crashContext("NotificationDirect:entry", methodName, 0);
    auto origFn = g_origNotificationDirect.load(std::memory_order_acquire);
    for (int i = 0; !origFn && i < 1000; ++i) {
        usleep(100);
        origFn = g_origNotificationDirect.load(std::memory_order_acquire);
    }
    if (!origFn) return 0;

    // Only intercept Cloud.* notifications
    if (!IsCloudRpc(methodName)) {
        return origFn(pThis, methodName, body, flags);
    }

    uint32_t appId = CheckNotificationNamespaceApp(methodName, body);
    CR_SetCrashContext("NotificationDirect:checked", methodName, appId);
    if (appId == 0) {
        // Not a namespace app - pass through to Steam servers
        LOG("[Hook-Notif] %s: not namespace, passing through", methodName);
        return origFn(pThis, methodName, body, flags);
    }

    // ExitSyncDone: let Steam process it (updates remotecache.vdf CN).
    if (strcmp(methodName, CloudIntercept::RPC_EXIT_SYNC) == 0) {
        CR_SetCrashContext("NotificationDirect:exit-sync", methodName, appId);
        auto bodyBytes = SerializeMessage(body);
        auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
        uint64_t clientId = 0;
        bool uploadsCompleted = false;
        bool uploadsRequired = false;
        if (auto* f = PB::FindField(fields, 2)) clientId = f->varintVal;
        if (auto* f = PB::FindField(fields, 3)) uploadsCompleted = f->varintVal != 0;
        if (auto* f = PB::FindField(fields, 4)) uploadsRequired = f->varintVal != 0;
        uint32_t accountId = CloudIntercept::GetAccountId();
        if (accountId != 0) {
            PendingOpsJournal::RecordExitSyncState(accountId, appId,
                uploadsCompleted, uploadsRequired, clientId);
            CloudStorage::ReleaseCloudSession(accountId, appId, clientId);
        }
        LOG("[Hook-Notif] %s app=%u: letting Steam process internally", methodName, appId);
        return origFn(pThis, methodName, body, flags);
    }

    // ConflictResolution: parse chose_local_files so HandleLaunchIntent
    // knows whether to skip pre-restore (user chose "keep local files").
    if (strcmp(methodName, CloudIntercept::RPC_CONFLICT) == 0) {
        auto bodyBytes = SerializeMessage(body);
        auto fields = PB::Parse(bodyBytes.data(), bodyBytes.size());
        bool choseLocal = false;
        if (auto* f = PB::FindField(fields, 2)) choseLocal = f->varintVal != 0;
        CloudIntercept::RecordConflictResolution(appId, choseLocal);
    }

    // Suppress other Cloud notifications for namespace apps
    LOG("[Hook-Notif] SUPPRESSED %s app=%u (notification not sent to server)", methodName, appId);
    return 1;
}

// Hook: SyncSend2 (slot 8)
//
// 32-bit cdecl: int(void* this, const char* method, void* buf, uint32_t bufLen, void* resp, int* flags)
// Buffer-based variant -- raw protobuf bytes are directly available.

extern "C" int hook_SyncSend2(void* pThis, const char* methodName, void* buf, unsigned int bufLen, void* response, int* flags)
{
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        auto fn = g_origSyncSend2.load(std::memory_order_acquire);
        return fn ? fn(pThis, methodName, buf, bufLen, response, flags) : 0;
    }
    CrashContextScope crashContext("SyncSend2:entry", methodName, 0);
    auto origFn = g_origSyncSend2.load(std::memory_order_acquire);
    for (int i = 0; !origFn && i < 1000; ++i) {
        usleep(100);
        origFn = g_origSyncSend2.load(std::memory_order_acquire);
    }
    if (!origFn) return 0;
    
    if (!IsCloudRpc(methodName))
        return origFn(pThis, methodName, buf, bufLen, response, flags);

    if (!buf || bufLen == 0)
        return origFn(pThis, methodName, buf, bufLen, response, flags);

    EnsureInitialized();

    auto reqFields = PB::Parse(static_cast<const uint8_t*>(buf), bufLen);
    uint32_t appId = CloudRpcUtils::ExtractAppId(methodName, reqFields);

    if (appId == 0) {
        return origFn(pThis, methodName, buf, bufLen, response, flags);
    }
    CR_SetCrashContext("SyncSend2:app", methodName, appId);

    if (!CloudIntercept::IsNamespaceApp(appId)) {
        return origFn(pThis, methodName, buf, bufLen, response, flags);
    }
    CR_SetCrashContext("SyncSend2:namespace", methodName, appId);

    uint32_t accountId = CloudIntercept::GetAccountId();
    if (accountId == 0) {
        return origFn(pThis, methodName, buf, bufLen, response, flags);
    }

    LocalStorage::InitApp(accountId, appId);
    CR_SetCrashContext("SyncSend2:metadata-init", methodName, appId);
    LocalMetadataStore::InitApp(accountId, appId);

    CR_SetCrashContext("SyncSend2:dispatch", methodName, appId);
    auto dispatched = DispatchCloudRpc(methodName, appId, reqFields);
    if (!dispatched.has_value()) {
        return origFn(pThis, methodName, buf, bufLen, response, flags);
    }
    auto& result = *dispatched;

    LOG("[Hook] INTERCEPT SyncSend2 %s app=%u -> %zu bytes, eresult=%d",
        methodName, appId, result.body.Size(), result.eresult);

    if (response && result.body.Size() > 0 && g_parseFromArray) {
        CR_SetCrashContext("SyncSend2:parse-response", methodName, appId);
        if (!ParseIntoMessage(response, result.body.Data().data(), result.body.Size())) {
            LOG("[Hook] SyncSend2 %s: ParseFromArray failed", methodName);
            return origFn(pThis, methodName, buf, bufLen, response, flags);
        }
    }

    // Flags layout (from IDA): [0]=routing, [1]=mode, [2]=transport_success, [3]=eresult
    if (flags) {
        flags[2] = 1;  // transport success
        flags[3] = result.eresult;
    }

    return 1;
}

// Hook: IsCloudEnabledForApp (CUserRemoteStorage vtable slot 24)
// 32-bit cdecl: bool(void* this, unsigned int appId)
// Returns true for namespace apps so cloud toggle stays enabled.

using IsCloudEnabledForApp_t = bool(*)(void* pThis, unsigned int appId);
static std::atomic<IsCloudEnabledForApp_t> g_origIsCloudEnabledForApp{nullptr};

void CloudHooks::SetOriginalIsCloudEnabled(void* orig) {
    g_origIsCloudEnabledForApp.store(reinterpret_cast<IsCloudEnabledForApp_t>(orig), std::memory_order_release);
}

extern "C" bool hook_IsCloudEnabledForApp(void* pThis, unsigned int appId)
{
    HookGuard guard;
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        auto fn = g_origIsCloudEnabledForApp.load(std::memory_order_acquire);
        return fn ? fn(pThis, appId) : true;
    }
    CrashContextScope crashContext("IsCloudEnabledForApp:entry", "IsCloudEnabledForApp", appId);
    if (CloudIntercept::IsNamespaceApp(appId)) {
        LOG("[Hook] IsCloudEnabledForApp(%u) -> true (namespace app)", appId);
        return true;
    }

    auto origFn = g_origIsCloudEnabledForApp.load(std::memory_order_acquire);
    if (origFn) {
        return origFn(pThis, appId);
    }
    return true;
}

void CloudHooks::BeginShutdown() {
    g_shuttingDown.store(true, std::memory_order_release);
    GamesPlayedHook::Remove();
    LivePlaytime::RemoveUserCapture();
    for (int i = 0; i < 300 && g_hookRefCount.load(std::memory_order_acquire) > 0; ++i)
        usleep(10000); // 10ms, up to 3s total
}
