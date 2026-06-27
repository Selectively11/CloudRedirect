// cloud_redirect.so entry point

#include "vtable_hook.h"

// Exported version string for update detection by UI
#ifndef CR_VERSION_STRING
#define CR_VERSION_STRING "0.0.0+unknown"
#endif
extern "C" __attribute__((visibility("default")))
const char* CR_GetVersion() { return CR_VERSION_STRING; }
#include "cloud_hooks.h"
#include "cloud_intercept.h"
#include "cloud_storage.h"
#include "http_server.h"
#include "legacy_metadata_cleanup.h"
#include "log.h"
#include "rpc_handlers.h"
#include "steam_kv_injector.h"

#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <execinfo.h>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <string>
#include <cstdint>
#include <pthread.h>

static VtableHook::VtableInfo g_vtableInfo{};
static VtableHook::CloudEnabledHookInfo g_cloudEnabledInfo{};
static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_hookAttempted{false};
static std::atomic<bool> g_logInitialized{false};
static pthread_t g_initThread{};
static std::atomic<bool> g_initThreadDone{false};

// Raw diagnostic logging (survives even if C++ runtime is broken)

static int g_debugFd = -1;
static char g_crashContext[192] = "none";

static void DebugLog(const char* msg)
{
    if (g_debugFd < 0) {
        const char* home = getenv("HOME");
        std::string path = home && home[0]
            ? std::string(home) + "/.config/CloudRedirect/cr_debug.log"
            : "/tmp/cr_debug.log";
        g_debugFd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    }
    if (g_debugFd >= 0)
        write(g_debugFd, msg, strlen(msg));
}

extern "C" void CR_SetCrashContext(const char* hook, const char* method, uint32_t appId)
{
    if (!hook) hook = "unknown";
    if (!method) method = "(null)";
    snprintf(g_crashContext, sizeof(g_crashContext), "%s method=%s app=%u",
             hook, method, appId);
    g_crashContext[sizeof(g_crashContext) - 1] = '\0';
}

extern "C" void CR_ClearCrashContext()
{
    g_crashContext[0] = '\0';
}



static void EnsureLogInit()
{
    bool expected = false;
    if (g_logInitialized.compare_exchange_strong(expected, true))
        Log::Init();
}

static bool NotificationsEnabled()
{
    const char* home = getenv("HOME");
    if (!home || !home[0]) return true;

    std::string configPath = std::string(home) + "/.config/CloudRedirect/config.json";
    FILE* f = fopen(configPath.c_str(), "r");
    if (!f) return true;

    char buf[65536] = {};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    const char* key = strstr(buf, "\"notifications_enabled\"");
    if (!key) return true;

    const char* p = key + strlen("\"notifications_enabled\"");
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') ++p;

    return strncmp(p, "false", 5) != 0;
}

static void Notify(const char* msg, bool critical = false)
{
    if (!NotificationsEnabled()) return;

    pid_t pid = fork();
    if (pid == 0) {
        // Child: exec notify-send and exit
        if (critical)
            execlp("notify-send", "notify-send", "-u", "critical", "CloudRedirect", msg, nullptr);
        else
            execlp("notify-send", "notify-send", "-t", "5000", "-u", "normal", "CloudRedirect", msg, nullptr);
        _exit(1);
    }
    // Parent: don't wait -- reap asynchronously via SIGCHLD (default ignore)
}

static std::string GetProcessName()
{
    char buf[256] = {};
    FILE* f = fopen("/proc/self/comm", "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
        }
        fclose(f);
    }
    return buf;
}

static void CleanLdPreload()
{
    char* preload = getenv("LD_PRELOAD");
    if (!preload) return;

    std::string val(preload);
    std::string cleaned;
    size_t pos = 0;
    while (pos < val.size())
    {
        size_t sep = val.find_first_of(": ", pos);
        if (sep == std::string::npos) sep = val.size();
        std::string entry = val.substr(pos, sep - pos);
        if (!entry.empty() && entry.find("cloud_redirect") == std::string::npos)
        {
            if (!cleaned.empty()) cleaned += ':';
            cleaned += entry;
        }
        pos = sep + 1;
    }
    if (cleaned.empty())
        unsetenv("LD_PRELOAD");
    else
        setenv("LD_PRELOAD", cleaned.c_str(), 1);
}

static void DoInit()
{
    DebugLog("[CR] DoInit: version=" CR_VERSION_STRING " finding steamclient.so in /proc/self/maps\n");
    Log::Info("CloudRedirect build %s", CR_VERSION_STRING);

    // Kill-switch: if disable file exists, bail without hooking
    const char* home = getenv("HOME");
    if (home) {
        std::string disablePath = std::string(home) + "/.config/CloudRedirect/disable";
        if (access(disablePath.c_str(), F_OK) == 0) {
            DebugLog("[CR] DoInit: kill-switch active (~/.config/CloudRedirect/disable exists), aborting\n");
            Log::Warn("Kill-switch active, skipping all hooks");
            return;
        }
    }

    size_t steamSize = 0;
    uintptr_t steamBase = VtableHook::FindSteamclient(steamSize);
    if (!steamBase)
    {
        DebugLog("[CR] DoInit: FAILED - steamclient.so not found\n");
        Log::Error("Init failed: steamclient.so not found in maps");
        Notify("Failed: steamclient.so not found", true);
        return;
    }
    Log::Info("steamclient.so base=%p size=0x%zx", (void*)steamBase, steamSize);

    DebugLog("[CR] DoInit: finding transport vtable\n");
    void** vtable = VtableHook::FindTransportVtable(steamBase, steamSize);
    if (!vtable)
    {
        DebugLog("[CR] DoInit: FAILED - transport vtable not found\n");
        Log::Error("Init failed: transport vtable not found");
        Notify("Incompatible Steam client - hooks disabled", true);
        return;
    }
    Log::Info("Transport vtable at %p, slots: [5]=%p [7]=%p [8]=%p",
              (void*)vtable, vtable[5], vtable[7], vtable[8]);

    DebugLog("[CR] DoInit: saving originals\n");
    CloudHooks::SetOriginals(vtable[5], vtable[7], vtable[8]);

    DebugLog("[CR] DoInit: installing transport hooks\n");
    if (!VtableHook::InstallHooks(vtable, g_vtableInfo))
    {
        DebugLog("[CR] DoInit: FAILED - hook installation failed\n");
        Log::Error("Init failed: transport hook installation failed");
        return;
    }
    Log::Info("Transport hooks installed on slots 5/7/8");

    DebugLog("[CR] DoInit: looking for RemoteStorage vtable\n");
    void** rsVtable = VtableHook::FindRemoteStorageVtable(steamBase, steamSize);
    if (rsVtable)
    {
        if (VtableHook::InstallCloudEnabledHook(rsVtable, g_cloudEnabledInfo))
        {
            CloudHooks::SetOriginalIsCloudEnabled(g_cloudEnabledInfo.origSlot);
            Log::Info("IsCloudEnabledForApp hook installed");
        }
        else
            Log::Warn("IsCloudEnabledForApp hook install failed (cloud toggle may not work)");
    }
    else
        Log::Warn("CUserRemoteStorage vtable not found (cloud toggle may not work)");

    DebugLog("[CR] DoInit: resolving protobuf helpers\n");
    bool pbOk = CloudHooks::ResolveProtobufHelpers(reinterpret_cast<void*>(steamBase), steamSize);
    if (!pbOk)
        Log::Error("Protobuf helpers not fully resolved -- cloud RPCs may fail");

    // Sweep stray *.cloudredirect metadata from userdata/{app}/remote/.
    {
        std::string steamPath = CloudIntercept::GetSteamPath();
        if (!steamPath.empty())
            LegacyMetadataCleanup::PruneSteamUserdata(steamPath);
    }

    DebugLog("[CR] DoInit: initializing KV injector\n");
    SteamKvInjector::Init();

    g_initialized.store(true, std::memory_order_release);
    DebugLog("[CR] DoInit: SUCCESS\n");
    Log::Info("CloudRedirect initialized successfully (all hooks active)");
}



static sigjmp_buf g_crashJmpBuf;
static volatile sig_atomic_t g_inScan = 0;

static void ScanCrashHandler(int sig)
{
    if (g_inScan)
        siglongjmp(g_crashJmpBuf, 1);
    // Not our crash -- SA_RESETHAND already restored default, just re-raise
    raise(sig);
}

// ── Post-init crash handler: dumps backtrace to log ─────────────────────
static volatile sig_atomic_t g_inCrashHandler = 0;

static char* AppendLiteral(char* out, char* end, const char* s)
{
    while (out < end && *s) *out++ = *s++;
    return out;
}

static char* AppendUInt(char* out, char* end, unsigned int v)
{
    char tmp[16];
    int n = 0;
    do {
        tmp[n++] = char('0' + (v % 10));
        v /= 10;
    } while (v && n < (int)sizeof(tmp));
    while (n > 0 && out < end) *out++ = tmp[--n];
    return out;
}

static char* AppendHex(char* out, char* end, uintptr_t v)
{
    static const char hex[] = "0123456789abcdef";
    out = AppendLiteral(out, end, "0x");
    bool started = false;
    for (int shift = (int)(sizeof(uintptr_t) * 8) - 4; shift >= 0; shift -= 4) {
        unsigned int nibble = (unsigned int)((v >> shift) & 0xF);
        if (nibble || started || shift == 0) {
            started = true;
            if (out < end) *out++ = hex[nibble];
        }
    }
    return out;
}

static uintptr_t FaultInstructionPointer(void* ctx)
{
    if (!ctx) return 0;
    ucontext_t* uc = static_cast<ucontext_t*>(ctx);
#if defined(__i386__)
    return static_cast<uintptr_t>(uc->uc_mcontext.gregs[14]); // REG_EIP
#elif defined(__x86_64__)
    return static_cast<uintptr_t>(uc->uc_mcontext.gregs[16]); // REG_RIP
#elif defined(__aarch64__)
    return static_cast<uintptr_t>(uc->uc_mcontext.pc);
#else
    return 0;
#endif
}

static void CrashDumpHandler(int sig, siginfo_t* info, void* ctx)
{
    if (g_inCrashHandler) { _exit(128 + sig); }
    g_inCrashHandler = 1;

    char buf[512];
    char* out = buf;
    char* end = buf + sizeof(buf);
    out = AppendLiteral(out, end, "\n[CR] *** CRASH: signal ");
    out = AppendUInt(out, end, (unsigned int)sig);
    out = AppendLiteral(out, end, ", fault addr=");
    out = AppendHex(out, end, (uintptr_t)(info ? info->si_addr : nullptr));
    out = AppendLiteral(out, end, ", ip=");
    out = AppendHex(out, end, FaultInstructionPointer(ctx));
    if (g_crashContext[0]) {
        out = AppendLiteral(out, end, ", context=");
        out = AppendLiteral(out, end, g_crashContext);
    }
    out = AppendLiteral(out, end, ", pid=");
    out = AppendUInt(out, end, (unsigned int)getpid());
    out = AppendLiteral(out, end, " ***\n");
    if (g_debugFd >= 0)
        write(g_debugFd, buf, (size_t)(out - buf));


    void* frames[64];
    int frameCount = backtrace(frames, 64);
    if (frameCount > 0) {
        const char* btHeader = "[CR] Backtrace:\n";
        if (g_debugFd >= 0)
            write(g_debugFd, btHeader, strlen(btHeader));
        
        // backtrace_symbols_fd writes directly to fd (async-signal-safe)
        if (g_debugFd >= 0)
            backtrace_symbols_fd(frames, frameCount, g_debugFd);
        
        const char* btFooter = "[CR] End backtrace\n";
        if (g_debugFd >= 0)
            write(g_debugFd, btFooter, strlen(btFooter));
    }

    // SA_RESETHAND already restored default - just re-raise for core dump
    raise(sig);
}

static void InstallCrashDumpHandler()
{
    struct sigaction sa = {};
    sa.sa_sigaction = CrashDumpHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;  // one-shot, with siginfo
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
}

static bool SteamclientMapped()
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "steamclient.so")) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static void* DeferredInitThread(void*)
{
    // Poll for steamclient.so -- under LD_PRELOAD we load before Steam has
    // mapped steamclient, so a fixed delay is insufficient.
    DebugLog("[CR] DeferredInit: waiting for steamclient.so\n");
    bool mapped = false;
    for (int i = 0; i < 240; i++) {  // up to 120 seconds
        if (SteamclientMapped()) { mapped = true; break; }
        usleep(500000);
    }
    if (!mapped) {
        DebugLog("[CR] DeferredInit: steamclient.so never mapped; aborting\n");
        Log::Error("DeferredInit: steamclient.so never appeared; aborting");
        g_initThreadDone.store(true, std::memory_order_release);
        return nullptr;
    }
    DebugLog("[CR] DeferredInit: starting\n");

    // Install crash guard so a bad memory read aborts correctly
    struct sigaction sa = {}, old_segv = {}, old_bus = {};
    sa.sa_handler = ScanCrashHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;  // Reset to default on signal (async-signal-safe)
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    g_inScan = 1;
    if (sigsetjmp(g_crashJmpBuf, 1) == 0) {
        DoInit();
    } else {
        DebugLog("[CR] DeferredInit: CRASHED during init, aborting safely\n");
        Log::Error("Caught signal during init - incompatible steamclient? Hooks NOT installed.");
        Notify("Crashed during init - hooks disabled", true);
    }
    g_inScan = 0;

    // Restore original handlers and install crash dump handler if init succeeded
    sigaction(SIGSEGV, &old_segv, nullptr);
    sigaction(SIGBUS, &old_bus, nullptr);

    if (g_initialized.load(std::memory_order_acquire)) {
        InstallCrashDumpHandler();
    }

    g_initThreadDone.store(true, std::memory_order_release);
    return nullptr;
}



static void SpawnDeferredInit()
{
    // Clean ourselves from LD_PRELOAD so child processes don't inherit us
    CleanLdPreload();

    EnsureLogInit();
    DebugLog("[CR] OnLoad: target process (steam), spawning deferred init thread\n");
    Log::Info("cloud_redirect.so active in process 'steam' (pid=%d)", getpid());

    bool expected = false;
    if (g_hookAttempted.compare_exchange_strong(expected, true))
    {
        if (pthread_create(&g_initThread, nullptr, DeferredInitThread, nullptr) != 0) {
            DebugLog("[CR] OnLoad: FAILED to create init thread\n");
            g_initThreadDone.store(true, std::memory_order_release);
        }
    }
}

__attribute__((constructor))
static void OnLoad()
{
    std::string proc = GetProcessName();
    if (proc != "steam" && !SteamclientMapped())
        return;

    SpawnDeferredInit();
}

__attribute__((destructor))
static void OnUnload()
{
    DebugLog("[CR] OnUnload: shutting down\n");

    // Wait for the init thread to finish so we don't unmap code it's executing.
    // The thread runs for ~2s (usleep) + init time, so this is bounded.
    if (g_hookAttempted.load(std::memory_order_acquire)) {
        if (!g_initThreadDone.load(std::memory_order_acquire)) {
            DebugLog("[CR] OnUnload: waiting for init thread\n");
            pthread_join(g_initThread, nullptr);
        }
    }

    // Write final sync icon states to registry.vdf (last-write-wins after
    // Steam's PosixRegistryManager has done its final in-memory flush).
    CloudIntercept::FlushPendingSyncStates();

    // Shut down cloud storage (signals workers, drains queue with timeout)
    CloudStorage::Shutdown();

    // Stop the HTTP server (joins accept + client threads)
    HttpServer::Stop();

    if (g_initialized.load(std::memory_order_acquire))
    {
        CloudHooks::BeginShutdown();
        VtableHook::RemoveHooks(g_vtableInfo);
        VtableHook::RemoveCloudEnabledHook(g_cloudEnabledInfo);
        Log::Info("cloud_redirect.so unloaded");
    }
    if (g_debugFd >= 0)
        close(g_debugFd);
}

