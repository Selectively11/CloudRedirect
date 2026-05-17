#include "common.h"
#include "log.h"
#include "cloud_intercept.h"
#include "file_util.h"
#include "cli.h"
#include <atomic>
#include <mutex>

static HMODULE g_thisModule = nullptr;
static std::once_flag g_initFlag;

// Steam dir from the DLL's own location, UTF-8.
// All "narrow" std::string paths in the DLL are UTF-8; ACP narrowing here
// would corrupt every non-ASCII Steam install.
static std::string GetSteamPath() {
    wchar_t wdllPath[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_thisModule, wdllPath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};

    // Trim to parent on wide data so we don't split a multi-byte sequence.
    DWORD endIdx = n;
    for (DWORD i = n; i > 0; --i) {
        if (wdllPath[i - 1] == L'\\') { endIdx = i; break; }
    }

    // WideToUtf8 rejects ill-formed UTF-16 (init then logs+skips).
    return FileUtil::WideToUtf8(wdllPath, (size_t)endIdx);
}

// Entry point from the SteamTools payload code cave.
// Returns nonzero if we handled the packet; zero lets Steam's SendPkt run.
extern "C" __declspec(dllexport)
int CloudOnSendPkt(void* thisptr, const uint8_t* data, uint32_t size, void* recvPktFn) {
    // One-time init; init failure -> return 0 (let Steam handle).
    static std::atomic<bool> g_initFailed{false};
    std::call_once(g_initFlag, [&]() {
        try {
            std::string steamPath = GetSteamPath();
            std::string logPath = steamPath + "cloud_redirect.log";

            Log::Init(logPath.c_str());
            LOG("CloudRedirect loaded via code cave, PID=%u", GetCurrentProcessId());
            LOG("Steam path: %s", steamPath.c_str());

            // Module bases (for IDA mapping).
            HMODULE hSteamClient = GetModuleHandleA("steamclient64.dll");
            LOG("steamclient64.dll base: %p", hSteamClient);

            CloudIntercept::Init(steamPath);

            if (recvPktFn) {
                CloudIntercept::SetSendPktAddr(recvPktFn);

                // recvPktFn = RecvPkt slot (RVA 0x1CAB48); saved orig at RVA 0x1CAB20.
                uintptr_t recvPktGlobal = (uintptr_t)recvPktFn;
                uintptr_t payloadBase = recvPktGlobal - 0x1CAB48;
                uintptr_t savedOrigAddr = payloadBase + 0x1CAB20;
                CloudIntercept::InstallRecvPktMonitor((void*)savedOrigAddr);
            }

            CloudIntercept::InstallManifestPinHook();

            LOG("CloudRedirect fully initialized with hooks");
        } catch (const std::exception& ex) {
            LOG("CloudRedirect init FAILED: %s", ex.what());
            g_initFailed.store(true, std::memory_order_relaxed);
        } catch (...) {
            LOG("CloudRedirect init FAILED: unknown exception");
            g_initFailed.store(true, std::memory_order_relaxed);
        }
    });

    if (g_initFailed.load(std::memory_order_relaxed)) return 0;
    return CloudIntercept::OnSendPkt(thisptr, data, size) ? 1 : 0;
}

// Local declarations for LdrRegisterDllNotification (NTDLL); not in winternl.h.
namespace {
struct CR_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
};
struct CR_LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    const CR_UNICODE_STRING* FullDllName;
    const CR_UNICODE_STRING* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
};
union CR_LDR_DLL_NOTIFICATION_DATA {
    CR_LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    CR_LDR_DLL_LOADED_NOTIFICATION_DATA Unloaded;
};
constexpr ULONG CR_LDR_DLL_NOTIFICATION_REASON_LOADED = 1;
using CR_PLDR_DLL_NOTIFICATION_FUNCTION = VOID (CALLBACK*)(
    ULONG, const CR_LDR_DLL_NOTIFICATION_DATA*, PVOID);
using CR_PfnLdrRegisterDllNotification = LONG (NTAPI*)(
    ULONG, CR_PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID*);
}

static HANDLE g_diversionLoadedEvent = nullptr;
static PVOID  g_dllNotifyCookie = nullptr;

// Runs under the loader lock; must not allocate, take locks, or block.
static VOID CALLBACK OnDllLoaded(
    ULONG reason,
    const CR_LDR_DLL_NOTIFICATION_DATA* data,
    PVOID /*context*/)
{
    if (reason != CR_LDR_DLL_NOTIFICATION_REASON_LOADED) return;
    if (!data || !data->Loaded.BaseDllName || !data->Loaded.BaseDllName->Buffer) return;
    if (_wcsicmp(data->Loaded.BaseDllName->Buffer, L"diversion.dll") == 0) {
        SetEvent(g_diversionLoadedEvent);
    }
}

// Waits for diversion.dll to be mapped, then drives CR init by invoking
// CloudOnSendPkt with null args. CR's vtable hooks resolve their module
// base from diversion.dll under OpenSteamTool.
static DWORD WINAPI SelfInitThread(LPVOID /*param*/) {
    if (GetModuleHandleA("diversion.dll") != nullptr) {
        CloudOnSendPkt(nullptr, nullptr, 0, nullptr);
        return 0;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    auto pReg = reinterpret_cast<CR_PfnLdrRegisterDllNotification>(
        GetProcAddress(ntdll, "LdrRegisterDllNotification"));
    if (!pReg) return 0;

    g_diversionLoadedEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_diversionLoadedEvent) return 0;

    if (pReg(0, OnDllLoaded, nullptr, &g_dllNotifyCookie) != 0) {
        CloseHandle(g_diversionLoadedEvent);
        g_diversionLoadedEvent = nullptr;
        return 0;
    }

    // Closes the window where diversion.dll loaded between the initial check
    // and the subscription taking effect.
    if (GetModuleHandleA("diversion.dll") != nullptr) {
        SetEvent(g_diversionLoadedEvent);
    }

    WaitForSingleObject(g_diversionLoadedEvent, INFINITE);
    CloudOnSendPkt(nullptr, nullptr, 0, nullptr);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_thisModule = hModule;
        DisableThreadLibraryCalls(hModule);

        // Pin against FreeLibrary so hook threads survive.
        {
            HMODULE pinned = nullptr;
            GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCSTR>(&DllMain),
                &pinned);
        }

        {
            HANDLE h = CreateThread(nullptr, 0, SelfInitThread, nullptr, 0, nullptr);
            if (h) CloseHandle(h);
        }
        break;

    case DLL_PROCESS_DETACH:
        // FreeLibrary path only (we're pinned, so unreachable today). ExitProcess
        // path runs from an atexit hook installed in CloudIntercept::Init.
        if (reserved == nullptr) {
            CloudIntercept::Shutdown();
        }
        break;
    }
    return TRUE;
}
