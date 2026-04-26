#include "common.h"
#include "log.h"
#include "cloud_intercept.h"
#include "file_util.h"
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
