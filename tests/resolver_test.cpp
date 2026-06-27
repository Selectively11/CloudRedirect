// Offline resolver test: loads steamclient64.dll and runs the auto-resolver.
// Usage: resolver_test.exe <steamclient64.dll> [<dll2> ...]

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <cstring>

// Stub common.h requirements
#ifndef COMMON_H_STUB
#define COMMON_H_STUB
#endif

// Provide Log::Write as printf
namespace Log {
    void Init(const char*) {}
    void Shutdown() {}
    void Write(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        printf("\n");
    }
}

#include "sc_resolver.h"
#include "sig_scanner.h"

static int TestDll(const char* path) {
    HMODULE hMod = LoadLibraryExA(path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) {
        printf("  LOAD FAILED: error %lu\n", GetLastError());
        return -1;
    }

    uintptr_t base = reinterpret_cast<uintptr_t>(hMod);
    printf("  Loaded at %p (size ~%u MB)\n", (void*)base,
        (unsigned)(SigScanner::Init(base) ? SigScanner::GetImageSize() / (1024*1024) : 0));

    // Re-init for Resolve (Resolve calls Init internally too)
    ScResolver::ResolvedAddrs r = ScResolver::Resolve(base);

    struct { const char* name; uintptr_t val; } fields[] = {
        {"CCMInterface VT",       r.ccmInterfaceVtable},
        {"ServiceTransport VT",   r.serviceTransportVtable},
        {"GlobalEngine",          r.globalEngine},
        {"ParseFromArray",        r.parseFromArray},
        {"SerializeToArray",      r.serializeToArray},
        {"WrapPacket",            r.wrapPacket},
        {"BRouteMsgToJob",        r.bRouteMsgToJob},
        {"ReleaseWrapped",        r.releaseWrapped},
        {"RefCountHelper",        r.refCountHelper},
        {"FindJob",               r.findJob},
        {"RefCountGlobal",        r.refCountGlobal},
        {"JobCurGlobal",          r.jobCurGlobal},
        {"BuildDepotDependency",  r.buildDepotDependency},
        {"GetAppMinutesPlayed",   r.getAppMinutesPlayedData},
        {"FlushAppMinutesPlayed", r.flushAppMinutesPlayed},
        {"SetAppLastPlayedTime",  r.setAppLastPlayedTime},
        {"KvFindKey",             r.kvFindKey},
        {"KvGetUint64",           r.kvGetUint64},
        {"KvGetInt",              r.kvGetInt},
        {"KvSetUint64",           r.kvSetUint64},
        {"KvSetInt",              r.kvSetInt},
        {"KvSetString",           r.kvSetString},
        {"GetAppInfo",            r.getAppInfo},
        {"GetSection",            r.getSection},
        {"ReadConfigU64",         r.readConfigU64},
    };
    constexpr int total = 25;
    int ok = 0, failed = 0;

    printf("\n  %-28s %-12s %s\n", "Address", "RVA", "Status");
    printf("  %-28s %-12s %s\n", "---", "---", "---");
    for (auto& f : fields) {
        if (f.val) {
            printf("  %-28s 0x%-10llX OK\n", f.name, (uint64_t)(f.val - base));
            ok++;
        } else {
            printf("  %-28s %-12s FAILED\n", f.name, "---");
            failed++;
        }
    }

    printf("\n  === %d/%d resolved, %d failed ===\n", ok, total, failed);

    FreeLibrary(hMod);
    return failed;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <steamclient64.dll> [<dll2> ...]\n", argv[0]);
        return 1;
    }

    int totalFailed = 0;
    for (int i = 1; i < argc; i++) {
        printf("\n========================================\n");
        printf("Testing: %s\n", argv[i]);
        printf("========================================\n");
        int ret = TestDll(argv[i]);
        if (ret < 0) totalFailed++;
        else totalFailed += ret;
    }

    printf("\n========================================\n");
    printf("OVERALL: %s\n", totalFailed == 0 ? "ALL PASSED" : "FAILURES DETECTED");
    printf("========================================\n");
    return totalFailed;
}
