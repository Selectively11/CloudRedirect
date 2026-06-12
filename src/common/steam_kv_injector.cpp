#include "steam_kv_injector.h"
#include "log.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <link.h>
#include <cstdio>
#include <cstring>
#endif

namespace SteamKvInjector {

// Plausibility bounds for UFS quota; reject pointer-sized garbage reads.
static constexpr uint64_t kMaxPlausibleQuotaBytes = 1024ULL * 1024 * 1024 * 1024; // 1 TiB
static constexpr uint64_t kMaxPlausibleMaxFiles   = 10ULL * 1000 * 1000;          // 10M

static bool QuotaValueLooksValid(uint64_t quota, uint64_t files) {
    if (quota == 0 || files == 0) return false;
    if (quota > kMaxPlausibleQuotaBytes) return false;
    if (files > kMaxPlausibleMaxFiles)   return false;
    return true;
}

#ifdef _WIN32

// steamclient64.dll RVAs (IDA image base: 0x138000000)

// Global CSteamEngine* pointer. Same global already used by cloud_intercept.
// (SC_RVA_GLOBAL_ENGINE = 0x17A70E8 in that module.)
static constexpr uintptr_t SC_RVA_GLOBAL_ENGINE = 0x17C2D08;

// Offset from *qword_1397A70E8 to the CAppInfoCache instance.
// Pattern observed in many callers:
//   mov rbx, cs:qword_1397A70E8
//   lea rcx, [rbx + 0xE68]   ; 0xE68 = 3688
//   call CAppInfoCache::BlockOnInitialization
static constexpr uintptr_t APPINFOCACHE_OFFSET = 0xE68;

// CAppInfoCache::GetAppInfo(appId) -> appInfo*
static constexpr uintptr_t SC_RVA_GET_APP_INFO = 0x49D9C0;

// CAppInfoCache::GetSection(appInfo, sectionId) -> KeyValues*
// sectionId 10 = "ufs"
static constexpr uintptr_t SC_RVA_GET_SECTION = 0x49FCF0;

// CAppInfoCache::ReadAppConfigUint64(cache, appId, sectionId, keyName, defaultVal)
static constexpr uintptr_t SC_RVA_READ_CONFIG_U64 = 0x49EA30;

// BlockOnInit -- calls CThread::Join off-engine-thread, crashes/deadlocks. Do not call.
// Cache is already loaded before our RPC handlers run.
// static constexpr uintptr_t SC_RVA_BLOCK_ON_INIT = 0x4B4D90;

// KeyValues::FindKey(parent, name, bCreate, out)
// When bCreate=1 creates the key if not present.
static constexpr uintptr_t SC_RVA_KV_FIND_KEY = 0xCFA7F0;

// KeyValues::GetUint64(kv, defaultVal, key)
static constexpr uintptr_t SC_RVA_KV_GET_UINT64 = 0xCFBB40;

// KeyValues::GetInt(kv, defaultVal, key)
static constexpr uintptr_t SC_RVA_KV_GET_INT = 0xCFB6F0;

// KeyValues::SetUint64(kv, value)
static constexpr uintptr_t SC_RVA_KV_SET_UINT64 = 0xCFBDB0;

// KeyValues::SetInt(kv, value)
static constexpr uintptr_t SC_RVA_KV_SET_INT = 0xCFBDF0;

// KeyValues::SetString(kv, value) -- sets string value on a KV leaf node
static constexpr uintptr_t SC_RVA_KV_SET_STRING = 0xCFBE30;

// CAppInfoUpdater::RequestAppInfoUpdate -- not yet wired (offset unconfirmed).
// Steam's background PICS populates KV on its own schedule; cached values suffice.
// static constexpr uintptr_t SC_RVA_REQUEST_APP_INFO = 0x4B9EA0;

using GetAppInfoFn = void* (__fastcall*)(void* cache, uint32_t appId);
using GetSectionFn = void* (__fastcall*)(void* appInfo, uint32_t sectionId);
using KvFindKeyFn = void* (__fastcall*)(void* parent, const char* name, uint8_t bCreate, void* outChild);
// ReadAppConfigUint64(cache, appId, sectionId, keyName, defaultVal)
using ReadConfigU64Fn = uint64_t (__fastcall*)(void* cache, uint64_t appId, uint32_t sectionId, const char* keyName, uint64_t defaultVal);
// KV::GetUint64(kvNode, defaultVal, outStatusOrNull) -- raw node accessor
using KvGetUint64Fn = uint64_t (__fastcall*)(void* kvNode, uint64_t defaultVal, void* outStatus);
using KvGetIntFn = int (__fastcall*)(void* kvNode, int defaultVal, void* outStatus);
using KvSetUint64Fn = void (__fastcall*)(void* kvNode, uint64_t value);
using KvSetIntFn = void (__fastcall*)(void* kvNode, int value);
using KvSetStringFn = void (__fastcall*)(void* kvNode, const char* value);

struct Resolved {
    void** globalEnginePtrPtr = nullptr; // address of qword_1397A70E8 (a void**)
    GetAppInfoFn     getAppInfo = nullptr;
    GetSectionFn     getSection = nullptr;
    ReadConfigU64Fn  readConfigU64 = nullptr;
    KvFindKeyFn      kvFindKey = nullptr;
    KvGetUint64Fn    kvGetUint64 = nullptr;
    KvGetIntFn       kvGetInt = nullptr;
    KvSetUint64Fn    kvSetUint64 = nullptr;
    KvSetIntFn       kvSetInt = nullptr;
    KvSetStringFn    kvSetString = nullptr;
};

static Resolved g_r;
static std::atomic<bool> g_ready{false};
static std::once_flag g_initOnce;

// Section ID for "ufs" in the app config KV tree.
static constexpr uint32_t kSectionUfs = 10;

// Resolve CAppInfoCache from global engine ptr; null if Steam not init'd
static void* GetCachePtr() {
    if (!g_r.globalEnginePtrPtr) return nullptr;
    void* engine = *g_r.globalEnginePtrPtr;
    if (!engine) return nullptr;
    return reinterpret_cast<uint8_t*>(engine) + APPINFOCACHE_OFFSET;
}

bool Init() {
    bool success = false;
    std::call_once(g_initOnce, [&]() {
        HMODULE hSC = GetModuleHandleA("steamclient64.dll");
        if (!hSC) {
            LOG("[KvInjector] Init: steamclient64.dll not loaded yet");
            return;
        }
        uintptr_t base = reinterpret_cast<uintptr_t>(hSC);
        LOG("[KvInjector] Init: steamclient64.dll base %p", hSC);

        g_r.globalEnginePtrPtr = reinterpret_cast<void**>(base + SC_RVA_GLOBAL_ENGINE);
        g_r.getAppInfo    = reinterpret_cast<GetAppInfoFn>(base + SC_RVA_GET_APP_INFO);
        g_r.getSection    = reinterpret_cast<GetSectionFn>(base + SC_RVA_GET_SECTION);
        g_r.readConfigU64 = reinterpret_cast<ReadConfigU64Fn>(base + SC_RVA_READ_CONFIG_U64);
        g_r.kvFindKey     = reinterpret_cast<KvFindKeyFn>(base + SC_RVA_KV_FIND_KEY);
        g_r.kvGetUint64   = reinterpret_cast<KvGetUint64Fn>(base + SC_RVA_KV_GET_UINT64);
        g_r.kvGetInt      = reinterpret_cast<KvGetIntFn>(base + SC_RVA_KV_GET_INT);
        g_r.kvSetUint64   = reinterpret_cast<KvSetUint64Fn>(base + SC_RVA_KV_SET_UINT64);
        g_r.kvSetInt      = reinterpret_cast<KvSetIntFn>(base + SC_RVA_KV_SET_INT);
        g_r.kvSetString   = reinterpret_cast<KvSetStringFn>(base + SC_RVA_KV_SET_STRING);

        // Guard against wrong steamclient build -- bad RVA crashes on first call
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((LPCVOID)g_r.getAppInfo, &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY)) == 0) {
            LOG("[KvInjector] Init: getAppInfo at %p not in executable memory; aborting",
                g_r.getAppInfo);
            return;
        }

        LOG("[KvInjector] Init: resolved function pointers (engine global @ %p)",
            g_r.globalEnginePtrPtr);
        g_ready.store(true, std::memory_order_release);
        success = true;
    });
    return success || g_ready.load(std::memory_order_acquire);
}

bool IsReady() {
    return g_ready.load(std::memory_order_acquire);
}

bool ReadAppQuota(uint32_t appId, uint64_t& outQuotaBytes, uint32_t& outMaxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;

    void* cache = GetCachePtr();
    if (!cache) return false;

    uint64_t quota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
    uint64_t files = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);

    if (!QuotaValueLooksValid(quota, files)) {
        if (quota != 0 || files != 0) {
            LOG("[KvInjector] ReadAppQuota app=%u: implausible quota=%llu files=%llu",
                appId, (unsigned long long)quota, (unsigned long long)files);
        }
        outQuotaBytes = 0;
        outMaxNumFiles = 0;
        return true;
    }

    outQuotaBytes  = quota;
    outMaxNumFiles = static_cast<uint32_t>(files);
    return true;
}

bool TriggerPicsAndWait(uint32_t appId,
                        uint64_t& outQuotaBytes,
                        uint32_t& outMaxNumFiles,
                        int timeoutMs) {
    if (!g_ready.load(std::memory_order_acquire)) return false;

    // No PICS trigger wired yet -- just poll. Returns false so caller uses cached values.

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    uint64_t q = 0;
    uint32_t f = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (ReadAppQuota(appId, q, f) && q > 0 && f > 0) {
            outQuotaBytes = q;
            outMaxNumFiles = f;
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

bool InjectAppQuota(uint32_t appId, uint64_t quotaBytes, uint32_t maxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (quotaBytes == 0 || maxNumFiles == 0) {
        LOG("[KvInjector] InjectAppQuota app=%u: refusing zero values "
            "(quota=%llu files=%u)",
            appId, (unsigned long long)quotaBytes, maxNumFiles);
        return false;
    }

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectAppQuota app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = g_r.getAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectAppQuota app=%u: no app info entry "
            "(PICS has never returned for this app)", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectAppQuota app=%u: ufs section missing "
            "(app config has no cloud config at all)", appId);
        // No ufs section -> AutoCloud short-circuits with "no config data"; saves stay intact
        return false;
    }

    // Preserve Steam's PICS values only if plausible; overwrite garbage.
    uint64_t existingQuota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
    uint64_t existingFiles = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);
    bool existingValid = QuotaValueLooksValid(existingQuota, existingFiles);

    bool wroteQuota = false;
    bool wroteFiles = false;

    bool quotaNeedsWrite = (existingQuota == 0) ||
                           (existingQuota > kMaxPlausibleQuotaBytes) || !existingValid;
    bool filesNeedsWrite = (existingFiles == 0) ||
                           (existingFiles > kMaxPlausibleMaxFiles) || !existingValid;

    if (quotaNeedsWrite) {
        void* quotaKv = g_r.kvFindKey(ufs, "quota", 1, nullptr);
        if (quotaKv) {
            g_r.kvSetUint64(quotaKv, quotaBytes);
            wroteQuota = true;
        }
    }
    if (filesNeedsWrite) {
        void* filesKv = g_r.kvFindKey(ufs, "maxnumfiles", 1, nullptr);
        if (filesKv) {
            g_r.kvSetInt(filesKv, static_cast<int>(maxNumFiles));
            wroteFiles = true;
        }
    }

    if (wroteQuota || wroteFiles) {
        LOG("[KvInjector] InjectAppQuota app=%u: injected quota=%llu files=%u "
            "(wroteQuota=%d wroteFiles=%d, existingQuota=%llu existingFiles=%llu)",
            appId, (unsigned long long)quotaBytes, maxNumFiles,
            wroteQuota ? 1 : 0, wroteFiles ? 1 : 0,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    } else {
        LOG("[KvInjector] InjectAppQuota app=%u: skipped (Steam already has "
            "quota=%llu files=%llu)", appId,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    }
    return true;
}

bool InjectSaveFiles(uint32_t appId, const std::vector<SaveFileRule>& rules) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (rules.empty()) return false;

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectSaveFiles app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = g_r.getAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectSaveFiles app=%u: no app info entry", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectSaveFiles app=%u: ufs section missing", appId);
        return false;
    }

    // Check if savefiles already exists with children. If so, don't clobber.
    void* existing = g_r.kvFindKey(ufs, "savefiles", 0, nullptr);
    if (existing) {
        // KV node exists -- check if it has children by trying to find child "0"
        void* child0 = g_r.kvFindKey(existing, "0", 0, nullptr);
        if (child0) {
            LOG("[KvInjector] InjectSaveFiles app=%u: savefiles already populated, skipping",
                appId);
            return true;
        }
    }

    // Create or get the savefiles subsection
    void* savefiles = g_r.kvFindKey(ufs, "savefiles", 1, nullptr);
    if (!savefiles) {
        LOG("[KvInjector] InjectSaveFiles app=%u: failed to create savefiles key", appId);
        return false;
    }

    int injected = 0;
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& rule = rules[i];
        std::string idxStr = std::to_string(i);

        // Create numbered subsection: savefiles/"0", savefiles/"1", etc.
        void* entry = g_r.kvFindKey(savefiles, idxStr.c_str(), 1, nullptr);
        if (!entry) continue;

        // Set root
        void* rootKv = g_r.kvFindKey(entry, "root", 1, nullptr);
        if (rootKv) g_r.kvSetString(rootKv, rule.root.c_str());

        // Set path
        if (!rule.path.empty()) {
            void* pathKv = g_r.kvFindKey(entry, "path", 1, nullptr);
            if (pathKv) g_r.kvSetString(pathKv, rule.path.c_str());
        }

        // Set pattern
        void* patternKv = g_r.kvFindKey(entry, "pattern", 1, nullptr);
        if (patternKv) g_r.kvSetString(patternKv, rule.pattern.c_str());

        // Set recursive (only if true, since Steam defaults to false)
        if (rule.recursive) {
            void* recursiveKv = g_r.kvFindKey(entry, "recursive", 1, nullptr);
            if (recursiveKv) g_r.kvSetInt(recursiveKv, 1);
        }

        // Set platforms (only if not all-platforms)
        if (rule.platforms != 0xFFFFFFFFu) {
            void* platformsKv = g_r.kvFindKey(entry, "platforms", 1, nullptr);
            if (platformsKv) {
                // Steam iterates "platforms" children as named strings ("windows", "macos", etc.).
                if (rule.platforms & 1) {
                    void* k = g_r.kvFindKey(platformsKv, "1", 1, nullptr);
                    if (k) g_r.kvSetString(k, "windows");
                }
                if (rule.platforms & 2) {
                    void* k = g_r.kvFindKey(platformsKv, "2", 1, nullptr);
                    if (k) g_r.kvSetString(k, "macos");
                }
                if (rule.platforms & 8) {
                    void* k = g_r.kvFindKey(platformsKv, "3", 1, nullptr);
                    if (k) g_r.kvSetString(k, "linux");
                }
            }
        }

        ++injected;
    }

    LOG("[KvInjector] InjectSaveFiles app=%u: injected %d savefiles rules", appId, injected);
    return injected > 0;
}

#else // !_WIN32 -- Linux 32-bit steamclient.so

// Linux steamclient.so -- runtime signature scanning; falls back to hardcoded RVAs (build 1781043450)

// Fallback RVAs (steamclient.so build 1781043450, IDA image base 0x0).
static constexpr uintptr_t FALLBACK_RVA_GLOBAL_ENGINE   = 0x2ED1BC0;
static constexpr uintptr_t FALLBACK_RVA_READ_CONFIG_U64 = 0xF77960;
static constexpr uintptr_t FALLBACK_RVA_GET_SECTION     = 0xF74EC0;
static constexpr uintptr_t FALLBACK_RVA_KV_FIND_KEY     = 0x2517320;
static constexpr uintptr_t FALLBACK_RVA_KV_SET_UINT64   = 0x2512070;
static constexpr uintptr_t FALLBACK_RVA_KV_SET_INT32    = 0x2512040;
static constexpr uintptr_t FALLBACK_RVA_KV_SET_STRING   = 0x2511EE0;

// Offset from CSteamEngine* to CAppInfoCache instance.
static constexpr uintptr_t APPINFOCACHE_OFFSET = 2952; // 0xB88

// Inline BST node layout (read off CAppInfoCache at offset 96, stride 24):
//   +0   uint32   left child index
//   +4   uint32   right child index
//   +16  uint32   appId  (key)
//   +20  uint32*  appInfo pointer  (value)
// Root index is at (manager + 76), -1 means empty tree.

using ReadConfigU64Fn = uint64_t(*)(void* cache, uint32_t appId, uint32_t sectionId,
                                    const char* keyName, uint64_t defaultVal);
using GetSectionFn   = void*(*)(void* appInfo, uint32_t sectionId);
using KvFindKeyFn    = void*(*)(void* parent, const char* name, uint8_t bCreate, void* outArr);
using KvSetUint64Fn  = void (*)(void* kv, uint32_t lo, uint32_t hi);
using KvSetInt32Fn   = void (*)(void* kv, int32_t value);
using KvSetStringFn  = void (*)(void* kv, const char* value);

struct Resolved {
    void**          globalEnginePtr  = nullptr;
    ReadConfigU64Fn readConfigU64    = nullptr;
    GetSectionFn    getSection       = nullptr;
    KvFindKeyFn     kvFindKey        = nullptr;
    KvSetUint64Fn   kvSetUint64      = nullptr;
    KvSetInt32Fn    kvSetInt32       = nullptr;
    KvSetStringFn   kvSetString      = nullptr;
};

static Resolved g_r;
static std::atomic<bool> g_ready{false};
static std::once_flag g_initOnce;

static constexpr uint32_t kSectionUfs = 10;

struct MemRegion { uintptr_t start; uintptr_t end; };

// Find steamclient.so base and executable region via dl_iterate_phdr.
struct FindSteamCtx {
    uintptr_t base = 0;
    uintptr_t textStart = 0;
    uintptr_t textEnd = 0;
    uintptr_t moduleEnd = 0; // highest mapped VA across all PT_LOAD segments
};

static int FindSteamPhdrCb(struct dl_phdr_info* info, size_t, void* data) {
    if (!info || !info->dlpi_name) return 0;
    const char* name = info->dlpi_name;
    const char* slash = strrchr(name, '/');
    const char* leaf = slash ? slash + 1 : name;
    if (strcmp(leaf, "steamclient.so") != 0) return 0;

    auto* ctx = static_cast<FindSteamCtx*>(data);
    ctx->base = info->dlpi_addr;

    // Largest PF_X segment is .text; track the highest mapped VA for bounds checks.
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        uintptr_t segStart = info->dlpi_addr + ph.p_vaddr;
        uintptr_t segEnd = segStart + ph.p_memsz;
        if (segEnd > ctx->moduleEnd) ctx->moduleEnd = segEnd;
        if ((ph.p_flags & PF_X) &&
            (segEnd - segStart) > (ctx->textEnd - ctx->textStart)) {
            ctx->textStart = segStart;
            ctx->textEnd = segEnd;
        }
    }
    return 1;
}

// Pattern match with '?' as wildcard byte. Pattern is a string like
// "55 57 56 53 E8 ? ? ? ? 81 C3 ? ? ? ? 83 EC 1C".
// Returns absolute address of first match, or 0 on failure.
static uintptr_t ScanPattern(uintptr_t start, uintptr_t end,
                             const uint8_t* pattern, const uint8_t* mask,
                             size_t patLen) {
    if (patLen == 0 || start >= end) return 0;
    size_t scanLen = end - start - patLen;
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(start);
    for (size_t i = 0; i <= scanLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < patLen; ++j) {
            if (mask[j] && mem[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return start + i;
    }
    return 0;
}

static uintptr_t DecodeRelCall(uintptr_t addr) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(addr);
    if (p[0] != 0xE8) return 0;
    int32_t rel;
    memcpy(&rel, p + 1, 4);
    return addr + 5 + rel;
}

static bool IsLeaEbxDisp32(const uint8_t* p, uint8_t& outReg) {
    if (p[0] != 0x8D || (p[1] & 0xC7) != 0x83) return false;
    outReg = (p[1] >> 3) & 7;
    return true;
}

// Resolve &g_engine at runtime by decoding the GOTOFF address-of idiom:
//   lea reg2,[ebx+leaDisp]; mov reg,[reg2]; add reg,0xB88
// where ebx is the GOT base from this function's "add ebx,imm32" prologue.
// Build-independent, unlike a hardcoded RVA.
static uintptr_t FindGlobalEnginePtr(uintptr_t textStart, uintptr_t textEnd,
                                     uintptr_t soBase, uintptr_t soEnd) {
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(textStart);
    size_t len = textEnd - textStart;

    for (size_t i = 8; i + 6 <= len; ++i) {
        // add reg, 0xB88
        if (mem[i] != 0x81) continue;
        if (mem[i + 1] < 0xC0 || mem[i + 1] > 0xC7) continue;
        if (mem[i + 2] != 0x88 || mem[i + 3] != 0x0B ||
            mem[i + 4] != 0x00 || mem[i + 5] != 0x00) continue;

        uintptr_t addAddr = textStart + i;

        // mov reg, [reg2]
        if (mem[i - 2] != 0x8B) continue;
        uint8_t movModrm = mem[i - 1];
        if ((movModrm >> 6) != 0) continue;
        uint8_t movBase = movModrm & 7;
        if (movBase == 4 || movBase == 5) continue;

        // lea reg2, [ebx + leaDisp], feeding the mov above
        uint8_t leaReg = 0;
        if (!IsLeaEbxDisp32(&mem[i - 8], leaReg)) continue;
        if (leaReg != movBase) continue;

        int32_t leaDisp;
        memcpy(&leaDisp, &mem[i - 8 + 2], 4);

        // get_pc_thunk.bx returns the address of the "add ebx,imm32" itself, so
        // the runtime GOT base is addr_of_add + imm32 (not the add's end).
        uintptr_t gotBase = 0;
        size_t maxBack = (i < 512) ? i : 512;
        for (size_t back = 9; back <= maxBack; ++back) {
            size_t k = i - back;
            if (mem[k] == 0x81 && mem[k + 1] == 0xC3) {
                int32_t gotDisp;
                memcpy(&gotDisp, &mem[k + 2], 4);
                gotBase = (textStart + k) + static_cast<uintptr_t>(static_cast<intptr_t>(gotDisp));
                break;
            }
        }
        if (!gotBase) continue;

        uintptr_t engineGlobal = gotBase + static_cast<uintptr_t>(static_cast<intptr_t>(leaDisp));
        if (engineGlobal <= soBase || engineGlobal >= soEnd) continue;

        LOG("[KvInjector] SigScan: engine global &g_engine = 0x%lx (base+0x%lx)",
            (unsigned long)engineGlobal, (unsigned long)(engineGlobal - soBase));
        return engineGlobal;
    }
    return 0;
}

static void* GetCachePtr() {
    if (!g_r.globalEnginePtr) return nullptr;
    void* engine = *g_r.globalEnginePtr;
    if (!engine) return nullptr;
    return reinterpret_cast<uint8_t*>(engine) + APPINFOCACHE_OFFSET;
}

// ReadConfigU64: push ebp; push edi; push esi; push ebx; call thunk;
//   add ebx,<GOT>; sub esp,1Ch; mov eax,[esp+40h]; mov ebp,[esp+...]
// Unique: "55 57 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 83 EC 1C 8B 44 24 40"
static const uint8_t kSigReadConfigU64[] = {
    0x55, 0x57, 0x56, 0x53, 0xE8, 0x00, 0x00, 0x00, 0x00,
    0x81, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x1C,
    0x8B, 0x44, 0x24, 0x40
};
static const uint8_t kMaskReadConfigU64[] = {
    1, 1, 1, 1, 1, 0, 0, 0, 0,  // push*4 + call rel32 (wildcard offset)
    1, 1, 0, 0, 0, 0, 1, 1, 1,  // add ebx,<GOT> (wildcard imm) + sub esp,1Ch
    1, 1, 1, 1                   // mov eax,[esp+40h]
};

// KvSetUint64: push edi; push esi; push ebx; mov ebx,[esp+10];
//   mov esi,[esp+14]; mov edi,[esp+18]; test ebx,ebx; jz short
static const uint8_t kSigKvSetUint64[] = {
    0x57, 0x56, 0x53, 0x8B, 0x5C, 0x24, 0x10,
    0x8B, 0x74, 0x24, 0x14, 0x8B, 0x7C, 0x24, 0x18,
    0x85, 0xDB, 0x74
};
static const uint8_t kMaskKvSetUint64[] = {
    1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1
};

// KvSetInt32: push ebx; sub esp,8; mov ebx,[esp+10]; test ebx,ebx; jz short;
// then sub esp,0Ch; push ebx; call type-clear-helper; mov eax,[esp+24].
// The "8B 44 24 24" (mov eax,[esp+24]) at offset +0x15 distinguishes int from
// the same-shape KvSetFloat which has "D9 44 24 0C" (fld dword [esp+0Ch]).
static const uint8_t kSigKvSetInt32[] = {
    0x53, 0x83, 0xEC, 0x08, 0x8B, 0x5C, 0x24, 0x10,
    0x85, 0xDB, 0x74, 0x00, 0x83, 0xEC, 0x0C, 0x53,
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x24
};
static const uint8_t kMaskKvSetInt32[] = {
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 0, 1, 1, 1, 1,
    1, 0, 0, 0, 0, 1, 1, 1, 1
};

// Offset from ReadConfigU64 start to the "call GetSection" instruction.
// In the current build: 0xF49C8B - 0xF49BD0 = 0xBB.
// We scan nearby (+/- 32 bytes) for the call to handle minor recompilation shifts.
static constexpr size_t kReadConfigGetSectionCallMin = 0xA0;
static constexpr size_t kReadConfigGetSectionCallMax = 0xD0;

// Extract a call target by scanning for E8 in [minOff, maxOff] within funcStart.
static uintptr_t FindCallInRange(uintptr_t funcStart, size_t minOff, size_t maxOff,
                                 uintptr_t minTarget, uintptr_t maxTarget) {
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(funcStart);
    for (size_t off = minOff; off <= maxOff; ++off) {
        if (mem[off] != 0xE8) continue;
        uintptr_t target = DecodeRelCall(funcStart + off);
        if (target >= minTarget && target < maxTarget) return target;
    }
    return 0;
}

bool Init() {
    bool success = false;
    std::call_once(g_initOnce, [&]() {
        FindSteamCtx ctx;
        dl_iterate_phdr(FindSteamPhdrCb, &ctx);
        if (!ctx.base) {
            LOG("[KvInjector] Init: steamclient.so not yet loaded");
            return;
        }
        uintptr_t base = ctx.base;
        LOG("[KvInjector] Init: steamclient.so base 0x%lx, text 0x%lx-0x%lx (%lu MB)",
            (unsigned long)base,
            (unsigned long)ctx.textStart, (unsigned long)ctx.textEnd,
            (unsigned long)((ctx.textEnd - ctx.textStart) / (1024*1024)));

        bool usedSigs = false;

        uintptr_t readCfg = ScanPattern(ctx.textStart, ctx.textEnd,
                                        kSigReadConfigU64, kMaskReadConfigU64,
                                        sizeof(kSigReadConfigU64));
        if (readCfg) {
            LOG("[KvInjector] SigScan: ReadConfigU64 at 0x%lx (base+0x%lx)",
                (unsigned long)readCfg, (unsigned long)(readCfg - base));
        }

        // GetSection: within 64KB before ReadConfigU64 (rejects far PLT thunks).
        uintptr_t getSect = 0;
        if (readCfg) {
            uintptr_t minTarget = (readCfg > 0x10000) ? readCfg - 0x10000 : ctx.textStart;
            getSect = FindCallInRange(readCfg,
                                      kReadConfigGetSectionCallMin,
                                      kReadConfigGetSectionCallMax,
                                      minTarget, readCfg);
            if (getSect) {
                LOG("[KvInjector] SigScan: GetSection at 0x%lx (base+0x%lx)",
                    (unsigned long)getSect, (unsigned long)(getSect - base));
            }
        }

        // Match "push 0; push 0; push eax; push esi; call" (the 4-arg
        // FindKey call) to skip the earlier string-normalize call.
        uintptr_t kvFind = 0;
        if (getSect) {
            const uint8_t kCallPrefix[] = { 0x6A, 0x00, 0x6A, 0x00, 0x50, 0x56, 0xE8 };
            const uint8_t* mem = reinterpret_cast<const uint8_t*>(getSect);
            constexpr size_t kSearchLen = 0x80; // enough for the dispatch arm
            for (size_t i = 0; i + sizeof(kCallPrefix) + 4 <= kSearchLen; ++i) {
                if (memcmp(mem + i, kCallPrefix, sizeof(kCallPrefix)) == 0) {
                    uintptr_t callAddr = getSect + i + sizeof(kCallPrefix) - 1;
                    kvFind = DecodeRelCall(callAddr);
                    break;
                }
            }
            if (kvFind) {
                LOG("[KvInjector] SigScan: KvFindKey at 0x%lx (base+0x%lx)",
                    (unsigned long)kvFind, (unsigned long)(kvFind - base));
            }
        }

        uintptr_t kvSetU64 = ScanPattern(ctx.textStart, ctx.textEnd,
                                         kSigKvSetUint64, kMaskKvSetUint64,
                                         sizeof(kSigKvSetUint64));
        if (kvSetU64) {
            LOG("[KvInjector] SigScan: KvSetUint64 at 0x%lx (base+0x%lx)",
                (unsigned long)kvSetU64, (unsigned long)(kvSetU64 - base));
        }

        uintptr_t kvSetI32 = ScanPattern(ctx.textStart, ctx.textEnd,
                                         kSigKvSetInt32, kMaskKvSetInt32,
                                         sizeof(kSigKvSetInt32));
        if (kvSetI32) {
            LOG("[KvInjector] SigScan: KvSetInt32 at 0x%lx (base+0x%lx)",
                (unsigned long)kvSetI32, (unsigned long)(kvSetI32 - base));
        }

        uintptr_t globalEng = FindGlobalEnginePtr(ctx.textStart, ctx.textEnd, base,
                                                  ctx.moduleEnd);
        if (globalEng) {
            LOG("[KvInjector] SigScan: globalEnginePtr at 0x%lx (base+0x%lx)",
                (unsigned long)globalEng, (unsigned long)(globalEng - base));
        }

        // KvSetString: scan backward from KvSetInt32 for the type=2 tail
        // (and eax,0xE1; or eax,2; mov [esi+0Bh],al), then walk back to the
        // push ebp/edi/esi/ebx prologue.
        uintptr_t kvSetStr = 0;
        if (kvSetI32) {
            const uint8_t kTyp2[] = { 0x83, 0xE0, 0xE1, 0x83, 0xC8, 0x02, 0x88, 0x46, 0x0B };
            uintptr_t scanStart = (kvSetI32 > 0x400) ? kvSetI32 - 0x400 : ctx.textStart;
            const uint8_t* mem = reinterpret_cast<const uint8_t*>(scanStart);
            size_t scanLen = kvSetI32 - scanStart;
            for (size_t i = 0; i + sizeof(kTyp2) <= scanLen; ++i) {
                if (memcmp(mem + i, kTyp2, sizeof(kTyp2)) == 0) {
                    uintptr_t matchAddr = scanStart + i;
                    for (size_t back = 0x20; back < 0xB0; ++back) {
                        uintptr_t candidate = matchAddr - back;
                        const uint8_t* fb = reinterpret_cast<const uint8_t*>(candidate);
                        if (fb[0] == 0x55 && fb[1] == 0x57 && fb[2] == 0x56 &&
                            fb[3] == 0x53 && fb[4] == 0xE8) {
                            kvSetStr = candidate;
                            break;
                        }
                    }
                    if (kvSetStr) break;
                }
            }
        }
        if (kvSetStr) {
            LOG("[KvInjector] SigScan: KvSetString at 0x%lx (base+0x%lx)",
                (unsigned long)kvSetStr, (unsigned long)(kvSetStr - base));
        }

        if (readCfg && getSect && kvFind && kvSetU64 && kvSetI32 && kvSetStr && globalEng) {
            g_r.globalEnginePtr = reinterpret_cast<void**>(globalEng);
            g_r.readConfigU64   = reinterpret_cast<ReadConfigU64Fn>(readCfg);
            g_r.getSection      = reinterpret_cast<GetSectionFn>(getSect);
            g_r.kvFindKey       = reinterpret_cast<KvFindKeyFn>(kvFind);
            g_r.kvSetUint64     = reinterpret_cast<KvSetUint64Fn>(kvSetU64);
            g_r.kvSetInt32      = reinterpret_cast<KvSetInt32Fn>(kvSetI32);
            g_r.kvSetString     = reinterpret_cast<KvSetStringFn>(kvSetStr);
            usedSigs = true;
            LOG("[KvInjector] Init: all signatures resolved successfully");
        } else {
            LOG("[KvInjector] SigScan: partial (readCfg=%d getSect=%d kvFind=%d "
                "kvSetU64=%d kvSetI32=%d kvSetStr=%d global=%d)",
                readCfg ? 1 : 0, getSect ? 1 : 0, kvFind ? 1 : 0,
                kvSetU64 ? 1 : 0, kvSetI32 ? 1 : 0, kvSetStr ? 1 : 0, globalEng ? 1 : 0);

            g_r.globalEnginePtr = reinterpret_cast<void**>(globalEng ? globalEng : (base + FALLBACK_RVA_GLOBAL_ENGINE));
            g_r.readConfigU64   = reinterpret_cast<ReadConfigU64Fn>(readCfg ? readCfg : (base + FALLBACK_RVA_READ_CONFIG_U64));
            g_r.getSection      = reinterpret_cast<GetSectionFn>(getSect ? getSect : (base + FALLBACK_RVA_GET_SECTION));
            g_r.kvFindKey       = reinterpret_cast<KvFindKeyFn>(kvFind ? kvFind : (base + FALLBACK_RVA_KV_FIND_KEY));
            g_r.kvSetUint64     = reinterpret_cast<KvSetUint64Fn>(kvSetU64 ? kvSetU64 : (base + FALLBACK_RVA_KV_SET_UINT64));
            g_r.kvSetInt32      = reinterpret_cast<KvSetInt32Fn>(kvSetI32 ? kvSetI32 : (base + FALLBACK_RVA_KV_SET_INT32));
            g_r.kvSetString     = reinterpret_cast<KvSetStringFn>(kvSetStr ? kvSetStr : (base + FALLBACK_RVA_KV_SET_STRING));

            // Don't trust fallback RVAs if criticals couldn't be sig-scanned.
            // readConfigU64 is included: a stale fallback there crashes in
            // steamclient's BST walk on the first GetChangelist RPC.
            if (!globalEng || !getSect || !kvFind || !readCfg) {
                LOG("[KvInjector] Critical functions unresolved -- KV injector DISABLED (prevents crash on stale RVAs)");
                return;
            }
            usedSigs = true;
        }

        LOG("[KvInjector] Init: resolved Linux pointers (engine global @ %p, sigs=%d)",
            g_r.globalEnginePtr, usedSigs ? 1 : 0);
        g_ready.store(true, std::memory_order_release);
        success = true;
    });
    return success || g_ready.load(std::memory_order_acquire);
}

bool IsReady() {
    return g_ready.load(std::memory_order_acquire);
}

bool ReadAppQuota(uint32_t appId, uint64_t& outQuotaBytes, uint32_t& outMaxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    void* cache = GetCachePtr();
    if (!cache) return false;

    uint64_t quota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
    uint64_t files = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);

    if (!QuotaValueLooksValid(quota, files)) {
        if (quota != 0 || files != 0) {
            LOG("[KvInjector] ReadAppQuota app=%u: implausible quota=%llu files=%llu",
                appId, (unsigned long long)quota, (unsigned long long)files);
        }
        outQuotaBytes = 0;
        outMaxNumFiles = 0;
        return true;
    }

    outQuotaBytes  = quota;
    outMaxNumFiles = static_cast<uint32_t>(files);
    return true;
}

bool TriggerPicsAndWait(uint32_t appId,
                        uint64_t& outQuotaBytes,
                        uint32_t& outMaxNumFiles,
                        int timeoutMs) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    // No active PICS-trigger plumbing yet on Linux; poll only.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    uint64_t q = 0;
    uint32_t f = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (ReadAppQuota(appId, q, f) && q > 0 && f > 0) {
            outQuotaBytes = q;
            outMaxNumFiles = f;
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

// Inline BST walk: manager+76=rootIndex, manager+96=nodes (24-byte stride).
// node+16=appId, node+20=appInfo. Returns null if appId not in cache.
static void* ResolveAppInfo(void* cache, uint32_t appId) {
    if (!cache) return nullptr;
    uint8_t* cacheBytes = static_cast<uint8_t*>(cache);
    int32_t  rootIdx = *reinterpret_cast<int32_t*>(cacheBytes + 76);
    uint8_t* nodes   = *reinterpret_cast<uint8_t**>(cacheBytes + 96);
    if (rootIdx < 0 || !nodes) return nullptr;

    int32_t idx = rootIdx;
    while (idx >= 0) {
        uint8_t* node = nodes + static_cast<size_t>(idx) * 24;
        uint32_t nodeAppId = *reinterpret_cast<uint32_t*>(node + 16);
        if (appId < nodeAppId) {
            idx = *reinterpret_cast<int32_t*>(node + 0);
        } else if (appId > nodeAppId) {
            idx = *reinterpret_cast<int32_t*>(node + 4);
        } else {
            return *reinterpret_cast<void**>(node + 20);
        }
    }
    return nullptr;
}

bool InjectAppQuota(uint32_t appId, uint64_t quotaBytes, uint32_t maxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (quotaBytes == 0 || maxNumFiles == 0) {
        LOG("[KvInjector] InjectAppQuota app=%u: refusing zero values "
            "(quota=%llu files=%u)",
            appId, (unsigned long long)quotaBytes, maxNumFiles);
        return false;
    }

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectAppQuota app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = ResolveAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectAppQuota app=%u: no app info entry "
            "(PICS has never returned for this app)", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectAppQuota app=%u: ufs section missing "
            "(app config has no cloud config at all)", appId);
        return false;
    }

    // Preserve Steam's PICS values only if plausible; overwrite garbage.
    uint64_t existingQuota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
    uint64_t existingFiles = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);
    bool existingValid = QuotaValueLooksValid(existingQuota, existingFiles);

    bool wroteQuota = false;
    bool wroteFiles = false;

    bool quotaNeedsWrite = (existingQuota == 0) ||
                           (existingQuota > kMaxPlausibleQuotaBytes) || !existingValid;
    bool filesNeedsWrite = (existingFiles == 0) ||
                           (existingFiles > kMaxPlausibleMaxFiles) || !existingValid;

    if (quotaNeedsWrite) {
        void* quotaKv = g_r.kvFindKey(ufs, "quota", 1, nullptr);
        if (quotaKv) {
            uint32_t lo = static_cast<uint32_t>(quotaBytes & 0xFFFFFFFFu);
            uint32_t hi = static_cast<uint32_t>((quotaBytes >> 32) & 0xFFFFFFFFu);
            g_r.kvSetUint64(quotaKv, lo, hi);
            wroteQuota = true;
        }
    }
    if (filesNeedsWrite) {
        void* filesKv = g_r.kvFindKey(ufs, "maxnumfiles", 1, nullptr);
        if (filesKv) {
            g_r.kvSetInt32(filesKv, static_cast<int32_t>(maxNumFiles));
            wroteFiles = true;
        }
    }

    if (wroteQuota || wroteFiles) {
        LOG("[KvInjector] InjectAppQuota app=%u: injected quota=%llu files=%u "
            "(wroteQuota=%d wroteFiles=%d, existingQuota=%llu existingFiles=%llu)",
            appId, (unsigned long long)quotaBytes, maxNumFiles,
            wroteQuota ? 1 : 0, wroteFiles ? 1 : 0,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    } else {
        LOG("[KvInjector] InjectAppQuota app=%u: skipped (Steam already has "
            "quota=%llu files=%llu)", appId,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    }
    return true;
}

bool InjectSaveFiles(uint32_t appId, const std::vector<SaveFileRule>& rules) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (rules.empty()) return false;

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectSaveFiles app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = ResolveAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectSaveFiles app=%u: no app info entry", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectSaveFiles app=%u: ufs section missing", appId);
        return false;
    }

    // Check if savefiles already exists with children. If so, don't clobber.
    void* existing = g_r.kvFindKey(ufs, "savefiles", 0, nullptr);
    if (existing) {
        void* child0 = g_r.kvFindKey(existing, "0", 0, nullptr);
        if (child0) {
            LOG("[KvInjector] InjectSaveFiles app=%u: savefiles already populated, skipping",
                appId);
            return true;
        }
    }

    void* savefiles = g_r.kvFindKey(ufs, "savefiles", 1, nullptr);
    if (!savefiles) {
        LOG("[KvInjector] InjectSaveFiles app=%u: failed to create savefiles key", appId);
        return false;
    }

    int injected = 0;
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& rule = rules[i];
        std::string idxStr = std::to_string(i);

        void* entry = g_r.kvFindKey(savefiles, idxStr.c_str(), 1, nullptr);
        if (!entry) continue;

        void* rootKv = g_r.kvFindKey(entry, "root", 1, nullptr);
        if (rootKv) g_r.kvSetString(rootKv, rule.root.c_str());

        if (!rule.path.empty()) {
            void* pathKv = g_r.kvFindKey(entry, "path", 1, nullptr);
            if (pathKv) g_r.kvSetString(pathKv, rule.path.c_str());
        }

        void* patternKv = g_r.kvFindKey(entry, "pattern", 1, nullptr);
        if (patternKv) g_r.kvSetString(patternKv, rule.pattern.c_str());

        if (rule.recursive) {
            void* recursiveKv = g_r.kvFindKey(entry, "recursive", 1, nullptr);
            if (recursiveKv) g_r.kvSetInt32(recursiveKv, 1);
        }

        if (rule.platforms != 0xFFFFFFFFu) {
            void* platformsKv = g_r.kvFindKey(entry, "platforms", 1, nullptr);
            if (platformsKv) {
                if (rule.platforms & 1) {
                    void* k = g_r.kvFindKey(platformsKv, "1", 1, nullptr);
                    if (k) g_r.kvSetString(k, "windows");
                }
                if (rule.platforms & 2) {
                    void* k = g_r.kvFindKey(platformsKv, "2", 1, nullptr);
                    if (k) g_r.kvSetString(k, "macos");
                }
                if (rule.platforms & 8) {
                    void* k = g_r.kvFindKey(platformsKv, "3", 1, nullptr);
                    if (k) g_r.kvSetString(k, "linux");
                }
            }
        }

        ++injected;
    }

    LOG("[KvInjector] InjectSaveFiles app=%u: injected %d savefiles rules", appId, injected);
    return injected > 0;
}

#endif // _WIN32

} // namespace SteamKvInjector
