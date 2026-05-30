#include "parental_bypass.h"
#include "log.h"

#include <cstring>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace ParentalBypass {

static int s_dailyLimitMinutes = -1;

// ─── Helpers ──────────────────────────────────────────────────────────

#ifdef _WIN32
static bool GetSteamClient(uint8_t*& base, MODULEINFO& mi) {
    HMODULE hSC = GetModuleHandleW(L"steamclient64.dll");
    if (!hSC) return false;
    base = reinterpret_cast<uint8_t*>(hSC);
    return GetModuleInformation(GetCurrentProcess(), hSC, &mi, sizeof(mi)) != 0;
}

static uint8_t* FindString(uint8_t* base, size_t imageSize, const char* needle) {
    size_t len = strlen(needle);
    for (size_t i = 0; i + len < imageSize; i++)
        if (memcmp(base + i, needle, len) == 0) return base + i;
    return nullptr;
}

static uint8_t* FindLeaRef(uint8_t* base, size_t imageSize, uint8_t* target) {
    for (size_t i = 0; i + 7 < imageSize; i++) {
        if ((base[i] == 0x48 || base[i] == 0x4C) && base[i+1] == 0x8D &&
            (base[i+2] & 0xC7) == 0x05) {
            int32_t disp = *reinterpret_cast<int32_t*>(base + i + 3);
            if (base + i + 7 + disp == target) return base + i;
        }
    }
    return nullptr;
}

static void NopCall(uint8_t* base, uint8_t* site, const char* label) {
    if (site[0] != 0xE8) return;
    DWORD op;
    if (VirtualProtect(site, 5, PAGE_EXECUTE_READWRITE, &op)) {
        memset(site, 0x90, 5);
        VirtualProtect(site, 5, op, &op);
        FlushInstructionCache(GetCurrentProcess(), site, 5);
        LOG("[Parental] NOPed %s at +0x%zX", label, (size_t)(site - base));
    }
}

static bool InstallDetour(uint8_t* funcStart, int stolenBytes, void* hookFn,
                           uint8_t*& trampoline, const char* label, uint8_t* base) {
    trampoline = reinterpret_cast<uint8_t*>(
        VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!trampoline) return false;

    memcpy(trampoline, funcStart, stolenBytes);
    trampoline[stolenBytes]     = 0x48;
    trampoline[stolenBytes + 1] = 0xB8;
    *reinterpret_cast<uint64_t*>(trampoline + stolenBytes + 2) =
        reinterpret_cast<uint64_t>(funcStart + stolenBytes);
    trampoline[stolenBytes + 10] = 0xFF;
    trampoline[stolenBytes + 11] = 0xE0;

    DWORD oldProtect;
    if (!VirtualProtect(funcStart, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    funcStart[0] = 0x48;
    funcStart[1] = 0xB8;
    *reinterpret_cast<uint64_t*>(funcStart + 2) = reinterpret_cast<uint64_t>(hookFn);
    funcStart[10] = 0xFF;
    funcStart[11] = 0xE0;
    for (int i = 12; i < stolenBytes; i++) funcStart[i] = 0xCC;

    VirtualProtect(funcStart, stolenBytes, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), funcStart, stolenBytes);

    LOG("[Parental] %s detour at steamclient64+0x%zX", label, (size_t)(funcStart - base));
    return true;
}
#endif

// ─── Daily limit extraction ───────────────────────────────────────────

static void ExtractAndSaveDailyLimit(const uint8_t* data, size_t len) {
    auto fields = PB::Parse(data, len);
    for (const auto& f : fields) {
        if (f.fieldNum != Fields::PLAYTIME_RESTRICTIONS || f.wireType != PB::LengthDelimited || !f.data)
            continue;
        for (const auto& rf : PB::Parse(f.data, f.dataLen)) {
            if (rf.fieldNum != 2 || rf.wireType != PB::LengthDelimited || !rf.data) continue;
            for (const auto& df : PB::Parse(rf.data, rf.dataLen)) {
                if (df.fieldNum == 2 && df.wireType == PB::Varint && df.varintVal > 0) {
                    int mins = static_cast<int>(df.varintVal);
                    if (s_dailyLimitMinutes == -1 || mins < s_dailyLimitMinutes)
                        s_dailyLimitMinutes = mins;
                }
            }
        }
        break;
    }
    if (s_dailyLimitMinutes == -1) s_dailyLimitMinutes = 0;
    LOG("[Parental] Daily limit: %d minutes", s_dailyLimitMinutes);
}

// ─── Settings stripping ───────────────────────────────────────────────

std::vector<uint8_t> StripPlaytimeRestrictions(const uint8_t* data, size_t len, bool fullBypass) {
    auto fields = PB::Parse(data, len);
    PB::Writer out;

    for (const auto& f : fields) {
        if (f.fieldNum == Fields::PLAYTIME_RESTRICTIONS ||
            f.fieldNum == Fields::TEMP_PLAYTIME_RESTRICTIONS)
            continue;

        if (fullBypass) {
            if (f.fieldNum == Fields::IS_ENABLED) { out.WriteVarint(f.fieldNum, 0); continue; }
            if (f.fieldNum == Fields::ENABLED_FEATURES ||
                f.fieldNum == Fields::TEMP_ENABLED_FEATURES) { out.WriteVarint(f.fieldNum, 0xFFFFFFFF); continue; }
        }

        switch (f.wireType) {
            case PB::Varint:          out.WriteVarint(f.fieldNum, f.varintVal); break;
            case PB::Fixed64:         out.WriteFixed64(f.fieldNum, f.varintVal); break;
            case PB::Fixed32:         out.WriteVarint(f.fieldNum, f.varintVal); break;
            case PB::LengthDelimited: out.WriteBytes(f.fieldNum, f.data, f.dataLen); break;
        }
    }

    return {out.Data().begin(), out.Data().end()};
}

// ─── Notification routing ─────────────────────────────────────────────

bool IsParentalNotification(const char* methodName) {
    return methodName && strncmp(methodName, "ParentalClient.", 15) == 0;
}

bool ShouldSuppressNotification(const char* methodName) {
    if (!methodName) return false;
    return strcmp(methodName, NOTIFY_PLAYTIME_USED) == 0 ||
           strcmp(methodName, NOTIFY_LOCK) == 0;
}

// ─── ReportPlaytime hook ──────────────────────────────────────────────

#ifdef _WIN32
using ReportPlaytimeFn = __int64(__fastcall*)(__int64, int, int);
static ReportPlaytimeFn g_origReportPlaytime = nullptr;
static uint8_t* g_reportTrampoline = nullptr;

static __int64 __fastcall ReportPlaytimeHook(__int64 a1, int day, int minutes) {
    if (s_dailyLimitMinutes >= 0 && minutes > s_dailyLimitMinutes) return 0;
    return g_origReportPlaytime(a1, day, minutes);
}
#endif

// ─── OnParentalSettingsReceived hook ──────────────────────────────────

#ifdef _WIN32
using OnParentalSettingsFn = char(__fastcall*)(__int64, __int64, unsigned int, __int64, unsigned int, __int64, __int64);
static OnParentalSettingsFn g_origOnParentalSettings = nullptr;
static uint8_t* g_parentalTrampoline = nullptr;
static bool g_fullBypass = false;

static char __fastcall OnParentalSettingsHook(__int64 a1, __int64 a2, unsigned int a3,
                                               __int64 a4, unsigned int a5, __int64 a6, __int64 a7) {
    if (a2 && a3 > 0) {
        if (!g_fullBypass)
            ExtractAndSaveDailyLimit(reinterpret_cast<const uint8_t*>(a2), a3);
        auto stripped = StripPlaytimeRestrictions(reinterpret_cast<const uint8_t*>(a2), a3, g_fullBypass);
        LOG("[Parental] Modified settings: %u -> %zu bytes (full=%d)", a3, stripped.size(), g_fullBypass);
        return g_origOnParentalSettings(a1, reinterpret_cast<__int64>(stripped.data()),
                                        static_cast<unsigned int>(stripped.size()), a4, a5, a6, a7);
    }
    return g_origOnParentalSettings(a1, a2, a3, a4, a5, a6, a7);
}
#endif

// ─── Signature bypass ─────────────────────────────────────────────────

bool PatchParentalSignatureCheck() {
#ifdef _WIN32
    uint8_t* base; MODULEINFO mi;
    if (!GetSteamClient(base, mi)) return false;

    const char* needle = "Parental settings signature did not ver";
    size_t needleLen = strlen(needle);
    int patchCount = 0;

    for (size_t si = 0; si + needleLen < mi.SizeOfImage; si++) {
        if (memcmp(base + si, needle, needleLen) != 0) continue;

        uint8_t* lea = FindLeaRef(base, mi.SizeOfImage, base + si);
        if (!lea) { si += needleLen; continue; }

        for (int back = 4; back < 40; back++) {
            uint8_t* c = lea - back;
            if (c[0] == 0x84 && c[1] == 0xC0 && (c[2] == 0x75 || c[2] == 0xEB)) {
                if (c[2] == 0x75) {
                    DWORD op;
                    if (VirtualProtect(c + 2, 1, PAGE_EXECUTE_READWRITE, &op)) {
                        c[2] = 0xEB;
                        VirtualProtect(c + 2, 1, op, &op);
                    }
                }
                LOG("[Parental] Sig check patched at +0x%zX", (size_t)(c + 2 - base));
                patchCount++;
                break;
            }
        }
        si += needleLen;
    }

    LOG("[Parental] Patched %d sig check site(s)", patchCount);
    return patchCount > 0;
#else
    return false;
#endif
}

// ─── Playtime enforcement NOP patches ─────────────────────────────────

static bool InstallPlaytimeReportHook();

bool PatchPlaytimeEnforcement() {
#ifdef _WIN32
    uint8_t* base; MODULEINFO mi;
    if (!GetSteamClient(base, mi)) return false;

    // Find the timer function via anchor string
    uint8_t* anchor = FindString(base, mi.SizeOfImage, "Timeslot is blocked, closing games");
    if (!anchor) { LOG("[Parental] Timer anchor not found"); return false; }

    uint8_t* lea = FindLeaRef(base, mi.SizeOfImage, anchor);
    if (!lea) return false;

    uint8_t* timerFunc = nullptr;
    for (int back = 0; back < 2048; back++) {
        uint8_t* c = lea - back;
        if (c[0] == 0x40 && c[1] == 0x53 && c[2] == 0x55 &&
            c[3] == 0x56 && c[4] == 0x57 && c[5] == 0x48 && c[6] == 0x81) {
            timerFunc = c;
            break;
        }
    }
    if (!timerFunc) { LOG("[Parental] Timer prologue not found"); return false; }
    LOG("[Parental] CheckPlaytimeRestrictions at +0x%zX", (size_t)(timerFunc - base));

    // Resolve CloseGamesForParental target
    uint8_t* dailyStr = FindString(base, mi.SizeOfImage, "Daily playtime expired, closing games");
    uint8_t* dailyLea = dailyStr ? FindLeaRef(base, mi.SizeOfImage, dailyStr) : nullptr;
    uint8_t* closeTarget = nullptr;
    if (dailyLea) {
        for (int fwd = 0; fwd < 80; fwd++) {
            if (dailyLea[fwd] == 0xE8) {
                int32_t rel = *reinterpret_cast<int32_t*>(dailyLea + fwd + 1);
                uint8_t* t = dailyLea + fwd + 5 + rel;
                if (t > base && t < base + mi.SizeOfImage && t[0] == 0x48) {
                    closeTarget = t;
                    break;
                }
            }
        }
    }
    if (!closeTarget) { LOG("[Parental] CloseGamesForParental not resolved"); return false; }

    // NOP all calls to CloseGamesForParental within the timer
    int nopCount = 0;
    for (size_t off = 0; off + 5 < 1600; off++) {
        if (timerFunc[off] == 0xE8) {
            int32_t rel = *reinterpret_cast<int32_t*>(timerFunc + off + 1);
            if (timerFunc + off + 5 + rel == closeTarget) {
                NopCall(base, timerFunc + off, "CloseGames");
                nopCount++;
            }
        }
    }
    LOG("[Parental] NOPed %d CloseGames call(s)", nopCount);

    // NOP 1070006 (0x1053B6) callback dispatches
    for (size_t off = 0; off + 20 < 1600; off++) {
        if (timerFunc[off] == 0xBA && timerFunc[off+1] == 0xB6 &&
            timerFunc[off+2] == 0x53 && timerFunc[off+3] == 0x10 && timerFunc[off+4] == 0x00) {
            for (int fwd = 5; fwd < 30; fwd++) {
                if (timerFunc[off + fwd] == 0xE8) {
                    NopCall(base, timerFunc + off + fwd, "1070006 callback");
                    break;
                }
            }
        }
    }

    InstallPlaytimeReportHook();
    return true;
#else
    return false;
#endif
}

// ─── Settings hook install ────────────────────────────────────────────

bool InstallParentalSettingsHook(bool fullBypass) {
    g_fullBypass = fullBypass;
#ifdef _WIN32
    uint8_t* base; MODULEINFO mi;
    if (!GetSteamClient(base, mi)) return false;

    uint8_t* anchor = FindString(base, mi.SizeOfImage, "Failed to cache settings for account ID %u");
    if (!anchor) { LOG("[Parental] Settings anchor not found"); return false; }

    uint8_t* lea = FindLeaRef(base, mi.SizeOfImage, anchor);
    if (!lea) return false;

    uint8_t* funcStart = nullptr;
    for (int back = 0; back < 512; back++) {
        uint8_t* c = lea - back;
        if (c[0] == 0x40 && c[1] == 0x55 && c[2] == 0x53 && c[3] == 0x56 && c[4] == 0x57) {
            funcStart = c;
            break;
        }
    }
    if (!funcStart) { LOG("[Parental] Settings prologue not found"); return false; }

    if (!InstallDetour(funcStart, 17, (void*)&OnParentalSettingsHook,
                       g_parentalTrampoline, "OnParentalSettingsReceived", base))
        return false;
    g_origOnParentalSettings = reinterpret_cast<OnParentalSettingsFn>(g_parentalTrampoline);
    return true;
#else
    return false;
#endif
}

// ─── Report hook install ──────────────────────────────────────────────

static bool InstallPlaytimeReportHook() {
#ifdef _WIN32
    uint8_t* base; MODULEINFO mi;
    if (!GetSteamClient(base, mi)) return false;

    uint8_t* anchor = FindString(base, mi.SizeOfImage, "CClientJobReportParentalPlaytime");
    if (!anchor || anchor[strlen("CClientJobReportParentalPlaytime")] != 0) return false;

    uint8_t* lea = FindLeaRef(base, mi.SizeOfImage, anchor);
    if (!lea) return false;

    uint8_t* funcStart = nullptr;
    for (int back = 0; back < 128; back++) {
        uint8_t* c = lea - back;
        if (c[0] == 0x40 && c[1] == 0x53 && c[2] == 0x55 && c[3] == 0x56 && c[4] == 0x57) {
            funcStart = c;
            break;
        }
    }
    if (!funcStart) return false;

    if (!InstallDetour(funcStart, 15, (void*)&ReportPlaytimeHook,
                       g_reportTrampoline, "ReportPlaytime", base))
        return false;
    g_origReportPlaytime = reinterpret_cast<ReportPlaytimeFn>(g_reportTrampoline);
    return true;
#else
    return false;
#endif
}

} // namespace ParentalBypass
