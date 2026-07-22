#include "sc_resolver.h"
#include "sig_scanner.h"
#include "log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>

namespace ScResolver {

// ── Helpers ───────────────────────────────────────────────────────────

// Find the Nth call target (E8 rel32) scanning from `start` within `maxBytes`.
static uintptr_t FindNthCallTarget(uintptr_t start, size_t maxBytes, int n) {
    if (!start || !maxBytes || n < 1) return 0;
    int count = 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(start);
        for (size_t i = 0; i + 5 <= maxBytes; ++i) {
            if (p[i] == 0xE8) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 1);
                uintptr_t target = start + i + 5 + disp;
                if (target >= SigScanner::GetImageBase() &&
                    target < SigScanner::GetImageBase() + SigScanner::GetImageSize()) {
                    if (++count == n) return target;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

// Find a string in .rdata, then locate the first LEA xref in .text that
// references it, and walk backward to the containing function's prologue.
static uintptr_t ResolveFuncByStringXref(const char* searchStr, const char* label) {
    size_t searchLen = strlen(searchStr);
    if (searchLen == 0 || searchLen >= 128) return 0;

    // Build mask (all exact)
    char mask[128];
    memset(mask, 'x', searchLen);
    mask[searchLen] = '\0';

    uintptr_t strAddr = SigScanner::FindPatternInRange(
        SigScanner::GetRdataBase(), SigScanner::GetRdataSize(),
        (const uint8_t*)searchStr, mask, searchLen);
    if (!strAddr) {
        LOG("[Resolver] %s: string '%s' not found in .rdata", label, searchStr);
        return 0;
    }

    // Find the first LEA [rip+disp] in .text that targets this string address.
    const auto* text = reinterpret_cast<const uint8_t*>(SigScanner::GetTextBase());
    size_t textSize = SigScanner::GetTextSize();

    __try {
        for (size_t i = 0; i + 7 <= textSize; ++i) {
            // Check for LEA with REX.W: 48 8D xx or 4C 8D xx where ModRM & 0xC7 == 0x05
            if ((text[i] == 0x48 || text[i] == 0x4C) && text[i+1] == 0x8D &&
                (text[i+2] & 0xC7) == 0x05) {
                uintptr_t instrAddr = SigScanner::GetTextBase() + i;
                int32_t disp = *reinterpret_cast<const int32_t*>(text + i + 3);
                uintptr_t refTarget = instrAddr + 7 + disp;
                if (refTarget == strAddr) {
                    // Walk backward to find function start (prologue + boundary check)
                    for (int back = 0; back < 0x600; back++) {
                        uintptr_t candidate = instrAddr - back;
                        if (candidate < SigScanner::GetTextBase()) break;
                        if (SigScanner::LooksLikeFunctionStart(candidate)) {
                            LOG("[Resolver] %s @ %p (RVA 0x%llX) via string xref",
                                label, (void*)candidate,
                                (uint64_t)(candidate - SigScanner::GetImageBase()));
                            return candidate;
                        }
                    }
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    LOG("[Resolver] %s: LEA xref walk failed", label);
    return 0;
}

// ── RTTI-based vtable resolution ──────────────────────────────────────

static uintptr_t ResolveCCMInterfaceVtable() {
    return SigScanner::ResolveVtableByRtti(".?AVCCMInterface@@");
}

static uintptr_t ResolveServiceTransportVtable() {
    return SigScanner::ResolveVtableByRtti(".?AVCClientUnifiedServiceTransport@@");
}

// ── Global engine pointer ─────────────────────────────────────────────
// Approach: FlushAppMinutesPlayed at +0x09 loads g_pCSteamEngine via
// `mov rax, cs:[rip+disp]`. We can also scan for `lea rcx/rbx, [reg+0xE68]`
// (CAppInfoCache offset) and backwalk to the preceding mov from global.
// The CAppInfoCache approach is more generic and doesn't depend on any
// single function existing.

static uintptr_t ResolveGlobalEngine(uintptr_t scBase) {
    // Strategy A: scan for `lea rcx, [reg+0xE68]` pattern (CAppInfoCache offset)
    // Pattern bytes: 48 8D 89 68 0E 00 00 (lea rcx,[rcx+0xE68])
    //           or:  48 8D 8B 68 0E 00 00 (lea rcx,[rbx+0xE68])
    // ModR/M byte 89=rcx+rcx, 8B=rcx+rbx, 8F=rcx+rdi, 8E=rcx+rsi
    // We use wildcard on the ModR/M to catch any source register:
    //   48 8D ?? 68 0E 00 00  where byte[2] & 0xC7 == 0x81 (disp32 + base reg)
    // Actually simpler: the 4-byte immediate 68 0E 00 00 (=0xE68) is distinctive.

    // Scan for any `lea reg, [reg + 0x00000E68]` -- 7-byte form with disp32
    // The full pattern is: REX 8D ModRM disp32
    // REX = 48 or 4C; opcode = 8D; ModRM & 0xC0 == 0x80 (mod=10 = disp32)
    // and disp = 0x00000E68.
    const auto* text = reinterpret_cast<const uint8_t*>(SigScanner::GetTextBase());
    size_t textSize = SigScanner::GetTextSize();

    __try {
        for (size_t i = 0; i + 7 <= textSize; ++i) {
            if ((text[i] == 0x48 || text[i] == 0x4C) && text[i+1] == 0x8D &&
                (text[i+2] & 0xC0) == 0x80) {
                // Check disp32 == 0xE68
                int32_t disp = *reinterpret_cast<const int32_t*>(text + i + 3);
                if (disp != 0xE68) continue;

                uintptr_t leaAddr = SigScanner::GetTextBase() + i;

                // Walk backward up to 40 bytes looking for `mov reg, [rip+disp]`
                for (int back = 7; back <= 40; ++back) {
                    uintptr_t candidate = leaAddr - back;
                    if (candidate < SigScanner::GetTextBase()) break;
                    uintptr_t global = SigScanner::DecodeRipRelMov(candidate);
                    if (global && global >= SigScanner::GetDataBase() &&
                        global < SigScanner::GetDataBase() + SigScanner::GetDataSize()) {
                        LOG("[Resolver] GlobalEngine @ %p (RVA 0x%llX) via lea+0xE68 backwalk",
                            (void*)global, (uint64_t)(global - scBase));
                        return global;
                    }
                }
                // Try next lea+0xE68 occurrence if backwalk failed
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    LOG("[Resolver] GlobalEngine: all strategies failed");
    return 0;
}

// ── Protobuf helpers ──────────────────────────────────────────────────
// From IDA (build 1782344391):
//
// SerializeToArray (UNIQUE at 16B, wildcarding security cookie displacement):
//   48 89 5C 24 18 55 56 57 48 81 EC 90 00 00 00 48
//   (mov [rsp+18h],rbx; push rbp; push rsi; push rdi; sub rsp,90h; mov rax,cs:cookie)
//   The `sub rsp, 90h` (0x90) is distinctive -- large stack frame for serialization.
//
// ParseFromArray is 0x410 bytes before SerializeToArray in this build. They're compiled
// together from the same TU. Once we find SerializeToArray, we scan backward for a
// function prologue within ~0x500 bytes that matches ParseFromArray's shape:
//   48 89 5C 24 10 48 89 74 24 18 55 57 41 56 48 8D 6C 24 B9 48 81 EC A0 00 00 00
//   The `sub rsp, A0h` and `lea rbp,[rsp-47h]` combo is distinctive.

static uintptr_t ResolveSerializeToArray() {
    // Prologue saves + sub rsp (wildcard) + cookie xor (48 33 C4).
    static const uint8_t pat[] = {
        0x48, 0x89, 0x5C, 0x24, 0x18,  // mov [rsp+18h], rbx
        0x55,                            // push rbp
        0x56,                            // push rsi
        0x57,                            // push rdi
        0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00,  // sub rsp, ?? (wildcard)
        0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,  // mov rax, cs:cookie (wildcard)
        0x48, 0x33, 0xC4,              // xor rax, rsp
    };
    static const char mask[] = "xxxxxxxxxxx????xxx????xxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 25);
    if (result)
        LOG("[Resolver] SerializeToArray @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] SerializeToArray: signature not found");
    return result;
}

static uintptr_t ResolveParseFromArray(uintptr_t serializeAddr) {
    // Scan backward from SerializeToArray. Wildcard the lea displacement.
    static const uint8_t pat[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10,  // mov [rsp+10h], rbx
        0x48, 0x89, 0x74, 0x24, 0x18,  // mov [rsp+18h], rsi
        0x55,                            // push rbp
        0x57,                            // push rdi
        0x41, 0x56,                      // push r14
        0x48, 0x8D, 0x6C, 0x24, 0x00, // lea rbp, [rsp+??] (wildcard disp)
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxxx?";

    if (!serializeAddr) {
        // Try global scan if no anchor
        return SigScanner::FindPattern(pat, mask, 19);
    }

    uintptr_t scanStart = (serializeAddr > 0x1000) ? serializeAddr - 0x1000 : SigScanner::GetTextBase();
    size_t scanSize = serializeAddr - scanStart;

    uintptr_t result = SigScanner::FindPatternInRange(scanStart, scanSize, pat, mask, 19);

    if (!result) {
        // Proximity failed — try global scan as fallback
        result = SigScanner::FindPattern(pat, mask, 19);
    }

    if (result)
        LOG("[Resolver] ParseFromArray @ %p (RVA 0x%llX) via %s",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()),
            (result >= scanStart && result < scanStart + scanSize) ? "proximity to SerializeToArray" : "global scan");
    else
        LOG("[Resolver] ParseFromArray: not found");
    return result;
}

// ── Packet routing: WrapPacket ────────────────────────────────────────
// Unique 16B signature (all position-independent):
//   48 89 5C 24 20  55  57  41 54  48 8D 6C 24 B9  48 81
// The `48 81 EC E0 00 00 00` (sub rsp, E0h) at +0x0E distinguishes it.

static uintptr_t ResolveWrapPacket() {
    // Use first 21 bytes (includes the sub rsp, E0h)
    static const uint8_t pat[] = {
        0x48, 0x89, 0x5C, 0x24, 0x20,  // mov [rsp+20h], rbx
        0x55,                            // push rbp
        0x57,                            // push rdi
        0x41, 0x54,                      // push r12
        0x48, 0x8D, 0x6C, 0x24, 0xB9,  // lea rbp, [rsp-47h]
        0x48, 0x81, 0xEC, 0xE0, 0x00, 0x00, 0x00  // sub rsp, E0h
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 21);
    if (result)
        LOG("[Resolver] WrapPacket @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] WrapPacket: signature not found");
    return result;
}

// ── RefCountHelper ────────────────────────────────────────────────────
// Tiny function (8 bytes): mov rax,[rcx]; lock inc qword [rax]; ret
//   48 8B 01  F0 48 FF 00  C3
// This is unique in steamclient64.dll.

static uintptr_t ResolveRefCountHelper() {
    static const uint8_t pat[] = { 0x48, 0x8B, 0x01, 0xF0, 0x48, 0xFF, 0x00, 0xC3 };
    static const char mask[] = "xxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 8);
    if (result)
        LOG("[Resolver] RefCountHelper @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] RefCountHelper: signature not found");
    return result;
}

// ── FindJob (CUtlSortedVector::Find) ─────────────────────────────────
// 24B unique: all push + sub rsp + cmp [rcx+44h],0 -- position-independent.
//   40 53 55 56 57 41 56 48 83 EC 20 83 79 44 00 4C 8B F2 48 8B F9 74 5F 8B

static uintptr_t ResolveFindJob() {
    // 22 bytes; trailing `jz short` (74) disambiguates from jz-near variant.
    static const uint8_t pat[] = {
        0x40, 0x53,              // push rbx
        0x55,                    // push rbp
        0x56,                    // push rsi
        0x57,                    // push rdi
        0x41, 0x56,              // push r14
        0x48, 0x83, 0xEC, 0x20, // sub rsp, 20h
        0x83, 0x79, 0x44, 0x00, // cmp dword ptr [rcx+44h], 0
        0x4C, 0x8B, 0xF2,       // mov r14, rdx
        0x48, 0x8B, 0xF9,       // mov rdi, rcx
        0x74,                    // jz short (distinguishes from jz near variant)
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 22);
    if (result)
        LOG("[Resolver] FindJob @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] FindJob: signature not found");
    return result;
}

// ── ReleaseWrapped ────────────────────────────────────────────────────
// First 21 bytes are position-independent (before the LEA with RIP-relative):
//   40 53  48 83 EC 20  8B 41 08  48 8B D9  FF C8  3D FE FF FF 00  76 28
// The `cmp eax, 0FFFFFEh` is highly distinctive.

static uintptr_t ResolveReleaseWrapped() {
    static const uint8_t pat[] = {
        0x40, 0x53,                    // push rbx
        0x48, 0x83, 0xEC, 0x20,        // sub rsp, 20h
        0x8B, 0x41, 0x08,              // mov eax, [rcx+8]
        0x48, 0x8B, 0xD9,              // mov rbx, rcx
        0xFF, 0xC8,                    // dec eax
        0x3D, 0xFE, 0xFF, 0xFF, 0x00,  // cmp eax, 0FFFFFEh
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 19);
    if (result)
        LOG("[Resolver] ReleaseWrapped @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] ReleaseWrapped: signature not found");
    return result;
}

// ── BRouteMsgToJob ────────────────────────────────────────────────────
// Two approaches: signature (24B unique) AND string xref backup.
// Signature (all position-independent -- just register/stack saves):
//   4C 89 4C 24 20  4C 89 44 24 18  48 89 54 24 10  48 89 4C 24 08  55 56 57 41 54

static uintptr_t ResolveBRouteMsgToJob() {
    // Try signature first (faster)
    static const uint8_t pat[] = {
        0x4C, 0x89, 0x4C, 0x24, 0x20,  // mov [rsp+20h], r9
        0x4C, 0x89, 0x44, 0x24, 0x18,  // mov [rsp+18h], r8
        0x48, 0x89, 0x54, 0x24, 0x10,  // mov [rsp+10h], rdx
        0x48, 0x89, 0x4C, 0x24, 0x08,  // mov [rsp+8], rcx
        0x55,                            // push rbp
        0x56,                            // push rsi
        0x57,                            // push rdi
        0x41, 0x54,                      // push r12
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 25);
    if (result) {
        LOG("[Resolver] BRouteMsgToJob @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
        return result;
    }

    // Fallback: string xref
    result = ResolveFuncByStringXref("CJobMgr::BRouteMsgToJob", "BRouteMsgToJob");
    return result;
}

// ── KvFindKey ─────────────────────────────────────────────────────────

static uintptr_t ResolveKvFindKey() {
    return ResolveFuncByStringXref("KeyValues::FindKey( StringView ... )", "KvFindKey");
}

// ── KvSetUint64 / KvSetInt / KvSetString ──────────────────────────────
// These all start with `test rcx, rcx; jz ...` (null check on this pointer).
// They're adjacent in the binary. Once we find one, the others are nearby.

// KvSetInt is unique at 16B (the jz offset 0x2E differs from KvSetUint64's 0x30):
//   48 85 C9  74 2E  48 89 5C 24 08  57  48 83 EC 20  8B FA
static uintptr_t ResolveKvSetInt() {
    static const uint8_t pat[] = {
        0x48, 0x85, 0xC9,              // test rcx, rcx
        0x74, 0x2E,                    // jz +2Eh
        0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
        0x57,                          // push rdi
        0x48, 0x83, 0xEC, 0x20,        // sub rsp, 20h
        0x8B, 0xFA,                    // mov edi, edx  (32-bit mov = int arg)
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 17);
    if (result)
        LOG("[Resolver] KvSetInt @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] KvSetInt: signature not found");
    return result;
}

// KvSetString starts with `test rcx,rcx; jz` but has a 6-byte jz (0F 84 xx xx xx xx):
//   48 85 C9  0F 84 9E 00 00 00  48 89 74 24 10  57
// Wildcard the jz displacement (bytes 5-8):
static uintptr_t ResolveKvSetString() {
    static const uint8_t pat[] = {
        0x48, 0x85, 0xC9,              // test rcx, rcx
        0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,  // jz near (wildcard offset)
        0x48, 0x89, 0x74, 0x24, 0x10, // mov [rsp+10h], rsi
        0x57,                          // push rdi
        0x48, 0x83, 0xEC, 0x30,        // sub rsp, 30h
    };
    static const char mask[] = "xxxxx????xxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 19);
    if (result)
        LOG("[Resolver] KvSetString @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] KvSetString: signature not found");
    return result;
}

// KvSetUint64: unique with jz +30h and 64-bit mov rdi,rdx:
//   48 85 C9  74 30  48 89 5C 24 08  57  48 83 EC 20  48 8B FA
static uintptr_t ResolveKvSetUint64() {
    static const uint8_t pat[] = {
        0x48, 0x85, 0xC9,              // test rcx, rcx
        0x74, 0x30,                    // jz +30h
        0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
        0x57,                          // push rdi
        0x48, 0x83, 0xEC, 0x20,        // sub rsp, 20h
        0x48, 0x8B, 0xFA,             // mov rdi, rdx  (64-bit mov = uint64 arg)
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 18);
    if (result)
        LOG("[Resolver] KvSetUint64 @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] KvSetUint64: signature not found");
    return result;
}

// ── KV Getters: GetInt, GetUint64 ─────────────────────────────────────
// KvGetInt (unique 16B):
//   48 89 5C 24 10  57  48 83 EC 30  4D 85 C0  48 8D 7C 24 40
static uintptr_t ResolveKvGetInt() {
    static const uint8_t pat[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, // mov [rsp+10h], rbx
        0x57,                          // push rdi
        0x48, 0x83, 0xEC, 0x30,        // sub rsp, 30h
        0x4D, 0x85, 0xC0,             // test r8, r8
        0x48, 0x8D, 0x7C, 0x24, 0x40, // lea rdi, [rsp+40h]
    };
    static const char mask[] = "xxxxxxxxxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 18);
    if (result)
        LOG("[Resolver] KvGetInt @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] KvGetInt: signature not found");
    return result;
}

// KvGetUint64: disambiguate from KvGetInt64 via unique string xref.
static uintptr_t ResolveKvGetUint64(uintptr_t /*kvFindKeyAddr*/) {
    return ResolveFuncByStringXref(
        "can't convert int64 to uint64", "KvGetUint64");
}

// ── GetAppInfo, GetSection, ReadConfigU64 ─────────────────────────────
// GetAppInfo has a distinctive prologue: mov r8d,[rcx+68h]; mov r9d,edx; cmp r8d,0FFFFFFFFh
//   44 8B 41 68  44 8B CA  41 83 F8 FF
static uintptr_t ResolveGetAppInfo() {
    static const uint8_t pat[] = {
        0x44, 0x8B, 0x41, 0x68,       // mov r8d, [rcx+68h]
        0x44, 0x8B, 0xCA,             // mov r9d, edx
        0x41, 0x83, 0xF8, 0xFF,       // cmp r8d, 0FFFFFFFFh
    };
    static const char mask[] = "xxxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 11);
    if (result)
        LOG("[Resolver] GetAppInfo @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] GetAppInfo: signature not found");
    return result;
}

// GetSection: sub rsp,28h; lea eax,[edx-2]; cmp eax,12h
//   48 83 EC 28  8D 42 FE  83 F8 12
static uintptr_t ResolveGetSection() {
    static const uint8_t pat[] = {
        0x48, 0x83, 0xEC, 0x28,       // sub rsp, 28h
        0x8D, 0x42, 0xFE,             // lea eax, [rdx-2]
        0x83, 0xF8, 0x12,             // cmp eax, 12h
    };
    static const char mask[] = "xxxxxxxxxx";

    uintptr_t result = SigScanner::FindPattern(pat, mask, 10);
    if (result)
        LOG("[Resolver] GetSection @ %p (RVA 0x%llX) via signature",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] GetSection: signature not found");
    return result;
}

// ReadConfigU64: same prologue as an overload; take the last match after GetAppInfo.
static uintptr_t ResolveReadConfigU64(uintptr_t getAppInfoAddr) {
    static const uint8_t pat[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
        0x57,                          // push rdi
        0x48, 0x83, 0xEC, 0x20,        // sub rsp, 20h
        0x49, 0x8B, 0xD9,             // mov rbx, r9
        0x41, 0x8B, 0xF8,             // mov edi, r8d
    };
    static const char mask[] = "xxxxxxxxxxxxxxxx";

    if (!getAppInfoAddr) {
        // Fall back to global scan (may hit the wrong overload, but still functional)
        uintptr_t result = SigScanner::FindPattern(pat, mask, 16);
        if (result)
            LOG("[Resolver] ReadConfigU64 @ %p (RVA 0x%llX) via signature (no anchor)",
                (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
        else
            LOG("[Resolver] ReadConfigU64: signature not found");
        return result;
    }

    // Scan forward from GetAppInfo; take the last match in the window.
    uintptr_t scanStart = getAppInfoAddr + 0x80;
    size_t scanSize = 0x2000;
    uintptr_t result = 0;
    uintptr_t pos = scanStart;
    while (pos < scanStart + scanSize) {
        size_t remaining = scanStart + scanSize - pos;
        uintptr_t hit = SigScanner::FindPatternInRange(pos, remaining, pat, mask, 16);
        if (!hit) break;
        result = hit; // keep the last match
        pos = hit + 16;
    }
    if (result)
        LOG("[Resolver] ReadConfigU64 @ %p (RVA 0x%llX) via proximity to GetAppInfo",
            (void*)result, (uint64_t)(result - SigScanner::GetImageBase()));
    else
        LOG("[Resolver] ReadConfigU64: not found near GetAppInfo");
    return result;
}

// ── RefCountGlobal ────────────────────────────────────────────────────
// RefCountGlobal: second LEA target in the "client/AsyncFileIO/ReadItemsPending" function.
static uintptr_t ResolveRefCountGlobal() {
    uintptr_t funcAddr = ResolveFuncByStringXref(
        "client/AsyncFileIO/ReadItemsPending", "RefCountGlobal_anchor");
    if (!funcAddr) return 0;

    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(funcAddr);
        int leaCount = 0;
        for (size_t i = 0; i + 7 <= 32; ++i) {
            if ((p[i] == 0x48 || p[i] == 0x4C) && p[i+1] == 0x8D && (p[i+2] & 0xC7) == 0x05) {
                leaCount++;
                if (leaCount == 2) { // second LEA is the one loading RefCountGlobal
                    int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 3);
                    uintptr_t target = funcAddr + i + 7 + disp;
                    LOG("[Resolver] RefCountGlobal @ %p (RVA 0x%llX) via anchor func LEA",
                        (void*)target, (uint64_t)(target - SigScanner::GetImageBase()));
                    return target;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    LOG("[Resolver] RefCountGlobal: LEA extraction failed");
    return 0;
}

// JobCurGlobal: first mov [rip+disp], rax targeting .data in ~CJob destructor.
static uintptr_t ResolveJobCurGlobal() {
    uintptr_t funcAddr = ResolveFuncByStringXref(
        "~CJOB: %s has an unexpected threaded work item", "JobCurGlobal_anchor");
    if (!funcAddr) return 0;

    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(funcAddr);
        for (size_t i = 0; i + 7 <= 0x400; ++i) {
            if (p[i] == 0x48 && p[i+1] == 0x89 && (p[i+2] & 0xC7) == 0x05) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 3);
                uintptr_t target = funcAddr + i + 7 + disp;
                // Verify target is in .data section
                if (target >= SigScanner::GetDataBase() &&
                    target < SigScanner::GetDataBase() + SigScanner::GetDataSize()) {
                    LOG("[Resolver] JobCurGlobal @ %p (RVA 0x%llX) via ~CJob store",
                        (void*)target, (uint64_t)(target - SigScanner::GetImageBase()));
                    return target;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    LOG("[Resolver] JobCurGlobal: store extraction failed");
    return 0;
}

// ── Main resolver entry point ─────────────────────────────────────────

ResolvedAddrs Resolve(uintptr_t steamClientBase) {
    ResolvedAddrs r = {};
    memset(&r, 0, sizeof(r));

    if (!SigScanner::Init(steamClientBase)) {
        LOG("[Resolver] SigScanner::Init failed");
        return r;
    }

    LOG("[Resolver] === Beginning auto-resolution of steamclient64.dll addresses ===");

    // Phase 1: RTTI vtables (highest confidence)
    r.ccmInterfaceVtable = ResolveCCMInterfaceVtable();
    r.serviceTransportVtable = ResolveServiceTransportVtable();

    // Phase 2: Global engine pointer
    r.globalEngine = ResolveGlobalEngine(steamClientBase);

    // Phase 3: Protobuf helpers (signature-based)
    r.serializeToArray = ResolveSerializeToArray();
    r.parseFromArray   = ResolveParseFromArray(r.serializeToArray);

    // Phase 4: Packet routing (signature + string xref)
    r.bRouteMsgToJob = ResolveBRouteMsgToJob();
    r.wrapPacket     = ResolveWrapPacket();
    r.releaseWrapped = ResolveReleaseWrapped();
    r.refCountHelper = ResolveRefCountHelper();
    r.findJob        = ResolveFindJob();

    // Phase 5: Globals
    r.refCountGlobal = ResolveRefCountGlobal();
    r.jobCurGlobal = ResolveJobCurGlobal();

    // Phase 6: Manifest pinning (string xref)
    r.buildDepotDependency = ResolveFuncByStringXref(
        "CUserAppManager::BuildDepotDependency", "BuildDepotDependency");

    // Phase 7: Playtime functions (string xref)
    r.getAppMinutesPlayedData = ResolveFuncByStringXref(
        "CUser::GetAppMinutesPlayedData", "GetAppMinutesPlayedData");
    r.setAppLastPlayedTime = ResolveFuncByStringXref(
        "CUser::SetAppLastPlayedTime", "SetAppLastPlayedTime");
    // FlushAppMinutesPlayed has no string refs. It's adjacent to GetAppMinutesPlayedData.
    // From IDA: GetAppMinutesPlayedData=0x9BFA40, FlushAppMinutesPlayed=0x9CFEF0 (gap ~0x104B0).
    // Instead, resolve via the unique prologue. FlushAppMinutesPlayed starts with:
    //   40 55  57  41 56  48 83 EC 30  (push rbp; push rdi; push r14; sub rsp,30h)
    // followed immediately by a mov from the global engine pointer.
    // But this prologue isn't unique enough alone. We use the full 9 bytes + the fact
    // that the very next instruction loads g_pCSteamEngine (which we already resolved).
    if (r.globalEngine) {
        // Scan .text for: 40 55 57 41 56 48 83 EC 30 48 8B 05 XX XX XX XX
        // where the XX bytes, when decoded as rip+disp, point to r.globalEngine.
        static const uint8_t pat[] = {
            0x40, 0x55,              // push rbp
            0x57,                    // push rdi
            0x41, 0x56,              // push r14
            0x48, 0x83, 0xEC, 0x30, // sub rsp, 30h
            0x48, 0x8B, 0x05,       // mov rax, [rip+...]
        };
        static const char mask[] = "xxxxxxxxxxxx";
        uintptr_t scanAddr = SigScanner::GetTextBase();
        size_t remaining = SigScanner::GetTextSize();
        while (remaining >= 16) {
            uintptr_t hit = SigScanner::FindPatternInRange(scanAddr, remaining, pat, mask, 12);
            if (!hit) break;
            // Ensure 16 bytes (12 prologue + 4 displacement) fit within scan range
            size_t offset = hit - scanAddr;
            if (offset + 16 > remaining) break;
            // Verify the RIP-relative target points to globalEngine
            int32_t disp = *reinterpret_cast<const int32_t*>((const uint8_t*)hit + 12);
            uintptr_t target = hit + 16 + disp;  // instruction is 16 bytes total (12 matched + 4 disp)
            if (target == r.globalEngine) {
                r.flushAppMinutesPlayed = hit;
                LOG("[Resolver] FlushAppMinutesPlayed @ %p (RVA 0x%llX) via prologue+engine ref",
                    (void*)hit, (uint64_t)(hit - steamClientBase));
                break;
            }
            // Advance past this match
            scanAddr = hit + 16;
            remaining -= (offset + 16);
        }
    }
    if (!r.flushAppMinutesPlayed)
        LOG("[Resolver] FlushAppMinutesPlayed: not resolved");

    // Phase 8: KV functions (signature-based, some anchored to KvFindKey)
    r.kvFindKey    = ResolveKvFindKey();
    r.kvGetUint64  = ResolveKvGetUint64(r.kvFindKey);
    r.kvGetInt     = ResolveKvGetInt();
    r.kvSetUint64  = ResolveKvSetUint64();
    r.kvSetInt     = ResolveKvSetInt();
    r.kvSetString  = ResolveKvSetString();

    // Phase 9: AppInfo functions (signature-based, ReadConfigU64 anchored to GetAppInfo)
    r.getAppInfo     = ResolveGetAppInfo();
    r.getSection     = ResolveGetSection();
    r.readConfigU64  = ResolveReadConfigU64(r.getAppInfo);

    // Phase 10: BAsyncSend (string xref — unique "CProtoBufMsg::BAsyncSend")
    r.bAsyncSend = ResolveFuncByStringXref(
        "CProtoBufMsg::BAsyncSend", "BAsyncSend");

    // Phase 11: PlaytimeWriter — first E8 call after LEA to the handler string.
    {
        const char* handlerStr = "Player.ClientGetLastPlayedTimes#1";
        size_t handlerLen = strlen(handlerStr);
        char hmask[64];
        memset(hmask, 'x', handlerLen);
        hmask[handlerLen] = '\0';

        uintptr_t hStrAddr = SigScanner::FindPatternInRange(
            SigScanner::GetRdataBase(), SigScanner::GetRdataSize(),
            (const uint8_t*)handlerStr, hmask, handlerLen);
        if (hStrAddr) {
            const auto* text = reinterpret_cast<const uint8_t*>(SigScanner::GetTextBase());
            size_t textSize = SigScanner::GetTextSize();
            __try {
                for (size_t i = 0; i + 7 <= textSize; ++i) {
                    if ((text[i] == 0x48 || text[i] == 0x4C) && text[i+1] == 0x8D &&
                        (text[i+2] & 0xC7) == 0x05) {
                        uintptr_t instrAddr = SigScanner::GetTextBase() + i;
                        int32_t disp = *reinterpret_cast<const int32_t*>(text + i + 3);
                        if (instrAddr + 7 + disp != hStrAddr) continue;

                        // Found the LEA to the handler string. Scan forward for first E8 call.
                        for (size_t j = i + 7; j + 5 <= textSize; ++j) {
                            if (text[j] == 0xE8) {
                                int32_t callDisp = *reinterpret_cast<const int32_t*>(text + j + 1);
                                uintptr_t target = SigScanner::GetTextBase() + j + 5 + callDisp;
                                if (target >= SigScanner::GetImageBase() &&
                                    target < SigScanner::GetImageBase() + SigScanner::GetImageSize()) {
                                    r.playtimeWriter = target;
                                    LOG("[Resolver] PlaytimeWriter @ %p (RVA 0x%llX) via GetLastPlayedTimes handler call",
                                        (void*)target, (uint64_t)(target - steamClientBase));
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (!r.playtimeWriter)
            LOG("[Resolver] PlaytimeWriter: not resolved");
    }

    // Phase 12: PbMsgCtor — loads CProtoBufMsgBase vtable via RTTI, stores to [rcx],
    // and has `mov [rcx+38h], r8d` (44 89 41 38) at +0x0A.
    {
        uintptr_t baseMsgVtable = SigScanner::ResolveVtableByRtti(".?AVCProtoBufMsgBase@@");
        if (baseMsgVtable) {
            // PbMsgCtor: sub rsp,30h then LEA rax, CProtoBufMsgBase_vt; mov [rcx], rax
            // Unique anchor: 44 89 41 38 (mov [rcx+38h], r8d) at offset +0x0A
            // Full prologue: 48 89 5C 24 08 57 48 83 EC 30 44 89 41 38
            static const uint8_t pat[] = {
                0x48, 0x89, 0x5C, 0x24, 0x08,  // mov [rsp+8], rbx
                0x57,                           // push rdi
                0x48, 0x83, 0xEC, 0x30,         // sub rsp, 30h
                0x44, 0x89, 0x41, 0x38,         // mov [rcx+38h], r8d
            };
            static const char mask[] = "xxxxxxxxxxxxxx";
            uintptr_t hit = SigScanner::FindPattern(pat, mask, 14);
            if (hit) {
                // Verify it LEAs the CProtoBufMsgBase vtable within the next 10 bytes
                uintptr_t leaTarget = SigScanner::FindFirstRipRelLeaTarget(hit + 14, 10);
                if (leaTarget == baseMsgVtable) {
                    r.pbMsgCtor = hit;
                    LOG("[Resolver] PbMsgCtor @ %p (RVA 0x%llX) via signature + vtable verify",
                        (void*)hit, (uint64_t)(hit - steamClientBase));
                }
            }
            if (!r.pbMsgCtor)
                LOG("[Resolver] PbMsgCtor: not resolved");

            // Phase 13: PbMsgCleanup — push rbx; sub rsp, 20h; lea rax, CProtoBufMsgBase_vt
            // Pattern: 40 53 48 83 EC 20 48 8D 05 XX XX XX XX 48 8B D9
            // where the LEA target == baseMsgVtable
            const auto* text = reinterpret_cast<const uint8_t*>(SigScanner::GetTextBase());
            size_t textSize = SigScanner::GetTextSize();
            __try {
                for (size_t i = 0; i + 16 <= textSize; ++i) {
                    if (text[i] == 0x40 && text[i+1] == 0x53 &&
                        text[i+2] == 0x48 && text[i+3] == 0x83 && text[i+4] == 0xEC && text[i+5] == 0x20 &&
                        text[i+6] == 0x48 && text[i+7] == 0x8D && text[i+8] == 0x05) {
                        int32_t disp = *reinterpret_cast<const int32_t*>(text + i + 9);
                        uintptr_t instrAddr = SigScanner::GetTextBase() + i + 6;
                        uintptr_t target = instrAddr + 7 + disp;
                        if (target == baseMsgVtable) {
                            r.pbMsgCleanup = SigScanner::GetTextBase() + i;
                            LOG("[Resolver] PbMsgCleanup @ %p (RVA 0x%llX) via prologue + vtable LEA",
                                (void*)r.pbMsgCleanup, (uint64_t)(r.pbMsgCleanup - steamClientBase));
                            break;
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            if (!r.pbMsgCleanup)
                LOG("[Resolver] PbMsgCleanup: not resolved");
        } else {
            LOG("[Resolver] PbMsgCtor/Cleanup: CProtoBufMsgBase RTTI not found");
        }
    }

    // Phase 14: PbMsgFinalize — string xref "!m_pProtoBufBody" + cmp [rcx+30h] guard.
    {
        const char* searchStr = "!m_pProtoBufBody";
        size_t searchLen = strlen(searchStr);
        char mask[128];
        memset(mask, 'x', searchLen);
        mask[searchLen] = '\0';

        uintptr_t strAddr = SigScanner::FindPatternInRange(
            SigScanner::GetRdataBase(), SigScanner::GetRdataSize(),
            (const uint8_t*)searchStr, mask, searchLen);

        r.pbMsgFinalize = 0;
        if (strAddr) {
            const auto* text = reinterpret_cast<const uint8_t*>(SigScanner::GetTextBase());
            size_t textSize = SigScanner::GetTextSize();
            // Check bytes: 48 83 79 30 00 = cmp qword ptr [rcx+30h], 0
            static const uint8_t cmpPat[] = { 0x48, 0x83, 0x79, 0x30, 0x00 };

            __try {
                for (size_t i = 0; i + 7 <= textSize; ++i) {
                    if ((text[i] == 0x48 || text[i] == 0x4C) && text[i+1] == 0x8D &&
                        (text[i+2] & 0xC7) == 0x05) {
                        uintptr_t instrAddr = SigScanner::GetTextBase() + i;
                        int32_t disp = *reinterpret_cast<const int32_t*>(text + i + 3);
                        uintptr_t refTarget = instrAddr + 7 + disp;
                        if (refTarget != strAddr) continue;

                        // Found LEA to "!m_pProtoBufBody". Walk back to function start.
                        for (int back = 0; back < 0x80; back++) {
                            uintptr_t candidate = instrAddr - back;
                            if (candidate < SigScanner::GetTextBase()) break;
                            if (!SigScanner::LooksLikeFunctionStart(candidate)) continue;

                            // Verify: cmp [rcx+30h], 0 within first 13 bytes (prologue + guard)
                            const uint8_t* fn = reinterpret_cast<const uint8_t*>(candidate);
                            bool hasCmp = false;
                            for (int off = 0; off <= 8; off++) {
                                if (memcmp(fn + off, cmpPat, 5) == 0) { hasCmp = true; break; }
                            }
                            if (!hasCmp) break; // wrong function, try next xref

                            r.pbMsgFinalize = candidate;
                            break;
                        }
                        if (r.pbMsgFinalize) break;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (r.pbMsgFinalize)
            LOG("[Resolver] PbMsgFinalize @ %p (RVA 0x%llX) via string xref + cmp guard",
                (void*)r.pbMsgFinalize, (uint64_t)(r.pbMsgFinalize - steamClientBase));
        else
            LOG("[Resolver] PbMsgFinalize: not resolved");
    }

    // Phase 15: YieldIfTimeSlice — prologue + cmp rcx, [rip+g_pJobCur]
    if (r.jobCurGlobal) {
        static const uint8_t pat[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
            0x48, 0x89, 0x74, 0x24, 0x10, // mov [rsp+10h], rsi
            0x57,                          // push rdi
            0x48, 0x83, 0xEC, 0x20,        // sub rsp, 20h
            0x48, 0x3B, 0x0D,              // cmp rcx, [rip+...]
        };
        static const char mask[] = "xxxxxxxxxxxxxxxxxx";
        uintptr_t scanAddr = SigScanner::GetTextBase();
        size_t remaining = SigScanner::GetTextSize();
        while (remaining > 22) {
            uintptr_t hit = SigScanner::FindPatternInRange(scanAddr, remaining, pat, mask, 18);
            if (!hit) break;
            // Verify the RIP-relative target is g_pJobCur
            int32_t disp = *reinterpret_cast<const int32_t*>((const uint8_t*)hit + 18);
            uintptr_t target = hit + 22 + disp;  // instr at +15 is 7 bytes (48 3B 0D xx xx xx xx)
            if (target == r.jobCurGlobal) {
                r.yieldIfTimeSlice = hit;
                LOG("[Resolver] YieldIfTimeSlice @ %p (RVA 0x%llX) via prologue + g_pJobCur ref",
                    (void*)hit, (uint64_t)(hit - steamClientBase));
                break;
            }
            size_t consumed = (hit - scanAddr) + 18;
            scanAddr = hit + 18;
            remaining -= consumed;
        }
        if (!r.yieldIfTimeSlice)
            LOG("[Resolver] YieldIfTimeSlice: not resolved");
    } else {
        LOG("[Resolver] YieldIfTimeSlice: skipped (jobCurGlobal not resolved)");
    }

    // Phase 16: RTTI vtables for protobuf message wrappers
    r.getUserStatsVtable = SigScanner::ResolveVtableByRtti(
        ".?AV?$CProtoBufMsg@VCMsgClientGetUserStats@@@@");
    if (r.getUserStatsVtable)
        LOG("[Resolver] GetUserStatsVtable @ %p (RVA 0x%llX) via RTTI",
            (void*)r.getUserStatsVtable, (uint64_t)(r.getUserStatsVtable - steamClientBase));
    else
        LOG("[Resolver] GetUserStatsVtable: RTTI not found");

    r.respWrapperVtable = SigScanner::ResolveVtableByRtti(
        ".?AV?$CProtoBufMsg@VCPlayer_GetLastPlayedTimes_Response@@@@");
    if (r.respWrapperVtable)
        LOG("[Resolver] RespWrapperVtable @ %p (RVA 0x%llX) via RTTI",
            (void*)r.respWrapperVtable, (uint64_t)(r.respWrapperVtable - steamClientBase));
    else
        LOG("[Resolver] RespWrapperVtable: RTTI not found");

    // Phase 17: Descriptor pointers (vtable ptr in .data/.rdata).
    {
        // GetUserStatsDesc: find QWORD in .rdata/.data pointing to CMsgClientGetUserStats vtable
        uintptr_t msgVtable = SigScanner::ResolveVtableByRtti(".?AVCMsgClientGetUserStats@@");
        if (msgVtable) {
            // Scan .data then .rdata for a QWORD containing this vtable address
            auto scanForPtr = [&](uintptr_t sectionBase, size_t sectionSize) -> uintptr_t {
                const auto* mem = reinterpret_cast<const uint8_t*>(sectionBase);
                for (size_t i = 0; i + 8 <= sectionSize; i += 8) {
                    if (*reinterpret_cast<const uintptr_t*>(mem + i) == msgVtable)
                        return sectionBase + i;
                }
                return 0;
            };
            r.getUserStatsDesc = scanForPtr(SigScanner::GetDataBase(), SigScanner::GetDataSize());
            if (!r.getUserStatsDesc)
                r.getUserStatsDesc = scanForPtr(SigScanner::GetRdataBase(), SigScanner::GetRdataSize());
            if (r.getUserStatsDesc)
                LOG("[Resolver] GetUserStatsDesc @ %p (RVA 0x%llX) via vtable-ptr scan",
                    (void*)r.getUserStatsDesc, (uint64_t)(r.getUserStatsDesc - steamClientBase));
            else
                LOG("[Resolver] GetUserStatsDesc: vtable pointer not found in .data/.rdata");
        } else {
            LOG("[Resolver] GetUserStatsDesc: CMsgClientGetUserStats RTTI not found");
        }

        // RespDescriptor: same for CPlayer_GetLastPlayedTimes_Response
        uintptr_t respVtable = SigScanner::ResolveVtableByRtti(".?AVCPlayer_GetLastPlayedTimes_Response@@");
        if (respVtable) {
            auto scanForPtr = [&](uintptr_t sectionBase, size_t sectionSize) -> uintptr_t {
                const auto* mem = reinterpret_cast<const uint8_t*>(sectionBase);
                for (size_t i = 0; i + 8 <= sectionSize; i += 8) {
                    if (*reinterpret_cast<const uintptr_t*>(mem + i) == respVtable)
                        return sectionBase + i;
                }
                return 0;
            };
            r.respDescriptor = scanForPtr(SigScanner::GetDataBase(), SigScanner::GetDataSize());
            if (!r.respDescriptor)
                r.respDescriptor = scanForPtr(SigScanner::GetRdataBase(), SigScanner::GetRdataSize());
            if (r.respDescriptor)
                LOG("[Resolver] RespDescriptor @ %p (RVA 0x%llX) via vtable-ptr scan",
                    (void*)r.respDescriptor, (uint64_t)(r.respDescriptor - steamClientBase));
            else
                LOG("[Resolver] RespDescriptor: vtable pointer not found in .data/.rdata");
        } else {
            LOG("[Resolver] RespDescriptor: CPlayer_GetLastPlayedTimes_Response RTTI not found");
        }
    }

    // Phase 18: RegKeySyncTime — string ptr scan, synthetic slot fallback.
    {
        const char needle[] = "LastPlayedTimesSyncTime";
        size_t needleLen = sizeof(needle) - 1;
        char nmask[32];
        memset(nmask, 'x', needleLen);
        nmask[needleLen] = '\0';

        uintptr_t strAddr = SigScanner::FindPatternInRange(
            SigScanner::GetRdataBase(), SigScanner::GetRdataSize(),
            (const uint8_t*)needle, nmask, needleLen);
        if (!strAddr) strAddr = SigScanner::FindPatternInRange(
            SigScanner::GetDataBase(), SigScanner::GetDataSize(),
            (const uint8_t*)needle, nmask, needleLen);
        if (strAddr) {
            // The needle may match inside a longer string (e.g.
            // "Software\Valve\Steam\LastPlayedTimesSyncTime"). Walk backward to
            // the containing C-string's start for the pointer search.
            {
                const uint8_t* p = reinterpret_cast<const uint8_t*>(strAddr);
                const uint8_t* modBase = reinterpret_cast<const uint8_t*>(steamClientBase);
                while (p > modBase && *(p - 1) != 0) { p--; strAddr--; }
                LOG("[Resolver] RegKeySyncTime: needle in containing string at RVA 0x%llX: \"%.80s\"",
                    (uint64_t)(strAddr - steamClientBase), (const char*)strAddr);
            }
            // Find the QWORD pointer to this string in .data/.rdata
            auto scanForPtr = [&](uintptr_t sectionBase, size_t sectionSize) -> uintptr_t {
                const auto* mem = reinterpret_cast<const uint8_t*>(sectionBase);
                for (size_t i = 0; i + 8 <= sectionSize; i += 8) {
                    if (*reinterpret_cast<const uintptr_t*>(mem + i) == strAddr)
                        return sectionBase + i;
                }
                return 0;
            };
            r.regKeySyncTime = scanForPtr(SigScanner::GetDataBase(), SigScanner::GetDataSize());
            if (!r.regKeySyncTime)
                r.regKeySyncTime = scanForPtr(SigScanner::GetRdataBase(), SigScanner::GetRdataSize());
            if (r.regKeySyncTime) {
                LOG("[Resolver] RegKeySyncTime @ %p (RVA 0x%llX) via string-ptr scan",
                    (void*)r.regKeySyncTime, (uint64_t)(r.regKeySyncTime - steamClientBase));
            } else {
                // Newer builds: no absolute pointer in data sections (LEA-referenced).
                // Synthesize a stable slot that dereferences to the string address.
                static uintptr_t s_syntheticSlot = 0;
                s_syntheticSlot = strAddr;
                r.regKeySyncTime = (uintptr_t)&s_syntheticSlot;
                LOG("[Resolver] RegKeySyncTime @ %p (synthetic, string at RVA 0x%llX)",
                    (void*)r.regKeySyncTime, (uint64_t)(strAddr - steamClientBase));
            }
        } else {
            LOG("[Resolver] RegKeySyncTime: 'LastPlayedTimesSyncTime' string not found");
        }
    }

    // Phase 19: Struct offsets (leave at 0 -- use hardcoded fallbacks for now)
    r.engineOffJobMgr       = 0;
    r.engineOffGlobalHandle = 0;
    r.engineOffUserMap      = 0;
    r.ccmOffConnContext     = 0;
    r.userOffCcmInterface   = 0;
    r.engineOffAppInfoCache = 0xE68;

    LOG("[Resolver] === Auto-resolution complete ===");
    return r;
}

void LogComparison(const ResolvedAddrs& r, uintptr_t base) {
    LOG("[Resolver] === Comparison (resolved RVA vs expected) ===");

    int total = 0, matched = 0, failed = 0;
    auto logEntry = [&](const char* name, uintptr_t resolved, uintptr_t expectedRva) {
        total++;
        if (resolved) {
            uintptr_t resolvedRva = resolved - base;
            bool match = (resolvedRva == expectedRva);
            if (match) matched++;
            LOG("[Resolver]   %-30s 0x%llX  %s",
                name, (uint64_t)resolvedRva, match ? "OK" : "MISMATCH");
        } else {
            failed++;
            LOG("[Resolver]   %-30s FAILED (expected 0x%llX)", name, (uint64_t)expectedRva);
        }
    };

    logEntry("CCMInterface VT",        r.ccmInterfaceVtable,      0x1279888);
    logEntry("ServiceTransport VT",    r.serviceTransportVtable,  0x1256DF0);
    logEntry("GlobalEngine",           r.globalEngine,            0x17D3628);
    logEntry("ParseFromArray",         r.parseFromArray,          0xBD03F0);
    logEntry("SerializeToArray",       r.serializeToArray,        0xBD0800);
    logEntry("WrapPacket",             r.wrapPacket,              0xD022F0);
    logEntry("BRouteMsgToJob",         r.bRouteMsgToJob,          0xD0DBD0);
    logEntry("ReleaseWrapped",         r.releaseWrapped,          0x0EC300);
    logEntry("RefCountHelper",         r.refCountHelper,          0xDC6ED0);
    logEntry("FindJob",                r.findJob,                 0xD10670);
    logEntry("RefCountGlobal",         r.refCountGlobal,          0x17BED58);
    logEntry("JobCurGlobal",           r.jobCurGlobal,            0x17F0940);
    logEntry("BuildDepotDependency",   r.buildDepotDependency,    0x4B73B0);
    logEntry("GetAppMinutesPlayed",    r.getAppMinutesPlayedData, 0x9C37A0);
    logEntry("FlushAppMinutesPlayed",  r.flushAppMinutesPlayed,   0x9D3C40);
    logEntry("SetAppLastPlayedTime",   r.setAppLastPlayedTime,    0x9D6A70);
    logEntry("KvFindKey",              r.kvFindKey,               0xD01190);
    logEntry("KvGetUint64",            r.kvGetUint64,             0xD05E20);
    logEntry("KvGetInt",               r.kvGetInt,                0xD059D0);
    logEntry("KvSetUint64",            r.kvSetUint64,             0xD06090);
    logEntry("KvSetInt",               r.kvSetInt,                0xD060D0);
    logEntry("KvSetString",            r.kvSetString,             0xD06110);
    logEntry("GetAppInfo",             r.getAppInfo,              0x4A8380);
    logEntry("GetSection",             r.getSection,              0x4AA6B0);
    logEntry("ReadConfigU64",          r.readConfigU64,           0x4A93F0);
    logEntry("BAsyncSend",             r.bAsyncSend,              0xCFCDD0);
    logEntry("PlaytimeWriter",         r.playtimeWriter,          0x9CFDA0);
    logEntry("PbMsgCtor",              r.pbMsgCtor,               0xCFC7D0);
    logEntry("PbMsgFinalize",          r.pbMsgFinalize,           0xCFF370);
    logEntry("PbMsgCleanup",           r.pbMsgCleanup,            0xCFCA80);
    logEntry("YieldIfTimeSlice",       r.yieldIfTimeSlice,        0xCF2AC0);
    logEntry("GetUserStatsVtable",     r.getUserStatsVtable,      0x1347988);
    logEntry("GetUserStatsDesc",       r.getUserStatsDesc,        0x16F8830);
    logEntry("RespWrapperVtable",      r.respWrapperVtable,       0x1334340);
    logEntry("RespDescriptor",         r.respDescriptor,          0x16D5590);
    logEntry("RegKeySyncTime",         r.regKeySyncTime,          0x16E8248);

    LOG("[Resolver] Result: %d/%d matched, %d failed", matched, total, failed);
}

} // namespace ScResolver
