#include "sig_scanner.h"
#include "log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>

namespace SigScanner {

// ── Cached PE section info ────────────────────────────────────────────

static uintptr_t s_imageBase  = 0;
static size_t    s_imageSize  = 0;
static uintptr_t s_textBase   = 0;
static size_t    s_textSize   = 0;
static uintptr_t s_rdataBase  = 0;
static size_t    s_rdataSize  = 0;
static uintptr_t s_dataBase   = 0;
static size_t    s_dataSize   = 0;

bool Init(uintptr_t steamClientBase) {
    if (!steamClientBase) return false;
    s_imageBase = steamClientBase;

    auto base   = reinterpret_cast<uint8_t*>(steamClientBase);
    auto dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto ntHdr  = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return false;

    s_imageSize = ntHdr->OptionalHeader.SizeOfImage;

    auto sec = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text\0", 6) == 0) {
            s_textBase = steamClientBase + sec->VirtualAddress;
            s_textSize = sec->Misc.VirtualSize;
        } else if (memcmp(sec->Name, ".rdata", 6) == 0) {
            s_rdataBase = steamClientBase + sec->VirtualAddress;
            s_rdataSize = sec->Misc.VirtualSize;
        } else if (memcmp(sec->Name, ".data\0", 6) == 0) {
            s_dataBase = steamClientBase + sec->VirtualAddress;
            s_dataSize = sec->Misc.VirtualSize;
        }
    }

    LOG("[SigScan] Init: base=%p text=%p+0x%zX rdata=%p+0x%zX data=%p+0x%zX",
        (void*)s_imageBase,
        (void*)s_textBase, s_textSize,
        (void*)s_rdataBase, s_rdataSize,
        (void*)s_dataBase, s_dataSize);
    return s_textBase != 0;
}

// ── Accessors ─────────────────────────────────────────────────────────

uintptr_t GetTextBase()  { return s_textBase; }
size_t    GetTextSize()  { return s_textSize; }
uintptr_t GetRdataBase() { return s_rdataBase; }
size_t    GetRdataSize() { return s_rdataSize; }
uintptr_t GetDataBase()  { return s_dataBase; }
size_t    GetDataSize()  { return s_dataSize; }
uintptr_t GetImageBase() { return s_imageBase; }
size_t    GetImageSize() { return s_imageSize; }

// ── Pattern scanning ──────────────────────────────────────────────────

uintptr_t FindPatternInRange(uintptr_t start, size_t size,
                             const uint8_t* pattern, const char* mask, size_t patternLen) {
    if (!start || !size || !pattern || !mask || patternLen == 0 || size < patternLen)
        return 0;

    const auto* mem = reinterpret_cast<const uint8_t*>(start);
    const size_t scanEnd = size - patternLen;

    __try {
        for (size_t i = 0; i <= scanEnd; ++i) {
            bool match = true;
            for (size_t j = 0; j < patternLen; ++j) {
                if (mask[j] == 'x' && mem[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return start + i;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 0;
}

uintptr_t FindPattern(const uint8_t* pattern, const char* mask, size_t patternLen) {
    return FindPatternInRange(s_textBase, s_textSize, pattern, mask, patternLen);
}

// ── Instruction operand extraction ────────────────────────────────────

uintptr_t DecodeRelCall(uintptr_t callAddr) {
    if (!callAddr) return 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(callAddr);
        if (p[0] != 0xE8) return 0;
        int32_t disp = *reinterpret_cast<const int32_t*>(p + 1);
        return callAddr + 5 + disp;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

uintptr_t DecodeRipRelLea(uintptr_t leaAddr) {
    if (!leaAddr) return 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(leaAddr);
        // LEA reg, [rip+disp32]:
        //   REX.W prefix (0x48 or 0x4C) + 0x8D + ModR/M(05/0D/15/1D/25/2D/35/3D) + disp32
        //   ModR/M & 0xC7 == 0x05 means [rip+disp32]
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8D && (p[2] & 0xC7) == 0x05) {
            int32_t disp = *reinterpret_cast<const int32_t*>(p + 3);
            return leaAddr + 7 + disp;
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

uintptr_t DecodeRipRelMov(uintptr_t movAddr) {
    if (!movAddr) return 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(movAddr);
        // MOV reg, [rip+disp32]:
        //   REX.W prefix (0x48 or 0x4C) + 0x8B + ModR/M & 0xC7 == 0x05 + disp32
        if ((p[0] == 0x48 || p[0] == 0x4C) && p[1] == 0x8B && (p[2] & 0xC7) == 0x05) {
            int32_t disp = *reinterpret_cast<const int32_t*>(p + 3);
            return movAddr + 7 + disp;
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

uintptr_t FindFirstCallTarget(uintptr_t start, size_t maxBytes) {
    if (!start || !maxBytes) return 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(start);
        for (size_t i = 0; i + 5 <= maxBytes; ++i) {
            if (p[i] == 0xE8) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 1);
                uintptr_t target = start + i + 5 + disp;
                // Sanity: target should be within the image
                if (target >= s_imageBase && target < s_imageBase + s_imageSize)
                    return target;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 0;
}

uintptr_t FindFirstRipRelMovTarget(uintptr_t start, size_t maxBytes) {
    if (!start || !maxBytes) return 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(start);
        for (size_t i = 0; i + 7 <= maxBytes; ++i) {
            if ((p[i] == 0x48 || p[i] == 0x4C) && p[i+1] == 0x8B && (p[i+2] & 0xC7) == 0x05) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 3);
                uintptr_t target = start + i + 7 + disp;
                if (target >= s_imageBase && target < s_imageBase + s_imageSize)
                    return target;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 0;
}

uintptr_t FindFirstRipRelLeaTarget(uintptr_t start, size_t maxBytes) {
    if (!start || !maxBytes) return 0;
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(start);
        for (size_t i = 0; i + 7 <= maxBytes; ++i) {
            if ((p[i] == 0x48 || p[i] == 0x4C) && p[i+1] == 0x8D && (p[i+2] & 0xC7) == 0x05) {
                int32_t disp = *reinterpret_cast<const int32_t*>(p + i + 3);
                uintptr_t target = start + i + 7 + disp;
                if (target >= s_imageBase && target < s_imageBase + s_imageSize)
                    return target;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 0;
}

// ── RTTI vtable resolution ────────────────────────────────────────────

uintptr_t ResolveVtableByRtti(const char* className) {
    if (!className || !s_imageBase) return 0;

    const size_t nameLen = strlen(className) + 1; // include NUL

    // Step 1: find the RTTI type descriptor name string in .data or .rdata
    // MSVC TypeDescriptor layout: { void* pVFTable, void* spare, char name[] }
    // name is at offset +0x10 from the TypeDescriptor start.
    auto findNameInSection = [&](uintptr_t sStart, size_t sSize) -> const uint8_t* {
        if (!sStart || sSize < nameLen) return nullptr;
        const auto* mem = reinterpret_cast<const uint8_t*>(sStart);
        __try {
            for (size_t i = 0; i + nameLen <= sSize; ++i) {
                if (mem[i] == className[0] && memcmp(mem + i, className, nameLen) == 0)
                    return mem + i;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return nullptr;
        }
        return nullptr;
    };

    const uint8_t* nameAddr = findNameInSection(s_dataBase, s_dataSize);
    if (!nameAddr) nameAddr = findNameInSection(s_rdataBase, s_rdataSize);
    if (!nameAddr) {
        LOG("[SigScan-RTTI] type name '%s' not found", className);
        return 0;
    }

    // Step 2: TypeDescriptor starts 0x10 bytes before the name string
    const uint8_t* tdAddr = nameAddr - 0x10;
    const uint32_t tdRva  = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(tdAddr) - s_imageBase);

    // Step 3: find the CompleteObjectLocator (COL) in .rdata that references this TD
    // COL layout (MSVC x64):
    //   +0x00: DWORD signature (1 for 64-bit)
    //   +0x04: DWORD offset
    //   +0x08: DWORD cdOffset
    //   +0x0C: DWORD pTypeDescriptor (RVA)
    //   +0x10: DWORD pClassHierarchy (RVA)
    //   +0x14: DWORD pSelf (RVA of this COL itself)
    const uint8_t* col = nullptr;
    __try {
        const auto* rdata = reinterpret_cast<const uint8_t*>(s_rdataBase);
        for (size_t i = 0; i + 4 <= s_rdataSize; i += 4) {
            if (*reinterpret_cast<const uint32_t*>(rdata + i) != tdRva) continue;
            if (i < 0x0C) continue;
            const uint8_t* candidate = rdata + i - 0x0C;
            const uint32_t sig   = *reinterpret_cast<const uint32_t*>(candidate + 0x00);
            const uint32_t pSelf = *reinterpret_cast<const uint32_t*>(candidate + 0x14);
            if (sig == 1 && pSelf == static_cast<uint32_t>(reinterpret_cast<uintptr_t>(candidate) - s_imageBase)) {
                col = candidate;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    if (!col) {
        LOG("[SigScan-RTTI] COL for '%s' (TD RVA 0x%X) not found", className, tdRva);
        return 0;
    }

    // Step 4: find the vtable pointer in .rdata that points to the COL
    // vtable layout: { COL*, slot0, slot1, ... }
    // We scan .rdata for a QWORD matching the COL absolute address.
    const uint64_t colAbs = reinterpret_cast<uint64_t>(col);
    const uint8_t* vtable = nullptr;
    __try {
        const auto* rdata = reinterpret_cast<const uint8_t*>(s_rdataBase);
        for (size_t i = 0; i + sizeof(uint64_t) <= s_rdataSize; i += sizeof(void*)) {
            if (*reinterpret_cast<const uint64_t*>(rdata + i) == colAbs) {
                // vtable starts at the next slot (first function pointer)
                if (i + 2 * sizeof(uint64_t) > s_rdataSize) break;
                vtable = rdata + i + sizeof(uint64_t);
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    if (!vtable) {
        LOG("[SigScan-RTTI] vtable backref for '%s' not found", className);
        return 0;
    }

    uintptr_t result = reinterpret_cast<uintptr_t>(vtable);
    LOG("[SigScan-RTTI] resolved '%s' vtable @ %p (RVA 0x%llX)",
        className, (void*)result, (uint64_t)(result - s_imageBase));
    return result;
}

// ── Utility ───────────────────────────────────────────────────────────

bool LooksLikePrologue(uintptr_t addr) {
    if (!addr) return false;
    uint8_t b[8] = {};
    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(addr);
        for (int i = 0; i < 8; ++i) b[i] = p[i];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    // mov [rsp+N], reg (save non-volatile)
    if ((b[0] == 0x48 || b[0] == 0x4C) && b[1] == 0x89 &&
        (b[2] == 0x5C || b[2] == 0x4C || b[2] == 0x54 || b[2] == 0x44) && b[3] == 0x24) return true;
    // sub rsp, imm8
    if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC) return true;
    // sub rsp, imm32
    if (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC) return true;
    // mov r12, rsp
    if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xDC) return true;
    // mov rax, rsp / mov rax, rdx
    if (b[0] == 0x48 && b[1] == 0x8B && (b[2] == 0xC4 || b[2] == 0xC2)) return true;
    // push with REX prefix (40 53/55/56/57)
    if (b[0] == 0x40 && (b[1] == 0x53 || b[1] == 0x55 || b[1] == 0x56 || b[1] == 0x57)) return true;
    // push r12..r15 (41 54/55/56/57)
    if (b[0] == 0x41 && (b[1] == 0x54 || b[1] == 0x55 || b[1] == 0x56 || b[1] == 0x57)) return true;
    // push rbx/rbp/rsi/rdi (no REX)
    if (b[0] == 0x53 || b[0] == 0x55 || b[0] == 0x56 || b[0] == 0x57) return true;
    // jmp (thunk)
    if (b[0] == 0xE9) return true;
    // mov [rsp+N], edx/ecx (32-bit arg save, common non-REX prologue)
    if (b[0] == 0x89 && (b[1] == 0x54 || b[1] == 0x4C) && b[2] == 0x24) return true;
    // cmp edx, imm32 (parameter validation at function start)
    if (b[0] == 0x81 && b[1] == 0xFA) return true;
    // mov r8d, [rcx+N] (load from this ptr, common leaf start)
    if (b[0] == 0x44 && b[1] == 0x8B && b[2] == 0x41) return true;
    // test rcx, rcx (null-guard on this ptr, common for small functions)
    if (b[0] == 0x48 && b[1] == 0x85 && b[2] == 0xC9) return true;
    return false;
}

// Prologue check + boundary validation (CC/C3 padding or 16-byte aligned).
bool LooksLikeFunctionStart(uintptr_t addr) {
    if (!LooksLikePrologue(addr)) return false;
    if (addr <= s_textBase) return true;
    if ((addr & 0xF) == 0) return true;

    __try {
        const auto* p = reinterpret_cast<const uint8_t*>(addr);
        if (p[-1] == 0xCC || p[-1] == 0xC3) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    return false;
}

} // namespace SigScanner
