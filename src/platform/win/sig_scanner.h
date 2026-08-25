#pragma once
// sig_scanner.h -- x64 pattern scanner and RTTI-based address resolver for steamclient64.dll
// Eliminates manual RVA updates on Steam builds by resolving addresses at runtime.

#include <cstdint>
#include <cstddef>

namespace SigScanner {

// Must be called once with the loaded steamclient64.dll base address.
// Caches PE section boundaries (.text, .rdata, .data) for all subsequent scans.
bool Init(uintptr_t steamClientBase);

// ── Pattern scanning ──────────────────────────────────────────────────

// Scan .text section for a byte pattern with wildcard mask.
// pattern: raw bytes to match
// mask: "x" = must match, "?" = wildcard. Length must equal patternLen.
// Returns absolute address of first match, or 0 on failure.
uintptr_t FindPattern(const uint8_t* pattern, const char* mask, size_t patternLen);

// Scan arbitrary memory range with mask.
uintptr_t FindPatternInRange(uintptr_t start, size_t size,
                             const uint8_t* pattern, const char* mask, size_t patternLen);

// ── Instruction operand extraction ────────────────────────────────────

// Given an absolute address of a `call rel32` instruction (E8 xx xx xx xx),
// decode and return the call target (absolute address).
uintptr_t DecodeRelCall(uintptr_t callAddr);

// Given an absolute address of a `lea reg, [rip+disp32]` instruction,
// decode and return the target address. Handles 7-byte LEA (48 8D xx xx xx xx xx).
uintptr_t DecodeRipRelLea(uintptr_t leaAddr);

// Given an absolute address of a `mov reg, [rip+disp32]` instruction,
// decode and return the address of the global (the memory operand target).
uintptr_t DecodeRipRelMov(uintptr_t movAddr);

// Scan forward from `start` for up to `maxBytes`, looking for a `call rel32` (E8)
// instruction. Returns the absolute address of the call target, or 0.
uintptr_t FindFirstCallTarget(uintptr_t start, size_t maxBytes);

// Scan forward from `start` for a `mov reg, cs:[rip+disp32]` to a global.
// Returns the address of the global (memory operand), or 0.
uintptr_t FindFirstRipRelMovTarget(uintptr_t start, size_t maxBytes);

// Scan forward from `start` for a `lea reg, [rip+disp32]`.
// Returns the address of the target, or 0.
uintptr_t FindFirstRipRelLeaTarget(uintptr_t start, size_t maxBytes);

// ── RTTI-based vtable resolution ──────────────────────────────────────

// Resolve a vtable address by MSVC-x64 RTTI type name.
// className: decorated RTTI name, e.g. ".?AVCCMInterface@@"
// Returns absolute address of the vtable (first function pointer slot), or 0.
uintptr_t ResolveVtableByRtti(const char* className);

// ── Utility ───────────────────────────────────────────────────────────

// Check if an address looks like a valid x64 function prologue.
bool LooksLikePrologue(uintptr_t addr);

// Prologue check + CC/C3 boundary validation.
bool LooksLikeFunctionStart(uintptr_t addr);

// Get cached section info.
uintptr_t GetTextBase();
size_t    GetTextSize();
uintptr_t GetRdataBase();
size_t    GetRdataSize();
uintptr_t GetDataBase();
size_t    GetDataSize();
uintptr_t GetImageBase();
size_t    GetImageSize();

} // namespace SigScanner
