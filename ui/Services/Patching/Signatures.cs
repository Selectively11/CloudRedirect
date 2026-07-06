using System;
using System.Collections.Generic;

namespace CloudRedirect.Services.Patching
{
    internal static class Signatures
    {
        public static int ScanForPattern(byte[] data, int start, int end, byte[] pattern, byte[] mask)
        {
            int limit = Math.Min(end, data.Length) - pattern.Length;
            for (int i = start; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (mask[j] != 0 && data[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        public static int ScanForBytes(byte[] data, int start, int end, byte[] needle)
        {
            int limit = Math.Min(end, data.Length) - needle.Length;
            for (int i = start; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (data[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        /// <summary>
        /// Resolve a PatternPatch to a file offset. Returns the patch site offset, or -1.
        /// </summary>
        public static int ResolvePatternPatch(byte[] data, PatternPatch patch,
            int sectionStart, int sectionEnd, int[]? resolvedOffsets = null)
        {
            int scanStart = sectionStart;
            int scanEnd = sectionEnd;

            if (patch.RelativeToPatchIndex.HasValue && resolvedOffsets != null)
            {
                int idx = patch.RelativeToPatchIndex.Value;
                if (idx >= 0 && idx < resolvedOffsets.Length && resolvedOffsets[idx] >= 0)
                {
                    scanStart = Math.Max(sectionStart, resolvedOffsets[idx] + patch.RelativeStart);
                    scanEnd = Math.Min(resolvedOffsets[idx] + patch.RelativeEnd, sectionEnd);
                }
            }

            int pos = scanStart;
            while (pos < scanEnd)
            {
                int hit = ScanForPattern(data, pos, scanEnd, patch.Pattern, patch.Mask);
                if (hit < 0) break;

                if (patch.Validator != null && !patch.Validator(data, hit))
                {
                    pos = hit + 1;
                    continue;
                }

                if (patch.PatchSiteResolver != null)
                {
                    int resolved = patch.PatchSiteResolver(data, hit);
                    if (resolved >= 0)
                        return resolved;
                    pos = hit + 1;
                    continue;
                }

                return hit + patch.PatchOffset;
            }
            return -1;
        }

        /// <summary>
        /// Resolve an array of PatternPatches in order. Each patch can reference
        /// earlier resolved offsets via RelativeToPatchIndex. Returns resolved
        /// PatchEntry[] or null if any required patch fails.
        /// </summary>
        public static PatchEntry[]? ResolvePatternGroup(byte[] data, PatternPatch[] patches,
            int textStart, int textEnd, int obfStart, int obfEnd, Action<string>? log = null)
        {
            var result = new PatchEntry[patches.Length];
            var offsets = new int[patches.Length];

            for (int i = 0; i < patches.Length; i++)
            {
                var p = patches[i];
                int sStart, sEnd;
                switch (p.Region)
                {
                    case ScanRegion.Text:
                        sStart = textStart; sEnd = textEnd; break;
                    case ScanRegion.Obfuscated:
                        sStart = obfStart; sEnd = obfEnd; break;
                    default:
                        sStart = 0; sEnd = data.Length; break;
                }

                int offset = ResolvePatternPatch(data, p, sStart, sEnd, offsets);
                if (offset < 0)
                {
                    log?.Invoke($"  Could not locate {p.Name}");
                    return null;
                }

                offsets[i] = offset;
                result[i] = SnapshotPatch(data, offset, p);
                log?.Invoke($"  {p.Name} at 0x{offset:X}");
            }
            return result;
        }

        static PatchEntry SnapshotPatch(byte[] data, int offset, PatternPatch template)
        {
            var orig = (byte[])template.Original.Clone();
            var repl = (byte[])template.Replacement.Clone();
            int len = orig.Length;

            if (template.WildcardLen > 0
                && template.WildcardStart + template.WildcardLen <= len
                && offset + template.WildcardStart + template.WildcardLen <= data.Length)
            {
                Buffer.BlockCopy(data, offset + template.WildcardStart, orig, template.WildcardStart, template.WildcardLen);
                Buffer.BlockCopy(data, offset + template.WildcardStart, repl, template.WildcardStart, template.WildcardLen);
            }

            return new PatchEntry(offset, orig, repl);
        }

        // ── Core DLL patches (xinput1_4.dll / dwmapi.dll) ──────────────

        public static readonly PatternPatch[] CorePatchDefs =
        {
            // Core1: NOP download call (E8 -> B8). 26 bytes, 15 fixed; unique in .text.
            // 48 8B 4C 24 ?? 48 8D 55 ?? [E8|B8] ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 41 83 FC 01
            new PatternPatch
            {
                Name = "Core1 (download call)",
                Pattern = new byte[] {
                    0x48, 0x8B, 0x4C, 0x24, 0x00,
                    0x48, 0x8D, 0x55, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00,
                    0x85, 0xC0, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,
                    0x41, 0x83, 0xFC, 0x01 },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00,
                    0xFF, 0xFF, 0xFF, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF, 0xFF },
                PatchOffset = 9,
                Original    = new byte[] { 0xE8, 0x7C, 0xF5, 0xFF, 0xFF },
                Replacement = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00 },
                Region = ScanRegion.Text,
                WildcardStart = 1, WildcardLen = 4,
                Validator = (data, hit) =>
                {
                    byte opcode = data[hit + 9];
                    if (opcode == 0xE8)
                        return BitConverter.ToInt32(data, hit + 10) < 0;
                    return opcode == 0xB8;
                },
            },
            // Core2: jz -> jmp (hash check bypass). 19 bytes, 12 fixed; relative to Core1.
            // 49 8B D5 48 8D 4D ?? E8 ?? ?? ?? ?? 85 C0 [74|EB] ?? 33 FF E9
            new PatternPatch
            {
                Name = "Core2 (hash check jz)",
                Pattern = new byte[] {
                    0x49, 0x8B, 0xD5,
                    0x48, 0x8D, 0x4D, 0x00,
                    0xE8, 0x00, 0x00, 0x00, 0x00,
                    0x85, 0xC0, 0x00, 0x00,
                    0x33, 0xFF, 0xE9 },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0x00,
                    0xFF, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF },
                PatchOffset = 14,
                Original    = new byte[] { 0x74 },
                Replacement = new byte[] { 0xEB },
                Region = ScanRegion.Text,
                RelativeToPatchIndex = 0, RelativeStart = -0x300, RelativeEnd = 0x300,
                Validator = (data, hit) =>
                {
                    byte b = data[hit + 14];
                    return b == 0x74 || b == 0xEB;
                },
            },
        };

        // ── Payload patches P1-P3 (cloud redirect disable) ─────────────

        // V1 P1/P2/P3: old obfuscated payload layout.
        public static readonly PatternPatch[] PayloadP123Defs =
        {
            // P1: cloud rewrite jz -> nop jmp. Anchor: 44 8B 3D (r15d global load) +
            // test/jnz/test/jz; 15 fixed anchor bytes.
            new PatternPatch
            {
                Name = "P1 (cloud rewrite skip)",
                Pattern = new byte[] {
                    0x44, 0x8B, 0x3D, 0x00, 0x00, 0x00, 0x00,
                    0x85, 0xC0, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,
                    0x45, 0x85, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF },
                PatchOffset = 18,
                Original    = new byte[] { 0x0F, 0x84, 0x3B, 0x01, 0x00, 0x00 },
                Replacement = new byte[] { 0x90, 0xE9, 0x3B, 0x01, 0x00, 0x00 },
                Region = ScanRegion.Text,
                WildcardStart = 2, WildcardLen = 4,
                Validator = (data, hit) =>
                {
                    // 18-19: 0F 84 (orig jz) or 90 E9 (patched nop+jmp).
                    return (data[hit + 18] == 0x0F && data[hit + 19] == 0x84) ||
                           (data[hit + 18] == 0x90 && data[hit + 19] == 0xE9);
                },
            },
            // P2: zero proxy appid load. 28 fixed bytes across 39-byte span,
            // ending in lea rdx,[rsi+rdi] + cmp rcx,80h (varint threshold).
            new PatternPatch
            {
                Name = "P2 (proxy appid zero)",
                Pattern = new byte[] {
                    0x48, 0x8B, 0xF0,                         // mov rsi, rax
                    0x4C, 0x8B, 0xC7,                         // mov r8, rdi
                    0x4C, 0x8B, 0x7C, 0x24, 0x00,             // mov r15, [rsp+disp8]
                    0x49, 0x8B, 0xD7,                         // mov rdx, r15
                    0x48, 0x8B, 0xC8,                         // mov rcx, rax
                    0xE8, 0x00, 0x00, 0x00, 0x00,             // call memcpy_wrapper
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // PATCH SITE (6 bytes wildcarded)
                    0x48, 0x8D, 0x14, 0x3E,                   // lea rdx, [rsi+rdi]
                    0x48, 0x81, 0xF9, 0x80, 0x00, 0x00, 0x00  // cmp rcx, 80h
                },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00,
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
                },
                PatchOffset = 22,
                Original    = new byte[] { 0x8B, 0x0D, 0x7D, 0xCA, 0x1B, 0x00 },
                Replacement = new byte[] { 0x31, 0xC9, 0x90, 0x90, 0x90, 0x90 },
                Region = ScanRegion.Text,
                RelativeToPatchIndex = 0, RelativeStart = 0, RelativeEnd = 0x500,
                Validator = (data, hit) =>
                {
                    // hit+22: 8B 0D (orig) or 31 C9 (patched).
                    return (data[hit + 22] == 0x8B && data[hit + 23] == 0x0D) ||
                           (data[hit + 22] == 0x31 && data[hit + 23] == 0xC9);
                },
            },
            // P3: NOP IPC appid preserve
            // Anchor: Spacewar 480 constant (C7 40 09 E0 01 00 00), then next 89 3D or 6x NOP
            new PatternPatch
            {
                Name = "P3 (IPC appid preserve)",
                Pattern = new byte[] { 0xC7, 0x40, 0x09, 0xE0, 0x01, 0x00, 0x00 },
                Mask    = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
                PatchOffset = 0,
                Original    = new byte[] { 0x89, 0x3D, 0x00, 0x00, 0x00, 0x00 },
                Replacement = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
                Region = ScanRegion.Obfuscated,
                WildcardStart = 2, WildcardLen = 4,
                PatchSiteResolver = (data, hit) =>
                {
                    int searchStart = hit + 7;
                    int searchEnd = Math.Min(searchStart + 30, data.Length);
                    for (int i = searchStart; i < searchEnd - 5; i++)
                    {
                        if (data[i] == 0x89 && data[i + 1] == 0x3D)
                            return i;
                        if (data[i] == 0x90 && data[i + 1] == 0x90 &&
                            data[i + 2] == 0x90 && data[i + 3] == 0x90 &&
                            data[i + 4] == 0x90 && data[i + 5] == 0x90)
                            return i;
                    }
                    return -1;
                },
            },
        };

        // V2 P1/P2/P3: new plain .text payload (no obfuscator, restructured code).
        public static readonly PatternPatch[] PayloadP123DefsV2 =
        {
            // P1 V2: cloud rewrite jbe -> nop jmp. Anchor: test eax,eax; jnz +
            // cmp [rip+disp],r12d; jbe (PATCH SITE). Unique 17-byte pattern.
            new PatternPatch
            {
                Name = "P1 (cloud rewrite skip)",
                Pattern = new byte[] {
                    0x85, 0xC0, 0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,
                    0x44, 0x39, 0x25, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00 },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00 },
                PatchOffset = 15,
                Original    = new byte[] { 0x0F, 0x86, 0x00, 0x00, 0x00, 0x00 },
                Replacement = new byte[] { 0x90, 0xE9, 0x00, 0x00, 0x00, 0x00 },
                Region = ScanRegion.Text,
                WildcardStart = 2, WildcardLen = 4,
                Validator = (data, hit) =>
                {
                    return (data[hit + 15] == 0x0F && data[hit + 16] == 0x86) ||
                           (data[hit + 15] == 0x90 && data[hit + 16] == 0xE9);
                },
            },
            // P2 V2: zero proxy appid load. Registers changed:
            // mov r15,rax / mov r8,rsi (was mov rsi,rax / mov r8,rdi).
            // lea rdx,[r15+rdi] (was lea rdx,[rsi+rdi]).
            new PatternPatch
            {
                Name = "P2 (proxy appid zero)",
                Pattern = new byte[] {
                    0x4C, 0x8B, 0xF8,                         // mov r15, rax
                    0x4C, 0x8B, 0xC6,                         // mov r8, rsi
                    0x48, 0x8B, 0x54, 0x24, 0x30,             // mov rdx, [rsp+30h]
                    0x48, 0x8B, 0xC8,                         // mov rcx, rax
                    0xE8, 0x00, 0x00, 0x00, 0x00,             // call
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,       // PATCH SITE (wildcarded)
                    0x49, 0x8D, 0x14, 0x37,                   // lea rdx, [r15+rdi]
                    0x48, 0x81, 0xF9, 0x80, 0x00, 0x00, 0x00  // cmp rcx, 80h
                },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF,
                    0xFF, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
                },
                PatchOffset = 19,
                Original    = new byte[] { 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00 },
                Replacement = new byte[] { 0x31, 0xC9, 0x90, 0x90, 0x90, 0x90 },
                Region = ScanRegion.Text,
                WildcardStart = 2, WildcardLen = 4,
                Validator = (data, hit) =>
                {
                    return (data[hit + 19] == 0x8B && data[hit + 20] == 0x0D) ||
                           (data[hit + 19] == 0x31 && data[hit + 20] == 0xC9);
                },
            },
            // P3 V2: NOP IPC appid preserve. Anchor changed from C7 40 09
            // (mov [rax+9],480) to 41 C7 46 09 (mov [r14+9],480). Now in .text
            // (was in obfuscated section).
            new PatternPatch
            {
                Name = "P3 (IPC appid preserve)",
                Pattern = new byte[] { 0x41, 0xC7, 0x46, 0x09, 0xE0, 0x01, 0x00, 0x00 },
                Mask    = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
                PatchOffset = 0,
                Original    = new byte[] { 0x89, 0x3D, 0x00, 0x00, 0x00, 0x00 },
                Replacement = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
                Region = ScanRegion.Text,
                WildcardStart = 2, WildcardLen = 4,
                PatchSiteResolver = (data, hit) =>
                {
                    int searchStart = hit + 8;
                    int searchEnd = Math.Min(searchStart + 20, data.Length);
                    for (int i = searchStart; i < searchEnd - 5; i++)
                    {
                        if (data[i] == 0x89 && data[i + 1] == 0x3D)
                            return i;
                        if (data[i] == 0x90 && data[i + 1] == 0x90 &&
                            data[i + 2] == 0x90 && data[i + 3] == 0x90 &&
                            data[i + 4] == 0x90 && data[i + 5] == 0x90)
                            return i;
                    }
                    return -1;
                },
            },
        };

        // ── Payload setup patches P4/P5/P6 ──────────────────────────────

        // V1 P4: old obfuscated layout with E9 bridges.
        static readonly PatternPatch P4_V1 = new PatternPatch
        {
            Name = "P4 (activation flag)",
            Pattern = new byte[] { 0x4D, 0x85, 0xC0 },
            Mask = new byte[] { 0xFF, 0xFF, 0xFF },
            PatchOffset = 0,
            Original    = new byte[] { 0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 },
            Replacement = new byte[] { 0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01 },
            Region = ScanRegion.Obfuscated,
            WildcardStart = 2, WildcardLen = 4,
            PatchSiteResolver = (data, hit) =>
            {
                static bool HasBytes(byte[] bytes, int pos, params byte[] expected)
                {
                    if (pos < 0 || pos + expected.Length > bytes.Length) return false;
                    for (int i = 0; i < expected.Length; i++)
                        if (bytes[pos + i] != expected[i]) return false;
                    return true;
                }

                static int SkipOptionalBridge(byte[] bytes, int pos)
                {
                    return HasBytes(bytes, pos, 0xE9) ? pos + 5 : pos;
                }

                int pos = hit + 3;
                pos = SkipOptionalBridge(data, pos);
                if (!HasBytes(data, pos, 0x0F, 0x84)) return -1;
                pos += 6;
                if (!HasBytes(data, pos, 0xE8)) return -1;
                pos += 5;
                if (!HasBytes(data, pos, 0x85, 0xC0)) return -1;
                pos += 2;
                pos = SkipOptionalBridge(data, pos);
                if (!HasBytes(data, pos, 0x0F, 0x85)) return -1;
                pos += 6;
                if (!HasBytes(data, pos, 0xC6, 0x05)) return -1;
                if (pos + 6 >= data.Length || data[pos + 6] != 0x01) return -1;
                pos += 7;
                pos = SkipOptionalBridge(data, pos);
                if (!HasBytes(data, pos, 0xE9)) return -1;
                pos += 5;
                if (!HasBytes(data, pos, 0xC6, 0x05)) return -1;
                if (pos + 6 >= data.Length) return -1;
                byte val = data[pos + 6];
                return (val == 0x00 || val == 0x01) ? pos : -1;
            },
        };

        // V2 P4: new plain .text layout (no obfuscator). setnz al -> mov al,1; nop.
        static readonly PatternPatch P4_V2 = new PatternPatch
        {
            Name = "P4 (activation flag)",
            Pattern = new byte[] {
                0x85, 0xD2, 0x00, 0x00, 0x00, 0xEB, 0x02, 0xB0, 0x01, 0x88, 0x47, 0x01,
            },
            Mask = new byte[] {
                0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            },
            PatchOffset = 2,
            Original    = new byte[] { 0x0F, 0x95, 0xC0 },
            Replacement = new byte[] { 0xB0, 0x01, 0x90 },
            Region = ScanRegion.Text,
            Validator = (data, hit) =>
            {
                return (data[hit + 2] == 0x0F && data[hit + 3] == 0x95 && data[hit + 4] == 0xC0) ||
                       (data[hit + 2] == 0xB0 && data[hit + 3] == 0x01 && data[hit + 4] == 0x90);
            },
        };

        // P7: force activation confirmed flag. Bypass hash check: jnz->nop+nop, jz->jmp.
        static readonly PatternPatch P7_V2 = new PatternPatch
        {
            Name = "P7 (activation confirmed)",
            Pattern = new byte[] {
                0x4C, 0x3B, 0xC0, 0x75, 0x17, 0x4D, 0x85, 0xC0,
                0x74, 0x09, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85,
                0xC0, 0x75, 0x09, 0xC6, 0x05 },
            Mask = new byte[] {
                0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            PatchOffset = 3,
            Original    = new byte[] { 0x75, 0x17, 0x4D, 0x85, 0xC0, 0x74, 0x09 },
            Replacement = new byte[] { 0x90, 0x90, 0x4D, 0x85, 0xC0, 0xEB, 0x09 },
            Region = ScanRegion.Text,
            Validator = (data, hit) =>
            {
                return (data[hit + 3] == 0x75 && data[hit + 8] == 0x74) ||
                       (data[hit + 3] == 0x90 && data[hit + 8] == 0xEB);
            },
        };

        public static readonly PatternPatch[] PayloadSetupDefs =
        {
            P4_V2,
            P7_V2,
            // P5: skip GetCookie retry. Anchor: paired movq reg,xmm (66 48 0F 7E C7/CE);
            // 18 fixed anchor bytes.
            new PatternPatch
            {
                Name = "P5 (GetCookie retry skip)",
                Pattern = new byte[] {
                    0x66, 0x48, 0x0F, 0x7E, 0xC7,
                    0x66, 0x48, 0x0F, 0x7E, 0xCE,
                    0x48, 0x8D, 0x4D, 0x00,
                    0xE8, 0x00, 0x00, 0x00, 0x00,
                    0x48, 0x85, 0xF6, 0x00 },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0x00,
                    0xFF, 0x00, 0x00, 0x00, 0x00,
                    0xFF, 0xFF, 0xFF, 0x00 },
                PatchOffset = 22,
                Original    = new byte[] { 0x75 },
                Replacement = new byte[] { 0xEB },
                Region = ScanRegion.Text,
                Validator = (data, hit) =>
                {
                    if (hit + 24 > data.Length) return false;

                    byte opcode = data[hit + 22];
                    if (opcode != 0x75 && opcode != 0xEB) return false;

                    int skipDist = (sbyte)data[hit + 23];
                    if (skipDist <= 0) return false;
                    int afterSkip = hit + 24 + skipDist;
                    if (afterSkip > data.Length) return false;

                    for (int j = hit + 24; j < afterSkip && j < data.Length - 4; j++)
                    {
                        if (data[j] == 0xE9)
                        {
                            int rel = BitConverter.ToInt32(data, j + 1);
                            if (rel < 0) return true;
                        }
                    }
                    return false;
                },
            },
            // P6: fix GMRC pattern string. The May 27 2026 Steam update changed
            // GetManifestRequestCode's prologue, breaking SteamTools' pattern scan.
            // Patch the ASCII hex pattern in .rdata to match the new prologue.
            new PatternPatch
            {
                Name = "P6 (GMRC pattern fix)",
                // Scan for the common prefix "48 89 5C 24 18 55 " (18 ASCII bytes).
                // Matches both old and new pattern strings. Validator confirms full match.
                Pattern = new byte[] {
                    0x34, 0x38, 0x20, 0x38, 0x39, 0x20, 0x35, 0x43, 0x20, 0x32,
                    0x34, 0x20, 0x31, 0x38, 0x20, 0x35, 0x35, 0x20,
                },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                },
                PatchOffset = 0,
                Validator = (data, hit) =>
                {
                    // Accept if the full old OR new pattern is present at this offset
                    if (hit + 48 > data.Length) return false;
                    // Old: ends with "56 57 41 55 41 57 48 8D 6C^\0"
                    bool isOld = data[hit + 18] == 0x35 && data[hit + 19] == 0x36  // "56"
                              && data[hit + 44] == 0x5E && data[hit + 45] == 0x00; // "^\0"
                    // New: ends with "57 41 54 41 56 41 57 48 8D 6C\0"
                    bool isNew = data[hit + 18] == 0x35 && data[hit + 19] == 0x37  // "57"
                              && data[hit + 46] == 0x43 && data[hit + 47] == 0x00; // "C\0"
                    return isOld || isNew;
                },
                // Old: "48 89 5C 24 18 55 56 57 41 55 41 57 48 8D 6C^\0\0\0"
                Original = new byte[] {
                    0x34, 0x38, 0x20, 0x38, 0x39, 0x20, 0x35, 0x43, 0x20, 0x32,
                    0x34, 0x20, 0x31, 0x38, 0x20, 0x35, 0x35, 0x20, 0x35, 0x36,
                    0x20, 0x35, 0x37, 0x20, 0x34, 0x31, 0x20, 0x35, 0x35, 0x20,
                    0x34, 0x31, 0x20, 0x35, 0x37, 0x20, 0x34, 0x38, 0x20, 0x38,
                    0x44, 0x20, 0x36, 0x43, 0x5E, 0x00, 0x00, 0x00,
                },
                // New: "48 89 5C 24 18 55 57 41 54 41 56 41 57 48 8D 6C\0\0"
                Replacement = new byte[] {
                    0x34, 0x38, 0x20, 0x38, 0x39, 0x20, 0x35, 0x43, 0x20, 0x32,
                    0x34, 0x20, 0x31, 0x38, 0x20, 0x35, 0x35, 0x20, 0x35, 0x37,
                    0x20, 0x34, 0x31, 0x20, 0x35, 0x34, 0x20, 0x34, 0x31, 0x20,
                    0x35, 0x36, 0x20, 0x34, 0x31, 0x20, 0x35, 0x37, 0x20, 0x34,
                    0x38, 0x20, 0x38, 0x44, 0x20, 0x36, 0x43, 0x00,
                },
                Region = ScanRegion.All,
            },
        };

        public static readonly PatternPatch[] PayloadSetupDefsV1 =
        {
            P4_V1,
            P7_V2, // P7 exists in both old and new payloads
            PayloadSetupDefs[2], // P5
            PayloadSetupDefs[3], // P6
        };



        private static int ScanForPattern(byte[] data, byte[] pattern, byte[]? mask,
                                          int start, int end)
        {
            int pLen = pattern.Length;
            for (int i = start; i <= end - pLen; i++)
            {
                bool match = true;
                for (int j = 0; j < pLen; j++)
                {
                    byte m = mask != null ? mask[j] : (byte)0xFF;
                    if ((data[i + j] & m) != (pattern[j] & m))
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        // ── CloudRedirect hook finders ──────────────────────────────────

        /// <summary>
        /// Locate SendPkt (sub_18000DB50) via its alloca_probe setup
        /// (B8 00 11 00 00 E8) and walk back to the prologue. Returns -1 if absent.
        /// </summary>
        public static int FindSendPktFunction(byte[] data, int textStart, int textEnd)
        {
            // mov eax, 1100h; call __alloca_probe
            byte[] needle = { 0xB8, 0x00, 0x11, 0x00, 0x00, 0xE8 };
            int pos = textStart;
            while (pos < textEnd)
            {
                int hit = ScanForBytes(data, pos, textEnd, needle);
                if (hit < 0) break;

                // Prologue is 0x18 bytes back (push regs + lea rbp).
                int funcStart = hit - 0x18;
                if (funcStart < textStart) { pos = hit + 1; continue; }

                // Validate: 48 89 5C 24 20 (orig) or E9 xx xx xx xx (already patched).
                if ((data[funcStart] == 0x48 && data[funcStart + 1] == 0x89 &&
                     data[funcStart + 2] == 0x5C && data[funcStart + 3] == 0x24 &&
                     data[funcStart + 4] == 0x20) ||
                    data[funcStart] == 0xE9)
                {
                    return funcStart;
                }

                pos = hit + 1;
            }
            return -1;
        }

        /// <summary>Find a zero-filled code cave in an executable PE section, or -1.</summary>
        public static int FindCodeCave(byte[] data, PeSection[] sections, int requiredSize)
        {
            for (int s = 0; s < sections.Length; s++)
            {
                var sec = sections[s];
                if (!sec.IsExecutable) continue;

                int mappedSize = (int)Math.Min(sec.VirtualSize, sec.RawSize);
                int mappedEnd = Math.Min((int)sec.RawOffset + mappedSize, data.Length);
                int rawStart = (int)sec.RawOffset;

                int zeroRun = 0;
                for (int i = mappedEnd - 1; i >= rawStart; i--)
                {
                    if (data[i] == 0)
                        zeroRun++;
                    else
                        break;
                }

                if (zeroRun >= requiredSize)
                {
                    int caveStart = mappedEnd - zeroRun;
                    return caveStart;
                }
            }
            return -1;
        }

        /// <summary>
        /// Locate recvPktGlobal: find `lea rcx, SendPkt`, then the nearby
        /// `mov [rip+disp], rcx` that stores the original function pointer.
        /// Backward scan first, forward scan as fallback.
        /// </summary>
        public static int FindRecvPktGlobalRva(byte[] data, PeSection[] sections,
            int sendPktRva, int searchStart, int searchEnd)
        {
            // 48 8D 0D xx xx xx xx with target == sendPktRva.
            for (int i = searchStart; i < searchEnd - 7; i++)
            {
                if (data[i] != 0x48 || data[i + 1] != 0x8D || data[i + 2] != 0x0D)
                    continue;

                int rel = BitConverter.ToInt32(data, i + 3);
                int instrRva = PeSection.FileOffsetToRva(sections, i);
                if (instrRva < 0) continue;

                int targetRva = instrRva + 7 + rel;
                if (targetRva != sendPktRva) continue;

                // Backward-scan for `mov [rip+disp], rcx` (48 89 0D).
                for (int j = i - 1; j >= Math.Max(searchStart, i - 0x100); j--)
                {
                    if (data[j] == 0x48 && data[j + 1] == 0x89 && data[j + 2] == 0x0D)
                    {
                        int movRel = BitConverter.ToInt32(data, j + 3);
                        int movRva = PeSection.FileOffsetToRva(sections, j);
                        if (movRva < 0) continue;
                        int globalRva = movRva + 7 + movRel;
                        return globalRva;
                    }
                }

                // Forward-scan fallback (48 89 xx, modrm rip-relative).
                for (int j = i + 7; j < Math.Min(i + 0x100, searchEnd) - 7; j++)
                {
                    if (data[j] == 0x48 && data[j + 1] == 0x89 && (data[j + 2] & 0xC7) == 0x05)
                    {
                        int movRel = BitConverter.ToInt32(data, j + 3);
                        int movRva = PeSection.FileOffsetToRva(sections, j);
                        if (movRva < 0) continue;
                        return movRva + 7 + movRel;
                    }
                }
            }
            return -1;
        }

    }
}
