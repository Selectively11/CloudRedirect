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
            int sectionStart, int sectionEnd, int[] resolvedOffsets = null)
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
        public static PatchEntry[] ResolvePatternGroup(byte[] data, PatternPatch[] patches,
            int textStart, int textEnd, int obfStart, int obfEnd, Action<string> log = null)
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
            // Core1: NOP download call (E8 -> B8)
            // Anchored on: mov rcx,[rsp+disp8] + lea rdx,[rbp+disp8] + call/mov eax +
            //   test eax,eax + jz near + cmp r12d,1
            // 48 8B 4C 24 ?? 48 8D 55 ?? [E8|B8] ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 41 83 FC 01
            // 26 bytes, 15 fixed. Unique in .text.
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
            // Core2: jz -> jmp (hash check bypass)
            // Anchored on: mov rdx,r13 + lea rcx,[rbp+disp8] + call + test eax,eax +
            //   [jz|jmp] short + xor edi,edi + jmp near
            // 49 8B D5 48 8D 4D ?? E8 ?? ?? ?? ?? 85 C0 [74|EB] ?? 33 FF E9
            // 19 bytes, 12 fixed. Unique in .text. Relative to Core1.
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

        public static readonly PatternPatch[] PayloadP123Defs =
        {
            // P1: cloud rewrite jz -> nop jmp
            // Anchored on: mov r15d,[rip+disp32] (44 8B 3D) loading the cloud spoof target id,
            // followed by test eax,eax / jnz near / test r15d,r15d / jz near (patch site).
            // 44 8B 3D is a distinctive opcode (r15d global load), giving 15 fixed anchor bytes.
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
                    // bytes 18-19 must be either 0F 84 (original jz) or 90 E9 (patched nop+jmp)
                    return (data[hit + 18] == 0x0F && data[hit + 19] == 0x84) ||
                           (data[hit + 18] == 0x90 && data[hit + 19] == 0xE9);
                },
            },
            // P2: zero proxy appid load
            // Anchored on: mov rsi,rax + mov r8,rdi + mov r15,[rsp+disp8] + mov rdx,r15 +
            //   mov rcx,rax + call + [mov ecx,[rip+X] | xor ecx,ecx] + lea rdx,[rsi+rdi] +
            //   cmp rcx,80h (varint threshold). 28 fixed bytes across 39-byte span.
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
                    // patch site at hit+22: must be 8B 0D (original) or 31 C9 (patched)
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
                Original    = new byte[] { 0x89, 0x3D, 0x28, 0xD5, 0xFE, 0xFF },
                Replacement = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
                Region = ScanRegion.Obfuscated,
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

        // ── Payload setup patches P4/P5 ────────────────────────────────

        public static readonly PatternPatch[] PayloadSetupDefs =
        {
            // P4: force activation flag to 1
            // Anchored on: test r8,r8 + jz + call strcmp + test eax,eax + jnz +
            //   mov [flag],1 + jmp $+5 (obfuscator bridge) + jmp merge + mov [flag],0
            // The null-check-before-strcmp pattern + E9 00 00 00 00 bridge is very distinctive.
            // 21 fixed bytes across 46-byte span.
            new PatternPatch
            {
                Name = "P4 (activation flag)",
                Pattern = new byte[] {
                    0x4D, 0x85, 0xC0,                                     // test r8, r8
                    0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,                   // jz near
                    0xE8, 0x00, 0x00, 0x00, 0x00,                         // call strcmp_wrapper
                    0x85, 0xC0,                                           // test eax, eax
                    0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,                   // jnz near (to patch site)
                    0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,             // mov [g_bActivationFlag], 1
                    0xE9, 0x00, 0x00, 0x00, 0x00,                         // jmp $+5 (obfuscator bridge)
                    0xE9, 0x00, 0x00, 0x00, 0x00,                         // jmp merge
                    0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00              // PATCH SITE: mov [flag], 0
                },
                Mask = new byte[] {
                    0xFF, 0xFF, 0xFF,                                     // test r8, r8
                    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,                   // jz near
                    0xFF, 0x00, 0x00, 0x00, 0x00,                         // call
                    0xFF, 0xFF,                                           // test eax, eax
                    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,                   // jnz near
                    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF,             // mov [flag], 1
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF,                         // E9 00 00 00 00
                    0xFF, 0x00, 0x00, 0x00, 0x00,                         // jmp merge
                    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00              // PATCH SITE
                },
                PatchOffset = 39,
                Original    = new byte[] { 0xC6, 0x05, 0xC6, 0x20, 0xFE, 0xFF, 0x00 },
                Replacement = new byte[] { 0xC6, 0x05, 0xC6, 0x20, 0xFE, 0xFF, 0x01 },
                Region = ScanRegion.Obfuscated,
                WildcardStart = 2, WildcardLen = 4,
                Validator = (data, hit) =>
                {
                    byte val = data[hit + 45];
                    return val == 0x00 || val == 0x01;
                },
            },
            // P5: skip GetCookie retry
            // Anchored on: two consecutive movq reg,xmm instructions (66 48 0F 7E C7 / CE),
            // followed by lea rcx,[rbp+disp8] + call + test rsi,rsi + jnz.
            // The paired movq-from-xmm sequence is extremely distinctive -- 18 fixed anchor bytes.
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
        };

        // ── CloudRedirect hook finders ──────────────────────────────────

        /// <summary>
        /// Find the SendPkt function (sub_18000DB50) by scanning for its
        /// distinctive alloca_probe setup: B8 00 11 00 00 E8 (mov eax, 1100h; call)
        /// then walking back to the function prologue.
        /// Returns the file offset of the function's first byte, or -1.
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

                // the prologue is 0x18 bytes before: push regs + lea rbp
                int funcStart = hit - 0x18;
                if (funcStart < textStart) { pos = hit + 1; continue; }

                // validate prologue: 48 89 5C 24 20 (original) or E9 xx xx xx xx (already patched jmp)
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

        /// <summary>
        /// Find a code cave (zero-filled region) in an executable PE section
        /// where VirtualSize > RawSize or at the end of raw data.
        /// Returns the file offset of the cave, or -1.
        /// </summary>
        public static int FindCodeCave(byte[] data, PeSection[] sections, int requiredSize)
        {
            for (int s = 0; s < sections.Length; s++)
            {
                var sec = sections[s];
                if (!sec.IsExecutable) continue;

                int rawEnd = (int)(sec.RawOffset + sec.RawSize);
                if (rawEnd > data.Length) rawEnd = data.Length;
                int rawStart = (int)sec.RawOffset;

                // scan backward from end of raw data for zero-filled region
                int zeroRun = 0;
                for (int i = rawEnd - 1; i >= rawStart; i--)
                {
                    if (data[i] == 0)
                        zeroRun++;
                    else
                        break;
                }

                if (zeroRun >= requiredSize)
                {
                    // place cave at the start of the zero run, aligned to leave some margin
                    int caveStart = rawEnd - zeroRun;
                    return caveStart;
                }
            }
            return -1;
        }

        /// <summary>
        /// Find the recvPktGlobal RVA by locating the LEA that references SendPkt's
        /// address in the hook installer, then finding the nearby MOV that stores
        /// the RecvPkt vtable pointer.
        ///
        /// Sequence in the hook installer:
        ///   lea rcx, sub_SendPkt       (48 8D 0D xx xx xx xx)  -- references our SendPkt
        ///   ... (obfuscated junk, VirtualProtect, etc.) ...
        ///   mov cs:qword_recvPkt, rcx  (48 89 0D xx xx xx xx)  -- stores RecvPkt ptr
        ///
        /// Returns the RVA of the recvPktGlobal, or -1.
        /// </summary>
        public static int FindRecvPktGlobalRva(byte[] data, PeSection[] sections,
            int sendPktRva, int searchStart, int searchEnd)
        {
            // scan for 48 8D 0D xx xx xx xx where target = sendPktRva
            for (int i = searchStart; i < searchEnd - 7; i++)
            {
                if (data[i] != 0x48 || data[i + 1] != 0x8D || data[i + 2] != 0x0D)
                    continue;

                int rel = BitConverter.ToInt32(data, i + 3);
                int instrRva = PeSection.FileOffsetToRva(sections, i);
                if (instrRva < 0) continue;

                int targetRva = instrRva + 7 + rel;
                if (targetRva != sendPktRva) continue;

                // found the lea rcx, sub_SendPkt
                // now search forward for 48 89 0D (mov cs:qword, rcx) which
                // stores recvPktGlobal -- the first such instruction after the lea
                for (int j = i + 7; j < Math.Min(i + 0x100, searchEnd) - 7; j++)
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
            }
            return -1;
        }

    }
}
