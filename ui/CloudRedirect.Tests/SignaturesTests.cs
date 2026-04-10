using CloudRedirect.Services.Patching;
using Xunit;

namespace CloudRedirect.Tests;

/// <summary>
/// Tests for Signatures: pattern scanning, byte scanning,
/// and PatternPatch-based resolvers for Core/Payload patches.
/// </summary>
public class SignaturesTests
{
    // ── ScanForBytes ─────────────────────────────────────────────────

    [Fact]
    public void ScanForBytes_FindsNeedleAtStart()
    {
        byte[] data = { 0xAA, 0xBB, 0xCC, 0xDD };
        byte[] needle = { 0xAA, 0xBB };
        Assert.Equal(0, Signatures.ScanForBytes(data, 0, data.Length, needle));
    }

    [Fact]
    public void ScanForBytes_FindsNeedleInMiddle()
    {
        byte[] data = { 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0x00 };
        byte[] needle = { 0xAA, 0xBB, 0xCC };
        Assert.Equal(2, Signatures.ScanForBytes(data, 0, data.Length, needle));
    }

    [Fact]
    public void ScanForBytes_FindsNeedleAtEnd()
    {
        byte[] data = { 0x00, 0x00, 0xAA, 0xBB };
        byte[] needle = { 0xAA, 0xBB };
        Assert.Equal(2, Signatures.ScanForBytes(data, 0, data.Length, needle));
    }

    [Fact]
    public void ScanForBytes_NotFound_ReturnsNegative()
    {
        byte[] data = { 0x00, 0x01, 0x02, 0x03 };
        byte[] needle = { 0xFF, 0xFE };
        Assert.Equal(-1, Signatures.ScanForBytes(data, 0, data.Length, needle));
    }

    [Fact]
    public void ScanForBytes_RespectsStartOffset()
    {
        byte[] data = { 0xAA, 0xBB, 0x00, 0xAA, 0xBB };
        byte[] needle = { 0xAA, 0xBB };
        Assert.Equal(3, Signatures.ScanForBytes(data, 1, data.Length, needle));
    }

    [Fact]
    public void ScanForBytes_RespectsEndBound()
    {
        byte[] data = { 0x00, 0x00, 0xAA, 0xBB, 0xCC };
        byte[] needle = { 0xAA, 0xBB, 0xCC };
        // end=4 means the needle starting at index 2 would need indices 2,3,4 -- but 4 < end wouldn't hold
        Assert.Equal(-1, Signatures.ScanForBytes(data, 0, 4, needle));
    }

    [Fact]
    public void ScanForBytes_EmptyNeedle_ReturnsStart()
    {
        byte[] data = { 0x00, 0x01 };
        byte[] needle = Array.Empty<byte>();
        Assert.Equal(0, Signatures.ScanForBytes(data, 0, data.Length, needle));
    }

    // ── ScanForPattern (with mask) ───────────────────────────────────

    [Fact]
    public void ScanForPattern_ExactMatch()
    {
        byte[] data = { 0x00, 0xE8, 0x10, 0x20, 0x85 };
        byte[] pattern = { 0xE8, 0x10, 0x20, 0x85 };
        byte[] mask =    { 0xFF, 0xFF, 0xFF, 0xFF };
        Assert.Equal(1, Signatures.ScanForPattern(data, 0, data.Length, pattern, mask));
    }

    [Fact]
    public void ScanForPattern_WildcardBytes()
    {
        byte[] data = { 0xE8, 0xAA, 0xBB, 0xCC, 0xDD, 0x85, 0xC0 };
        byte[] pattern = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0 };
        byte[] mask =    { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };
        Assert.Equal(0, Signatures.ScanForPattern(data, 0, data.Length, pattern, mask));
    }

    [Fact]
    public void ScanForPattern_NoMatch()
    {
        byte[] data = { 0xE8, 0xAA, 0xBB, 0xCC, 0xDD, 0x84, 0xC0 };
        byte[] pattern = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0 };
        byte[] mask =    { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };
        Assert.Equal(-1, Signatures.ScanForPattern(data, 0, data.Length, pattern, mask));
    }

    [Fact]
    public void ScanForPattern_AllWildcard_MatchesAtStart()
    {
        byte[] data = { 0x12, 0x34, 0x56 };
        byte[] pattern = { 0x00, 0x00 };
        byte[] mask =    { 0x00, 0x00 };
        Assert.Equal(0, Signatures.ScanForPattern(data, 0, data.Length, pattern, mask));
    }

    // ── CorePatchDefs[0] (Core1: negative call target) ─────────────
    // New pattern (26 bytes, PatchOffset=9):
    // 48 8B 4C 24 ?? 48 8D 55 ?? [E8|B8] ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 41 83 FC 01

    [Fact]
    public void Core1_MatchesNegativeCallTarget()
    {
        byte[] data = new byte[64];
        int pos = 10;
        // prefix: mov rcx,[rsp+58h] + lea rdx,[rbp+40h]
        data[pos]     = 0x48; data[pos + 1] = 0x8B; data[pos + 2] = 0x4C; data[pos + 3] = 0x24; data[pos + 4] = 0x58;
        data[pos + 5] = 0x48; data[pos + 6] = 0x8D; data[pos + 7] = 0x55; data[pos + 8] = 0x40;
        // call with negative displacement
        data[pos + 9] = 0xE8;
        BitConverter.TryWriteBytes(data.AsSpan(pos + 10, 4), -0x100);
        // test eax,eax + jz near
        data[pos + 14] = 0x85; data[pos + 15] = 0xC0;
        data[pos + 16] = 0x0F; data[pos + 17] = 0x84;
        // cmp r12d, 1
        data[pos + 22] = 0x41; data[pos + 23] = 0x83; data[pos + 24] = 0xFC; data[pos + 25] = 0x01;

        var patch = Signatures.CorePatchDefs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(pos + 9, result);
    }

    [Fact]
    public void Core1_IgnoresPositiveCallTarget()
    {
        byte[] data = new byte[64];
        int pos = 10;
        data[pos]     = 0x48; data[pos + 1] = 0x8B; data[pos + 2] = 0x4C; data[pos + 3] = 0x24; data[pos + 4] = 0x58;
        data[pos + 5] = 0x48; data[pos + 6] = 0x8D; data[pos + 7] = 0x55; data[pos + 8] = 0x40;
        data[pos + 9] = 0xE8;
        BitConverter.TryWriteBytes(data.AsSpan(pos + 10, 4), 0x100);
        data[pos + 14] = 0x85; data[pos + 15] = 0xC0;
        data[pos + 16] = 0x0F; data[pos + 17] = 0x84;
        data[pos + 22] = 0x41; data[pos + 23] = 0x83; data[pos + 24] = 0xFC; data[pos + 25] = 0x01;

        var patch = Signatures.CorePatchDefs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(-1, result);
    }

    [Fact]
    public void Core1_MatchesAlreadyPatched_B8()
    {
        byte[] data = new byte[64];
        int pos = 10;
        data[pos]     = 0x48; data[pos + 1] = 0x8B; data[pos + 2] = 0x4C; data[pos + 3] = 0x24; data[pos + 4] = 0x58;
        data[pos + 5] = 0x48; data[pos + 6] = 0x8D; data[pos + 7] = 0x55; data[pos + 8] = 0x40;
        // already patched: B8 + preserved displacement (wildcard snapshot keeps original disp)
        data[pos + 9] = 0xB8;
        BitConverter.TryWriteBytes(data.AsSpan(pos + 10, 4), -0x100);
        data[pos + 14] = 0x85; data[pos + 15] = 0xC0;
        data[pos + 16] = 0x0F; data[pos + 17] = 0x84;
        data[pos + 22] = 0x41; data[pos + 23] = 0x83; data[pos + 24] = 0xFC; data[pos + 25] = 0x01;

        var patch = Signatures.CorePatchDefs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(pos + 9, result);
    }

    [Fact]
    public void Core1_IgnoresB8_UnknownOpcode()
    {
        byte[] data = new byte[64];
        int pos = 10;
        data[pos]     = 0x48; data[pos + 1] = 0x8B; data[pos + 2] = 0x4C; data[pos + 3] = 0x24; data[pos + 4] = 0x58;
        data[pos + 5] = 0x48; data[pos + 6] = 0x8D; data[pos + 7] = 0x55; data[pos + 8] = 0x40;
        // neither E8 nor B8
        data[pos + 9] = 0x90;
        data[pos + 14] = 0x85; data[pos + 15] = 0xC0;
        data[pos + 16] = 0x0F; data[pos + 17] = 0x84;
        data[pos + 22] = 0x41; data[pos + 23] = 0x83; data[pos + 24] = 0xFC; data[pos + 25] = 0x01;

        var patch = Signatures.CorePatchDefs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(-1, result);
    }

    // ── CorePatchDefs[1] (Core2: hash check jz) ─────────────────────
    // New pattern (19 bytes, PatchOffset=14):
    // 49 8B D5 48 8D 4D ?? E8 ?? ?? ?? ?? 85 C0 [74|EB] ?? 33 FF E9

    [Fact]
    public void Core2_StrictMatch_85C0_74_33FF()
    {
        byte[] data = new byte[128];
        // place Core1 match first so relative scan has an anchor
        int c1pos = 10;
        data[c1pos]     = 0x48; data[c1pos + 1] = 0x8B; data[c1pos + 2] = 0x4C; data[c1pos + 3] = 0x24; data[c1pos + 4] = 0x58;
        data[c1pos + 5] = 0x48; data[c1pos + 6] = 0x8D; data[c1pos + 7] = 0x55; data[c1pos + 8] = 0x40;
        data[c1pos + 9] = 0xE8;
        BitConverter.TryWriteBytes(data.AsSpan(c1pos + 10, 4), -0x10);
        data[c1pos + 14] = 0x85; data[c1pos + 15] = 0xC0;
        data[c1pos + 16] = 0x0F; data[c1pos + 17] = 0x84;
        data[c1pos + 22] = 0x41; data[c1pos + 23] = 0x83; data[c1pos + 24] = 0xFC; data[c1pos + 25] = 0x01;

        // Core2 pattern at offset 60
        int c2pos = 60;
        data[c2pos]     = 0x49; data[c2pos + 1] = 0x8B; data[c2pos + 2] = 0xD5;
        data[c2pos + 3] = 0x48; data[c2pos + 4] = 0x8D; data[c2pos + 5] = 0x4D; data[c2pos + 6] = 0xE0;
        data[c2pos + 7] = 0xE8; // call
        data[c2pos + 12] = 0x85; data[c2pos + 13] = 0xC0;
        data[c2pos + 14] = 0x74; data[c2pos + 15] = 0x17;
        data[c2pos + 16] = 0x33; data[c2pos + 17] = 0xFF;
        data[c2pos + 18] = 0xE9;

        var patch = Signatures.CorePatchDefs[1];
        int[] resolvedOffsets = { c1pos + 9 }; // Core1 resolved at PatchOffset
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length, resolvedOffsets);
        Assert.Equal(c2pos + 14, result);
    }

    [Fact]
    public void Core2_FoundWhenCore1AlreadyPatched()
    {
        byte[] data = new byte[128];
        // Core1 in already-patched form: B8 + preserved negative displacement
        int c1pos = 10;
        data[c1pos]     = 0x48; data[c1pos + 1] = 0x8B; data[c1pos + 2] = 0x4C; data[c1pos + 3] = 0x24; data[c1pos + 4] = 0x58;
        data[c1pos + 5] = 0x48; data[c1pos + 6] = 0x8D; data[c1pos + 7] = 0x55; data[c1pos + 8] = 0x40;
        data[c1pos + 9] = 0xB8;
        BitConverter.TryWriteBytes(data.AsSpan(c1pos + 10, 4), -0x100);
        data[c1pos + 14] = 0x85; data[c1pos + 15] = 0xC0;
        data[c1pos + 16] = 0x0F; data[c1pos + 17] = 0x84;
        data[c1pos + 22] = 0x41; data[c1pos + 23] = 0x83; data[c1pos + 24] = 0xFC; data[c1pos + 25] = 0x01;

        // Core2 pattern
        int c2pos = 60;
        data[c2pos]     = 0x49; data[c2pos + 1] = 0x8B; data[c2pos + 2] = 0xD5;
        data[c2pos + 3] = 0x48; data[c2pos + 4] = 0x8D; data[c2pos + 5] = 0x4D; data[c2pos + 6] = 0xE0;
        data[c2pos + 7] = 0xE8;
        data[c2pos + 12] = 0x85; data[c2pos + 13] = 0xC0;
        data[c2pos + 14] = 0x74; data[c2pos + 15] = 0x17;
        data[c2pos + 16] = 0x33; data[c2pos + 17] = 0xFF;
        data[c2pos + 18] = 0xE9;

        // resolve full group
        var result = Signatures.ResolvePatternGroup(data, Signatures.CorePatchDefs,
            0, data.Length, 0, 0, null);
        Assert.NotNull(result);
        Assert.Equal(2, result.Length);
        Assert.Equal(c1pos + 9, result[0].Offset);
        Assert.Equal(c2pos + 14, result[1].Offset);
    }

    [Fact]
    public void Core2_MatchesAlreadyPatched_EB()
    {
        byte[] data = new byte[128];
        // Core1 already patched
        int c1pos = 10;
        data[c1pos]     = 0x48; data[c1pos + 1] = 0x8B; data[c1pos + 2] = 0x4C; data[c1pos + 3] = 0x24; data[c1pos + 4] = 0x58;
        data[c1pos + 5] = 0x48; data[c1pos + 6] = 0x8D; data[c1pos + 7] = 0x55; data[c1pos + 8] = 0x40;
        data[c1pos + 9] = 0xB8;
        BitConverter.TryWriteBytes(data.AsSpan(c1pos + 10, 4), -0x100);
        data[c1pos + 14] = 0x85; data[c1pos + 15] = 0xC0;
        data[c1pos + 16] = 0x0F; data[c1pos + 17] = 0x84;
        data[c1pos + 22] = 0x41; data[c1pos + 23] = 0x83; data[c1pos + 24] = 0xFC; data[c1pos + 25] = 0x01;

        // Core2 already patched: EB instead of 74
        int c2pos = 60;
        data[c2pos]     = 0x49; data[c2pos + 1] = 0x8B; data[c2pos + 2] = 0xD5;
        data[c2pos + 3] = 0x48; data[c2pos + 4] = 0x8D; data[c2pos + 5] = 0x4D; data[c2pos + 6] = 0xE0;
        data[c2pos + 7] = 0xE8;
        data[c2pos + 12] = 0x85; data[c2pos + 13] = 0xC0;
        data[c2pos + 14] = 0xEB; // already patched
        data[c2pos + 15] = 0x17;
        data[c2pos + 16] = 0x33; data[c2pos + 17] = 0xFF;
        data[c2pos + 18] = 0xE9;

        var result = Signatures.ResolvePatternGroup(data, Signatures.CorePatchDefs,
            0, data.Length, 0, 0, null);
        Assert.NotNull(result);
        Assert.Equal(2, result.Length);
        Assert.Equal(c1pos + 9, result[0].Offset);
        Assert.Equal(c2pos + 14, result[1].Offset);
    }

    // ── PayloadP123Defs[2] (P3: Spacewar anchor) ────────────────────

    [Fact]
    public void P3_FindsAfterSpacewarAnchor()
    {
        byte[] data = new byte[64];
        int anchor = 10;
        byte[] spacewar = { 0xC7, 0x40, 0x09, 0xE0, 0x01, 0x00, 0x00 };
        spacewar.CopyTo(data, anchor);

        int targetPos = anchor + spacewar.Length + 5;
        data[targetPos] = 0x89;
        data[targetPos + 1] = 0x3D;

        var patch = Signatures.PayloadP123Defs[2];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(targetPos, result);
    }

    [Fact]
    public void P3_NoSpacewarAnchor_ReturnsNegative()
    {
        byte[] data = new byte[64];
        var patch = Signatures.PayloadP123Defs[2];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(-1, result);
    }

    // ── PayloadSetupDefs[1] (P5: GetCookie retry skip) ─────────────

    [Fact]
    public void P5_MatchesCallTestJnzWithBackwardJmp()
    {
        // Build: 66 48 0F 7E C7 66 48 0F 7E CE 48 8D 4D ?? E8 ?? ?? ?? ?? 48 85 F6 75 skipDist ... E9 (backward)
        byte[] data = new byte[80];
        int pos = 5;
        // movq rdi, xmm0
        data[pos] = 0x66; data[pos + 1] = 0x48; data[pos + 2] = 0x0F;
        data[pos + 3] = 0x7E; data[pos + 4] = 0xC7;
        // movq rsi, xmm1
        data[pos + 5] = 0x66; data[pos + 6] = 0x48; data[pos + 7] = 0x0F;
        data[pos + 8] = 0x7E; data[pos + 9] = 0xCE;
        // lea rcx, [rbp+disp8]
        data[pos + 10] = 0x48; data[pos + 11] = 0x8D; data[pos + 12] = 0x4D;
        data[pos + 13] = 0xC7;
        // call rel32
        data[pos + 14] = 0xE8; data[pos + 15] = 0x12; data[pos + 16] = 0x34;
        data[pos + 17] = 0x56; data[pos + 18] = 0x78;
        // test rsi, rsi
        data[pos + 19] = 0x48; data[pos + 20] = 0x85; data[pos + 21] = 0xF6;
        // jnz short +0x0A
        data[pos + 22] = 0x75;
        data[pos + 23] = 0x0A;
        // backward E9 jmp within skip range
        data[pos + 26] = 0xE9;
        BitConverter.TryWriteBytes(data.AsSpan(pos + 27, 4), -0x50);

        var patch = Signatures.PayloadSetupDefs[1];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(pos + 22, result);
    }

    [Fact]
    public void P5_RejectsWithoutBackwardJmp()
    {
        byte[] data = new byte[80];
        int pos = 5;
        data[pos] = 0x66; data[pos + 1] = 0x48; data[pos + 2] = 0x0F;
        data[pos + 3] = 0x7E; data[pos + 4] = 0xC7;
        data[pos + 5] = 0x66; data[pos + 6] = 0x48; data[pos + 7] = 0x0F;
        data[pos + 8] = 0x7E; data[pos + 9] = 0xCE;
        data[pos + 10] = 0x48; data[pos + 11] = 0x8D; data[pos + 12] = 0x4D;
        data[pos + 13] = 0xC7;
        data[pos + 14] = 0xE8; data[pos + 15] = 0x12; data[pos + 16] = 0x34;
        data[pos + 17] = 0x56; data[pos + 18] = 0x78;
        data[pos + 19] = 0x48; data[pos + 20] = 0x85; data[pos + 21] = 0xF6;
        data[pos + 22] = 0x75;
        data[pos + 23] = 0x0A;
        // no backward jmp in skip range

        var patch = Signatures.PayloadSetupDefs[1];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(-1, result);
    }

    // ── P1 already-patched (90 E9 instead of 0F 84) ───────────────

    [Fact]
    public void P1_MatchesAlreadyPatched_90E9()
    {
        byte[] data = new byte[80];
        int pos = 5;
        // 44 8B 3D xx xx xx xx (mov r15d, [rip+disp32])
        data[pos] = 0x44; data[pos + 1] = 0x8B; data[pos + 2] = 0x3D;
        // disp32 wildcarded
        // 85 C0 (test eax, eax)
        data[pos + 7] = 0x85; data[pos + 8] = 0xC0;
        // 0F 85 xx xx 00 00 (jnz near)
        data[pos + 9] = 0x0F; data[pos + 10] = 0x85;
        data[pos + 13] = 0x00; data[pos + 14] = 0x00;
        // 45 85 FF (test r15d, r15d)
        data[pos + 15] = 0x45; data[pos + 16] = 0x85; data[pos + 17] = 0xFF;
        // already-patched bytes at offset 18
        data[pos + 18] = 0x90; data[pos + 19] = 0xE9;
        data[pos + 22] = 0x00; data[pos + 23] = 0x00;

        var patch = Signatures.PayloadP123Defs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(pos + 18, result);
    }

    [Fact]
    public void P1_RejectsWrongBytesAt18()
    {
        byte[] data = new byte[80];
        int pos = 5;
        data[pos] = 0x44; data[pos + 1] = 0x8B; data[pos + 2] = 0x3D;
        data[pos + 7] = 0x85; data[pos + 8] = 0xC0;
        data[pos + 9] = 0x0F; data[pos + 10] = 0x85;
        data[pos + 13] = 0x00; data[pos + 14] = 0x00;
        data[pos + 15] = 0x45; data[pos + 16] = 0x85; data[pos + 17] = 0xFF;
        // wrong bytes -- neither 0F 84 nor 90 E9
        data[pos + 18] = 0xCC; data[pos + 19] = 0xCC;
        data[pos + 22] = 0x00; data[pos + 23] = 0x00;

        var patch = Signatures.PayloadP123Defs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(-1, result);
    }

    // ── P2 already-patched (31 C9 instead of 8B 0D) ────────────────

    [Fact]
    public void P2_MatchesAlreadyPatched_31C9()
    {
        // P2 is relative to P1, so we need a resolved P1 offset
        byte[] data = new byte[120];
        int p1offset = 5;
        int pos = p1offset + 10; // within RelativeEnd=0x500 of P1
        // [0-2] 48 8B F0 (mov rsi, rax)
        data[pos] = 0x48; data[pos + 1] = 0x8B; data[pos + 2] = 0xF0;
        // [3-5] 4C 8B C7 (mov r8, rdi)
        data[pos + 3] = 0x4C; data[pos + 4] = 0x8B; data[pos + 5] = 0xC7;
        // [6-10] 4C 8B 7C 24 xx (mov r15, [rsp+disp8])
        data[pos + 6] = 0x4C; data[pos + 7] = 0x8B; data[pos + 8] = 0x7C;
        data[pos + 9] = 0x24; data[pos + 10] = 0x40;
        // [11-13] 49 8B D7 (mov rdx, r15)
        data[pos + 11] = 0x49; data[pos + 12] = 0x8B; data[pos + 13] = 0xD7;
        // [14-16] 48 8B C8 (mov rcx, rax)
        data[pos + 14] = 0x48; data[pos + 15] = 0x8B; data[pos + 16] = 0xC8;
        // [17-21] E8 rel32 (call memcpy_wrapper)
        data[pos + 17] = 0xE8; data[pos + 18] = 0xAA; data[pos + 19] = 0xBB;
        data[pos + 20] = 0xCC; data[pos + 21] = 0xDD;
        // [22-27] 31 C9 90 90 90 90 (patched: xor ecx,ecx + 4 NOPs)
        data[pos + 22] = 0x31; data[pos + 23] = 0xC9;
        data[pos + 24] = 0x90; data[pos + 25] = 0x90;
        data[pos + 26] = 0x90; data[pos + 27] = 0x90;
        // [28-31] 48 8D 14 3E (lea rdx, [rsi+rdi])
        data[pos + 28] = 0x48; data[pos + 29] = 0x8D;
        data[pos + 30] = 0x14; data[pos + 31] = 0x3E;
        // [32-38] 48 81 F9 80 00 00 00 (cmp rcx, 80h)
        data[pos + 32] = 0x48; data[pos + 33] = 0x81;
        data[pos + 34] = 0xF9; data[pos + 35] = 0x80;
        data[pos + 36] = 0x00; data[pos + 37] = 0x00; data[pos + 38] = 0x00;

        var patch = Signatures.PayloadP123Defs[1];
        int[] resolvedOffsets = { p1offset };
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length, resolvedOffsets);
        Assert.Equal(pos + 22, result);
    }

    [Fact]
    public void P2_RejectsWrongOpcodePrefix()
    {
        byte[] data = new byte[120];
        int p1offset = 5;
        int pos = p1offset + 10;
        // same prefix
        data[pos] = 0x48; data[pos + 1] = 0x8B; data[pos + 2] = 0xF0;
        data[pos + 3] = 0x4C; data[pos + 4] = 0x8B; data[pos + 5] = 0xC7;
        data[pos + 6] = 0x4C; data[pos + 7] = 0x8B; data[pos + 8] = 0x7C;
        data[pos + 9] = 0x24; data[pos + 10] = 0x40;
        data[pos + 11] = 0x49; data[pos + 12] = 0x8B; data[pos + 13] = 0xD7;
        data[pos + 14] = 0x48; data[pos + 15] = 0x8B; data[pos + 16] = 0xC8;
        data[pos + 17] = 0xE8; data[pos + 18] = 0xAA; data[pos + 19] = 0xBB;
        data[pos + 20] = 0xCC; data[pos + 21] = 0xDD;
        // wrong opcode pair at patch site
        data[pos + 22] = 0xFF; data[pos + 23] = 0x15;
        // trailing context
        data[pos + 28] = 0x48; data[pos + 29] = 0x8D;
        data[pos + 30] = 0x14; data[pos + 31] = 0x3E;
        data[pos + 32] = 0x48; data[pos + 33] = 0x81;
        data[pos + 34] = 0xF9; data[pos + 35] = 0x80;
        data[pos + 36] = 0x00; data[pos + 37] = 0x00; data[pos + 38] = 0x00;

        var patch = Signatures.PayloadP123Defs[1];
        int[] resolvedOffsets = { p1offset };
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length, resolvedOffsets);
        Assert.Equal(-1, result);
    }

    // ── P3 already-patched (6x NOP instead of 89 3D) ───────────────

    [Fact]
    public void P3_MatchesAlreadyPatched_NOPs()
    {
        byte[] data = new byte[64];
        int anchor = 10;
        byte[] spacewar = { 0xC7, 0x40, 0x09, 0xE0, 0x01, 0x00, 0x00 };
        spacewar.CopyTo(data, anchor);

        int targetPos = anchor + spacewar.Length + 5;
        // already patched: 6x NOP
        for (int i = 0; i < 6; i++) data[targetPos + i] = 0x90;

        var patch = Signatures.PayloadP123Defs[2];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(targetPos, result);
    }

    // ── P4 already-patched (0x01 instead of 0x00) ──────────────────

    [Fact]
    public void P4_MatchesAlreadyPatched_01()
    {
        byte[] data = new byte[100];
        int pos = 5;
        // [0-2] 4D 85 C0 (test r8, r8)
        data[pos] = 0x4D; data[pos + 1] = 0x85; data[pos + 2] = 0xC0;
        // [3-8] 0F 84 xx xx xx xx (jz near)
        data[pos + 3] = 0x0F; data[pos + 4] = 0x84;
        // [9-13] E8 xx xx xx xx (call strcmp_wrapper)
        data[pos + 9] = 0xE8;
        // [14-15] 85 C0 (test eax, eax)
        data[pos + 14] = 0x85; data[pos + 15] = 0xC0;
        // [16-21] 0F 85 xx xx xx xx (jnz near)
        data[pos + 16] = 0x0F; data[pos + 17] = 0x85;
        // [22-28] C6 05 xx xx xx xx 01 (mov [flag], 1)
        data[pos + 22] = 0xC6; data[pos + 23] = 0x05; data[pos + 28] = 0x01;
        // [29-33] E9 00 00 00 00 (jmp $+5)
        data[pos + 29] = 0xE9; data[pos + 30] = 0x00; data[pos + 31] = 0x00;
        data[pos + 32] = 0x00; data[pos + 33] = 0x00;
        // [34-38] E9 xx xx xx xx (jmp merge)
        data[pos + 34] = 0xE9;
        // [39-45] C6 05 xx xx xx xx 01 (PATCH SITE, already patched)
        data[pos + 39] = 0xC6; data[pos + 40] = 0x05;
        data[pos + 45] = 0x01; // patched value

        var patch = Signatures.PayloadSetupDefs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(pos + 39, result);
    }

    [Fact]
    public void P4_MatchesUnpatched_00()
    {
        byte[] data = new byte[100];
        int pos = 5;
        data[pos] = 0x4D; data[pos + 1] = 0x85; data[pos + 2] = 0xC0;
        data[pos + 3] = 0x0F; data[pos + 4] = 0x84;
        data[pos + 9] = 0xE8;
        data[pos + 14] = 0x85; data[pos + 15] = 0xC0;
        data[pos + 16] = 0x0F; data[pos + 17] = 0x85;
        data[pos + 22] = 0xC6; data[pos + 23] = 0x05; data[pos + 28] = 0x01;
        data[pos + 29] = 0xE9; data[pos + 30] = 0x00; data[pos + 31] = 0x00;
        data[pos + 32] = 0x00; data[pos + 33] = 0x00;
        data[pos + 34] = 0xE9;
        data[pos + 39] = 0xC6; data[pos + 40] = 0x05;
        data[pos + 45] = 0x00; // original value

        var patch = Signatures.PayloadSetupDefs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(pos + 39, result);
    }

    [Fact]
    public void P4_RejectsWrongFlagValue()
    {
        byte[] data = new byte[100];
        int pos = 5;
        data[pos] = 0x4D; data[pos + 1] = 0x85; data[pos + 2] = 0xC0;
        data[pos + 3] = 0x0F; data[pos + 4] = 0x84;
        data[pos + 9] = 0xE8;
        data[pos + 14] = 0x85; data[pos + 15] = 0xC0;
        data[pos + 16] = 0x0F; data[pos + 17] = 0x85;
        data[pos + 22] = 0xC6; data[pos + 23] = 0x05; data[pos + 28] = 0x01;
        data[pos + 29] = 0xE9; data[pos + 30] = 0x00; data[pos + 31] = 0x00;
        data[pos + 32] = 0x00; data[pos + 33] = 0x00;
        data[pos + 34] = 0xE9;
        data[pos + 39] = 0xC6; data[pos + 40] = 0x05;
        data[pos + 45] = 0x02; // invalid -- neither 0x00 nor 0x01

        var patch = Signatures.PayloadSetupDefs[0];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(-1, result);
    }

    // ── P5 already-patched (EB instead of 75) ──────────────────────

    [Fact]
    public void P5_MatchesAlreadyPatched_EB()
    {
        byte[] data = new byte[80];
        int pos = 5;
        // movq rdi, xmm0
        data[pos] = 0x66; data[pos + 1] = 0x48; data[pos + 2] = 0x0F;
        data[pos + 3] = 0x7E; data[pos + 4] = 0xC7;
        // movq rsi, xmm1
        data[pos + 5] = 0x66; data[pos + 6] = 0x48; data[pos + 7] = 0x0F;
        data[pos + 8] = 0x7E; data[pos + 9] = 0xCE;
        // lea rcx, [rbp+disp8]
        data[pos + 10] = 0x48; data[pos + 11] = 0x8D; data[pos + 12] = 0x4D;
        data[pos + 13] = 0xC7;
        // call rel32
        data[pos + 14] = 0xE8; data[pos + 15] = 0x12; data[pos + 16] = 0x34;
        data[pos + 17] = 0x56; data[pos + 18] = 0x78;
        // test rsi, rsi
        data[pos + 19] = 0x48; data[pos + 20] = 0x85; data[pos + 21] = 0xF6;
        // already-patched: EB instead of 75
        data[pos + 22] = 0xEB;
        data[pos + 23] = 0x0A;
        // backward E9 jmp in skip range
        data[pos + 26] = 0xE9;
        BitConverter.TryWriteBytes(data.AsSpan(pos + 27, 4), -0x50);

        var patch = Signatures.PayloadSetupDefs[1];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(pos + 22, result);
    }

    [Fact]
    public void P5_RejectsNegativeSkipDist()
    {
        byte[] data = new byte[80];
        int pos = 5;
        data[pos] = 0x66; data[pos + 1] = 0x48; data[pos + 2] = 0x0F;
        data[pos + 3] = 0x7E; data[pos + 4] = 0xC7;
        data[pos + 5] = 0x66; data[pos + 6] = 0x48; data[pos + 7] = 0x0F;
        data[pos + 8] = 0x7E; data[pos + 9] = 0xCE;
        data[pos + 10] = 0x48; data[pos + 11] = 0x8D; data[pos + 12] = 0x4D;
        data[pos + 13] = 0xC7;
        data[pos + 14] = 0xE8; data[pos + 15] = 0x12; data[pos + 16] = 0x34;
        data[pos + 17] = 0x56; data[pos + 18] = 0x78;
        data[pos + 19] = 0x48; data[pos + 20] = 0x85; data[pos + 21] = 0xF6;
        data[pos + 22] = 0x75;
        data[pos + 23] = 0xF0; // -16 as sbyte

        var patch = Signatures.PayloadSetupDefs[1];
        int result = Signatures.ResolvePatternPatch(data, patch, 0, data.Length);
        Assert.Equal(-1, result);
    }

    // ── FindSendPktFunction: already-patched E9 prologue ────────────

    [Fact]
    public void FindSendPkt_AcceptsAlreadyPatchedE9()
    {
        byte[] data = new byte[0x100];
        // anchor: B8 00 11 00 00 E8 at offset 0x30
        int anchor = 0x30;
        data[anchor] = 0xB8; data[anchor + 1] = 0x00; data[anchor + 2] = 0x11;
        data[anchor + 3] = 0x00; data[anchor + 4] = 0x00; data[anchor + 5] = 0xE8;

        // prologue at anchor - 0x18 = 0x18, overwritten with E9 jmp
        int funcStart = anchor - 0x18;
        data[funcStart] = 0xE9;
        data[funcStart + 1] = 0x01; data[funcStart + 2] = 0x02;
        data[funcStart + 3] = 0x03; data[funcStart + 4] = 0x04;

        int result = Signatures.FindSendPktFunction(data, 0, data.Length);
        Assert.Equal(funcStart, result);
    }

    // ── Edge cases ───────────────────────────────────────────────────

    [Fact]
    public void ScanForBytes_DataSmallerThanNeedle()
    {
        byte[] data = { 0xAA };
        byte[] needle = { 0xAA, 0xBB };
        Assert.Equal(-1, Signatures.ScanForBytes(data, 0, data.Length, needle));
    }

    [Fact]
    public void ScanForPattern_EmptyData()
    {
        byte[] data = Array.Empty<byte>();
        byte[] pattern = { 0xE8 };
        byte[] mask = { 0xFF };
        Assert.Equal(-1, Signatures.ScanForPattern(data, 0, 0, pattern, mask));
    }
}
