using CloudRedirect.Services.Patching;
using Xunit;

namespace CloudRedirect.Tests;

/// <summary>
/// Integration tests that read real PE files (steamclient64.dll, user32.dll)
/// to verify PeSection.Parse produces structurally valid results against
/// real-world binaries, not just synthetic test data.
/// Tests are skipped if the required files are not present.
/// </summary>
public class PeIntegrationTests
{
    private const string SteamClient64Path = @"C:\Games\Steam\steamclient64.dll";

    [Fact]
    public void Parse_SteamClient64_ReturnsMultipleSections()
    {
        if (!File.Exists(SteamClient64Path))
            return; // skip on machines without Steam

        var pe = File.ReadAllBytes(SteamClient64Path);
        var sections = PeSection.Parse(pe);

        // steamclient64.dll is a large DLL; it should have several sections
        Assert.True(sections.Length >= 3, $"Expected >= 3 sections, got {sections.Length}");

        // Verify all section names are non-empty
        foreach (var s in sections)
        {
            Assert.False(string.IsNullOrEmpty(s.Name), "Section name should not be empty");
        }
    }

    [Fact]
    public void Parse_SteamClient64_HasTextSection()
    {
        if (!File.Exists(SteamClient64Path))
            return;

        var pe = File.ReadAllBytes(SteamClient64Path);
        var sections = PeSection.Parse(pe);

        var text = PeSection.Find(sections, ".text");
        Assert.NotNull(text);
        Assert.True(text.Value.IsExecutable, ".text should be executable");
        Assert.True(text.Value.VirtualSize > 0, ".text VirtualSize should be > 0");
        Assert.True(text.Value.RawSize > 0, ".text RawSize should be > 0");
    }

    [Fact]
    public void Parse_SteamClient64_HasRdataSection()
    {
        if (!File.Exists(SteamClient64Path))
            return;

        var pe = File.ReadAllBytes(SteamClient64Path);
        var sections = PeSection.Parse(pe);

        var rdata = PeSection.Find(sections, ".rdata");
        Assert.NotNull(rdata);
        Assert.False(rdata.Value.IsExecutable, ".rdata should not be executable");
    }

    [Fact]
    public void Parse_SteamClient64_SectionsHaveValidLayout()
    {
        if (!File.Exists(SteamClient64Path))
            return;

        var pe = File.ReadAllBytes(SteamClient64Path);
        var sections = PeSection.Parse(pe);

        for (int i = 0; i < sections.Length; i++)
        {
            var s = sections[i];

            // Virtual address should be positive (sections don't start at 0)
            Assert.True(s.VirtualAddress > 0, $"{s.Name}: VA should be > 0");

            // Raw offset should be within the file
            Assert.True(s.RawOffset < (uint)pe.Length, $"{s.Name}: RawOffset should be within file");

            // Raw data should not extend beyond the file
            Assert.True(s.RawOffset + s.RawSize <= (uint)pe.Length,
                $"{s.Name}: raw data extends beyond file ({s.RawOffset} + {s.RawSize} > {pe.Length})");
        }

        // Sections should be ordered by VirtualAddress (standard PE convention)
        for (int i = 1; i < sections.Length; i++)
        {
            Assert.True(sections[i].VirtualAddress > sections[i - 1].VirtualAddress,
                $"Sections should be ordered by VA: {sections[i - 1].Name} (0x{sections[i - 1].VirtualAddress:X}) >= {sections[i].Name} (0x{sections[i].VirtualAddress:X})");
        }
    }

    [Fact]
    public void Parse_SteamClient64_RvaRoundtrip()
    {
        if (!File.Exists(SteamClient64Path))
            return;

        var pe = File.ReadAllBytes(SteamClient64Path);
        var sections = PeSection.Parse(pe);

        // Pick a few RVAs in the .text section and verify roundtrip
        var text = PeSection.Find(sections, ".text");
        Assert.NotNull(text);

        int[] testRvas = {
            (int)text.Value.VirtualAddress,
            (int)text.Value.VirtualAddress + 0x100,
            (int)(text.Value.VirtualAddress + text.Value.RawSize - 1),
        };

        foreach (int rva in testRvas)
        {
            int fileOff = PeSection.RvaToFileOffset(sections, rva);
            Assert.NotEqual(-1, fileOff);
            int roundtrip = PeSection.FileOffsetToRva(sections, fileOff);
            Assert.Equal(rva, roundtrip);
        }
    }

    // ── CloudRedirect hook finders (payload_new.dll) ──────────────────

    private const string PayloadPath = @"C:\Users\Justin\Projects\CloudFix\ExtractTool\payload_new.dll";

    private (byte[] data, PeSection[] sections, int tStart, int tEnd, int gStart, int gEnd)
        LoadPayloadSections()
    {
        var data = File.ReadAllBytes(PayloadPath);
        var sections = PeSection.Parse(data);

        var textSec = PeSection.Find(sections, ".text");
        Assert.NotNull(textSec);

        var knownNames = new HashSet<string> { ".text", ".rdata", ".data", ".pdata", ".fptable", ".rsrc", ".reloc" };
        PeSection? obfSec = null;
        foreach (var sec in sections)
        {
            if (!knownNames.Contains(sec.Name)) { obfSec = sec; break; }
        }
        Assert.NotNull(obfSec);

        int tStart = (int)textSec.Value.RawOffset;
        int tEnd = Math.Min(tStart + (int)textSec.Value.RawSize, data.Length);
        int gStart = (int)obfSec.Value.RawOffset;
        int gEnd = Math.Min(gStart + (int)obfSec.Value.RawSize, data.Length);

        return (data, sections, tStart, tEnd, gStart, gEnd);
    }

    [Fact]
    public void FindSendPktFunction_ReturnsExpectedOffset()
    {
        if (!File.Exists(PayloadPath)) return;
        var (data, _, tStart, tEnd, _, _) = LoadPayloadSections();

        int result = Signatures.FindSendPktFunction(data, tStart, tEnd);
        Assert.Equal(0xCF50, result);
    }

    [Fact]
    public void FindCodeCave_ReturnsValidCave()
    {
        if (!File.Exists(PayloadPath)) return;
        var (data, sections, _, _, _, _) = LoadPayloadSections();

        int result = Signatures.FindCodeCave(data, sections, 144);
        Assert.True(result > 0, $"Expected positive cave offset, got {result}");

        // verify the cave region is actually zeroed
        for (int i = 0; i < 144; i++)
            Assert.Equal(0, data[result + i]);
    }

    [Fact]
    public void FindRecvPktGlobalRva_ReturnsExpectedRva()
    {
        if (!File.Exists(PayloadPath)) return;
        var (data, sections, tStart, tEnd, gStart, gEnd) = LoadPayloadSections();

        int sendPkt = Signatures.FindSendPktFunction(data, tStart, tEnd);
        Assert.Equal(0xCF50, sendPkt);

        int sendPktRva = PeSection.FileOffsetToRva(sections, sendPkt);
        Assert.True(sendPktRva > 0);

        int rva = Signatures.FindRecvPktGlobalRva(data, sections, sendPktRva, gStart, gEnd);
        Assert.Equal(0x1CAB48, rva);
    }

    [Fact]
    public void PayloadP123Defs_ResolveAgainstPayload()
    {
        if (!File.Exists(PayloadPath)) return;
        var (data, _, tStart, tEnd, gStart, gEnd) = LoadPayloadSections();

        var result = Signatures.ResolvePatternGroup(data, Signatures.PayloadP123Defs,
            tStart, tEnd, gStart, gEnd);
        Assert.NotNull(result);
        Assert.Equal(3, result.Length);

        // P1 should be in the text section
        Assert.True(result[0].Offset >= tStart && result[0].Offset < tEnd,
            $"P1 offset 0x{result[0].Offset:X} should be in text section [{tStart:X}..{tEnd:X})");
        // P2 should be in the text section
        Assert.True(result[1].Offset >= tStart && result[1].Offset < tEnd,
            $"P2 offset 0x{result[1].Offset:X} should be in text section [{tStart:X}..{tEnd:X})");
        // P3 should be in the obfuscated section
        Assert.True(result[2].Offset >= gStart && result[2].Offset < gEnd,
            $"P3 offset 0x{result[2].Offset:X} should be in obfuscated section [{gStart:X}..{gEnd:X})");

        // Verify exact file offsets match known values
        Assert.Equal(0x00D4CF, result[0].Offset);
        Assert.Equal(0x00D7D9, result[1].Offset);
        Assert.Equal(0x1D555A, result[2].Offset);
    }

    // ── user32.dll sanity check (should always exist on Windows) ─────

    [Fact]
    public void PayloadSetupDefs_ResolveAgainstPayload()
    {
        if (!File.Exists(PayloadPath)) return;
        var (data, _, tStart, tEnd, gStart, gEnd) = LoadPayloadSections();

        var result = Signatures.ResolvePatternGroup(data, Signatures.PayloadSetupDefs,
            tStart, tEnd, gStart, gEnd);
        Assert.NotNull(result);
        Assert.Equal(2, result.Length);

        // P4 should be in the obfuscated section
        Assert.True(result[0].Offset >= gStart && result[0].Offset < gEnd,
            $"P4 offset 0x{result[0].Offset:X} should be in obfuscated section [{gStart:X}..{gEnd:X})");
        // P5 should be in the text section
        Assert.True(result[1].Offset >= tStart && result[1].Offset < tEnd,
            $"P5 offset 0x{result[1].Offset:X} should be in text section [{tStart:X}..{tEnd:X})");

        // Verify exact file offsets
        Assert.Equal(0x1E0A15, result[0].Offset);
        Assert.Equal(0x03BAE0, result[1].Offset);
    }

    [Fact]
    public void Parse_User32Dll_HasTextSection()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "user32.dll");
        if (!File.Exists(path))
            return;

        var pe = File.ReadAllBytes(path);
        var sections = PeSection.Parse(pe);

        Assert.True(sections.Length >= 2, $"user32.dll should have >= 2 sections, got {sections.Length}");

        var text = PeSection.Find(sections, ".text");
        Assert.NotNull(text);
        Assert.True(text.Value.IsExecutable);
    }
}
