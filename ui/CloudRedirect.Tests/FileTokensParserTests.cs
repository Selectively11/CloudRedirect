using CloudRedirect.Services;
using Xunit;

namespace CloudRedirect.Tests;

/// <summary>
/// Tests for FileTokensParser. The parser must stay permissive in the same
/// ways as the native loader in <c>src/local_storage.cpp</c> LoadFileTokens,
/// so that a UI scan sees the same set of referenced filenames the DLL does.
/// </summary>
public class FileTokensParserTests
{
    [Fact]
    public void ParseContent_NullOrEmpty_ReturnsEmptySet()
    {
        Assert.Empty(FileTokensParser.ParseContent(null));
        Assert.Empty(FileTokensParser.ParseContent(""));
    }

    [Fact]
    public void ParseContent_SingleEntry_ReturnsFilename()
    {
        var set = FileTokensParser.ParseContent("save.dat\t%AppData%\n");
        Assert.Single(set);
        Assert.Contains("save.dat", set);
    }

    [Fact]
    public void ParseContent_MultipleEntries_AllFilenamesReturned()
    {
        var content =
            "save.dat\t%AppData%\n" +
            "config.ini\t%AppData%\n" +
            "slot1/quick.sav\t%MyDocs%\n";
        var set = FileTokensParser.ParseContent(content);
        Assert.Equal(3, set.Count);
        Assert.Contains("save.dat", set);
        Assert.Contains("config.ini", set);
        Assert.Contains("slot1/quick.sav", set);
    }

    [Fact]
    public void ParseContent_TrailingCR_Stripped()
    {
        // DLL writes LF-only but may encounter CRLF on some file systems.
        var set = FileTokensParser.ParseContent("save.dat\t%AppData%\r\n");
        Assert.Single(set);
        Assert.Contains("save.dat", set);
    }

    [Fact]
    public void ParseContent_MissingFinalNewline_StillParsed()
    {
        var set = FileTokensParser.ParseContent("save.dat\t%AppData%");
        Assert.Single(set);
        Assert.Contains("save.dat", set);
    }

    [Fact]
    public void ParseContent_EmptyLines_Skipped()
    {
        var content = "\nsave.dat\t%AppData%\n\nother.dat\t%AppData%\n\n";
        var set = FileTokensParser.ParseContent(content);
        Assert.Equal(2, set.Count);
    }

    [Fact]
    public void ParseContent_LineWithoutTab_Skipped()
    {
        var content = "garbagewithouttab\nsave.dat\t%AppData%\n";
        var set = FileTokensParser.ParseContent(content);
        Assert.Single(set);
        Assert.Contains("save.dat", set);
    }

    [Fact]
    public void ParseContent_EmptyFilename_Skipped()
    {
        // Native LoadFileTokens rejects empty cleanName before insert.
        var content = "\t%AppData%\nsave.dat\t%AppData%\n";
        var set = FileTokensParser.ParseContent(content);
        Assert.Single(set);
        Assert.Contains("save.dat", set);
        Assert.DoesNotContain("", set);
    }

    [Fact]
    public void ParseContent_FilenameWithMultipleTabs_KeepsFirstTabAsSeparator()
    {
        // Native code uses line.substr(0, tab) where tab is the FIRST tab;
        // any subsequent tabs are part of the token, not the filename.
        var content = "save.dat\ttoken\twith\ttabs\n";
        var set = FileTokensParser.ParseContent(content);
        Assert.Single(set);
        Assert.Contains("save.dat", set);
    }

    [Fact]
    public void ParseContent_CaseSensitive()
    {
        // Native storage uses std::unordered_map<std::string,...> which is
        // case-sensitive. UI must agree so orphan detection matches reality.
        var set = FileTokensParser.ParseContent("Save.dat\tA\nsave.dat\tB\n");
        Assert.Equal(2, set.Count);
        Assert.Contains("Save.dat", set);
        Assert.Contains("save.dat", set);
    }

    [Fact]
    public void ParseContent_DuplicateFilenames_CollapsedToSingleEntry()
    {
        // HashSet semantics: second occurrence is ignored. Native map overwrites,
        // but since we only care about the key set either answer is identical.
        var set = FileTokensParser.ParseContent("save.dat\tA\nsave.dat\tB\n");
        Assert.Single(set);
        Assert.Contains("save.dat", set);
    }

    // ── ReadFromDisk ──────────────────────────────────────────────────

    private static string GetTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "CloudRedirect_FileTokens_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void ReadFromDisk_FileMissing_ReturnsEmpty()
    {
        var dir = GetTempDir();
        try
        {
            var set = FileTokensParser.ReadFromDisk(Path.Combine(dir, "nonexistent.dat"));
            Assert.Empty(set);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ReadFromDisk_ValidFile_ParsedCorrectly()
    {
        var dir = GetTempDir();
        try
        {
            var path = Path.Combine(dir, "file_tokens.dat");
            File.WriteAllText(path, "a.sav\tA\nb.sav\tB\n");
            var set = FileTokensParser.ReadFromDisk(path);
            Assert.Equal(2, set.Count);
            Assert.Contains("a.sav", set);
            Assert.Contains("b.sav", set);
        }
        finally { Directory.Delete(dir, true); }
    }
}
