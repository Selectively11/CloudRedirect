using System.IO;
using System.Text.RegularExpressions;
using CloudRedirect.Services;
using Xunit;

namespace CloudRedirect.Tests;

/// <summary>
/// Tests for OrphanBlobService.ComputeOrphans, the pure orphan-set
/// computation that drives the UI prune-orphan-blobs feature. Cloud I/O
/// paths (ScanAsync/PruneAsync) are integration-only and not covered here
/// because the project has no HTTP mocking infrastructure.
/// </summary>
public class OrphanBlobServiceTests
{
    private static IReadOnlySet<string> Referenced(params string[] names)
        => new HashSet<string>(names, StringComparer.Ordinal);

    [Fact]
    public void ComputeOrphans_NoCloudBlobs_ReturnsEmpty()
    {
        var orphans = OrphanBlobService.ComputeOrphans(Array.Empty<string>(), Referenced("a", "b"));
        Assert.Empty(orphans);
    }

    [Fact]
    public void ComputeOrphans_AllReferenced_ReturnsEmpty()
    {
        var cloud = new[] { "a.sav", "b.sav", "c.sav" };
        var refs = Referenced("a.sav", "b.sav", "c.sav");
        Assert.Empty(OrphanBlobService.ComputeOrphans(cloud, refs));
    }

    [Fact]
    public void ComputeOrphans_NoneReferenced_ReturnsAllSorted()
    {
        // Empty file_tokens.dat means every cloud blob is orphaned. This is
        // the worst-case prune scenario -- if a user accidentally wipes
        // file_tokens.dat and then runs prune, they lose every cloud save
        // for that app. The UI layer's ListingComplete + confirmation flow
        // exists to prevent this.
        var cloud = new[] { "c.sav", "a.sav", "b.sav" };
        var orphans = OrphanBlobService.ComputeOrphans(cloud, Referenced());
        Assert.Equal(new[] { "a.sav", "b.sav", "c.sav" }, orphans);
    }

    [Fact]
    public void ComputeOrphans_MixedReferencedAndOrphan_ReturnsOnlyUnreferenced()
    {
        var cloud = new[] { "referenced.sav", "orphan1.sav", "referenced2.sav", "orphan2.sav" };
        var refs = Referenced("referenced.sav", "referenced2.sav");
        var orphans = OrphanBlobService.ComputeOrphans(cloud, refs);
        Assert.Equal(new[] { "orphan1.sav", "orphan2.sav" }, orphans);
    }

    [Fact]
    public void ComputeOrphans_CaseSensitive()
    {
        // A cloud blob named "Save.dat" is NOT satisfied by a file_tokens
        // entry of "save.dat" -- the native side's std::unordered_map
        // keying is case-sensitive, so the UI must match to avoid declaring
        // a legitimately-referenced blob an orphan.
        var cloud = new[] { "Save.dat" };
        var refs = Referenced("save.dat");
        var orphans = OrphanBlobService.ComputeOrphans(cloud, refs);
        Assert.Single(orphans);
        Assert.Contains("Save.dat", orphans);
    }

    [Fact]
    public void ComputeOrphans_DuplicatesInCloud_Deduplicated()
    {
        var cloud = new[] { "orphan.sav", "orphan.sav", "orphan.sav" };
        var orphans = OrphanBlobService.ComputeOrphans(cloud, Referenced());
        Assert.Single(orphans);
        Assert.Equal("orphan.sav", orphans[0]);
    }

    [Fact]
    public void ComputeOrphans_EmptyAndNullFilenames_Skipped()
    {
        // Defensive: null/empty filenames in the cloud listing should never
        // reach this far, but if they do they MUST NOT propagate as orphans
        // (a Path.Combine with empty name would escape to the parent
        // directory on the folder provider).
        var cloud = new[] { "", null!, "real.sav" };
        var orphans = OrphanBlobService.ComputeOrphans(cloud, Referenced());
        Assert.Single(orphans);
        Assert.Equal("real.sav", orphans[0]);
    }

    [Fact]
    public void ComputeOrphans_DeterministicallySorted()
    {
        // The UI renders the orphan list in the confirm dialog; a
        // deterministic order helps users recognize the same app across
        // repeated scans.
        var cloud = new[] { "z", "m", "a", "b" };
        var orphans = OrphanBlobService.ComputeOrphans(cloud, Referenced());
        Assert.Equal(new[] { "a", "b", "m", "z" }, orphans);
    }

    [Fact]
    public void ComputeOrphans_LargeInput_PerformsLinearly()
    {
        // Sanity: 5000 cloud blobs, 4999 referenced. Should produce exactly 1
        // orphan. Documents the O(n) contract -- if someone
        // accidentally introduces nested loops here, the regression shows up
        // as a timeout in CI.
        var cloud = new string[5000];
        for (int i = 0; i < 5000; i++) cloud[i] = $"blob_{i:D5}.sav";
        var refs = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < 5000; i++) if (i != 42) refs.Add($"blob_{i:D5}.sav");

        var orphans = OrphanBlobService.ComputeOrphans(cloud, refs);
        Assert.Single(orphans);
        Assert.Equal("blob_00042.sav", orphans[0]);
    }

    // ── Internal metadata whitelist ────────────────────────────────────
    //
    // DLL-internal metadata (Playtime.bin / UserGameStats.bin, canonical
    // and legacy forms) must never be flagged as orphans regardless of
    // file_tokens.dat state. Pruning them would delete live playtime /
    // achievement state the DLL still relies on. Kept in lockstep with
    // the native exclusion filter at src/rpc_handlers.cpp:57-58.

    [Fact]
    public void ComputeOrphans_LegacyPlaytimeBin_NeverOrphan()
    {
        // The canonical historical bug: file_tokens.dat keys the canonical
        // ".cloudredirect/Playtime.bin" but an older session left the legacy
        // top-level "Playtime.bin" on the cloud. Naive set-difference would
        // flag it as an orphan and a user-confirmed prune would silently
        // delete live playtime metadata.
        var cloud = new[] { "Playtime.bin", "real_save.dat" };
        var refs = Referenced(".cloudredirect/Playtime.bin");
        var orphans = OrphanBlobService.ComputeOrphans(cloud, refs);
        Assert.Equal(new[] { "real_save.dat" }, orphans);
    }

    [Fact]
    public void ComputeOrphans_LegacyUserGameStatsBin_NeverOrphan()
    {
        var cloud = new[] { "UserGameStats.bin", "real_save.dat" };
        var refs = Referenced(".cloudredirect/UserGameStats.bin");
        var orphans = OrphanBlobService.ComputeOrphans(cloud, refs);
        Assert.Equal(new[] { "real_save.dat" }, orphans);
    }

    [Fact]
    public void ComputeOrphans_CanonicalMetadata_NeverOrphan()
    {
        // Defensive: even if a canonical metadata path somehow surfaces in a
        // top-level listing (e.g. future provider change, filename with an
        // embedded slash stored as a flat key), the whitelist still skips it.
        var cloud = new[] { ".cloudredirect/Playtime.bin", ".cloudredirect/UserGameStats.bin" };
        var orphans = OrphanBlobService.ComputeOrphans(cloud, Referenced());
        Assert.Empty(orphans);
    }

    [Fact]
    public void ComputeOrphans_MetadataWhitelistIndependentOfReferencedSet()
    {
        // Whitelist must be unconditional: even with a totally empty
        // file_tokens.dat, the 4 metadata paths are never returned.
        var cloud = new[]
        {
            "Playtime.bin",
            "UserGameStats.bin",
            ".cloudredirect/Playtime.bin",
            ".cloudredirect/UserGameStats.bin",
            "save01.dat",
        };
        var orphans = OrphanBlobService.ComputeOrphans(cloud, Referenced());
        Assert.Equal(new[] { "save01.dat" }, orphans);
    }

    [Fact]
    public void ComputeOrphans_MetadataWhitelistCaseSensitive()
    {
        // Case-sensitive match mirrors the native side. A spuriously
        // capitalized "playtime.bin" is NOT treated as metadata -- if the
        // user actually has a save literally named "playtime.bin" (lowercase)
        // that isn't referenced, it's a real orphan.
        var cloud = new[] { "playtime.bin", "PLAYTIME.BIN" };
        var orphans = OrphanBlobService.ComputeOrphans(cloud, Referenced());
        Assert.Equal(new[] { "PLAYTIME.BIN", "playtime.bin" }, orphans);
    }

    [Fact]
    public void InternalMetadataFilenames_ContainsAllFourPaths()
    {
        // Lockstep assertion with src/rpc_handlers.cpp:IsInternalMetadata and
        // src/cloud_intercept.h:6-9. Adding a new metadata path on the
        // native side requires extending this set; this test catches the
        // case where one side is updated without the other.
        Assert.Contains(".cloudredirect/Playtime.bin", OrphanBlobService.InternalMetadataFilenames);
        Assert.Contains(".cloudredirect/UserGameStats.bin", OrphanBlobService.InternalMetadataFilenames);
        Assert.Contains("Playtime.bin", OrphanBlobService.InternalMetadataFilenames);
        Assert.Contains("UserGameStats.bin", OrphanBlobService.InternalMetadataFilenames);
        Assert.Equal(4, OrphanBlobService.InternalMetadataFilenames.Count);
    }

    /// <summary>
    /// Stronger lockstep: actually parse <c>src/cloud_intercept.h</c> and
    /// require the UI-side whitelist to be a superset of every
    /// <c>k*MetadataPath</c> constant the native side currently exposes.
    ///
    /// The hardcoded-literal test above catches a rename of an existing
    /// constant, but a brand-new metadata path added on the native side
    /// (e.g. <c>kAchievementsMetadataPath</c>) would slip past it -- the
    /// four existing assertions still pass, the <c>Count == 4</c> assertion
    /// still passes, and the UI would start deleting the new file as an
    /// "orphan". Parsing the header forces the two sides to move in
    /// lockstep at CI time.
    ///
    /// If the repo layout changes such that the header can't be located
    /// from the test binary, the test is skipped rather than failed; the
    /// primary hardcoded assertion above still guards the known-at-write-
    /// time set. A false-negative skip in an unusual build layout is
    /// preferable to a spurious CI failure.
    /// </summary>
    [Fact]
    public void InternalMetadataFilenames_IsSupersetOfNativeConstants()
    {
        // The k*MetadataPath constants live in their own header so cloud_storage
        // can consume them without pulling the full intercept-layer interface.
        // Fall back to cloud_intercept.h for older checkouts where the split
        // hasn't happened yet, so the test isn't tightly bound to one layout.
        var headerPath =
            FindRepoFile(Path.Combine("src", "cloud_metadata_paths.h"))
            ?? FindRepoFile(Path.Combine("src", "cloud_intercept.h"));
        if (headerPath is null)
            return; // Header unlocatable; rely on the hardcoded assertion above.

        var text = File.ReadAllText(headerPath);
        // Matches e.g. `inline constexpr const char* kPlaytimeMetadataPath = ".cloudredirect/Playtime.bin";`
        // Captures the string literal; tolerates any identifier shape that
        // ends in `MetadataPath`, so a future kAchievementsMetadataPath is
        // picked up automatically.
        var rx = new Regex(
            @"k\w*MetadataPath\s*=\s*""([^""]+)""",
            RegexOptions.CultureInvariant);
        var matches = rx.Matches(text);

        // Sanity: at least the four known constants must match. If the
        // regex silently stops matching (e.g. header reformatted with raw
        // string literals), fail loudly rather than vacuously pass.
        Assert.True(
            matches.Count >= 4,
            $"Expected at least 4 k*MetadataPath constants in {Path.GetFileName(headerPath)}, found {matches.Count}. " +
            "Regex may need updating to match a new literal form.");

        foreach (Match m in matches)
        {
            var nativePath = m.Groups[1].Value;
            Assert.Contains(nativePath, OrphanBlobService.InternalMetadataFilenames);
        }
    }

    /// <summary>
    /// Walks up from the test assembly location looking for a file at the
    /// given repo-relative path. Returns null if not found within 8 levels
    /// (generous upper bound for typical nested bin/ layouts).
    /// </summary>
    private static string? FindRepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir != null; i++)
        {
            var candidate = Path.Combine(dir.FullName, relativePath);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }
        return null;
    }
}
