using System.IO;

namespace CloudRedirect.Services;

/// <summary>
/// Detect and prune orphan cloud blobs for one app. An orphan is a blob
/// under {accountId}/{appId}/blobs/ whose filename is not a key in the
/// local file_tokens.dat. ScanResult.ListingComplete=false means callers
/// must not prune — partial listings could mark live blobs as orphan.
/// </summary>
internal sealed class OrphanBlobService
{
    private readonly CloudProviderClient _client;
    private readonly string _steamPath;
    private readonly Action<string>? _log;

    public OrphanBlobService(CloudProviderClient client, string steamPath, Action<string>? log = null)
    {
        _client = client;
        _steamPath = steamPath;
        _log = log;
    }

    /// <summary>Scan result; Orphans is only meaningful when ListingComplete is true.</summary>
    public record ScanResult(
        IReadOnlyList<string> Orphans,
        int TotalCloudBlobs,
        int ReferencedCount,
        bool ListingComplete,
        string? Error);

    /// <summary>Prune result; already-absent blobs count as Deleted.</summary>
    public record PruneResult(
        int Deleted,
        int Failed,
        IReadOnlyList<string> FailedFilenames,
        string? Error);

    /// <summary>List cloud blobs and return ones absent from file_tokens.dat. Read-only.</summary>
    public async Task<ScanResult> ScanAsync(string accountId, string appId, CancellationToken cancel = default)
    {
        _log?.Invoke($"[OrphanBlob] Scanning cloud blobs for account {accountId} app {appId}...");

        CloudProviderClient.ListBlobsResult listing;
        try
        {
            listing = await _client.ListAppBlobsAsync(accountId, appId, cancel);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[OrphanBlob] Cloud listing threw: {ex.Message}");
            return new ScanResult(Array.Empty<string>(), 0, 0, false, ex.Message);
        }

        // If listing is incomplete or errored, refuse to compute orphans so
        // the caller cannot accidentally prune based on partial data.
        if (!listing.Complete || listing.Error != null)
        {
            _log?.Invoke($"[OrphanBlob] Cloud listing incomplete ({listing.BlobFilenames.Count} partial, error={listing.Error ?? "none"})");
            return new ScanResult(
                Array.Empty<string>(),
                listing.BlobFilenames.Count,
                0,
                listing.Complete,
                listing.Error);
        }

        HashSet<string> referenced;
        try
        {
            var ftPath = Path.Combine(_steamPath, "cloud_redirect", "storage", accountId, appId, "file_tokens.dat");
            referenced = FileTokensParser.ReadFromDisk(ftPath);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[OrphanBlob] Failed to read file_tokens.dat: {ex.Message}");
            // Safer to abort than assume zero referenced filenames -- a
            // false-empty referenced set would mark every cloud blob as an
            // orphan.
            return new ScanResult(Array.Empty<string>(), listing.BlobFilenames.Count, 0, false,
                $"Could not read file_tokens.dat: {ex.Message}");
        }

        var orphans = ComputeOrphans(listing.BlobFilenames, referenced);
        _log?.Invoke($"[OrphanBlob] Scan complete: cloud={listing.BlobFilenames.Count} referenced={referenced.Count} orphans={orphans.Count}");
        return new ScanResult(orphans, listing.BlobFilenames.Count, referenced.Count, true, null);
    }

    /// <summary>
    /// Delete given orphan filenames. Independently re-applies the
    /// InternalMetadataFilenames whitelist at this destructive boundary
    /// even though ComputeOrphans already filters at scan time.
    /// </summary>
    public async Task<PruneResult> PruneAsync(
        string accountId, string appId, IReadOnlyCollection<string> orphanFilenames,
        CancellationToken cancel = default)
    {
        if (orphanFilenames.Count == 0)
            return new PruneResult(0, 0, Array.Empty<string>(), null);

        // Whitelist-filter at the destructive boundary; drop empty names.
        var filtered = new List<string>(orphanFilenames.Count);
        int skipped = 0;
        foreach (var name in orphanFilenames)
        {
            if (string.IsNullOrEmpty(name)) { skipped++; continue; }
            if (InternalMetadataFilenames.Contains(name)) { skipped++; continue; }
            filtered.Add(name);
        }
        if (skipped > 0)
            _log?.Invoke($"[OrphanBlob] Refused to prune {skipped} invalid/metadata filename(s) at destructive boundary");
        if (filtered.Count == 0)
            return new PruneResult(0, 0, Array.Empty<string>(), null);

        _log?.Invoke($"[OrphanBlob] Pruning {filtered.Count} orphan blob(s) for account {accountId} app {appId}");

        CloudProviderClient.DeleteBlobsResult result;
        try
        {
            result = await _client.DeleteAppBlobsAsync(accountId, appId, filtered, cancel);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[OrphanBlob] Prune threw: {ex.Message}");
            return new PruneResult(0, filtered.Count, filtered, ex.Message);
        }

        _log?.Invoke($"[OrphanBlob] Prune complete: deleted={result.Deleted} failed={result.Failed}");
        return new PruneResult(result.Deleted, result.Failed, result.FailedFilenames, result.Error);
    }

    /// <summary>
    /// DLL-internal metadata filenames excluded from orphan scans. Mirrors
    /// the canonical and legacy forms in src/rpc_handlers.cpp:IsInternalMetadata.
    /// Adding a metadata path on the native side requires mirroring it here.
    /// </summary>
    internal static readonly IReadOnlySet<string> InternalMetadataFilenames =
        new HashSet<string>(StringComparer.Ordinal)
        {
            ".cloudredirect/Playtime.bin",
            ".cloudredirect/UserGameStats.bin",
            "Playtime.bin",
            "UserGameStats.bin",
        };

    /// <summary>
    /// Pure: cloud blobs minus referenced set, sorted, deduped, case-sensitive
    /// (matches the native unordered_map keying). Skips InternalMetadataFilenames.
    /// </summary>
    internal static List<string> ComputeOrphans(
        IEnumerable<string> cloudBlobFilenames,
        IReadOnlySet<string> referenced)
    {
        var orphans = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in cloudBlobFilenames)
        {
            if (string.IsNullOrEmpty(name)) continue;
            if (!seen.Add(name)) continue; // dedup
            if (InternalMetadataFilenames.Contains(name)) continue; // DLL-internal, never prune
            if (!referenced.Contains(name)) orphans.Add(name);
        }
        orphans.Sort(StringComparer.Ordinal);
        return orphans;
    }
}
