using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace CloudRedirect.Services;

// Source generator for AOT-compatible JSON serialization
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(StoreCache))]
internal partial class StoreCacheJsonContext : JsonSerializerContext { }

/// <summary>
/// Cached entry for a single app from IStoreBrowseService/GetItems.
/// </summary>
internal class StoreAppInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("headerUrl")]
    public string? HeaderUrl { get; set; }

    [JsonPropertyName("fetchedUtc")]
    public DateTime FetchedUtc { get; set; }
}

/// <summary>
/// Disk cache format.
/// </summary>
internal class StoreCache
{
    [JsonPropertyName("entries")]
    public Dictionary<uint, StoreAppInfo> Entries { get; set; } = new();
}

/// <summary>Fetches app names/headers from Steam's IStoreBrowseService; caches in memory and on disk.</summary>
internal sealed class SteamStoreClient : IDisposable
{
    /// <summary>Process-wide singleton; HttpClient is long-lived by design.</summary>
    public static SteamStoreClient Shared { get; } = new();

    private static readonly TimeSpan DiskCacheTtl = TimeSpan.FromDays(7);
    private static readonly TimeSpan ImageCacheTtl = TimeSpan.FromDays(60);
    private const long MaxCachedImageBytes = 5 * 1024 * 1024; // 5 MB sanity cap
    private static readonly string CachePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "CloudRedirect", "store_cache.json");

    /// <summary>Cache dir for JPEG headers; filenames are SHA-256 prefixes of the CDN URL.</summary>
    private static readonly string ImageCacheDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "CloudRedirect", "store_images");

    /// <summary>Allow-list of Steam CDN hosts; URLs from disk cache are validated against these.</summary>
    private static readonly string[] AllowedCdnHosts = new[]
    {
        ".steamstatic.com",
        ".steampowered.com",
        ".steamcdn-a.akamaihd.net"
    };

    private readonly HttpClient _http;
    private readonly ConcurrentDictionary<uint, StoreAppInfo> _mem = new();
    private volatile bool _diskLoaded;
    private readonly SemaphoreSlim _diskLock = new(1, 1);

    /// <summary>Per-URL in-flight download dedup so concurrent callers share one download.</summary>
    private readonly ConcurrentDictionary<string, Task> _inFlightDownloads = new();

    public SteamStoreClient()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
    }

    /// <summary>True if the URL is HTTPS on an allow-listed Steam CDN host.</summary>
    public static bool IsValidSteamCdnUrl(string? url)
    {
        if (string.IsNullOrEmpty(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        if (uri.Scheme != "https") return false;

        var host = uri.Host;
        foreach (var allowed in AllowedCdnHosts)
        {
            if (host.EndsWith(allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>True if the URL is a file:// URI inside the image cache dir (traversal-checked).</summary>
    public static bool IsValidCachedImagePath(string? url)
    {
        if (string.IsNullOrEmpty(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        if (uri.Scheme != "file") return false;

        string normalizedLocal;
        string normalizedCache;
        try
        {
            normalizedLocal = Path.GetFullPath(uri.LocalPath);
            normalizedCache = Path.GetFullPath(ImageCacheDir);
        }
        catch
        {
            return false;
        }

        var prefix = normalizedCache.EndsWith(Path.DirectorySeparatorChar)
            ? normalizedCache
            : normalizedCache + Path.DirectorySeparatorChar;

        return normalizedLocal.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Accepts a Steam CDN URL or a file:// URI under the local image cache.</summary>
    public static bool IsValidImageUrl(string? url)
        => IsValidSteamCdnUrl(url) || IsValidCachedImagePath(url);

    /// <summary>SHA-256-prefixed cache path for a CDN URL.</summary>
    private static string GetCachedImagePath(string cdnUrl)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(cdnUrl), hash);
        var hex = Convert.ToHexString(hash[..8]); // 16 hex chars is plenty for uniqueness
        return Path.Combine(ImageCacheDir, $"{hex}.jpg");
    }

    /// <summary>Look up names/headers for the given app IDs; missing apps are omitted.</summary>
    public async Task<Dictionary<uint, StoreAppInfo>> GetAppInfoAsync(IReadOnlyList<uint> appIds)
    {
        if (appIds.Count == 0)
            return new Dictionary<uint, StoreAppInfo>();

        // Load disk cache once
        await EnsureDiskCacheLoaded();

        var result = new Dictionary<uint, StoreAppInfo>();
        var toFetch = new List<uint>();

        foreach (var id in appIds)
        {
            if (_mem.TryGetValue(id, out var cached) && DateTime.UtcNow - cached.FetchedUtc < DiskCacheTtl)
                result[id] = cached;
            else
                toFetch.Add(id);
        }

        if (toFetch.Count > 0)
        {
            var fetched = await FetchFromApiAsync(toFetch);
            foreach (var (id, info) in fetched)
            {
                _mem[id] = info;
                result[id] = info;
            }

            // Persist to disk (fire and forget -- not critical)
            _ = SaveDiskCacheAsync();
        }

        // Prefer a locally cached JPEG; otherwise kick off a background fetch.
        // Keys snapshotted because the loop writes back into result.
        foreach (var key in result.Keys.ToArray())
        {
            var info = result[key];
            if (!IsValidSteamCdnUrl(info.HeaderUrl)) continue;

            var localPath = GetCachedImagePath(info.HeaderUrl!);
            if (File.Exists(localPath))
            {
                var rewritten = new StoreAppInfo
                {
                    Name = info.Name,
                    HeaderUrl = new Uri(localPath).AbsoluteUri,
                    FetchedUtc = info.FetchedUtc
                };
                result[key] = rewritten;
            }
            else
            {
                // GetOrAdd ensures concurrent callers with the same URL share one
                // download task instead of each racing to write the same .tmp file.
                _ = _inFlightDownloads.GetOrAdd(localPath, lp =>
                    DownloadImageToCacheAsync(info.HeaderUrl!, lp)
                        .ContinueWith(t =>
                        {
                            _inFlightDownloads.TryRemove(lp, out _);
                        }, TaskScheduler.Default));
            }
        }

        return result;
    }

    /// <summary>
    /// Stream a CDN image into the cache, capped at MaxCachedImageBytes,
    /// via a GUID-suffixed .tmp + atomic Move. Failures are swallowed.
    /// </summary>
    private async Task DownloadImageToCacheAsync(string cdnUrl, string localPath)
    {
        if (!IsValidSteamCdnUrl(cdnUrl)) return;

        string? tmp = null;
        try
        {
            Directory.CreateDirectory(ImageCacheDir);

            // Recheck: another caller may have produced the file already.
            if (File.Exists(localPath)) return;

            // ResponseHeadersRead lets us reject oversize before buffering.
            using var resp = await _http.GetAsync(cdnUrl, HttpCompletionOption.ResponseHeadersRead);
            if (!resp.IsSuccessStatusCode) return;

            if (resp.Content.Headers.ContentLength is long declared && declared > MaxCachedImageBytes)
                return;

            tmp = $"{localPath}.{Guid.NewGuid():N}.tmp";

            // Running byte count bounds chunked responses lacking Content-Length.
            long written = 0;
            await using (var src = await resp.Content.ReadAsStreamAsync())
            await using (var dst = new FileStream(
                tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var buf = new byte[81920];
                int n;
                while ((n = await src.ReadAsync(buf.AsMemory())) > 0)
                {
                    written += n;
                    if (written > MaxCachedImageBytes)
                        return; // tmp is cleaned up in finally
                    await dst.WriteAsync(buf.AsMemory(0, n));
                }
            }

            if (written == 0) return; // empty body -- treat as failure

            File.Move(tmp, localPath, overwrite: true);
            tmp = null; // don't delete the file we just moved
        }
        catch
        {
            // Non-fatal: caller will fall back to the CDN URL this session.
        }
        finally
        {
            if (tmp != null)
            {
                try { File.Delete(tmp); } catch { /* best-effort */ }
            }
        }
    }

    /// <summary>
    /// Delete cached images older than ImageCacheTtl and abandoned .tmp
    /// sidecars older than 10 minutes. Run off the UI thread.
    /// </summary>
    private static void EvictStaleImages()
    {
        try
        {
            if (!Directory.Exists(ImageCacheDir)) return;
            var cutoff = DateTime.UtcNow - ImageCacheTtl;

            foreach (var file in Directory.EnumerateFiles(ImageCacheDir, "*.jpg"))
            {
                try
                {
                    if (File.GetLastWriteTimeUtc(file) < cutoff)
                        File.Delete(file);
                }
                catch { /* skip files we can't stat/delete */ }
            }

            // Sweep .tmp sidecars older than any realistic HTTP timeout.
            var tmpCutoff = DateTime.UtcNow - TimeSpan.FromMinutes(10);
            foreach (var file in Directory.EnumerateFiles(ImageCacheDir, "*.tmp"))
            {
                try
                {
                    if (File.GetLastWriteTimeUtc(file) < tmpCutoff)
                        File.Delete(file);
                }
                catch { /* skip files we can't stat/delete */ }
            }
        }
        catch { /* non-fatal */ }
    }

    // ── API call ────────────────────────────────────────────────────────

    private async Task<Dictionary<uint, StoreAppInfo>> FetchFromApiAsync(List<uint> appIds)
    {
        var result = new Dictionary<uint, StoreAppInfo>();

        try
        {
            // Build the request JSON -- batch all IDs in one call
            var ids = appIds.Select(id => new { appid = id }).ToArray();
            var requestObj = new
            {
                ids,
                context = new { language = "english", country_code = "US" },
                data_request = new { include_basic_info = true, include_assets = true }
            };

            var inputJson = JsonSerializer.Serialize(requestObj);
            var encoded = Uri.EscapeDataString(inputJson);
            var url = $"https://api.steampowered.com/IStoreBrowseService/GetItems/v1?input_json={encoded}";

            var resp = await _http.GetAsync(url);
            if (!resp.IsSuccessStatusCode)
                return result;

            var body = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(body);

            if (!doc.RootElement.TryGetProperty("response", out var response))
                return result;
            if (!response.TryGetProperty("store_items", out var items))
                return result;

            foreach (var item in items.EnumerateArray())
            {
                if (!item.TryGetProperty("appid", out var appIdEl))
                    continue;

                uint appId = appIdEl.GetUInt32();

                var info = new StoreAppInfo
                {
                    FetchedUtc = DateTime.UtcNow
                };

                // Name
                if (item.TryGetProperty("name", out var nameEl))
                    info.Name = nameEl.GetString() ?? "";

                // Header image URL: assets.header can be "header.jpg" (old) or "{hash}/header.jpg" (new)
                if (item.TryGetProperty("assets", out var assets) &&
                    assets.TryGetProperty("header", out var headerEl))
                {
                    var header = headerEl.GetString();
                    if (!string.IsNullOrEmpty(header))
                        info.HeaderUrl = $"https://shared.steamstatic.com/store_item_assets/steam/apps/{appId}/{header}";
                }

                result[appId] = info;
            }
        }
        catch
        {
            // Network/parse failures are non-fatal -- we just don't get names
        }

        return result;
    }

    // ── Disk cache ──────────────────────────────────────────────────────

    private async Task EnsureDiskCacheLoaded()
    {
        if (_diskLoaded) return;

        await _diskLock.WaitAsync();
        try
        {
            if (_diskLoaded) return;

            if (File.Exists(CachePath))
            {
                var json = await File.ReadAllTextAsync(CachePath);
                var cache = JsonSerializer.Deserialize(json, StoreCacheJsonContext.Default.StoreCache);
                if (cache?.Entries != null)
                {
                    foreach (var (id, info) in cache.Entries)
                        _mem.TryAdd(id, info);
                }
            }

            // Age out stale image-cache entries off the UI thread.
            _ = Task.Run(EvictStaleImages);

            _diskLoaded = true;
        }
        catch
        {
            _diskLoaded = true; // Don't retry on corrupt cache
        }
        finally
        {
            _diskLock.Release();
        }
    }

    private async Task SaveDiskCacheAsync()
    {
        try
        {
            var cache = new StoreCache
            {
                Entries = new Dictionary<uint, StoreAppInfo>(_mem)
            };

            var dir = Path.GetDirectoryName(CachePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(cache, StoreCacheJsonContext.Default.StoreCache);
            await File.WriteAllTextAsync(CachePath, json);
        }
        catch
        {
            // Non-fatal
        }
    }

    public void Dispose()
    {
        _http.Dispose();
        _diskLock.Dispose();
    }
}
