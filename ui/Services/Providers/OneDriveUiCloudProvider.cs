using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace CloudRedirect.Services.Providers;

/// <summary>
/// OneDrive (Microsoft Graph) provider. Path-based: a single DELETE on the
/// app folder removes everything beneath it, so the prune-blob path is a
/// per-file enumerate-then-delete loop rather than a recursive walk.
/// </summary>
internal sealed class OneDriveUiCloudProvider : IUiCloudProvider
{
    // Same credentials as OAuthService / DLL (public client).
    private const string OneDriveClientId = "c582f799-5dc5-48a7-a4cd-cd0d8af354a2";
    private const string OneDriveTokenUrl = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";

    private readonly HttpClient _http;
    private readonly Action<string>? _log;
    private readonly string _tokenPath;

    public OneDriveUiCloudProvider(HttpClient http, Action<string>? log, string tokenPath)
    {
        _http = http;
        _log = log;
        _tokenPath = tokenPath;
    }

    /// <summary>
    /// Per-segment percent-encode a forward-slash-delimited path. The Graph
    /// "root:/{path}:" addressing requires literal slashes between segments
    /// but each segment must be URL-encoded -- a single Uri.EscapeDataString
    /// of the whole path would escape the slashes too and break the URL.
    /// </summary>
    private static string EncodePath(string path) =>
        string.Join("/", path.Split('/').Select(Uri.EscapeDataString));

    public async Task<CloudProviderClient.DeleteResult> DeleteAppDataAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var token = await GetAccessTokenAsync(cancel);
        if (token == null)
            return new CloudProviderClient.DeleteResult(false, 0, "Failed to get OneDrive access token. Re-authenticate in Cloud Provider settings.");

        // OneDrive is path-based -- delete the app folder directly.
        var encodedPath = EncodePath($"CloudRedirect/{accountId}/{appId}");

        // First check if the folder exists and count children.
        int fileCount = await CountFolderFilesAsync(token, encodedPath, cancel);

        _log?.Invoke($"Deleting OneDrive folder for app {appId} ({fileCount} files)...");
        var req = new HttpRequestMessage(HttpMethod.Delete,
            $"https://graph.microsoft.com/v1.0/me/drive/root:/{encodedPath}:");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _http.SendAsync(req, cancel);
        if (!resp.IsSuccessStatusCode && resp.StatusCode != HttpStatusCode.NotFound)
            return new CloudProviderClient.DeleteResult(false, 0, $"OneDrive delete failed (HTTP {(int)resp.StatusCode}).");

        _log?.Invoke($"Deleted {fileCount} files from OneDrive.");
        return new CloudProviderClient.DeleteResult(true, fileCount, null);
    }

    public async Task<CloudProviderClient.ListBlobsResult> ListAppBlobsAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var token = await GetAccessTokenAsync(cancel);
        if (token == null)
            return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), false,
                "Failed to get OneDrive access token. Re-authenticate in Cloud Provider settings.");

        var encoded = EncodePath($"CloudRedirect/{accountId}/{appId}/blobs");
        string? nextUrl = $"https://graph.microsoft.com/v1.0/me/drive/root:/{encoded}:/children?$top=200";

        var names = new List<string>();
        // Cap to break out of a stuck/cyclic @odata.nextLink. Well past any
        // real per-app blob count.
        const int kMaxPages = 10_000;
        int pages = 0;
        while (!string.IsNullOrEmpty(nextUrl))
        {
            cancel.ThrowIfCancellationRequested();
            if (++pages > kMaxPages)
                return new CloudProviderClient.ListBlobsResult(names, false, "OneDrive list exceeded pagination safety cap");

            var req = new HttpRequestMessage(HttpMethod.Get, nextUrl);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            HttpResponseMessage resp;
            try { resp = await _http.SendAsync(req, cancel); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                return new CloudProviderClient.ListBlobsResult(names, false, $"OneDrive list transport error: {ex.Message}");
            }

            // NotFound on the first request = empty listing (folder absent).
            // NotFound mid-pagination = the folder vanished or the link
            // expired; report as incomplete rather than silently truncating.
            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                if (names.Count == 0)
                    return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), true, null);
                return new CloudProviderClient.ListBlobsResult(names, false,
                    "OneDrive list returned NotFound mid-pagination; partial result cannot be treated as complete");
            }

            if (!resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(cancel);
                return new CloudProviderClient.ListBlobsResult(names, false,
                    $"OneDrive list failed: HTTP {(int)resp.StatusCode}: {body}");
            }

            string json;
            try { json = await resp.Content.ReadAsStringAsync(cancel); }
            catch (Exception ex)
            {
                return new CloudProviderClient.ListBlobsResult(names, false, $"OneDrive list read error: {ex.Message}");
            }

            JsonDocument doc;
            try { doc = JsonDocument.Parse(json); }
            catch (Exception ex)
            {
                return new CloudProviderClient.ListBlobsResult(names, false, $"OneDrive list parse error: {ex.Message}");
            }

            using (doc)
            {
                if (doc.RootElement.TryGetProperty("value", out var items))
                {
                    foreach (var item in items.EnumerateArray())
                    {
                        if (item.TryGetProperty("folder", out _)) continue; // skip subfolders
                        var name = item.TryGetProperty("name", out var n) ? n.GetString() : null;
                        if (!string.IsNullOrEmpty(name)) names.Add(name);
                    }
                }

                nextUrl = doc.RootElement.TryGetProperty("@odata.nextLink", out var nl)
                    ? nl.GetString() : null;
            }
        }

        return new CloudProviderClient.ListBlobsResult(names, true, null);
    }

    public async Task<CloudProviderClient.DeleteBlobsResult> DeleteAppBlobsAsync(
        string accountId, string appId,
        IReadOnlyCollection<string> blobFilenames, CancellationToken cancel)
    {
        var token = await GetAccessTokenAsync(cancel);
        if (token == null)
            return new CloudProviderClient.DeleteBlobsResult(0, blobFilenames.Count, blobFilenames.ToList(),
                "Failed to get OneDrive access token. Re-authenticate in Cloud Provider settings.");

        int deleted = 0, failed = 0;
        var failedNames = new List<string>();

        foreach (var filename in blobFilenames)
        {
            cancel.ThrowIfCancellationRequested();
            var encoded = EncodePath($"CloudRedirect/{accountId}/{appId}/blobs/{filename}");
            var req = new HttpRequestMessage(HttpMethod.Delete,
                $"https://graph.microsoft.com/v1.0/me/drive/root:/{encoded}:");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            HttpResponseMessage resp;
            try { resp = await _http.SendAsync(req, cancel); }
            catch (OperationCanceledException) { throw; } // propagate user cancel / timeout cleanly
            catch { failed++; failedNames.Add(filename); continue; }

            // NotFound == already-deleted (idempotent).
            if (resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.NotFound)
                deleted++;
            else { failed++; failedNames.Add(filename); }
        }

        string? err = failed > 0 ? $"{failed} of {blobFilenames.Count} file(s) could not be deleted." : null;
        return new CloudProviderClient.DeleteBlobsResult(deleted, failed, failedNames, err);
    }

    private async Task<string?> GetAccessTokenAsync(CancellationToken cancel)
    {
        var json = TokenFile.ReadJson(_tokenPath);
        if (json == null) return null;

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var accessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() : null;
        var refreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null;
        var expiresAt = root.TryGetProperty("expires_at", out var ea) ? ea.GetInt64() : 0;

        if (string.IsNullOrEmpty(refreshToken)) return null;

        if (!string.IsNullOrEmpty(accessToken) && expiresAt > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60)
            return accessToken;

        // Refresh.
        _log?.Invoke("Refreshing OneDrive access token...");
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = OneDriveClientId,
            ["refresh_token"] = refreshToken,
            ["grant_type"] = "refresh_token",
            ["scope"] = "Files.ReadWrite offline_access"
        });

        var resp = await _http.PostAsync(OneDriveTokenUrl, body, cancel);
        if (!resp.IsSuccessStatusCode) return null;

        var respJson = await resp.Content.ReadAsStringAsync(cancel);
        using var respDoc = JsonDocument.Parse(respJson);
        var respRoot = respDoc.RootElement;

        var newAccessToken = respRoot.TryGetProperty("access_token", out var nat) ? nat.GetString() : null;
        var newRefreshToken = respRoot.TryGetProperty("refresh_token", out var nrt) ? nrt.GetString() : refreshToken;
        var expiresIn = respRoot.TryGetProperty("expires_in", out var ei) ? ei.GetInt64() : 3600;

        if (string.IsNullOrEmpty(newAccessToken)) return null;

        try
        {
            var newToken = new
            {
                access_token = newAccessToken,
                refresh_token = newRefreshToken,
                expires_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expiresIn
            };
            TokenFile.WriteJson(_tokenPath, JsonSerializer.Serialize(newToken, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* best-effort save */ }

        return newAccessToken;
    }

    private async Task<int> CountFolderFilesAsync(string token, string encodedPath, CancellationToken cancel)
    {
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"https://graph.microsoft.com/v1.0/me/drive/root:/{encodedPath}:?$select=id,folder");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _http.SendAsync(req, cancel);
        if (!resp.IsSuccessStatusCode) return 0;

        var json = await resp.Content.ReadAsStringAsync(cancel);
        using var doc = JsonDocument.Parse(json);

        if (doc.RootElement.TryGetProperty("folder", out var folder) &&
            folder.TryGetProperty("childCount", out var cc))
            return cc.GetInt32();

        return 0;
    }
}
