using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace CloudRedirect.Services.Providers;

/// <summary>
/// Google Drive provider. ID-based: walks CloudRedirect/{accountId}/{appId}
/// by name to resolve folder IDs, then operates on IDs. Folder deletion is
/// bottom-up; drive.file scope can't DELETE a folder containing items from
/// a previous OAuth session. Same-name dedup ordering matches the DLL.
/// </summary>
internal sealed class GoogleDriveUiCloudProvider : IUiCloudProvider
{
    // Same credentials as OAuthService / DLL (public client).
    private const string GDriveClientId     = "1072944905499-vm2v2i5dvn0a0d2o4ca36i1vge8cvbn0.apps.googleusercontent.com";
    private const string GDriveClientSecret = "v6V3fKV_zWU7iw1DrpO1rknX";
    private const string GDriveTokenUrl     = "https://oauth2.googleapis.com/token";

    private readonly HttpClient _http;
    private readonly Action<string>? _log;
    private readonly string _tokenPath;

    public GoogleDriveUiCloudProvider(HttpClient http, Action<string>? log, string tokenPath)
    {
        _http = http;
        _log = log;
        _tokenPath = tokenPath;
    }

    // Public surface
    public async Task<CloudProviderClient.DeleteResult> DeleteAppDataAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var token = await GetAccessTokenAsync(cancel);
        if (token == null)
            return new CloudProviderClient.DeleteResult(false, 0, "Failed to get Google Drive access token. Re-authenticate in Cloud Provider settings.");

        // Walk the folder hierarchy: CloudRedirect -> {accountId} -> {appId}
        var rootId = await FindFolder(token, "CloudRedirect", "root", cancel);
        if (rootId == null)
        {
            _log?.Invoke("No CloudRedirect folder found on Google Drive -- nothing to delete.");
            return new CloudProviderClient.DeleteResult(true, 0, null);
        }

        var accountFolderId = await FindFolder(token, accountId, rootId, cancel);
        if (accountFolderId == null)
        {
            _log?.Invoke($"No account folder '{accountId}' found on Google Drive -- nothing to delete.");
            return new CloudProviderClient.DeleteResult(true, 0, null);
        }

        var appFolderId = await FindFolder(token, appId, accountFolderId, cancel);
        if (appFolderId == null)
        {
            _log?.Invoke($"No app folder '{appId}' found on Google Drive -- nothing to delete.");
            return new CloudProviderClient.DeleteResult(true, 0, null);
        }

        // Recursive bottom-up: drive.file scope can't DELETE a folder
        // whose children include items from a previous OAuth session.
        _log?.Invoke($"Recursively deleting Google Drive folder for app {appId}...");
        var (deleted, failed) = await DeleteFolderRecursive(token, appFolderId, cancel);
        _log?.Invoke($"Deleted {deleted} item(s) from Google Drive ({failed} failed).");

        if (failed > 0 && deleted == 0)
            return new CloudProviderClient.DeleteResult(false, 0, $"Could not delete any files from Google Drive ({failed} failed). Check Cloud Provider auth.");

        return new CloudProviderClient.DeleteResult(true, deleted, failed > 0 ? $"{failed} file(s) could not be deleted (may require re-authentication)." : null);
    }

    public async Task<CloudProviderClient.ListBlobsResult> ListAppBlobsAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var token = await GetAccessTokenAsync(cancel);
        if (token == null)
            return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), false,
                "Failed to get Google Drive access token. Re-authenticate in Cloud Provider settings.");

        // Checked walk so HTTP/parse errors don't masquerade as empty.
        var (blobsId, walkErr) = await ResolveBlobsFolderAsync(token, accountId, appId, cancel);
        if (walkErr != null)
            return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), false, walkErr);
        if (blobsId == null)
            return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), true, null);

        return await ListBlobsFolderCheckedAsync(token, blobsId, cancel);
    }

    public async Task<CloudProviderClient.DeleteBlobsResult> DeleteAppBlobsAsync(
        string accountId, string appId,
        IReadOnlyCollection<string> blobFilenames, CancellationToken cancel)
    {
        var token = await GetAccessTokenAsync(cancel);
        if (token == null)
            return new CloudProviderClient.DeleteBlobsResult(0, blobFilenames.Count, blobFilenames.ToList(),
                "Failed to get Google Drive access token. Re-authenticate in Cloud Provider settings.");

        // Resolver distinguishes "folder absent" from "couldn't verify";
        // on error every requested filename is reported as failed.
        var (blobsId, walkErr) = await ResolveBlobsFolderAsync(token, accountId, appId, cancel);
        if (walkErr != null)
            return new CloudProviderClient.DeleteBlobsResult(0, blobFilenames.Count, blobFilenames.ToList(), walkErr);
        if (blobsId == null)
        {
            // Folder absent → every requested filename already gone (idempotent success).
            return new CloudProviderClient.DeleteBlobsResult(blobFilenames.Count, 0, Array.Empty<string>(), null);
        }

        int deleted = 0, failed = 0;
        var failedNames = new List<string>();

        foreach (var filename in blobFilenames)
        {
            cancel.ThrowIfCancellationRequested();
            // Found / NotFound (idempotent) / Error (report as failed).
            var lookup = await FindBlobFileCheckedAsync(token, filename, blobsId, cancel);
            switch (lookup.Kind)
            {
                case LookupKind.Found:
                {
                    var (ok, _, _) = await DeleteItemAsync(token, lookup.FileId!, cancel);
                    if (ok) deleted++;
                    else { failed++; failedNames.Add(filename); }
                    break;
                }
                case LookupKind.NotFound:
                    deleted++; // genuinely absent on cloud -- idempotent
                    break;
                case LookupKind.Error:
                default:
                    failed++; failedNames.Add(filename);
                    break;
            }
        }

        string? err = failed > 0 ? $"{failed} of {blobFilenames.Count} file(s) could not be deleted." : null;
        return new CloudProviderClient.DeleteBlobsResult(deleted, failed, failedNames, err);
    }

    /// <summary>Lookup outcome that distinguishes Error from NotFound for prune paths.</summary>
    private enum LookupKind { Found, NotFound, Error }
    private record struct LookupResult(LookupKind Kind, string? FileId);

    private record GDriveChild(string Id, bool IsFolder);

    /// <summary>Recursively delete a folder's children then the folder. Returns (deleted, failed).</summary>
    private async Task<(int Deleted, int Failed)> DeleteFolderRecursive(
        string token, string folderId, CancellationToken cancel)
    {
        int deleted = 0;
        int failed = 0;

        var children = await ListFolderChildrenAsync(token, folderId, cancel);

        foreach (var child in children)
        {
            if (child.IsFolder)
            {
                // Recurse into subfolders first.
                var (subDel, subFail) = await DeleteFolderRecursive(token, child.Id, cancel);
                deleted += subDel;
                failed += subFail;
            }
            else
            {
                var (ok, _, _) = await DeleteItemAsync(token, child.Id, cancel);
                if (ok) deleted++;
                else failed++;
            }
        }

        // Children removed; delete the folder itself.
        var (folderOk, _, _) = await DeleteItemAsync(token, folderId, cancel);
        if (folderOk) deleted++;
        else failed++;

        return (deleted, failed);
    }

    /// <summary>
    /// Lists all direct children of a Google Drive folder (files and subfolders).
    /// </summary>
    private async Task<List<GDriveChild>> ListFolderChildrenAsync(
        string token, string folderId, CancellationToken cancel)
    {
        var result = new List<GDriveChild>();
        string? pageToken = null;

        do
        {
            var query = $"'{folderId}' in parents and trashed=false";
            var url = $"https://www.googleapis.com/drive/v3/files?q={Uri.EscapeDataString(query)}" +
                      "&fields=nextPageToken,files(id,mimeType)&pageSize=1000";
            if (pageToken != null)
                url += $"&pageToken={Uri.EscapeDataString(pageToken)}";

            var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var resp = await _http.SendAsync(req, cancel);
            if (!resp.IsSuccessStatusCode) break;

            var json = await resp.Content.ReadAsStringAsync(cancel);
            using var doc = JsonDocument.Parse(json);

            if (doc.RootElement.TryGetProperty("files", out var files))
            {
                foreach (var file in files.EnumerateArray())
                {
                    var id = file.GetProperty("id").GetString()!;
                    var mime = file.TryGetProperty("mimeType", out var mt) ? mt.GetString() : "";
                    result.Add(new GDriveChild(id, mime == "application/vnd.google-apps.folder"));
                }
            }

            pageToken = doc.RootElement.TryGetProperty("nextPageToken", out var npt)
                ? npt.GetString() : null;
        } while (pageToken != null);

        return result;
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

        // If token is still valid (with 60s buffer), use it.
        if (!string.IsNullOrEmpty(accessToken) && expiresAt > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60)
            return accessToken;

        // Refresh the token.
        _log?.Invoke("Refreshing Google Drive access token...");
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = GDriveClientId,
            ["client_secret"] = GDriveClientSecret,
            ["refresh_token"] = refreshToken,
            ["grant_type"] = "refresh_token"
        });

        var resp = await _http.PostAsync(GDriveTokenUrl, body, cancel);
        if (!resp.IsSuccessStatusCode) return null;

        var respJson = await resp.Content.ReadAsStringAsync(cancel);
        using var respDoc = JsonDocument.Parse(respJson);
        var respRoot = respDoc.RootElement;

        var newAccessToken = respRoot.TryGetProperty("access_token", out var nat) ? nat.GetString() : null;
        var expiresIn = respRoot.TryGetProperty("expires_in", out var ei) ? ei.GetInt64() : 3600;

        if (string.IsNullOrEmpty(newAccessToken)) return null;

        // Save updated token back to file.
        try
        {
            var newToken = new
            {
                access_token = newAccessToken,
                refresh_token = refreshToken,
                expires_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expiresIn
            };
            TokenFile.WriteJson(_tokenPath, JsonSerializer.Serialize(newToken, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* best-effort save */ }

        return newAccessToken;
    }

    /// <summary>Subfolder lookup that collapses Error and NotFound to null. DeleteAppData only.</summary>
    private async Task<string?> FindFolder(string token, string name, string parentId, CancellationToken cancel)
    {
        var escapedName = name.Replace("'", "\\'");
        var query = $"name='{escapedName}' and '{parentId}' in parents " +
                    "and mimeType='application/vnd.google-apps.folder' and trashed=false";
        var url = $"https://www.googleapis.com/drive/v3/files?q={Uri.EscapeDataString(query)}" +
                  "&fields=files(id,name)&orderBy=createdTime&pageSize=10";

        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _http.SendAsync(req, cancel);
        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(cancel);
            _log?.Invoke($"GDrive FindFolder '{name}' in {parentId}: HTTP {(int)resp.StatusCode}: {body}");
            return null;
        }

        var json = await resp.Content.ReadAsStringAsync(cancel);
        using var doc = JsonDocument.Parse(json);

        if (!doc.RootElement.TryGetProperty("files", out var files)) return null;
        if (files.GetArrayLength() == 0) return null;

        return files[0].GetProperty("id").GetString();
    }

    private async Task<(bool Ok, int StatusCode, string? Body)> DeleteItemAsync(
        string token, string fileId, CancellationToken cancel)
    {
        var req = new HttpRequestMessage(HttpMethod.Delete,
            $"https://www.googleapis.com/drive/v3/files/{fileId}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var resp = await _http.SendAsync(req, cancel);
        int status = (int)resp.StatusCode;
        if (resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.NotFound)
            return (true, status, null);

        var body = await resp.Content.ReadAsStringAsync(cancel);
        _log?.Invoke($"GDrive DELETE {fileId} failed: HTTP {status}: {body}");
        return (false, status, body);
    }

    /// <summary>
    /// Walk CloudRedirect/{accountId}/{appId}/blobs via the checked primitive.
    /// (id, null)  on success (id may be null = genuinely absent).
    /// (null, err) on HTTP/parse failure.
    /// </summary>
    private async Task<(string? BlobsId, string? Error)> ResolveBlobsFolderAsync(
        string token, string accountId, string appId, CancellationToken cancel)
    {
        var rootStep = await FindFolderCheckedAsync(token, "CloudRedirect", "root", cancel);
        if (rootStep.Kind == LookupKind.Error)
            return (null, "GDrive folder walk failed at 'CloudRedirect' (lookup error; see log)");
        if (rootStep.Kind == LookupKind.NotFound) return (null, null);

        var acctStep = await FindFolderCheckedAsync(token, accountId, rootStep.FileId!, cancel);
        if (acctStep.Kind == LookupKind.Error)
            return (null, $"GDrive folder walk failed at '{accountId}' (lookup error; see log)");
        if (acctStep.Kind == LookupKind.NotFound) return (null, null);

        var appStep = await FindFolderCheckedAsync(token, appId, acctStep.FileId!, cancel);
        if (appStep.Kind == LookupKind.Error)
            return (null, $"GDrive folder walk failed at '{appId}' (lookup error; see log)");
        if (appStep.Kind == LookupKind.NotFound) return (null, null);

        var blobsStep = await FindFolderCheckedAsync(token, "blobs", appStep.FileId!, cancel);
        if (blobsStep.Kind == LookupKind.Error)
            return (null, "GDrive folder walk failed at 'blobs' (lookup error; see log)");
        if (blobsStep.Kind == LookupKind.NotFound) return (null, null);

        return (blobsStep.FileId, null);
    }

    /// <summary>Subfolder lookup with explicit Found/NotFound/Error reporting.</summary>
    private async Task<LookupResult> FindFolderCheckedAsync(
        string token, string name, string parentId, CancellationToken cancel)
    {
        var escapedName = name.Replace("\\", "\\\\").Replace("'", "\\'");
        var query = $"name='{escapedName}' and '{parentId}' in parents " +
                    "and mimeType='application/vnd.google-apps.folder' and trashed=false";
        var url = $"https://www.googleapis.com/drive/v3/files?q={Uri.EscapeDataString(query)}" +
                  "&fields=files(id,name)&orderBy=createdTime&pageSize=10";

        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage resp;
        try { resp = await _http.SendAsync(req, cancel); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Invoke($"GDrive FindFolderChecked '{name}' in {parentId} transport error: {ex.Message}");
            return new LookupResult(LookupKind.Error, null);
        }

        if (!resp.IsSuccessStatusCode)
        {
            _log?.Invoke($"GDrive FindFolderChecked '{name}' in {parentId} HTTP {(int)resp.StatusCode}");
            return new LookupResult(LookupKind.Error, null);
        }

        string json;
        try { json = await resp.Content.ReadAsStringAsync(cancel); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Invoke($"GDrive FindFolderChecked '{name}' read error: {ex.Message}");
            return new LookupResult(LookupKind.Error, null);
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("files", out var files) ||
                files.ValueKind != JsonValueKind.Array)
            {
                _log?.Invoke($"GDrive FindFolderChecked '{name}' response missing 'files' array");
                return new LookupResult(LookupKind.Error, null);
            }
            if (files.GetArrayLength() == 0)
                return new LookupResult(LookupKind.NotFound, null);
            var id = files[0].GetProperty("id").GetString();
            if (string.IsNullOrEmpty(id))
                return new LookupResult(LookupKind.Error, null);
            return new LookupResult(LookupKind.Found, id);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"GDrive FindFolderChecked '{name}' parse error: {ex.Message}");
            return new LookupResult(LookupKind.Error, null);
        }
    }

    /// <summary>
    /// File lookup by exact name with Found/NotFound/Error reporting.
    /// On same-name siblings only the first match is deleted per run.
    /// </summary>
    private async Task<LookupResult> FindBlobFileCheckedAsync(
        string token, string name, string parentId, CancellationToken cancel)
    {
        var escapedName = name.Replace("\\", "\\\\").Replace("'", "\\'");
        var query = $"name='{escapedName}' and '{parentId}' in parents " +
                    "and mimeType!='application/vnd.google-apps.folder' and trashed=false";
        var url = $"https://www.googleapis.com/drive/v3/files?q={Uri.EscapeDataString(query)}" +
                  "&fields=files(id,name)&pageSize=10";

        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage resp;
        try { resp = await _http.SendAsync(req, cancel); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Invoke($"GDrive FindBlob '{name}' transport error: {ex.Message}");
            return new LookupResult(LookupKind.Error, null);
        }

        if (!resp.IsSuccessStatusCode)
        {
            // 4xx/5xx all mean "cannot verify," not "absent." Caller counts
            // these as failed deletes, not spurious successes.
            _log?.Invoke($"GDrive FindBlob '{name}' returned HTTP {(int)resp.StatusCode}; treating as lookup error");
            return new LookupResult(LookupKind.Error, null);
        }

        string json;
        try { json = await resp.Content.ReadAsStringAsync(cancel); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _log?.Invoke($"GDrive FindBlob '{name}' read error: {ex.Message}");
            return new LookupResult(LookupKind.Error, null);
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("files", out var files) ||
                files.ValueKind != JsonValueKind.Array)
            {
                // Malformed 200 response. Treat as error so the caller fails
                // the delete instead of reporting a spurious success.
                _log?.Invoke($"GDrive FindBlob '{name}' response missing 'files' array");
                return new LookupResult(LookupKind.Error, null);
            }
            if (files.GetArrayLength() == 0)
                return new LookupResult(LookupKind.NotFound, null);
            var id = files[0].GetProperty("id").GetString();
            if (string.IsNullOrEmpty(id))
                return new LookupResult(LookupKind.Error, null);
            return new LookupResult(LookupKind.Found, id);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"GDrive FindBlob '{name}' parse error: {ex.Message}");
            return new LookupResult(LookupKind.Error, null);
        }
    }

    /// <summary>Paginate file children (skip subfolders); Complete=false on any error.</summary>
    private async Task<CloudProviderClient.ListBlobsResult> ListBlobsFolderCheckedAsync(
        string token, string folderId, CancellationToken cancel)
    {
        var names = new List<string>();
        string? pageToken = null;
        // Cap to break out of a stuck/cyclic pageToken. 10k * 1000/page is
        // well past any real blob count; tripping it means the API is broken.
        const int kMaxPages = 10_000;
        int pages = 0;

        do
        {
            cancel.ThrowIfCancellationRequested();
            if (++pages > kMaxPages)
                return new CloudProviderClient.ListBlobsResult(names, false, "GDrive list exceeded pagination safety cap");
            var query = $"'{folderId}' in parents and trashed=false";
            var url = $"https://www.googleapis.com/drive/v3/files?q={Uri.EscapeDataString(query)}" +
                      "&fields=nextPageToken,files(name,mimeType)&pageSize=1000";
            if (pageToken != null)
                url += $"&pageToken={Uri.EscapeDataString(pageToken)}";

            var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

            HttpResponseMessage resp;
            try
            {
                resp = await _http.SendAsync(req, cancel);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                return new CloudProviderClient.ListBlobsResult(names, false, $"GDrive list transport error: {ex.Message}");
            }

            if (!resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(cancel);
                return new CloudProviderClient.ListBlobsResult(names, false,
                    $"GDrive list failed: HTTP {(int)resp.StatusCode}: {body}");
            }

            string json;
            try
            {
                json = await resp.Content.ReadAsStringAsync(cancel);
            }
            catch (Exception ex)
            {
                return new CloudProviderClient.ListBlobsResult(names, false, $"GDrive list read error: {ex.Message}");
            }

            JsonDocument doc;
            try { doc = JsonDocument.Parse(json); }
            catch (Exception ex)
            {
                return new CloudProviderClient.ListBlobsResult(names, false, $"GDrive list parse error: {ex.Message}");
            }

            using (doc)
            {
                if (doc.RootElement.TryGetProperty("files", out var files))
                {
                    foreach (var file in files.EnumerateArray())
                    {
                        var mime = file.TryGetProperty("mimeType", out var mt) ? mt.GetString() : "";
                        if (mime == "application/vnd.google-apps.folder") continue;
                        var name = file.TryGetProperty("name", out var n) ? n.GetString() : null;
                        if (!string.IsNullOrEmpty(name)) names.Add(name);
                    }
                }

                pageToken = doc.RootElement.TryGetProperty("nextPageToken", out var npt)
                    ? npt.GetString() : null;
            }
        } while (!string.IsNullOrEmpty(pageToken));

        return new CloudProviderClient.ListBlobsResult(names, true, null);
    }
}
