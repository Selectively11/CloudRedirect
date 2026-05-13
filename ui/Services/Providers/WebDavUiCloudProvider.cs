using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace CloudRedirect.Services.Providers;

internal sealed class WebDavUiCloudProvider : IUiCloudProvider
{
    private readonly HttpClient _http;
    private readonly Action<string>? _log;
    private readonly string _tokenPath;

    public WebDavUiCloudProvider(HttpClient http, Action<string>? log, string tokenPath)
    {
        _http = http;
        _log = log;
        _tokenPath = tokenPath;
    }

    private async Task<(string url, string user, string pass)?> GetConfigAsync()
    {
        try
        {
            var json = await Task.Run(() => TokenFile.ReadJson(_tokenPath));
            if (json == null) return null;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            return (
                root.TryGetProperty("webdav_url", out var url) ? url.GetString() ?? "" : "",
                root.TryGetProperty("webdav_user", out var user) ? user.GetString() ?? "" : "",
                root.TryGetProperty("webdav_pass", out var pass) ? pass.GetString() ?? "" : ""
            );
        }
        catch { return null; }
    }

    private static AuthenticationHeaderValue? GetAuthHeader(string user, string pass)
    {
        if (string.IsNullOrEmpty(user)) return null;
        var bytes = Encoding.UTF8.GetBytes($"{user}:{pass}");
        return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(bytes));
    }

    private static string GetFullUrl(string baseUrl, string relPath)
    {
        if (!baseUrl.EndsWith("/")) baseUrl += "/";
        if (relPath.StartsWith("/")) relPath = relPath.Substring(1);
        return baseUrl + relPath;
    }

    public async Task<CloudProviderClient.DeleteResult> DeleteAppDataAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var cfg = await GetConfigAsync();
        if (cfg == null || string.IsNullOrEmpty(cfg.Value.url))
            return new CloudProviderClient.DeleteResult(false, 0, "WebDAV configuration missing or unreadable.");

        var url = GetFullUrl(cfg.Value.url, $"CloudRedirect/{accountId}/{appId}/");
        _log?.Invoke($"Deleting WebDAV folder: {url}");

        var req = new HttpRequestMessage(HttpMethod.Delete, url);
        req.Headers.Authorization = GetAuthHeader(cfg.Value.user, cfg.Value.pass);

        var resp = await _http.SendAsync(req, cancel);
        if (!resp.IsSuccessStatusCode && resp.StatusCode != HttpStatusCode.NotFound)
            return new CloudProviderClient.DeleteResult(false, 0, $"WebDAV delete failed (HTTP {(int)resp.StatusCode}).");

        return new CloudProviderClient.DeleteResult(true, 0, null); // WebDAV doesn't easily give a count of deleted items
    }

    public async Task<CloudProviderClient.ListBlobsResult> ListAppBlobsAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var cfg = await GetConfigAsync();
        if (cfg == null || string.IsNullOrEmpty(cfg.Value.url))
            return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), false, "WebDAV configuration missing or unreadable.");

        var baseUrl = GetFullUrl(cfg.Value.url, $"CloudRedirect/{accountId}/{appId}/blobs/");
        var names = new List<string>();

        try
        {
            await ListRecursiveAsync(baseUrl, "", cfg.Value.user, cfg.Value.pass, names, cancel);
            return new CloudProviderClient.ListBlobsResult(names, true, null);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new CloudProviderClient.ListBlobsResult(names, false, $"WebDAV list failed: {ex.Message}");
        }
    }

    private async Task ListRecursiveAsync(string baseUrl, string relPath, string user, string pass, List<string> names, CancellationToken cancel)
    {
        var url = GetFullUrl(baseUrl, relPath);
        if (!url.EndsWith("/")) url += "/";

        var req = new HttpRequestMessage(new HttpMethod("PROPFIND"), url);
        req.Headers.Authorization = GetAuthHeader(user, pass);
        req.Headers.Add("Depth", "1");

        var resp = await _http.SendAsync(req, cancel);
        if (resp.StatusCode == HttpStatusCode.NotFound) return;
        if (!resp.IsSuccessStatusCode) throw new Exception($"HTTP {(int)resp.StatusCode}");

        var xml = await resp.Content.ReadAsStringAsync(cancel);
        var doc = XDocument.Parse(xml);
        XNamespace dav = "DAV:";

        // WebDAV responses include the directory itself as the first response
        var responses = doc.Descendants(dav + "response");
        
        // Normalize the base path for comparison
        var uri = new Uri(url);
        var normalizedBase = uri.AbsolutePath.EndsWith("/") ? uri.AbsolutePath : uri.AbsolutePath + "/";

        foreach (var res in responses)
        {
            var href = res.Element(dav + "href")?.Value;
            if (string.IsNullOrEmpty(href)) continue;

            var decodedHref = WebUtility.UrlDecode(href);
            var hrefUri = new Uri(new Uri(url), href);
            var absolutePath = hrefUri.AbsolutePath;
            
            // Skip the directory itself
            if (absolutePath == normalizedBase || absolutePath == normalizedBase.TrimEnd('/'))
                continue;

            var propstat = res.Element(dav + "propstat");
            var prop = propstat?.Element(dav + "prop");
            var resType = prop?.Element(dav + "resourcetype");
            bool isFolder = resType?.Element(dav + "collection") != null;

            var name = absolutePath.Substring(normalizedBase.Length).Trim('/');
            if (isFolder)
            {
                await ListRecursiveAsync(baseUrl, relPath + name + "/", user, pass, names, cancel);
            }
            else
            {
                names.Add(relPath + name);
            }
        }
    }

    public async Task<CloudProviderClient.DeleteBlobsResult> DeleteAppBlobsAsync(
        string accountId, string appId,
        IReadOnlyCollection<string> blobFilenames, CancellationToken cancel)
    {
        var cfg = await GetConfigAsync();
        if (cfg == null || string.IsNullOrEmpty(cfg.Value.url))
            return new CloudProviderClient.DeleteBlobsResult(0, blobFilenames.Count, blobFilenames.ToList(), "WebDAV configuration missing or unreadable.");

        int deleted = 0, failed = 0;
        var failedNames = new List<string>();

        foreach (var filename in blobFilenames)
        {
            cancel.ThrowIfCancellationRequested();
            var url = GetFullUrl(cfg.Value.url, $"CloudRedirect/{accountId}/{appId}/blobs/{filename}");
            
            var req = new HttpRequestMessage(HttpMethod.Delete, url);
            req.Headers.Authorization = GetAuthHeader(cfg.Value.user, cfg.Value.pass);

            try
            {
                var resp = await _http.SendAsync(req, cancel);
                if (resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.NotFound)
                    deleted++;
                else { failed++; failedNames.Add(filename); }
            }
            catch { failed++; failedNames.Add(filename); }
        }

        string? err = failed > 0 ? $"{failed} of {blobFilenames.Count} file(s) could not be deleted." : null;
        return new CloudProviderClient.DeleteBlobsResult(deleted, failed, failedNames, err);
    }
}
