using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace CloudRedirect.Services;

/// <summary>
/// Checks GitHub for a newer release and, if found, downloads the .exe asset,
/// validates it, swaps the running executable, and relaunches.
/// </summary>
internal static class AppUpdater
{
    private const string RepoOwner = "Selectively11";
    private const string RepoName = "CloudRedirect";
    /// <summary>
    /// Uses /releases (not /releases/latest) because all releases are pre-releases
    /// and the /latest endpoint only returns non-prerelease.
    /// </summary>
    private const string ReleasesApiUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    static AppUpdater()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("CloudRedirect-AutoUpdate");
    }

    /// <summary>
    /// Result of checking for an update.
    /// </summary>
    internal sealed class CheckResult
    {
        public bool UpdateAvailable { get; init; }
        public string? TagName { get; init; }
        public string? DownloadUrl { get; init; }
        public string? AssetName { get; init; }
        /// <summary>Release body (markdown changelog) from GitHub.</summary>
        public string? Body { get; init; }
    }

    /// <summary>
    /// Checks GitHub releases for a newer version. Returns null on any failure
    /// (network, parse, etc.) -- callers treat null as "no update / check failed".
    /// </summary>
    internal static async Task<CheckResult?> CheckAsync()
    {
        try
        {
            var json = await Http.GetStringAsync(ReleasesApiUrl);
            using var doc = JsonDocument.Parse(json);
            var releases = doc.RootElement;

            if (releases.GetArrayLength() == 0) return null;

            // First element is the newest release (includes pre-releases)
            var root = releases[0];

            var tagName = root.GetProperty("tag_name").GetString() ?? "";
            var remoteVersionStr = tagName.TrimStart('v');

            var localVersion = Assembly.GetExecutingAssembly().GetName().Version;
            if (localVersion == null) return null;

            if (!Version.TryParse(remoteVersionStr, out var remoteVersion))
                return null;

            if (remoteVersion <= localVersion)
                return new CheckResult { UpdateAvailable = false };

            // Find the .exe asset
            if (!root.TryGetProperty("assets", out var assets))
                return null;

            string? downloadUrl = null;
            string? assetName = null;
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString() ?? "";
                if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    downloadUrl = asset.GetProperty("browser_download_url").GetString();
                    assetName = name;
                    break;
                }
            }

            if (downloadUrl == null) return null;

            var body = root.TryGetProperty("body", out var bodyProp)
                ? bodyProp.GetString() ?? ""
                : "";

            return new CheckResult
            {
                UpdateAvailable = true,
                TagName = tagName,
                DownloadUrl = downloadUrl,
                AssetName = assetName,
                Body = body
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Downloads the update, validates it, swaps the running exe, and relaunches.
    /// Returns an error message on failure, or null on success (the process will exit).
    /// <paramref name="onProgress"/> receives values 0-100 for download progress, or -1 for non-download steps.
    /// </summary>
    internal static async Task<string?> DownloadAndApplyAsync(string downloadUrl, Action<int, string>? onProgress = null)
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"CloudRedirect_{Guid.NewGuid():N}.exe");
        try
        {
            onProgress?.Invoke(0, "Downloading update...");

            using var response = await Http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? -1;
            using var stream = await response.Content.ReadAsStreamAsync();
            using var ms = new MemoryStream();
            var buffer = new byte[81920];
            long bytesRead = 0;
            int read;
            while ((read = await stream.ReadAsync(buffer)) > 0)
            {
                ms.Write(buffer, 0, read);
                bytesRead += read;
                if (totalBytes > 0)
                {
                    var pct = (int)(bytesRead * 100 / totalBytes);
                    onProgress?.Invoke(pct, $"Downloading... {pct}%");
                }
            }

            var data = ms.ToArray();

            // Validate: size between 1 MB and 50 MB (framework-dependent single-file ~8 MB)
            if (data.Length < 1024 * 1024 || data.Length > 50 * 1024 * 1024)
                return $"Downloaded file has suspicious size ({data.Length} bytes)";

            // Validate: MZ header (PE executable)
            if (data.Length < 2 || data[0] != 'M' || data[1] != 'Z')
                return "Downloaded file is not a valid executable";

            onProgress?.Invoke(-1, "Installing update...");

            await File.WriteAllBytesAsync(tempPath, data);

            var currentExe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(currentExe))
                return "Could not determine current executable path";

            var backupPath = currentExe + ".old";

            // Swap: rename current -> .old, move downloaded -> current
            try
            {
                if (File.Exists(backupPath))
                    File.Delete(backupPath);
                File.Move(currentExe, backupPath);
                File.Move(tempPath, currentExe);
            }
            catch (Exception ex)
            {
                // Attempt rollback if the rename partially succeeded
                if (!File.Exists(currentExe) && File.Exists(backupPath))
                    File.Move(backupPath, currentExe);
                return $"Could not replace exe: {ex.Message}";
            }

            // Relaunch
            onProgress?.Invoke(100, "Relaunching...");
            Process.Start(new ProcessStartInfo(currentExe) { UseShellExecute = true });
            Environment.Exit(0);

            return null; // unreachable, but satisfies compiler
        }
        catch (Exception ex)
        {
            return $"Update failed: {ex.Message}";
        }
        finally
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
        }
    }
}
