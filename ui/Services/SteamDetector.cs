using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using CloudRedirect.Resources;
using Microsoft.Win32;

namespace CloudRedirect.Services;

/// <summary>
/// Detects the Steam installation path via the Windows registry or well-known paths.
/// </summary>
public static class SteamDetector
{
    private static readonly object _cacheLock = new();
    private static string? _cachedPath;

    /// <summary>
    /// Supported Steam client versions our patches and RVAs target. Index 0 is the newest.
    /// </summary>
    public static readonly long[] SupportedSteamVersions = { 1782866176, 1782533657, 1782437068, 1782428855, 1782344391, 1782257239, 1781041600, 1780352834, 1779918128, 1779486452, 1778281814, 1778003620 };

    public static long ExpectedSteamVersion => SupportedSteamVersions[0];

    public static bool IsSupportedSteamVersion(long version)
    {
        foreach (var v in SupportedSteamVersions)
            if (v == version) return true;
        return false;
    }

    /// <summary>
    /// Returns the Steam installation directory, or null if not found.
    /// Results are cached after the first successful lookup.
    /// </summary>
    public static string? FindSteamPath()
    {
        lock (_cacheLock)
        {
            if (_cachedPath != null)
                return _cachedPath;
        }

        // Resolve outside the lock to avoid stalling on slow filesystem lookups.
        var resolved = NormalizeToSteamRoot(TryRegistry())
                       ?? NormalizeToSteamRoot(TryKnownPaths());

        lock (_cacheLock)
        {
            // Another thread may have resolved while we were outside the lock;
            // prefer the already-cached value to keep a single stable result.
            if (_cachedPath != null)
                return _cachedPath;
            _cachedPath = resolved;
            return _cachedPath;
        }
    }

    /// <summary>
    /// Manually override the Steam path (e.g. from a Browse dialog).
    /// Validates that the directory exists before accepting.
    /// </summary>
    public static bool SetSteamPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
            return false;
        var root = NormalizeToSteamRoot(path);
        if (root == null)
            return false;
        lock (_cacheLock) { _cachedPath = root; }
        return true;
    }

    /// <summary>
    /// Reads the installed Steam client version from the manifest file.
    /// Returns null if the manifest is missing or unparseable.
    /// </summary>
    public static long? GetSteamVersion()
    {
        var steamPath = FindSteamPath();
        if (steamPath == null) return null;
        return GetSteamVersion(steamPath);
    }

    /// <summary>
    /// Reads the installed Steam client version from the manifest file at a given path.
    /// </summary>
    public static long? GetSteamVersion(string steamPath)
    {
        try
        {
            var manifest = Path.Combine(steamPath, "package", "steam_client_win64.manifest");
            if (!File.Exists(manifest)) return null;
            foreach (var line in File.ReadLines(manifest))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith("\"version\""))
                    continue;
                // format: "version"		"1777411435"
                var last = trimmed.LastIndexOf('"');
                var secondLast = trimmed.LastIndexOf('"', last - 1);
                if (last > secondLast && secondLast >= 0)
                {
                    var val = trimmed[(secondLast + 1)..last];
                    if (long.TryParse(val, out var ver))
                        return ver;
                }
            }
        }
        catch
        {
            // Version parse can fail if manifest is malformed — not critical
        }
        return null;
    }

    /// <summary>Walks up from <paramref name="path"/> to find the directory containing steam.exe, or null.</summary>
    private static string? NormalizeToSteamRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        try
        {
            var dir = new DirectoryInfo(path);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "steam.exe")))
                    return dir.FullName;
                dir = dir.Parent;
            }
        }
        catch
        {
            // Malformed path -- fall through to null
        }

        return null;
    }

    private static string? TryRegistry()
    {
        try
        {
            // 64-bit Steam
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Wow6432Node\Valve\Steam");
            var path = key?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                return path;

            // 32-bit Steam
            using var key32 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam");
            path = key32?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                return path;

            // Current user
            using var keyUser = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam");
            path = keyUser?.GetValue("SteamPath") as string;
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                return path;
        }
        catch
        {
            // Registry access can fail in sandboxed/restricted environments
        }

        return null;
    }

    private static string? TryKnownPaths()
    {
        string[] candidates =
        [
            @"C:\Games\Steam",
            @"C:\Program Files (x86)\Steam",
            @"C:\Program Files\Steam",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam"),
            @"D:\Steam",
            @"D:\Games\Steam",
        ];

        foreach (var path in candidates)
        {
            if (Directory.Exists(path) && File.Exists(Path.Combine(path, "steam.exe")))
                return path;
        }

        return null;
    }

    /// <summary>
    /// Returns the path to the CloudRedirect config directory (%AppData%/CloudRedirect).
    /// Per-user so each Windows account has its own provider settings.
    /// </summary>
    public static string GetConfigDir()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "CloudRedirect");
    }

    /// <summary>
    /// Returns the path to config.json (%AppData%/CloudRedirect/config.json).
    /// </summary>
    public static string GetConfigFilePath()
    {
        return Path.Combine(GetConfigDir(), "config.json");
    }

    /// <summary>
    /// Returns the path to the manifest pin config in the Steam folder
    /// (per-system, not per-user). Returns null if Steam isn't found.
    /// </summary>
    public static string? GetPinConfigPath()
    {
        var steamPath = FindSteamPath();
        if (steamPath == null) return null;
        return Path.Combine(steamPath, "cloud_redirect", "config.json");
    }

    /// <summary>
    /// Returns the log file path, or null if Steam isn't found.
    /// </summary>
    public static string? GetLogPath()
    {
        var steamPath = FindSteamPath();
        if (steamPath == null) return null;
        return Path.Combine(steamPath, "cloud_redirect.log");
    }

    /// <summary>
    /// Returns true if any Steam process is currently running.
    /// </summary>
    public static bool IsSteamRunning()
    {
        try
        {
            var procs = Process.GetProcessesByName("steam");
            bool running = procs.Length > 0;
            foreach (var p in procs) p.Dispose();
            return running;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if Steam is running and prompts the user to close it.
    /// Returns true if Steam is not running (safe to proceed), false if the user declined or Steam is still running.
    /// </summary>
    public static async Task<bool> EnsureSteamClosedAsync()
    {
        if (!IsSteamRunning())
            return true;

        await Dialog.ShowWarningAsync(S.Get("Steam_IsRunningTitle"),
            S.Get("Steam_IsRunningMessage"));

        return false;
    }

    /// <summary>
    /// Reads the "mode" value from settings.json. Returns null if unset or unreadable.
    /// </summary>
    public static string? ReadModeSetting()
    {
        try
        {
            var path = Path.Combine(GetConfigDir(), "settings.json");
            if (!File.Exists(path)) return null;

            var json = File.ReadAllText(path);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("mode", out var prop))
                return prop.GetString();
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Reads and parses config.json. Returns null if file doesn't exist or can't be parsed.
    /// </summary>
    public static CloudConfig? ReadConfig()
    {
        var configPath = GetConfigFilePath();
        if (!File.Exists(configPath)) return null;

        try
        {
            var json = File.ReadAllText(configPath);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (!root.TryGetProperty("provider", out var providerProp))
                return null;
            var provider = providerProp.GetString();
            if (provider == null) return null;

            string? tokenPath = null;
            if (root.TryGetProperty("token_path", out var tp))
                tokenPath = tp.GetString();

            string? syncPath = null;
            if (root.TryGetProperty("sync_path", out var sp))
                syncPath = sp.GetString();

            return new CloudConfig(provider, tokenPath, syncPath);
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Parsed contents of cloud_redirect/config.json.
/// </summary>
public record CloudConfig(string Provider, string? TokenPath, string? SyncPath)
{
    public string DisplayName => Provider switch
    {
        "gdrive" => S.Get("Provider_GoogleDrive"),
        "onedrive" => S.Get("Provider_OneDrive"),
        "r2" => S.Get("Provider_R2"),
        "s3" => S.Get("Provider_S3"),
        "folder" => S.Get("Provider_FolderNetworkDrive"),
        "local" => S.Get("Provider_LocalOnly"),
        _ => Provider
    };

    public bool IsFolder => Provider == "folder";
    public bool IsLocal => Provider == "local";
}
