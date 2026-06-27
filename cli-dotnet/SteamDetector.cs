using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace CloudRedirect.Services;

public static class SteamDetector
{
    private static string? _cachedPath;

    public static readonly long[] SupportedSteamVersions = { 1782437068, 1782428855, 1782344391, 1782257239, 1781041600, 1780352834, 1779918128, 1779486452, 1778281814, 1778003620 };

    public static long ExpectedSteamVersion => SupportedSteamVersions[0];

    public static bool IsSupportedSteamVersion(long version)
    {
        foreach (var v in SupportedSteamVersions)
            if (v == version) return true;
        return false;
    }

    public static string? FindSteamPath()
    {
        if (_cachedPath != null) return _cachedPath;

        _cachedPath = TryRegistry();
        if (_cachedPath != null) return _cachedPath;

        _cachedPath = TryKnownPaths();
        return _cachedPath;
    }

    public static long? GetSteamVersion() => GetSteamVersion(FindSteamPath()!);

    public static long? GetSteamVersion(string steamPath)
    {
        try
        {
            var manifest = Path.Combine(steamPath, "package", "steam_client_win64.manifest");
            if (!File.Exists(manifest)) return null;
            foreach (var line in File.ReadLines(manifest))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith("\"version\"")) continue;
                var last = trimmed.LastIndexOf('"');
                var secondLast = trimmed.LastIndexOf('"', last - 1);
                if (last > secondLast && secondLast >= 0)
                {
                    var val = trimmed[(secondLast + 1)..last];
                    if (long.TryParse(val, out var ver)) return ver;
                }
            }
        }
        catch { }
        return null;
    }

    public static bool IsSteamRunning()
    {
        try
        {
            var procs = Process.GetProcessesByName("steam");
            bool running = procs.Length > 0;
            foreach (var p in procs) p.Dispose();
            return running;
        }
        catch { return false; }
    }

    private static string? TryRegistry()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Wow6432Node\Valve\Steam");
            var path = key?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path)) return path;

            using var key32 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam");
            path = key32?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path)) return path;

            using var keyUser = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam");
            path = keyUser?.GetValue("SteamPath") as string;
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path)) return path;
        }
        catch { }
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
            if (Directory.Exists(path) && File.Exists(Path.Combine(path, "steam.exe")))
                return path;
        return null;
    }
}
