using System;
using System.IO;
using System.Text;

namespace CloudRedirect.Services;

public static class ThirdPartyDetector
{
    private static readonly string[] ProxyDllNames =
    {
        "dwmapi.dll",      // OST + HubcapTools + StealIdra
        "xinput1_4.dll",   // OST alternate
    };

    // Compatible clients (allow deployment).
    private static readonly string[] CompatibleMarkers =
    {
        "OpenSteamTool",  // OST
        "HubcapTools",    // HubcapTools
        "hubcaptools",    // HubcapTools (lowercase variant)
    };

    // Blacklisted clients
    private static readonly string[] BlockedMarkers =
    {
        "LumaCore",       // StealIdra
        "lumacore",       // StealIdra
    };

    public enum DetectionStatus
    {
        NotFound,
        Compatible,
        Blocked,
    }

    public sealed record DetectionResult(
        DetectionStatus Status,
        string? DetectedTool,
        string? DetectedDll,
        string? DetectedPath);

    // Scans for unlock solutions, classifies result
    public static DetectionResult Detect(string steamPath)
    {
        var lumaDllPath = Path.Combine(steamPath, "LumaCore.dll");
        if (File.Exists(lumaDllPath))
        {
            return new DetectionResult(
                Status: DetectionStatus.Blocked,
                DetectedTool: "StealIdra",
                DetectedDll: "LumaCore.dll",
                DetectedPath: lumaDllPath);
        }

        foreach (var name in ProxyDllNames)
        {
            var path = Path.Combine(steamPath, name);
            if (!File.Exists(path))
                continue;

            // Skip if it's tiny (< 50 KB) - likely a real system DLL stub, not a proxy.
            try
            {
                var info = new FileInfo(path);
                if (info.Length < 50 * 1024)
                    continue;
            }
            catch
            {
                continue;
            }

            byte[] fileBytes;
            try { fileBytes = File.ReadAllBytes(path); }
            catch { continue; }

            if (ContainsAnyMarker(fileBytes, BlockedMarkers))
            {
                return new DetectionResult(
                    Status: DetectionStatus.Blocked,
                    DetectedTool: "StealIdra",
                    DetectedDll: name,
                    DetectedPath: path);
            }

            var toolName = FindMatchingMarker(fileBytes, CompatibleMarkers);
            if (toolName != null)
            {
                return new DetectionResult(
                    Status: DetectionStatus.Compatible,
                    DetectedTool: toolName,
                    DetectedDll: name,
                    DetectedPath: path);
            }
        }

        return new DetectionResult(
            Status: DetectionStatus.NotFound,
            DetectedTool: null,
            DetectedDll: null,
            DetectedPath: null);
    }

    private static bool ContainsAnyMarker(byte[] fileBytes, string[] markers)
    {
        foreach (var marker in markers)
        {
            if (IndexOf(fileBytes, Encoding.ASCII.GetBytes(marker)) >= 0)
                return true;
        }
        return false;
    }

    private static string? FindMatchingMarker(byte[] fileBytes, string[] markers)
    {
        foreach (var marker in markers)
        {
            if (IndexOf(fileBytes, Encoding.ASCII.GetBytes(marker)) >= 0)
                return marker;
        }
        return null;
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
            return -1;

        int end = haystack.Length - needle.Length;
        for (int i = 0; i <= end; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }
}
