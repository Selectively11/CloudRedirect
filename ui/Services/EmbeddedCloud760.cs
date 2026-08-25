using System;
using System.IO;
using System.Reflection;

namespace CloudRedirect.Services;

// Extracts the embedded 32-bit cloud760_tool.exe + steam_api.dll into a
// hash-keyed temp dir (both in the same folder so LoadLibrary finds the DLL).
internal static class EmbeddedCloud760
{
    private const string ToolResourceName = "cloud760_tool.exe";
    private const string DllResourceName = "steam_api.dll";
    private static string? _cachedToolPath;

    // Returns the path to cloud760_tool.exe, or null if not embedded.
    public static string? EnsureExtracted()
    {
        if (_cachedToolPath != null && File.Exists(_cachedToolPath))
            return _cachedToolPath;

        var assembly = Assembly.GetExecutingAssembly();
        using var toolStream = assembly.GetManifestResourceStream(ToolResourceName);
        using var dllStream = assembly.GetManifestResourceStream(DllResourceName);
        if (toolStream == null || dllStream == null)
            return null;

        string baseDir = Path.Combine(Path.GetTempPath(), "CloudRedirect", "cloud760_" + ComputeResourceHash(toolStream));
        Directory.CreateDirectory(baseDir);

        string exePath = Path.Combine(baseDir, "cloud760_tool.exe");
        string dllPath = Path.Combine(baseDir, "steam_api.dll");

        if (!File.Exists(exePath))
        {
            toolStream.Position = 0;
            using var ms = new MemoryStream(checked((int)toolStream.Length));
            toolStream.CopyTo(ms);
            FileUtils.AtomicWriteAllBytes(exePath, ms.ToArray());
        }

        if (!File.Exists(dllPath))
        {
            dllStream.Position = 0;
            using var ms = new MemoryStream(checked((int)dllStream.Length));
            dllStream.CopyTo(ms);
            FileUtils.AtomicWriteAllBytes(dllPath, ms.ToArray());
        }

        _cachedToolPath = exePath;
        return exePath;
    }

    private static string ComputeResourceHash(Stream stream)
    {
        stream.Position = 0;
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash).Substring(0, 16);
    }
}
