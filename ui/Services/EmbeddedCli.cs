using System;
using System.IO;
using System.Reflection;

namespace CloudRedirect.Services;

internal static class EmbeddedCli
{
    private const string CliResourceName = "cloud_redirect_cli.exe";
    private const string DllResourceName = "cloud_redirect.dll";
    private static string? _cachedExtractedPath;

    public static string? EnsureExtracted()
    {
        if (_cachedExtractedPath != null && File.Exists(_cachedExtractedPath))
            return _cachedExtractedPath;

        var assembly = Assembly.GetExecutingAssembly();
        using var cliStream = assembly.GetManifestResourceStream(CliResourceName);
        using var dllStream = assembly.GetManifestResourceStream(DllResourceName);
        if (cliStream == null || dllStream == null)
            return null;

        string baseDir = Path.Combine(Path.GetTempPath(), "CloudRedirect", ComputeResourceHash(cliStream));
        Directory.CreateDirectory(baseDir);

        string exePath = Path.Combine(baseDir, "cloud_redirect_cli.exe");
        string dllPath = Path.Combine(baseDir, "cloud_redirect.dll");
        if (!File.Exists(exePath))
        {
            cliStream.Position = 0;
            using var ms = new MemoryStream(checked((int)cliStream.Length));
            cliStream.CopyTo(ms);
            FileUtils.AtomicWriteAllBytes(exePath, ms.ToArray());
        }

        if (!File.Exists(dllPath))
        {
            dllStream.Position = 0;
            using var ms = new MemoryStream(checked((int)dllStream.Length));
            dllStream.CopyTo(ms);
            FileUtils.AtomicWriteAllBytes(dllPath, ms.ToArray());
        }

        _cachedExtractedPath = exePath;
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
