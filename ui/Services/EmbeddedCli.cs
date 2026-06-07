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

        // Hash BOTH the launcher stub and the DLL: the stub (cli_main) loads the
        // DLL and runs the real CLI logic from it, so when only the DLL changes
        // (e.g. a new command) the stub hash alone would not change and we'd
        // reuse a temp dir with a stale DLL. Including the DLL forces a fresh
        // extract whenever either resource changes.
        string baseDir = Path.Combine(Path.GetTempPath(), "CloudRedirect",
            ComputeResourceHash(cliStream, dllStream));
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

    private static string ComputeResourceHash(params Stream[] streams)
    {
        using var sha = System.Security.Cryptography.SHA256.Create();
        foreach (var stream in streams)
        {
            stream.Position = 0;
            var bytes = new byte[stream.Length];
            int read = 0;
            while (read < bytes.Length)
            {
                int n = stream.Read(bytes, read, bytes.Length - read);
                if (n == 0) break;
                read += n;
            }
            sha.TransformBlock(bytes, 0, read, null, 0);
        }
        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Convert.ToHexString(sha.Hash!).Substring(0, 16);
    }
}
