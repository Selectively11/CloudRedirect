using System;
using System.IO;
using System.Reflection;

namespace CloudRedirect.Services.Patching;

internal static class EmbeddedBundledPayload
{
    public static bool IsAvailableForBuild(long steamBuild)
    {
        return GetResourceStream(steamBuild) != null;
    }

    public static bool TryInstall(string steamPath, long steamBuild, Action<string>? log)
    {
        try
        {
            using var stream = GetResourceStream(steamBuild);
            if (stream == null)
            {
                log?.Invoke($"Embedded payload: not present for build {steamBuild}");
                return false;
            }

            var dst = Fingerprint.GetExpectedCachePath(steamPath);
            var dstDir = Path.GetDirectoryName(dst);
            if (!string.IsNullOrEmpty(dstDir))
                Directory.CreateDirectory(dstDir);

            using var ms = new MemoryStream(checked((int)stream.Length));
            stream.CopyTo(ms);
            FileUtils.AtomicWriteAllBytes(dst, ms.ToArray());

            if (!Fingerprint.ValidatePayloadFile(dst))
            {
                log?.Invoke($"Embedded payload for build {steamBuild} failed validation after install");
                try { File.Delete(dst); } catch { }
                return false;
            }

            log?.Invoke($"Embedded payload installed to {dst}");
            return true;
        }
        catch (Exception ex)
        {
            log?.Invoke($"Embedded payload install failed: {ex.Message}");
            return false;
        }
    }

    private static Stream? GetResourceStream(long steamBuild)
    {
        var assembly = Assembly.GetExecutingAssembly();

        // Try machine-specific fingerprint first (legacy)
        var fp = Fingerprint.ComputeFingerprint();
        var fpName = $"payloads/{steamBuild}/{fp}";
        var stream = assembly.GetManifestResourceStream(fpName);
        if (stream != null) return stream;

        // Try generic payload (works on any machine)
        var genericName = $"payloads/{steamBuild}/payload";
        stream = assembly.GetManifestResourceStream(genericName);
        if (stream != null) return stream;

        // Fallback: scan for any resource under this build
        var prefix = $"payloads/{steamBuild}/";
        foreach (var candidate in assembly.GetManifestResourceNames())
        {
            var normalized = candidate.Replace('\\', '/');
            if (normalized.StartsWith(prefix))
                return assembly.GetManifestResourceStream(candidate);
        }

        return null;
    }
}
