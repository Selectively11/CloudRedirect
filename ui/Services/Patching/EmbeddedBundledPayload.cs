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
        var fp = Fingerprint.ComputeFingerprint();
        var resourceName = $"payloads/{steamBuild}/{fp}";
        var assembly = Assembly.GetExecutingAssembly();

        var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream != null)
            return stream;

        foreach (var candidate in assembly.GetManifestResourceNames())
        {
            if (candidate.Replace('\\', '/') == resourceName)
                return assembly.GetManifestResourceStream(candidate);
        }

        return null;
    }
}
