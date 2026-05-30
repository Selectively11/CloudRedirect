using System;
using System.IO;
using System.Security.Cryptography;

namespace CloudRedirect.Services;

internal static class EmbeddedDll
{
    private const string ResourceName = "cloud_redirect.dll";

    public static bool IsAvailable()
    {
        return typeof(EmbeddedDll).Assembly
            .GetManifestResourceInfo(ResourceName) != null;
    }

    public static string? DeployTo(string destPath)
    {
        byte[] payload;
        using (var stream = typeof(EmbeddedDll).Assembly
            .GetManifestResourceStream(ResourceName))
        {
            if (stream == null)
                return "cloud_redirect.dll is not embedded in this build.";

            using var ms = new MemoryStream(checked((int)stream.Length));
            stream.CopyTo(ms);
            payload = ms.ToArray();
        }

        try
        {
            FileUtils.AtomicWriteAllBytes(destPath, payload);
            return null;
        }
        catch (IOException ex) when (ex.Message.Contains("used by another process", StringComparison.OrdinalIgnoreCase)
                                   || ex.HResult == unchecked((int)0x80070020))
        {
            return "cloud_redirect.dll is in use -- close Steam first.";
        }
    }
}
