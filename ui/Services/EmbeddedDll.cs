using System;
using System.IO;
using System.Security.Cryptography;
using CloudRedirect.Resources;

namespace CloudRedirect.Services;

/// <summary>
/// Provides access to the cloud_redirect.dll embedded inside this assembly.
/// All DLL deploy operations should go through this class.
/// </summary>
internal static class EmbeddedDll
{
    private const string ResourceName = "cloud_redirect.dll";
    private static string? _cachedEmbeddedHash;

    /// <summary>
    /// Returns true if the embedded DLL resource exists in this assembly.
    /// </summary>
    public static bool IsAvailable()
    {
        return typeof(EmbeddedDll).Assembly
            .GetManifestResourceInfo(ResourceName) != null;
    }

    /// <summary>
    /// Returns the SHA-256 hash of the embedded DLL, or null if not embedded.
    /// Result is cached after first call.
    /// </summary>
    public static string? GetEmbeddedHash()
    {
        if (_cachedEmbeddedHash != null)
            return _cachedEmbeddedHash;

        using var stream = typeof(EmbeddedDll).Assembly
            .GetManifestResourceStream(ResourceName);
        if (stream == null)
            return null;

        _cachedEmbeddedHash = ComputeSha256(stream);
        return _cachedEmbeddedHash;
    }

    /// <summary>
    /// Checks whether the deployed DLL matches the embedded version.
    /// Returns null if the file doesn't exist, true if up to date, false if outdated.
    /// </summary>
    public static bool? IsDeployedCurrent(string deployedPath)
    {
        if (!File.Exists(deployedPath))
            return null;

        var embeddedHash = GetEmbeddedHash();
        if (embeddedHash == null)
            return null; // no embedded DLL to compare against

        try
        {
            using var fs = new FileStream(deployedPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var deployedHash = ComputeSha256(fs);
            return string.Equals(embeddedHash, deployedHash, StringComparison.OrdinalIgnoreCase);
        }
        catch (IOException)
        {
            return null; // can't read, treat as unknown
        }
    }

    /// <summary>
    /// Atomically deploys the embedded cloud_redirect.dll to the given destination path.
    /// Routes through FileUtils.AtomicWriteAllBytes so the bytes are forced
    /// out of the OS page cache (FlushFileBuffers) before the .tmp is
    /// renamed over destPath -- without that, a power loss between the
    /// write and the OS lazy-flush leaves the published file pointing at
    /// an inode whose data blocks were never written, even though NTFS
    /// journaled the rename. The DLL is ~900 KB so reading it into a
    /// byte[] up front is trivial.
    /// </summary>
    /// <returns>null on success, or an error message string on failure.</returns>
    public static string? DeployTo(string destPath)
    {
        byte[] payload;
        using (var stream = typeof(EmbeddedDll).Assembly
            .GetManifestResourceStream(ResourceName))
        {
            if (stream == null)
                return S.Get("EmbeddedDll_NotEmbedded");

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
                                  || ex.HResult == unchecked((int)0x80070020)) // ERROR_SHARING_VIOLATION
        {
            return S.Get("EmbeddedDll_InUse");
        }
    }

    private static string ComputeSha256(Stream stream)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }
}
