using System;
using System.IO;

namespace CloudRedirect.Services.Patching
{
    // Sibling-file fallback for when SteamTools' CDN is unreachable / Cloudflare-403'd.
    // Layout: <publish>/payloads/<steamBuild>/<fingerprint>
    internal static class BundledPayload
    {
        public static string GetBundledPath(long steamBuild)
        {
            var baseDir = AppContext.BaseDirectory;
            var fp = Fingerprint.ComputeFingerprint();
            var path = Path.Combine(baseDir, "payloads", steamBuild.ToString(), fp);
            return path;
        }

        public static bool IsAvailableForBuild(long steamBuild)
        {
            try { return File.Exists(GetBundledPath(steamBuild)); }
            catch { return false; }
        }

        // Copies the bundled payload into Steam's httpcache slot for the running build.
        // Returns false if bundled payload is missing, the build doesn't match what we have,
        // or the copy fails. Validates the bundled file before installing it.
        public static bool TryInstall(string steamPath, long steamBuild, Action<string> log)
        {
            try
            {
                var src = GetBundledPath(steamBuild);
                if (!File.Exists(src))
                {
                    // Exact build not found — try the newest available payload.
                    foreach (var fallback in SteamDetector.SupportedSteamVersions)
                    {
                        var fbSrc = GetBundledPath(fallback);
                        if (File.Exists(fbSrc))
                        {
                            log?.Invoke($"Bundled payload: build {steamBuild} not found, using latest ({fallback})");
                            src = fbSrc;
                            goto found;
                        }
                    }
                    log?.Invoke($"Bundled payload: not present for build {steamBuild} (looked in {src})");
                    return false;
                }
                found:

                if (!Fingerprint.ValidatePayloadFile(src))
                {
                    log?.Invoke($"Bundled payload at {src} failed validation, refusing to install");
                    return false;
                }

                var dst = Fingerprint.GetExpectedCachePath(steamPath);
                var dstDir = Path.GetDirectoryName(dst);
                if (!string.IsNullOrEmpty(dstDir)) Directory.CreateDirectory(dstDir);
                File.Copy(src, dst, overwrite: true);
                log?.Invoke($"Bundled payload installed: {src} -> {dst}");
                return true;
            }
            catch (Exception ex)
            {
                log?.Invoke($"Bundled payload copy failed: {ex.Message}");
                return false;
            }
        }
    }
}
