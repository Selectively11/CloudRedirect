using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace CloudRedirect.Services
{
    // Source generator for AOT-compatible JSON serialization
    [JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(UndoLog))]
    internal partial class CleanupJsonContext : JsonSerializerContext { }

    /// <summary>
    /// A single reversible operation performed during cleanup.
    /// </summary>
    internal class UndoOperation
    {
        [JsonPropertyName("type")]
        public string Type { get; set; }           // "file_move", "remotecache_backup", "dir_delete"

        [JsonPropertyName("sourcePath")]
        public string SourcePath { get; set; }      // Where the file/dir was originally

        [JsonPropertyName("destPath")]
        public string DestPath { get; set; }        // Where it was moved to (file_move only)

        [JsonPropertyName("backupContent")]
        public string BackupContent { get; set; }   // Original file content (remotecache_backup only)

        [JsonPropertyName("appId")]
        public uint AppId { get; set; }
    }

    /// <summary>Operation log for one cleanup run; stored under cloud_redirect/cleanup_tab_backup/{accountId}/{timestamp}/undo_log.json.</summary>
    internal class UndoLog
    {
        [JsonPropertyName("timestamp")]
        public string Timestamp { get; set; }

        [JsonPropertyName("version")]
        public int Version { get; set; } = 1;

        [JsonPropertyName("operations")]
        public List<UndoOperation> Operations { get; set; } = new();
    }

    /// <summary>Parsed remotecache.vdf entry; used to distinguish real saves from ghost contamination.</summary>
    internal class RemotecacheEntry
    {
        public string FileName { get; set; }
        public string Sha { get; set; }
        public long Size { get; set; }
        public int SyncState { get; set; }
        public int Root { get; set; }
        public long LocalTime { get; set; }
        public long RemoteTime { get; set; }

        /// <summary>Ghost = SHA=all-zeros, size=0, syncstate=2 (SteamTools app 760 cross-app sync artifact).</summary>
        public bool IsGhost =>
            Size == 0 &&
            SyncState == 2 &&
            !string.IsNullOrEmpty(Sha) &&
            Sha.All(c => c == '0');
    }

    /// <summary>
    /// Classification result for a file found in an app's remote directory.
    /// </summary>
    internal enum FileClassification
    {
        Legitimate,         // Real remotecache entry (valid SHA) or matches AutoCloud rules
        PollutionAppIdDir,  // File in a <otherAppId>/ subdirectory
        PollutionMangled,   // File with <appid>_%Token%...~... mangled name
        PollutionOrphan,    // File not in remotecache and doesn't match any AutoCloud rule
        PollutionCrossApp,  // Ghost entry in remotecache (SHA=0, syncstate=2) — SteamTools cloud spread
        Unknown             // Can't determine
    }

    internal class ClassifiedFile
    {
        public string RelativePath { get; set; }       // Relative to the app's remote/ directory
        public string FullPath { get; set; }
        public FileClassification Classification { get; set; }
        public string Reason { get; set; }
        public uint? SourceAppId { get; set; }         // For pollution: which app's files are these?
        public long SizeBytes { get; set; }            // File size on disk
    }

    /// <summary>Result of scanning one app's remote/ dir for the Cleanup UI.</summary>
    internal class AppScanResult
    {
        public uint AppId { get; set; }
        public string AccountId { get; set; }
        public string RemoteDir { get; set; }          // Full path to remote/ directory
        public List<ClassifiedFile> Files { get; set; } = new();

        // Cached counts, computed by ComputeStats() after classification
        public int PollutedCount { get; private set; }
        public int LegitimateCount { get; private set; }
        public int UnknownCount { get; private set; }
        public long PollutedBytes { get; private set; }
        public long TotalBytes { get; private set; }

        /// <summary>Compute counts/sizes in one pass after classification.</summary>
        public void ComputeStats()
        {
            int polluted = 0, legit = 0, unknown = 0;
            long pollutedBytes = 0, totalBytes = 0;
            foreach (var f in Files)
            {
                totalBytes += f.SizeBytes;
                if (f.Classification == FileClassification.Legitimate)
                    legit++;
                else if (f.Classification == FileClassification.Unknown)
                    unknown++;
                else
                {
                    polluted++;
                    pollutedBytes += f.SizeBytes;
                }
            }
            PollutedCount = polluted;
            LegitimateCount = legit;
            UnknownCount = unknown;
            PollutedBytes = pollutedBytes;
            TotalBytes = totalBytes;
        }
    }

    /// <summary>
    /// Handles cleanup of cross-app file pollution in Steam's userdata directories.
    /// </summary>
    internal class CloudCleanup
    {
        private readonly string _steamPath;
        private readonly string _userdataPath;
        private readonly string _appInfoPath;
        private readonly Action<string> _log;
        private Dictionary<uint, AppCloudConfig> _appConfigs;

        // Undo log for the current run (populated during --apply)
        private UndoLog _undoLog;

        // Batch support: when cleaning multiple apps in one session,
        // all files go into the same timestamped backup directory.
        private string _backupTimestamp;
        private bool _batchActive;

        // Namespace apps detected from stplug-in/*.lua
        private HashSet<uint> _namespaceApps;

        // Cross-app remotecache filename map: filename → set of appIds that have it in their remotecache.
        // Used to detect contamination: if a filename appears in 2+ namespace apps' remotecaches,
        // it's pollution from SteamTools redirecting all apps to app 760's cloud bucket.
        private Dictionary<string, HashSet<uint>> _crossAppFileMap;

        // Cache of parsed remotecache.vdf results, populated by BuildCrossAppRemotecacheMap
        // and reused by ScanApps to avoid double-parsing (H4).
        // Key: appDir path (e.g. "C:\...\userdata\54303850\760")
        private Dictionary<string, Dictionary<string, RemotecacheEntry>> _remotecacheCache;

        // Regex to match numeric AppID directory names or filename prefixes
        private static readonly Regex AppIdDirPattern = new(@"^(\d{3,10})[\\/]", RegexOptions.Compiled);
        // Regex to match mangled filenames: <appid>_%Token%path~segments~file
        private static readonly Regex MangledFilePattern = new(@"^(\d{3,10})_%[^%]+%", RegexOptions.Compiled);

        // Special Steam AppIDs whose remote/ directories legitimately contain <appid>/ subdirectories
        // 760 = Steam Screenshots (remote/<sourceAppId>/screenshots/...)
        // 7 = Steam Client (general config)
        private static readonly HashSet<uint> ExcludedAppIds = new() { 760, 7 };

        public CloudCleanup(string steamPath, Action<string> log = null)
        {
            _steamPath = steamPath;
            _userdataPath = Path.Combine(steamPath, "userdata");
            _appInfoPath = Path.Combine(steamPath, "appcache", "appinfo.vdf");
            _log = log ?? (_ => { });
        }

        /// <summary>Scan all namespace apps; results feed CleanupPage's selection list.</summary>
        public List<AppScanResult> ScanApps()
        {
            var results = new List<AppScanResult>();

            _namespaceApps = DetectNamespaceApps();
            _log($"Detected {_namespaceApps.Count} lua app(s) (self-unlocking base games only)");

            _log("Parsing appinfo.vdf...");
            if (!File.Exists(_appInfoPath))
            {
                _log($"ERROR: appinfo.vdf not found: {_appInfoPath}");
                return results;
            }
            try
            {
                _appConfigs = AppInfoParser.ParseAll(_appInfoPath);
            }
            catch (Exception ex)
            {
                _log($"ERROR: Failed to parse appinfo.vdf: {ex.Message}");
                return results;
            }

            _log("Building cross-app remotecache map...");
            _crossAppFileMap = BuildCrossAppRemotecacheMap();

            if (!Directory.Exists(_userdataPath)) return results;

            var accountDirs = Directory.GetDirectories(_userdataPath)
                .Where(d => uint.TryParse(Path.GetFileName(d), out _))
                .ToList();

            foreach (var accountDir in accountDirs)
            {
                string accountId = Path.GetFileName(accountDir);

                foreach (var appDir in Directory.GetDirectories(accountDir))
                {
                    string appName = Path.GetFileName(appDir);
                    if (!uint.TryParse(appName, out uint appId)) continue;
                    if (!_namespaceApps.Contains(appId)) continue;
                    if (ExcludedAppIds.Contains(appId)) continue;

                    string remoteDir = Path.Combine(appDir, "remote");
                    if (!Directory.Exists(remoteDir)) continue;

                    string[] files;
                    try { files = Directory.GetFiles(remoteDir, "*", SearchOption.AllDirectories); }
                    catch { continue; }
                    if (files.Length == 0) continue;

                    // Use cached remotecache parse from BuildCrossAppRemotecacheMap (H4)
                    if (!_remotecacheCache.TryGetValue(appDir, out var remotecacheEntries))
                        remotecacheEntries = ParseRemotecache(appDir, appId); // fallback if not cached
                    _appConfigs.TryGetValue(appId, out var cloudConfig);

                    var scanResult = new AppScanResult
                    {
                        AppId = appId,
                        AccountId = accountId,
                        RemoteDir = remoteDir
                    };

                    foreach (var file in files)
                    {
                        string relativePath = GetRelativePath(file, remoteDir);
                        var cf = ClassifyFile(appId, relativePath, file, cloudConfig, remotecacheEntries, _crossAppFileMap);

                        // Populate file size
                        try { cf.SizeBytes = new FileInfo(file).Length; } catch { }

                        scanResult.Files.Add(cf);
                    }

                    scanResult.ComputeStats();
                    results.Add(scanResult);
                }
            }

            return results;
        }

        /// <summary>Begin a batch; CleanFiles backups go into one timestamped dir until EndBatch.</summary>
        public void BeginBatch()
        {
            _backupTimestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            _undoLog = new UndoLog { Timestamp = DateTime.UtcNow.ToString("o") };
            _batchActive = true;
        }

        /// <summary>Save the undo log and reset batch state.</summary>
        public void EndBatch(string accountId)
        {
            if (_undoLog?.Operations.Count > 0)
                SaveUndoLog(accountId);
            _batchActive = false;
            _undoLog = null;
            _backupTimestamp = null;
        }

        /// <summary>
        /// Move specified files out of an app's remote/ dir into a backup dir
        /// (batch dir if BeginBatch is active). Returns count moved.
        /// </summary>
        public int CleanFiles(string accountId, uint appId, string appDir, List<ClassifiedFile> filesToRemove)
        {
            bool standalone = !_batchActive;
            if (standalone)
                BeginBatch();

            // Backup remotecache.vdf BEFORE modifying
            BackupRemotecache(appDir, appId);

            var (moved, movedFiles) = MoveToHoldover(accountId, appId, appDir, filesToRemove);

            // Clean remotecache entries for moved files
            if (movedFiles.Count > 0)
                CleanRemotecache(appDir, appId, movedFiles);

            // Clean up empty dirs
            string remoteDir = Path.Combine(appDir, "remote");
            if (Directory.Exists(remoteDir))
                CleanEmptyDirs(remoteDir);

            if (standalone)
                EndBatch(accountId);

            return moved;
        }

        /// <summary>
        /// Find namespace apps via stplug-in/*.lua. Only self-unlocking luas
        /// (addappid(&lt;own_appid&gt;) present) count, matching the DLL's logic.
        /// </summary>
        private HashSet<uint> DetectNamespaceApps()
        {
            var apps = new HashSet<uint>();
            string pluginDir = Path.Combine(_steamPath, "config", "stplug-in");

            if (!Directory.Exists(pluginDir))
            {
                _log($"  stplug-in directory not found: {pluginDir}");
                return apps;
            }

            foreach (var file in Directory.GetFiles(pluginDir, "*.lua"))
            {
                string stem = Path.GetFileNameWithoutExtension(file);
                if (!uint.TryParse(stem, out uint appId) || appId == 0)
                    continue;

                if (IsSelfUnlockingLua(file, appId))
                    apps.Add(appId);
            }

            return apps;
        }

        /// <summary>True if the lua contains addappid(&lt;appId&gt;) for its own filename appId.</summary>
        internal static bool IsSelfUnlockingLua(string filePath, uint appId)
        {
            // The pattern we're looking for: addappid(<appId>) at the start of a line,
            // possibly followed by more arguments like ", 1, "hash""
            // e.g. "addappid(1032760)" or "addappid(1032760, 1, "hash") -- comment"
            string marker = $"addappid({appId})";
            string markerWithArgs = $"addappid({appId},";

            try
            {
                foreach (string line in File.ReadLines(filePath))
                {
                    string trimmed = line.TrimStart();
                    // Skip Lua comments (e.g. "-- addappid(12345)" is not a real call)
                    if (trimmed.StartsWith("--", StringComparison.Ordinal))
                        continue;
                    if (trimmed.StartsWith(marker, StringComparison.Ordinal) ||
                        trimmed.StartsWith(markerWithArgs, StringComparison.Ordinal))
                        return true;
                }
            }
            catch
            {
                // If we can't read the file, assume it's NOT self-unlocking (safe default:
                // we'd rather skip an unreadable lua than accidentally manage an owned game)
            }

            return false;
        }

        /// <summary>
        /// Map filename → set of appIds across all namespace remotecaches.
        /// Files appearing in 2+ apps are cross-app contamination.
        /// </summary>
        private Dictionary<string, HashSet<uint>> BuildCrossAppRemotecacheMap()
        {
            var map = new Dictionary<string, HashSet<uint>>(StringComparer.OrdinalIgnoreCase);
            _remotecacheCache = new Dictionary<string, Dictionary<string, RemotecacheEntry>>(StringComparer.OrdinalIgnoreCase);

            if (!Directory.Exists(_userdataPath)) return map;

            // Iterate all account directories
            foreach (var accountDir in Directory.GetDirectories(_userdataPath))
            {
                if (!uint.TryParse(Path.GetFileName(accountDir), out _)) continue;

                // Iterate all app directories within this account
                foreach (var appDir in Directory.GetDirectories(accountDir))
                {
                    string appName = Path.GetFileName(appDir);
                    if (!uint.TryParse(appName, out uint appId)) continue;

                    // Only include namespace apps in the cross-app map
                    if (!_namespaceApps.Contains(appId)) continue;

                    // Skip excluded system apps
                    if (ExcludedAppIds.Contains(appId)) continue;

                    // Parse this app's remotecache.vdf and cache the result (H4)
                    var entries = ParseRemotecache(appDir, appId);
                    _remotecacheCache[appDir] = entries;
                    if (entries == null || entries.Count == 0) continue;

                    foreach (var fileName in entries.Keys)
                    {
                        if (!map.TryGetValue(fileName, out var appSet))
                        {
                            appSet = new HashSet<uint>();
                            map[fileName] = appSet;
                        }
                        appSet.Add(appId);
                    }
                }
            }

            return map;
        }

        /// <summary>Backup base for an account (outside userdata, safe from Steam).</summary>
        private string GetBackupBase(string accountId)
        {
            return Path.Combine(BackupPaths.GetCleanupRoot(_steamPath), accountId);
        }

        /// <summary>
        /// Write the undo log into the timestamped backup directory.
        /// </summary>
        private void SaveUndoLog(string accountId)
        {
            string backupDir = Path.Combine(GetBackupBase(accountId), _backupTimestamp);
            if (!Directory.Exists(backupDir))
                Directory.CreateDirectory(backupDir);

            string logPath = Path.Combine(backupDir, "undo_log.json");

            try
            {
                string json = JsonSerializer.Serialize(_undoLog, CleanupJsonContext.Default.UndoLog);
                FileUtils.AtomicWriteAllText(logPath, json);
                _log($"");
                _log($"  Undo log saved: {_backupTimestamp}/undo_log.json ({_undoLog.Operations.Count} operations)");
            }
            catch (Exception ex)
            {
                _log($"");
                _log($"  WARNING: Failed to write undo log: {ex.Message}");
            }
        }

        /// <summary>
        /// Classify a file: ghost entry, cross-app overlap, unique remotecache hit,
        /// AppID/mangled-name heuristics, AutoCloud rule, else Unknown.
        /// </summary>
        private ClassifiedFile ClassifyFile(
            uint appId,
            string relativePath,
            string fullPath,
            AppCloudConfig cloudConfig,
            Dictionary<string, RemotecacheEntry> remotecacheEntries,
            Dictionary<string, HashSet<uint>> crossAppFileMap)
        {
            var result = new ClassifiedFile
            {
                RelativePath = relativePath,
                FullPath = fullPath
            };

            // Normalize path separators to forward slash for matching
            string normalizedPath = relativePath.Replace('\\', '/');

            if (remotecacheEntries != null && remotecacheEntries.TryGetValue(normalizedPath, out var entry))
            {
                if (entry.IsGhost)
                {
                    result.Classification = FileClassification.PollutionCrossApp;
                    result.Reason = "Ghost remotecache entry (SHA=0, syncstate=2) — cloud sync contamination from app 760 bucket";
                    return result;
                }

                // Real remotecache entry: check cross-app overlap
                if (crossAppFileMap != null && crossAppFileMap.TryGetValue(normalizedPath, out var appsWithFile))
                {
                    if (appsWithFile.Count > 1)
                    {
                        // This filename exists in 2+ namespace apps' remotecaches — contamination
                        var otherApps = appsWithFile.Where(a => a != appId).ToList();
                        result.Classification = FileClassification.PollutionCrossApp;
                        result.Reason = $"Filename present in {appsWithFile.Count} apps' remotecaches (also in: {string.Join(", ", otherApps.Take(5))}{(otherApps.Count > 5 ? "..." : "")}) — cross-app contamination from app 760 bucket";
                        return result;
                    }
                    else
                    {
                        // Filename unique to this app's remotecache — legitimate
                        result.Classification = FileClassification.Legitimate;
                        result.Reason = $"Real remotecache entry, unique to this app (SHA={entry.Sha?[..Math.Min(12, entry.Sha?.Length ?? 0)]}..., size={entry.Size})";
                        return result;
                    }
                }

                // In remotecache but cross-app map not available or filename not in map (shouldn't happen)
                result.Classification = FileClassification.Legitimate;
                result.Reason = $"Real remotecache entry (SHA={entry.Sha?[..Math.Min(12, entry.Sha?.Length ?? 0)]}..., size={entry.Size}, syncstate={entry.SyncState})";
                return result;
            }

            // These catch structural pollution regardless of remotecache state

            // Check: Does the path start with a different AppID directory?
            var appIdDirMatch = AppIdDirPattern.Match(normalizedPath);
            if (appIdDirMatch.Success)
            {
                uint embeddedAppId = uint.Parse(appIdDirMatch.Groups[1].Value);
                if (embeddedAppId != appId)
                {
                    result.Classification = FileClassification.PollutionAppIdDir;
                    result.SourceAppId = embeddedAppId;
                    result.Reason = $"File belongs to AppID {embeddedAppId}, not {appId}";
                    return result;
                }
            }

            // Check: Is this a mangled filename with AppID prefix and token?
            var mangledMatch = MangledFilePattern.Match(normalizedPath);
            if (mangledMatch.Success)
            {
                uint embeddedAppId = uint.Parse(mangledMatch.Groups[1].Value);
                if (embeddedAppId != appId)
                {
                    result.Classification = FileClassification.PollutionMangled;
                    result.SourceAppId = embeddedAppId;
                    result.Reason = $"Mangled filename from AppID {embeddedAppId} (token+tilde encoding)";
                    return result;
                }
            }

            if (cloudConfig != null && MatchesAutoCloudRules(normalizedPath, cloudConfig))
            {
                result.Classification = FileClassification.Legitimate;
                result.Reason = "Matches AutoCloud rules";
                return result;
            }

            // Files absent from remotecache can be legitimate (e.g. cc_save.dat),
            // so leave them Unknown rather than calling them PollutionOrphan.
            result.Classification = FileClassification.Unknown;
            if (remotecacheEntries != null && remotecacheEntries.Count > 0)
            {
                // Check cross-app map: does this filename appear in OTHER apps' remotecaches?
                if (crossAppFileMap != null && crossAppFileMap.TryGetValue(normalizedPath, out var otherAppsWithFile))
                {
                    var otherApps = otherAppsWithFile.Where(a => a != appId).ToList();
                    if (otherApps.Count > 0)
                    {
                        // File is NOT in this app's remotecache but IS in other apps' remotecaches
                        // → contamination that wasn't synced into this app's remotecache
                        result.Classification = FileClassification.PollutionCrossApp;
                        result.Reason = $"Not in this app's remotecache but present in {otherApps.Count} other app(s)' remotecaches ({string.Join(", ", otherApps.Take(5))}{(otherApps.Count > 5 ? "..." : "")}) — cross-app contamination";
                        return result;
                    }
                }

                result.Reason = $"Not in any namespace app's remotecache (app has {remotecacheEntries.Count} tracked files) — ambiguous";
            }
            else if (remotecacheEntries != null && remotecacheEntries.Count == 0)
            {
                result.Reason = "remotecache.vdf exists but has no tracked files — ambiguous";
            }
            else
            {
                result.Reason = "No remotecache.vdf — cannot determine if file is legitimate or contamination";
            }
            return result;
        }

        /// <summary>
        /// Check if a file path matches any of the app's AutoCloud save file rules.
        /// </summary>
        private bool MatchesAutoCloudRules(string relativePath, AppCloudConfig config)
        {
            foreach (var rule in config.SaveFiles)
            {
                string expectedPrefix = string.IsNullOrEmpty(rule.Path) ? "" : rule.Path.Replace('\\', '/');

                if (!string.IsNullOrEmpty(expectedPrefix) && !expectedPrefix.EndsWith("/"))
                    expectedPrefix += "/";

                if (!string.IsNullOrEmpty(expectedPrefix) && !relativePath.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                string remainingPath = string.IsNullOrEmpty(expectedPrefix)
                    ? relativePath
                    : relativePath[expectedPrefix.Length..];

                if (!rule.Recursive && remainingPath.Contains('/'))
                    continue;

                string fileName = Path.GetFileName(relativePath);
                if (MatchesGlobPattern(fileName, rule.Pattern))
                    return true;
            }

            return false;
        }

        // Cache compiled glob-to-regex patterns to avoid recompilation per file
        private static readonly ConcurrentDictionary<string, Regex> GlobRegexCache = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Simple glob pattern matching supporting * and ? wildcards.
        /// </summary>
        private static bool MatchesGlobPattern(string input, string pattern)
        {
            var regex = GlobRegexCache.GetOrAdd(pattern, p =>
            {
                string regexPattern = "^" + Regex.Escape(p)
                    .Replace("\\*", ".*")
                    .Replace("\\?", ".") + "$";
                return new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
            });
            return regex.IsMatch(input);
        }

        /// <summary>Parse remotecache.vdf into filename → RemotecacheEntry.</summary>
        private Dictionary<string, RemotecacheEntry> ParseRemotecache(string appDir, uint appId)
        {
            string vdfPath = Path.Combine(appDir, "remotecache.vdf");
            if (!File.Exists(vdfPath)) return null;

            var entries = new Dictionary<string, RemotecacheEntry>(StringComparer.OrdinalIgnoreCase);

            try
            {
                string[] lines = File.ReadAllLines(vdfPath);

                // Known VDF metadata keys that are NOT filenames.
                var knownKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    // Top-level metadata
                    "ChangeNumber", "OSType",
                    // Per-file entry properties
                    "root", "size", "localtime", "time", "remotetime",
                    "sha", "syncstate", "persiststate", "platformstosync2",
                    // Additional keys observed in newer Steam versions
                    "localfilename", "remotepath", "originalpathsha",
                    "filetype", "flags"
                };

                for (int i = 0; i < lines.Length; i++)
                {
                    string trimmed = lines[i].Trim();

                    if (trimmed.StartsWith("\"") && trimmed.EndsWith("\""))
                    {
                        string value = trimmed.Trim('"');

                        if (value == appId.ToString()) continue;
                        if (knownKeys.Contains(value)) continue;
                        if (uint.TryParse(value, out _)) continue;

                        // Look ahead for '{' to confirm this is a file entry block
                        int nextIdx = i + 1;
                        while (nextIdx < lines.Length && string.IsNullOrWhiteSpace(lines[nextIdx]))
                            nextIdx++;

                        if (nextIdx < lines.Length && lines[nextIdx].Trim() == "{")
                        {
                            string fileName = value.Replace('\\', '/');
                            var entry = new RemotecacheEntry { FileName = fileName };

                            // Parse the property block between { and }
                            int blockStart = nextIdx + 1;
                            for (int j = blockStart; j < lines.Length; j++)
                            {
                                string propLine = lines[j].Trim();
                                if (propLine == "}") break;

                                // Parse key-value pairs like: "sha"  "0000...0000"
                                var parts = propLine.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 2)
                                {
                                    string key = parts[0].Trim('"');
                                    string val = parts[^1].Trim('"');

                                    switch (key.ToLowerInvariant())
                                    {
                                        case "sha":
                                            entry.Sha = val;
                                            break;
                                        case "size":
                                            long.TryParse(val, out long size);
                                            entry.Size = size;
                                            break;
                                        case "syncstate":
                                            int.TryParse(val, out int syncState);
                                            entry.SyncState = syncState;
                                            break;
                                        case "root":
                                            int.TryParse(val, out int root);
                                            entry.Root = root;
                                            break;
                                        case "localtime":
                                            long.TryParse(val, out long localTime);
                                            entry.LocalTime = localTime;
                                            break;
                                        case "remotetime":
                                            long.TryParse(val, out long remoteTime);
                                            entry.RemoteTime = remoteTime;
                                            break;
                                    }
                                }
                            }

                            entries[fileName] = entry;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log($"    WARNING: Could not parse remotecache.vdf: {ex.Message}");
                return null;
            }

            return entries;
        }

        /// <summary>Move polluted files into a timestamped per-batch backup dir.</summary>
        private (int moved, List<ClassifiedFile> movedFiles) MoveToHoldover(string accountId, uint appId, string appDir, List<ClassifiedFile> pollutedFiles)
        {
            // Each cleanup batch gets its own timestamped directory
            string backupDir = Path.Combine(GetBackupBase(accountId), _backupTimestamp);
            string backupAppDir = Path.Combine(backupDir, appId.ToString());

            int moved = 0;
            var actuallyMoved = new List<ClassifiedFile>();
            foreach (var pf in pollutedFiles)
            {
                string destPath = Path.Combine(backupAppDir, pf.RelativePath);
                string destDir = Path.GetDirectoryName(destPath);

                try
                {
                    if (!Directory.Exists(destDir))
                        Directory.CreateDirectory(destDir);

                    // If destination already exists (shouldn't happen with timestamped dirs,
                    // but be defensive), add a numeric suffix — never lose data
                    string finalDest = destPath;
                    if (File.Exists(finalDest))
                    {
                        int suffix = 1;
                        string ext = Path.GetExtension(destPath);
                        string nameWithoutExt = destPath[..^ext.Length];
                        while (File.Exists(finalDest))
                            finalDest = $"{nameWithoutExt}.dup{suffix++}{ext}";
                        _log($"    NOTE: backup collision, saving as {Path.GetFileName(finalDest)}");
                    }

                    File.Move(pf.FullPath, finalDest);
                    moved++;
                    actuallyMoved.Add(pf);

                    // Record in undo log
                    _undoLog?.Operations.Add(new UndoOperation
                    {
                        Type = "file_move",
                        SourcePath = pf.FullPath,
                        DestPath = finalDest,
                        AppId = appId
                    });

                    _log($"    MOVED: {pf.RelativePath}");
                }
                catch (Exception ex)
                {
                    _log($"    FAILED to move {pf.RelativePath}: {ex.Message}");
                }
            }

            return (moved, actuallyMoved);
        }

        /// <summary>
        /// Save a backup of the remotecache.vdf content to the undo log before editing.
        /// </summary>
        private void BackupRemotecache(string appDir, uint appId)
        {
            if (_undoLog == null) return;

            string vdfPath = Path.Combine(appDir, "remotecache.vdf");
            if (!File.Exists(vdfPath)) return;

            try
            {
                string content = File.ReadAllText(vdfPath);
                _undoLog.Operations.Add(new UndoOperation
                {
                    Type = "remotecache_backup",
                    SourcePath = vdfPath,
                    BackupContent = content,
                    AppId = appId
                });
            }
            catch (Exception ex)
            {
                _log($"    WARNING: Could not backup remotecache.vdf: {ex.Message}");
            }
        }

        /// <summary>
        /// Remove entries from remotecache.vdf that correspond to moved (polluted) files.
        /// </summary>
        private void CleanRemotecache(string appDir, uint appId, List<ClassifiedFile> movedFiles)
        {
            string vdfPath = Path.Combine(appDir, "remotecache.vdf");
            if (!File.Exists(vdfPath)) return;

            var toRemove = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in movedFiles)
                toRemove.Add(f.RelativePath.Replace('\\', '/'));

            if (toRemove.Count == 0) return;

            try
            {
                string[] lines = File.ReadAllLines(vdfPath);
                var output = new List<string>();
                int i = 0;
                int removedEntries = 0;

                while (i < lines.Length)
                {
                    string trimmed = lines[i].Trim();

                    bool shouldRemove = false;
                    if (trimmed.StartsWith("\"") && trimmed.EndsWith("\""))
                    {
                        string key = trimmed.Trim('"');
                        if (toRemove.Contains(key))
                        {
                            int nextIdx = i + 1;
                            while (nextIdx < lines.Length && string.IsNullOrWhiteSpace(lines[nextIdx]))
                                nextIdx++;

                            if (nextIdx < lines.Length && lines[nextIdx].Trim() == "{")
                            {
                                shouldRemove = true;
                            }
                        }
                    }

                    if (shouldRemove)
                    {
                        i++; // skip header line
                        while (i < lines.Length && lines[i].Trim() != "{") i++;
                        if (i < lines.Length) i++; // skip {

                        int depth = 1;
                        while (i < lines.Length && depth > 0)
                        {
                            if (lines[i].Trim() == "{") depth++;
                            else if (lines[i].Trim() == "}") depth--;
                            i++;
                        }
                        removedEntries++;
                    }
                    else
                    {
                        output.Add(lines[i]);
                        i++;
                    }
                }

                if (removedEntries > 0)
                {
                    FileUtils.AtomicWriteAllLines(vdfPath, output);
                    _log($"    Cleaned {removedEntries} entries from remotecache.vdf");
                }
            }
            catch (Exception ex)
            {
                _log($"    WARNING: Failed to clean remotecache.vdf: {ex.Message}");
            }
        }

        /// <summary>
        /// Remove empty directories left behind after moving files.
        /// </summary>
        private void CleanEmptyDirs(string rootDir)
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(rootDir, "*", SearchOption.AllDirectories)
                    .OrderByDescending(d => d.Length))
                {
                    if (Directory.Exists(dir) &&
                        !Directory.EnumerateFileSystemEntries(dir).Any())
                    {
                        Directory.Delete(dir);

                        _undoLog?.Operations.Add(new UndoOperation
                        {
                            Type = "dir_delete",
                            SourcePath = dir
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _log($"    WARNING: Could not clean empty directories: {ex.Message}");
            }
        }

        private static string GetRelativePath(string fullPath, string basePath)
        {
            string relative = Path.GetRelativePath(basePath, fullPath);
            return relative.Replace('\\', '/');
        }
    }
}
