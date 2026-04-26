using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;

namespace CloudRedirect.Services
{
    /// <summary>One backup entry, as displayed in the Restore tab.</summary>
    internal class BackupInfo
    {
        public string Id { get; set; }
        public string UndoLogPath { get; set; }
        public string BackupDir { get; set; }
        public string AccountId { get; set; }
        public DateTime Timestamp { get; set; }
        public int FileCount { get; set; }
        public int TotalOperations { get; set; }
        public long TotalBytes { get; set; }
        public List<uint> AppIds { get; set; } = new();
        public bool IsLegacy { get; set; }

        /// <summary>"cleanup" or "app_delete".</summary>
        public string Category { get; set; } = "";
    }

    /// <summary>
    /// Backup folder names under cloud_redirect/.
    /// </summary>
    internal static class BackupPaths
    {
        /// <summary>Backups from the Cleanup tab (SteamTools contamination cleanup).</summary>
        public const string CleanupDir = "cleanup_tab_backup";

        /// <summary>Backups from the Apps tab (full app save deletion).</summary>
        public const string AppDeleteDir = "app_tab_backup";

        /// <summary>Legacy backup dir (pre-separation). Migrated on first access.</summary>
        public const string LegacyDir = "cleanup_backup";

        public static string GetCleanupRoot(string steamPath)
            => Path.Combine(steamPath, "cloud_redirect", CleanupDir);

        public static string GetAppDeleteRoot(string steamPath)
            => Path.Combine(steamPath, "cloud_redirect", AppDeleteDir);

        public static string GetLegacyRoot(string steamPath)
            => Path.Combine(steamPath, "cloud_redirect", LegacyDir);
    }

    /// <summary>
    /// Lists backups across accounts; migrates legacy cleanup_backup/ on first call.
    /// </summary>
    internal static class BackupDiscovery
    {
        /// <summary>
        /// List only cleanup tab backups.
        /// </summary>
        public static List<BackupInfo> ListCleanupBackups(string steamPath)
        {
            MigrateLegacyBackups(steamPath);

            var backups = new List<BackupInfo>();
            ScanBackupRoot(backups, BackupPaths.GetCleanupRoot(steamPath), "cleanup");
            return backups.OrderByDescending(b => b.Timestamp).ToList();
        }

        /// <summary>
        /// List only app delete backups.
        /// </summary>
        public static List<BackupInfo> ListAppDeleteBackups(string steamPath)
        {
            MigrateLegacyBackups(steamPath);

            var backups = new List<BackupInfo>();
            ScanBackupRoot(backups, BackupPaths.GetAppDeleteRoot(steamPath), "app_delete");
            return backups.OrderByDescending(b => b.Timestamp).ToList();
        }

        /// <summary>Scan one backup root for account/timestamp entries.</summary>
        private static void ScanBackupRoot(List<BackupInfo> backups, string backupRoot, string category)
        {
            if (!Directory.Exists(backupRoot)) return;

            foreach (var accountDir in Directory.GetDirectories(backupRoot))
            {
                string accountId = Path.GetFileName(accountDir);
                if (!uint.TryParse(accountId, out _)) continue;

                // New: timestamped subdirs with undo_log.json
                foreach (var subDir in Directory.GetDirectories(accountDir))
                {
                    var logPath = Path.Combine(subDir, "undo_log.json");
                    if (File.Exists(logPath))
                    {
                        var info = ParseBackupFromLog(logPath, Path.GetFileName(subDir), subDir, accountId, isLegacy: false);
                        if (info != null)
                        {
                            info.Category = category;
                            backups.Add(info);
                        }
                    }
                }

                // Legacy: undo_log_*.json at account root
                foreach (var logPath in Directory.GetFiles(accountDir, "undo_log_*.json"))
                {
                    if (logPath.EndsWith(".reverted.json", StringComparison.OrdinalIgnoreCase))
                        continue;
                    var info = ParseBackupFromLog(logPath, Path.GetFileNameWithoutExtension(logPath), accountDir, accountId, isLegacy: true);
                    if (info != null)
                    {
                        info.Category = category;
                        backups.Add(info);
                    }
                }
            }
        }

        private static bool _legacyMigrationDone;
        private static readonly object _legacyMigrationGate = new();

        /// <summary>Test-only: re-arm the migration guard.</summary>
        internal static void ResetMigrationState()
        {
            lock (_legacyMigrationGate)
            {
                _legacyMigrationDone = false;
            }
        }

        /// <summary>
        /// Idempotent + once-per-process migration of cleanup_backup/ into the
        /// new split layout. Locked to defeat concurrent CleanupPage/AppsPage init.
        /// </summary>
        private static void MigrateLegacyBackups(string steamPath)
        {
            if (Volatile.Read(ref _legacyMigrationDone)) return;

            lock (_legacyMigrationGate)
            {
                if (_legacyMigrationDone) return;
                MigrateLegacyBackupsLocked(steamPath);
                _legacyMigrationDone = true;
            }
        }

        // Caller must hold _legacyMigrationGate.
        private static void MigrateLegacyBackupsLocked(string steamPath)
        {
            string cleanupRoot = BackupPaths.GetCleanupRoot(steamPath);
            string appDeleteRoot = BackupPaths.GetAppDeleteRoot(steamPath);

            // Phase 1: fix delete_-prefixed dirs left by a prior buggy migration.
            FixBrokenAppDeleteDirs(appDeleteRoot);

            // Phase 2: migrate remaining legacy backups.
            string legacyRoot = BackupPaths.GetLegacyRoot(steamPath);
            if (!Directory.Exists(legacyRoot)) return;

            foreach (var accountDir in Directory.GetDirectories(legacyRoot))
            {
                string accountId = Path.GetFileName(accountDir);
                if (!uint.TryParse(accountId, out _)) continue;

                foreach (var subDir in Directory.GetDirectories(accountDir))
                {
                    string dirName = Path.GetFileName(subDir);
                    string destRoot;
                    string destDirName;

                    if (dirName.StartsWith("delete_", StringComparison.OrdinalIgnoreCase))
                    {
                        // delete_{appId}_{ts} -> {appId}_{ts} under app_tab_backup/.
                        destRoot = appDeleteRoot;
                        destDirName = dirName.Substring("delete_".Length);
                    }
                    else
                    {
                        // Timestamp dir -> cleanup_tab_backup/.
                        destRoot = cleanupRoot;
                        destDirName = dirName;
                    }

                    string destDir = Path.Combine(destRoot, accountId, destDirName);
                    if (Directory.Exists(destDir)) continue; // already migrated

                    try
                    {
                        Directory.CreateDirectory(Path.Combine(destRoot, accountId));
                        Directory.Move(subDir, destDir);
                        RewriteUndoLogPaths(destDir, subDir, destDir);
                    }
                    catch
                    {
                        // Best-effort; failed moves stay in legacy.
                    }
                }

                // Legacy account-root logs -> cleanup_tab_backup/.
                foreach (var logFile in Directory.GetFiles(accountDir, "undo_log_*.json"))
                {
                    string fileName = Path.GetFileName(logFile);
                    string destFile = Path.Combine(cleanupRoot, accountId, fileName);
                    if (File.Exists(destFile)) continue;

                    try
                    {
                        Directory.CreateDirectory(Path.Combine(cleanupRoot, accountId));
                        File.Move(logFile, destFile);
                    }
                    catch { }
                }

                // Remove now-empty account dir.
                try
                {
                    if (!Directory.EnumerateFileSystemEntries(accountDir).Any())
                        Directory.Delete(accountDir);
                }
                catch { }
            }

            // Remove now-empty legacy root.
            try
            {
                if (!Directory.EnumerateFileSystemEntries(legacyRoot).Any())
                    Directory.Delete(legacyRoot);
            }
            catch { }
        }

        /// <summary>Strip leftover delete_ prefix on already-moved app_tab dirs.</summary>
        private static void FixBrokenAppDeleteDirs(string appDeleteRoot)
        {
            if (!Directory.Exists(appDeleteRoot)) return;

            foreach (var accountDir in Directory.GetDirectories(appDeleteRoot))
            {
                string accountId = Path.GetFileName(accountDir);
                if (!uint.TryParse(accountId, out _)) continue;

                foreach (var subDir in Directory.GetDirectories(accountDir))
                {
                    string dirName = Path.GetFileName(subDir);
                    if (!dirName.StartsWith("delete_", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string fixedName = dirName.Substring("delete_".Length);
                    string fixedDir = Path.Combine(accountDir, fixedName);
                    if (Directory.Exists(fixedDir)) continue;

                    try
                    {
                        Directory.Move(subDir, fixedDir);
                        RewriteUndoLogPaths(fixedDir, subDir, fixedDir);
                    }
                    catch { }
                }
            }
        }

        /// <summary>Repoint DestPath entries in undo_log.json from oldDir to newDir.</summary>
        private static void RewriteUndoLogPaths(string backupDir, string oldDir, string newDir)
        {
            string logPath = Path.Combine(backupDir, "undo_log.json");
            if (!File.Exists(logPath)) return;

            try
            {
                string json = File.ReadAllText(logPath);
                var log = JsonSerializer.Deserialize(json, CleanupJsonContext.Default.UndoLog);
                if (log == null) return;

                string oldPrefix = oldDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;
                string newPrefix = newDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;

                bool changed = false;
                foreach (var op in log.Operations)
                {
                    if (string.IsNullOrEmpty(op.DestPath)) continue;

                    if (op.DestPath.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        op.DestPath = newPrefix + op.DestPath.Substring(oldPrefix.Length);
                        changed = true;
                    }
                    else if (op.DestPath.Equals(oldDir, StringComparison.OrdinalIgnoreCase))
                    {
                        op.DestPath = newDir;
                        changed = true;
                    }
                }

                // Fall back to relative-tail rebinding for paths older than oldDir.
                {
                    var filesOnDisk = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    try
                    {
                        foreach (var f in new DirectoryInfo(backupDir).EnumerateFiles("*", SearchOption.AllDirectories))
                            filesOnDisk.Add(f.FullName);
                    }
                    catch { }

                    string backupId = Path.GetFileName(
                        backupDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

                    foreach (var op in log.Operations)
                    {
                        if (string.IsNullOrEmpty(op.DestPath)) continue;
                        if (op.DestPath.StartsWith(newPrefix, StringComparison.OrdinalIgnoreCase)) continue;

                        // Tail match preserves subdir structure (filename match is ambiguous).
                        string relativeTail = ExtractRelativeTail(op.DestPath, backupId);
                        if (relativeTail != null)
                        {
                            relativeTail = relativeTail.Replace('/', Path.DirectorySeparatorChar);
                            string candidate = Path.Combine(backupDir, relativeTail);
                            if (filesOnDisk.Contains(candidate))
                            {
                                op.DestPath = candidate;
                                changed = true;
                            }
                        }
                    }
                }

                if (changed)
                {
                    string updated = JsonSerializer.Serialize(log, CleanupJsonContext.Default.UndoLog);
                    FileUtils.AtomicWriteAllText(logPath, updated);
                }
            }
            catch { }
        }

        private static BackupInfo ParseBackupFromLog(string logPath, string id, string backupDir, string accountId, bool isLegacy)
        {
            try
            {
                string json = File.ReadAllText(logPath);
                var log = JsonSerializer.Deserialize(json, CleanupJsonContext.Default.UndoLog);
                if (log == null) return null;

                var fileMoves = log.Operations.Where(op => op.Type == "file_move").ToList();
                var appIds = fileMoves.Select(op => op.AppId).Where(a => a > 0).Distinct().OrderBy(a => a).ToList();

                // One directory enumeration replaces N File.Exists calls.
                long totalBytes = 0;
                int existingFiles = 0;
                if (!isLegacy && Directory.Exists(backupDir))
                {
                    var backupFiles = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
                    try
                    {
                        var dirInfo = new DirectoryInfo(backupDir);
                        foreach (var fi in dirInfo.EnumerateFiles("*", SearchOption.AllDirectories))
                            backupFiles[fi.FullName] = fi.Length;
                    }
                    catch { }

                    // Suffix index: rebind by relative tail when exact paths miss.
                    string normalizedBackupDir = backupDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                        + Path.DirectorySeparatorChar;
                    Dictionary<string, long> suffixIndex = null;

                    foreach (var op in fileMoves)
                    {
                        if (backupFiles.TryGetValue(op.DestPath, out long fileSize))
                        {
                            existingFiles++;
                            totalBytes += fileSize;
                        }
                        else
                        {
                            // Fallback: rebind via relative tail.
                            if (suffixIndex == null)
                            {
                                suffixIndex = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
                                foreach (var kv in backupFiles)
                                {
                                    if (kv.Key.StartsWith(normalizedBackupDir, StringComparison.OrdinalIgnoreCase))
                                    {
                                        string suffix = kv.Key.Substring(normalizedBackupDir.Length);
                                        suffixIndex[suffix] = kv.Value;
                                    }
                                }
                            }

                            // destPath: {someOldBase}/{accountId}/{backupId}/{tail}.
                            string relativeTail = ExtractRelativeTail(op.DestPath, id);
                            if (relativeTail != null)
                            {
                                relativeTail = relativeTail.Replace('/', Path.DirectorySeparatorChar);
                                if (suffixIndex.TryGetValue(relativeTail, out long fallbackSize))
                                {
                                    existingFiles++;
                                    totalBytes += fallbackSize;
                                }
                            }
                        }
                    }
                }
                else
                {
                    foreach (var op in fileMoves)
                    {
                        string resolved = ResolveDestPath(op.DestPath);
                        if (resolved != null)
                        {
                            existingFiles++;
                            try { totalBytes += new FileInfo(resolved).Length; } catch { }
                        }
                    }
                }

                DateTime timestamp = DateTime.MinValue;
                if (DateTime.TryParse(log.Timestamp, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
                    timestamp = parsed;

                return new BackupInfo
                {
                    Id = id,
                    UndoLogPath = logPath,
                    BackupDir = backupDir,
                    AccountId = accountId,
                    Timestamp = timestamp,
                    FileCount = existingFiles,
                    TotalOperations = fileMoves.Count,
                    TotalBytes = totalBytes,
                    AppIds = appIds,
                    IsLegacy = isLegacy
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Returns the path tail after the backupId segment, or null.</summary>
        private static string ExtractRelativeTail(string destPath, string backupId)
        {
            string normalized = destPath.Replace('/', Path.DirectorySeparatorChar);
            string needle = Path.DirectorySeparatorChar + backupId + Path.DirectorySeparatorChar;
            int idx = normalized.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;
            int start = idx + needle.Length;
            return start < normalized.Length ? normalized.Substring(start) : null;
        }

        /// <summary>Try the original path then the cleanup_backup→cleanup_tab_backup rewrite.</summary>
        internal static string ResolveDestPath(string destPath)
        {
            if (string.IsNullOrEmpty(destPath)) return null;
            if (File.Exists(destPath)) return destPath;

            string normalized = destPath.Replace('/', Path.DirectorySeparatorChar);
            string legacySeg = Path.DirectorySeparatorChar + BackupPaths.LegacyDir + Path.DirectorySeparatorChar;
            string newSeg = Path.DirectorySeparatorChar + BackupPaths.CleanupDir + Path.DirectorySeparatorChar;

            int idx = normalized.IndexOf(legacySeg, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                string corrected = normalized.Substring(0, idx) + newSeg + normalized.Substring(idx + legacySeg.Length);
                if (File.Exists(corrected)) return corrected;
            }

            return null;
        }
    }
}
