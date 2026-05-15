using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace CloudRedirect.Services
{
    /// <summary>
    /// Conflict resolution strategy when reverting files.
    /// </summary>
    internal enum RevertConflictMode
    {
        Skip,       // Skip files that already exist at the original location
        Overwrite,  // Overwrite existing files with the backup version
        Rename      // Rename the existing file with a .bak suffix, then restore
    }

    /// <summary>
    /// Result of a revert operation.
    /// </summary>
    internal class RevertResult
    {
        public int FilesRestored { get; set; }
        public int FilesSkipped { get; set; }
        public int FilesConflict { get; set; }
        public int RemotecachesRestored { get; set; }
        public int DirsRecreated { get; set; }
        public List<string> Errors { get; set; } = new();
    }

    /// <summary>
    /// Reverts cleanup operations using undo log files.
    /// No interactive prompts -- conflict mode is set at construction time.
    /// </summary>
    internal class CloudCleanupRevert
    {
        private readonly string _steamPath;
        private readonly RevertConflictMode _conflictMode;
        private readonly Action<string> _log;

        public CloudCleanupRevert(string steamPath, RevertConflictMode conflictMode = RevertConflictMode.Skip, Action<string>? log = null)
        {
            _steamPath = steamPath;
            _conflictMode = conflictMode;
            _log = log ?? (_ => { });
        }

        /// <summary>
        /// Validates that a path from the undo log is safe to use.
        /// Rejects relative paths and paths containing ".." traversal.
        /// Does NOT restrict to the Steam directory -- AutoCloud saves
        /// can live in AppData, Documents, game install dirs, etc.
        /// </summary>
        private bool IsPathSafe(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path)) return false;
                if (!Path.IsPathRooted(path)) return false;

                // Canonicalize and reject if ".." changed the result
                // (i.e. path was trying to traverse)
                var full = Path.GetFullPath(path);
                var normalized = Path.GetFullPath(path.Replace('/', '\\'));
                if (path.Contains("..")) return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Restore files from a specific undo log. Files are COPIED back to their
        /// original locations -- the backup is never modified or deleted.
        /// </summary>
        public RevertResult RestoreFromLog(string undoLogPath, bool dryRun = true)
        {
            _log("=== Restoring from Backup ===");
            _log("");
            return RevertUndoLog(undoLogPath, dryRun);
        }

        /// <summary>
        /// Revert a single undo log file.
        /// </summary>
        private RevertResult RevertUndoLog(string logPath, bool dryRun)
        {
            var result = new RevertResult();
            UndoLog log;
            try
            {
                string json = File.ReadAllText(logPath);
                log = JsonSerializer.Deserialize(json, CleanupJsonContext.Default.UndoLog);
            }
            catch (Exception ex)
            {
                _log($"  Failed to read undo log {Path.GetFileName(logPath)}: {ex.Message}");
                result.Errors.Add($"Failed to read {Path.GetFileName(logPath)}: {ex.Message}");
                return result;
            }

            if (log == null || log.Operations.Count == 0)
            {
                _log($"  {Path.GetFileName(logPath)}: empty, skipping");
                return result;
            }

            _log($"");
            _log($"  Undo log: {Path.GetFileName(logPath)} ({log.Timestamp})");
            _log($"  Operations: {log.Operations.Count}");

            // Replay in REVERSE order
            for (int i = log.Operations.Count - 1; i >= 0; i--)
            {
                var op = log.Operations[i];

                // Validate all paths from the undo log before using them
                if (op.SourcePath != null && !IsPathSafe(op.SourcePath))
                {
                    _log($"    SKIP (unsafe path): {op.SourcePath}");
                    result.FilesSkipped++;
                    continue;
                }
                if (op.DestPath != null && !IsPathSafe(op.DestPath))
                {
                    _log($"    SKIP (unsafe path): {op.DestPath}");
                    result.FilesSkipped++;
                    continue;
                }

                switch (op.Type)
                {
                    case "dir_delete":
                        if (!dryRun)
                        {
                            try
                            {
                                if (!Directory.Exists(op.SourcePath))
                                {
                                    Directory.CreateDirectory(op.SourcePath);
                                    result.DirsRecreated++;
                                }
                            }
                            catch (Exception ex)
                            {
                                _log($"    FAILED to recreate dir: {ex.Message}");
                            }
                        }
                        else
                        {
                            if (!Directory.Exists(op.SourcePath))
                                result.DirsRecreated++;
                        }
                        break;

                    case "remotecache_backup":
                        if (!dryRun)
                        {
                            try
                            {
                                FileUtils.AtomicWriteAllText(op.SourcePath, op.BackupContent);
                                result.RemotecachesRestored++;
                                _log($"    RESTORED remotecache.vdf for AppID {op.AppId}");
                            }
                            catch (Exception ex)
                            {
                                _log($"    FAILED to restore remotecache for AppID {op.AppId}: {ex.Message}");
                            }
                        }
                        else
                        {
                            _log($"    Would restore remotecache.vdf for AppID {op.AppId}");
                            result.RemotecachesRestored++;
                        }
                        break;

                    case "file_move":
                        // Resolve potentially-stale destPath (legacy logs may reference
                        // the old cleanup_backup/ dir after migration to cleanup_tab_backup/).
                        string resolvedDest = BackupDiscovery.ResolveDestPath(op.DestPath);
                        if (resolvedDest == null)
                        {
                             _log($"    SKIP (backup file missing): {op.DestPath}");
                            result.FilesSkipped++;
                            break;
                        }

                        // Re-validate the resolved path (defense-in-depth: the path
                        // substitution could theoretically produce an unsafe path).
                        if (!IsPathSafe(resolvedDest))
                        {
                            _log($"    SKIP (unsafe resolved path): {resolvedDest}");
                            result.FilesSkipped++;
                            break;
                        }

                        if (File.Exists(op.SourcePath))
                        {
                            // CONFLICT: file already exists at original location
                            switch (_conflictMode)
                            {
                                case RevertConflictMode.Skip:
                                    if (!dryRun)
                                        _log($"    SKIP (conflict): {Path.GetFileName(op.SourcePath)}");
                                    else
                                        _log($"    Would SKIP (conflict): {Path.GetFileName(op.SourcePath)}");
                                    result.FilesSkipped++;
                                    result.FilesConflict++;
                                    break;

                                    case RevertConflictMode.Overwrite:
                                    if (!dryRun)
                                    {
                                        try
                                        {
                                            File.Delete(op.SourcePath);
                                            EnsureDirectoryExists(op.SourcePath);
                                            File.Copy(resolvedDest, op.SourcePath);
                                            result.FilesRestored++;
                                            result.FilesConflict++;
                                            _log($"    RESTORED (overwrite): {Path.GetFileName(op.SourcePath)}");
                                        }
                                        catch (Exception ex)
                                        {
                                            _log($"    FAILED: {ex.Message}");
                                        }
                                    }
                                    else
                                    {
                                        _log($"    Would OVERWRITE: {Path.GetFileName(op.SourcePath)}");
                                        result.FilesRestored++;
                                        result.FilesConflict++;
                                    }
                                    break;

                                case RevertConflictMode.Rename:
                                    if (!dryRun)
                                    {
                                        try
                                        {
                                            string bakPath = op.SourcePath + ".pre-revert.bak";
                                            int bakNum = 1;
                                            while (File.Exists(bakPath))
                                                bakPath = op.SourcePath + $".pre-revert.{bakNum++}.bak";

                                            File.Move(op.SourcePath, bakPath);
                                            EnsureDirectoryExists(op.SourcePath);
                                            File.Copy(resolvedDest, op.SourcePath);
                                            result.FilesRestored++;
                                            result.FilesConflict++;
                                            _log($"    RESTORED (renamed existing): {Path.GetFileName(op.SourcePath)}");
                                        }
                                        catch (Exception ex)
                                        {
                                            _log($"    FAILED: {ex.Message}");
                                        }
                                    }
                                    else
                                    {
                                        _log($"    Would RENAME existing + RESTORE: {Path.GetFileName(op.SourcePath)}");
                                        result.FilesRestored++;
                                        result.FilesConflict++;
                                    }
                                    break;
                            }
                        }
                        else
                        {
                            // No conflict -- just move back
                            if (!dryRun)
                            {
                                try
                                {
                                    EnsureDirectoryExists(op.SourcePath);
                                    File.Copy(resolvedDest, op.SourcePath);
                                    result.FilesRestored++;
                                    _log($"    RESTORED: {Path.GetFileName(op.SourcePath)}");
                                }
                                catch (Exception ex)
                                {
                                    _log($"    FAILED to restore {Path.GetFileName(op.SourcePath)}: {ex.Message}");
                                }
                            }
                            else
                            {
                                _log($"    Would restore: {Path.GetFileName(op.SourcePath)}");
                                result.FilesRestored++;
                            }
                        }
                        break;

                    default:
                        _log($"    Unknown operation type: {op.Type}, skipping");
                        break;
                }
            }

            // Summary for this undo log
            _log("");
            string prefix = dryRun ? "Would restore" : "Restored";
            _log($"  {prefix}: {result.FilesRestored} file(s), {result.RemotecachesRestored} remotecache(s), {result.DirsRecreated} dir(s)");
            if (result.FilesSkipped > 0)
                _log($"  Skipped: {result.FilesSkipped} file(s)");
            if (result.FilesConflict > 0)
                _log($"  Conflicts: {result.FilesConflict}");

            // Backup data is intentionally preserved -- never rename or delete undo logs
            // or clean up backup directories. Users can restore the same backup multiple times.

            return result;
        }

        private static void EnsureDirectoryExists(string filePath)
        {
            string dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);
        }

    }
}
