using System.Text.Json;
using CloudRedirect.Services;
using Xunit;

namespace CloudRedirect.Tests;

/// <summary>
/// Tests for BackupDiscovery: ResolveDestPath, ListBackups, legacy migration,
/// and ParseBackupFromLog (via ListBackups).
/// </summary>
public class BackupDiscoveryTests
{
    private string GetTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "CloudRedirect_Tests_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>
    /// Creates a minimal undo_log.json with the given file_move operations.
    /// </summary>
    private static string MakeUndoLogJson(string timestamp, params (string src, string dest, uint appId)[] fileMoves)
    {
        var log = new UndoLog
        {
            Timestamp = timestamp,
            Version = 1,
            Operations = fileMoves.Select(fm => new UndoOperation
            {
                Type = "file_move",
                SourcePath = fm.src,
                DestPath = fm.dest,
                AppId = fm.appId
            }).ToList()
        };
        return JsonSerializer.Serialize(log, CleanupJsonContext.Default.UndoLog);
    }

    // ── ResolveDestPath ────────────────────────────────────────────────

    [Fact]
    public void ResolveDestPath_NullReturnsNull()
    {
        Assert.Null(BackupDiscovery.ResolveDestPath(null));
    }

    [Fact]
    public void ResolveDestPath_EmptyReturnsNull()
    {
        Assert.Null(BackupDiscovery.ResolveDestPath(""));
    }

    [Fact]
    public void ResolveDestPath_ExistingFileReturnsSamePath()
    {
        var dir = GetTempDir();
        try
        {
            var file = Path.Combine(dir, "test.bin");
            File.WriteAllBytes(file, new byte[] { 0x01 });

            var result = BackupDiscovery.ResolveDestPath(file);
            Assert.Equal(file, result);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ResolveDestPath_LegacyPathResolvedToNewLocation()
    {
        var dir = GetTempDir();
        try
        {
            // Create the new-location file (cleanup_tab_backup)
            var newPath = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "54303850", "foo.bin");
            Directory.CreateDirectory(Path.GetDirectoryName(newPath)!);
            File.WriteAllBytes(newPath, new byte[] { 0x42 });

            // Construct the legacy path (cleanup_backup) that no longer exists
            var legacyPath = Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir, "54303850", "foo.bin");

            var result = BackupDiscovery.ResolveDestPath(legacyPath);
            Assert.Equal(newPath, result);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ResolveDestPath_NonExistentReturnsNull()
    {
        var result = BackupDiscovery.ResolveDestPath(@"C:\nonexistent\path\file.bin");
        Assert.Null(result);
    }

    // ── ListBackups: empty ─────────────────────────────────────────────

    [Fact]
    public void ListBackups_EmptyDirReturnsEmptyList()
    {
        var dir = GetTempDir();
        try
        {
            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Empty(backups);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── ListBackups: new-format backup ─────────────────────────────────

    [Fact]
    public void ListBackups_NewFormatBackup_ParsesCorrectly()
    {
        var dir = GetTempDir();
        try
        {
            // Setup: cleanup_tab_backup/12345678/1221480_20250407/undo_log.json
            var backupDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678", "1221480_20250407");
            Directory.CreateDirectory(backupDir);

            // Create a backup file
            var backupFile = Path.Combine(backupDir, "save.dat");
            File.WriteAllBytes(backupFile, new byte[1024]);

            // Create undo_log.json referencing the backup file
            var json = MakeUndoLogJson("2025-04-07T12:00:00Z",
                (@"C:\Users\test\save.dat", backupFile, 1221480));
            File.WriteAllText(Path.Combine(backupDir, "undo_log.json"), json);

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(backups);

            var b = backups[0];
            Assert.Equal("1221480_20250407", b.Id);
            Assert.Equal("12345678", b.AccountId);
            Assert.Equal("cleanup", b.Category);
            Assert.False(b.IsLegacy);
            Assert.Single(b.AppIds);
            Assert.Equal(1221480u, b.AppIds[0]);
            Assert.Equal(1, b.FileCount);
            Assert.Equal(1024, b.TotalBytes);
            Assert.Equal(1, b.TotalOperations);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── ListBackups: legacy format ─────────────────────────────────────

    [Fact]
    public void ListBackups_LegacyFormat_ParsesCorrectly()
    {
        var dir = GetTempDir();
        try
        {
            // Setup: cleanup_tab_backup/12345678/undo_log_20250407.json
            var accountDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678");
            Directory.CreateDirectory(accountDir);

            // Create a backup file that the legacy log references
            var backupFile = Path.Combine(accountDir, "save.dat");
            File.WriteAllBytes(backupFile, new byte[512]);

            var json = MakeUndoLogJson("2025-04-07T10:00:00Z",
                (@"C:\original\save.dat", backupFile, 9999));
            File.WriteAllText(Path.Combine(accountDir, "undo_log_20250407.json"), json);

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(backups);

            var b = backups[0];
            Assert.Equal("undo_log_20250407", b.Id);
            Assert.True(b.IsLegacy);
            Assert.Equal(9999u, b.AppIds[0]);
            Assert.Equal(1, b.FileCount);
            Assert.Equal(512, b.TotalBytes);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── ListBackups: skips .reverted.json ──────────────────────────────

    [Fact]
    public void ListBackups_SkipsRevertedFiles()
    {
        var dir = GetTempDir();
        try
        {
            var accountDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678");
            Directory.CreateDirectory(accountDir);

            var json = MakeUndoLogJson("2025-04-07T10:00:00Z",
                (@"C:\original\save.dat", @"C:\backup\save.dat", 100));

            // Normal log
            File.WriteAllText(Path.Combine(accountDir, "undo_log_20250407.json"), json);
            // Reverted log -- should be skipped
            File.WriteAllText(Path.Combine(accountDir, "undo_log_20250406.reverted.json"), json);

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(backups);
            Assert.Equal("undo_log_20250407", backups[0].Id);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── ListBackups: app delete backups ────────────────────────────────

    [Fact]
    public void ListAppDeleteBackups_ReturnsOnlyAppDeleteCategory()
    {
        var dir = GetTempDir();
        try
        {
            // Create one cleanup backup
            var cleanupDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678", "backup1");
            Directory.CreateDirectory(cleanupDir);
            File.WriteAllText(Path.Combine(cleanupDir, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T10:00:00Z", (@"C:\a", @"C:\b", 100)));

            // Create one app delete backup
            var appDir = Path.Combine(dir, "cloud_redirect", BackupPaths.AppDeleteDir, "12345678", "200_20250407");
            Directory.CreateDirectory(appDir);
            File.WriteAllText(Path.Combine(appDir, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T11:00:00Z", (@"C:\c", @"C:\d", 200)));

            var cleanupBackups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(cleanupBackups);
            Assert.Equal("cleanup", cleanupBackups[0].Category);

            var appBackups = BackupDiscovery.ListAppDeleteBackups(dir);
            Assert.Single(appBackups);
            Assert.Equal("app_delete", appBackups[0].Category);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── Legacy migration ───────────────────────────────────────────────

    [Fact]
    public void ListBackups_MigratesLegacyCleanupBackups()
    {
        BackupDiscovery.ResetMigrationState();
        var dir = GetTempDir();
        try
        {
            // Create legacy backup at cleanup_backup/12345678/ts_20250407/undo_log.json
            var legacyDir = Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir, "12345678", "ts_20250407");
            Directory.CreateDirectory(legacyDir);

            var backupFile = Path.Combine(legacyDir, "save.dat");
            File.WriteAllBytes(backupFile, new byte[256]);

            File.WriteAllText(Path.Combine(legacyDir, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T10:00:00Z", (@"C:\orig\save.dat", backupFile, 500)));

            // ListCleanupBackups should trigger migration
            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(backups);
            Assert.Equal("cleanup", backups[0].Category);

            // Legacy dir should be gone
            Assert.False(Directory.Exists(Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir)));

            // New location should exist
            var newDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678", "ts_20250407");
            Assert.True(Directory.Exists(newDir));
            Assert.True(File.Exists(Path.Combine(newDir, "save.dat")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ListBackups_MigratesLegacyAppDeleteBackups()
    {
        BackupDiscovery.ResetMigrationState();
        var dir = GetTempDir();
        try
        {
            // Legacy app delete: cleanup_backup/12345678/delete_600_20250407/undo_log.json
            var legacyDir = Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir, "12345678", "delete_600_20250407");
            Directory.CreateDirectory(legacyDir);
            File.WriteAllText(Path.Combine(legacyDir, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T10:00:00Z", (@"C:\orig\save.dat", @"C:\dummy", 600)));

            var backups = BackupDiscovery.ListAppDeleteBackups(dir);
            Assert.Single(backups);
            Assert.Equal("app_delete", backups[0].Category);

            // Should be migrated with delete_ prefix stripped
            var newDir = Path.Combine(dir, "cloud_redirect", BackupPaths.AppDeleteDir, "12345678", "600_20250407");
            Assert.True(Directory.Exists(newDir));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ListBackups_MigratesLegacyStandaloneUndoLogs()
    {
        BackupDiscovery.ResetMigrationState();
        var dir = GetTempDir();
        try
        {
            // Legacy standalone: cleanup_backup/12345678/undo_log_20250407.json
            var legacyAccountDir = Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir, "12345678");
            Directory.CreateDirectory(legacyAccountDir);
            File.WriteAllText(Path.Combine(legacyAccountDir, "undo_log_20250407.json"),
                MakeUndoLogJson("2025-04-07T10:00:00Z", (@"C:\orig\save.dat", @"C:\dummy", 700)));

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(backups);

            // Should be moved to cleanup_tab_backup
            var newFile = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678", "undo_log_20250407.json");
            Assert.True(File.Exists(newFile));
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── Stale destPath fallback (suffix index) ─────────────────────────

    [Fact]
    public void ListBackups_NewFormat_StaleDestPathUseSuffixFallback()
    {
        var dir = GetTempDir();
        try
        {
            // Setup: the backup dir exists at the new location
            var backupDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678", "mybackup");
            Directory.CreateDirectory(backupDir);

            // Create a backup file in a subdirectory
            var subDir = Path.Combine(backupDir, "files", "1229490");
            Directory.CreateDirectory(subDir);
            File.WriteAllBytes(Path.Combine(subDir, "save.dat"), new byte[2048]);

            // The undo_log.json references the OLD location (cleanup_backup instead of cleanup_tab_backup)
            var staleDestPath = Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir, "12345678", "mybackup", "files", "1229490", "save.dat");

            File.WriteAllText(Path.Combine(backupDir, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T12:00:00Z",
                    (@"C:\original\save.dat", staleDestPath, 1229490)));

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(backups);
            // The fallback should resolve the file via suffix matching
            Assert.Equal(1, backups[0].FileCount);
            Assert.Equal(2048, backups[0].TotalBytes);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── Multiple app IDs in one backup ─────────────────────────────────

    [Fact]
    public void ListBackups_MultipleAppIds_AllExtracted()
    {
        var dir = GetTempDir();
        try
        {
            var backupDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678", "multi");
            Directory.CreateDirectory(backupDir);

            File.WriteAllText(Path.Combine(backupDir, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T12:00:00Z",
                    (@"C:\a", @"C:\b", 100),
                    (@"C:\c", @"C:\d", 200),
                    (@"C:\e", @"C:\f", 100)));

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Single(backups);
            Assert.Equal(2, backups[0].AppIds.Count);
            Assert.Contains(100u, backups[0].AppIds);
            Assert.Contains(200u, backups[0].AppIds);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── Non-numeric account dirs are skipped ───────────────────────────

    [Fact]
    public void ListBackups_SkipsNonNumericAccountDirs()
    {
        var dir = GetTempDir();
        try
        {
            // Non-numeric dir should be ignored
            var badDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "notanumber", "backup1");
            Directory.CreateDirectory(badDir);
            File.WriteAllText(Path.Combine(badDir, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T12:00:00Z", (@"C:\a", @"C:\b", 100)));

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Empty(backups);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── Concurrent migration regression ────────────────────────────────

    [Fact]
    public void ListBackups_ConcurrentMigration_DoesNotRaceOnDirectoryMove()
    {
        // Reproduces the W4 race: CleanupPage and AppsPage both spawn
        // Task.Run(() => BackupDiscovery.List...) from their Loaded
        // handlers. Without serialization both threads pass the
        // un-set guard and race on Directory.Move, surfacing
        // "destination already exists" IOExceptions.
        BackupDiscovery.ResetMigrationState();
        var dir = GetTempDir();
        try
        {
            // Seed a legacy tree with both cleanup and app-delete entries
            // so MigrateLegacyBackups has real work to do.
            var legacyAccount = Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir, "12345678");
            for (int i = 0; i < 5; i++)
            {
                var subDir = Path.Combine(legacyAccount, $"ts_2025040{i}");
                Directory.CreateDirectory(subDir);
                File.WriteAllText(Path.Combine(subDir, "undo_log.json"),
                    MakeUndoLogJson($"2025-04-0{i}T10:00:00Z", (@"C:\orig\save.dat", @"C:\dummy", (uint)(100 + i))));
            }
            for (int i = 0; i < 5; i++)
            {
                var subDir = Path.Combine(legacyAccount, $"delete_60{i}_2025040{i}");
                Directory.CreateDirectory(subDir);
                File.WriteAllText(Path.Combine(subDir, "undo_log.json"),
                    MakeUndoLogJson($"2025-04-0{i}T10:00:00Z", (@"C:\orig\save.dat", @"C:\dummy", (uint)(600 + i))));
            }

            // Fire several callers in parallel and use a barrier so
            // they all attempt the migration body concurrently. Without
            // serialization the second-mover's Directory.Move will fail
            // with "destination already exists" and surface as an
            // IOException out of the threadpool task.
            const int callers = 6;
            var barrier = new Barrier(callers);
            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();
            var threads = new Thread[callers];
            for (int i = 0; i < callers; i++)
            {
                int idx = i;
                threads[i] = new Thread(() =>
                {
                    barrier.SignalAndWait();
                    try
                    {
                        if (idx % 2 == 0) BackupDiscovery.ListCleanupBackups(dir);
                        else BackupDiscovery.ListAppDeleteBackups(dir);
                    }
                    catch (Exception ex) { exceptions.Add(ex); }
                });
            }
            foreach (var t in threads) t.Start();
            foreach (var t in threads) t.Join();

            Assert.Empty(exceptions);

            // Migration must have completed exactly once: both new
            // roots populated, legacy root removed.
            Assert.False(Directory.Exists(Path.Combine(dir, "cloud_redirect", BackupPaths.LegacyDir)));
            var cleanupBackups = BackupDiscovery.ListCleanupBackups(dir);
            var appBackups = BackupDiscovery.ListAppDeleteBackups(dir);
            Assert.Equal(5, cleanupBackups.Count);
            Assert.Equal(5, appBackups.Count);
        }
        finally { Directory.Delete(dir, true); }
    }

    // ── Backups sorted by timestamp (newest first) ─────────────────────

    [Fact]
    public void ListBackups_SortedByTimestampDescending()
    {
        var dir = GetTempDir();
        try
        {
            var accountDir = Path.Combine(dir, "cloud_redirect", BackupPaths.CleanupDir, "12345678");

            var dir1 = Path.Combine(accountDir, "older");
            Directory.CreateDirectory(dir1);
            File.WriteAllText(Path.Combine(dir1, "undo_log.json"),
                MakeUndoLogJson("2025-04-05T10:00:00Z", (@"C:\a", @"C:\b", 100)));

            var dir2 = Path.Combine(accountDir, "newer");
            Directory.CreateDirectory(dir2);
            File.WriteAllText(Path.Combine(dir2, "undo_log.json"),
                MakeUndoLogJson("2025-04-07T10:00:00Z", (@"C:\c", @"C:\d", 200)));

            var backups = BackupDiscovery.ListCleanupBackups(dir);
            Assert.Equal(2, backups.Count);
            Assert.True(backups[0].Timestamp > backups[1].Timestamp);
        }
        finally { Directory.Delete(dir, true); }
    }
}
