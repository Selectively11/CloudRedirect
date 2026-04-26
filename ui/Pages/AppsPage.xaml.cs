using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CloudRedirect.Resources;
using CloudRedirect.Services;

namespace CloudRedirect.Pages;

public partial class AppsPage : Page
{
    private bool _hasDeletedThisSession;
    private bool _hasPrunedThisSession;
    private bool _backupsLoaded;
    private List<BackupInfo> _backups;
    private string _steamPath;
    private readonly SteamStoreClient _storeClient = SteamStoreClient.Shared;
    private Dictionary<uint, StoreAppInfo> _backupAppNames = new();

    // Full lists for search filtering
    private List<AppInfo> _allApps;

    public AppsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try { await LoadAppsAsync(); }
            catch { }
        };
    }

    private void RestoreSavesButton_Click(object sender, RoutedEventArgs e)
    {
        AppListPanel.Visibility = Visibility.Collapsed;
        RestorePanel.Visibility = Visibility.Visible;

        if (!_backupsLoaded)
            LoadBackups();
    }

    private void BackToApps_Click(object sender, RoutedEventArgs e)
    {
        RestorePanel.Visibility = Visibility.Collapsed;
        AppListPanel.Visibility = Visibility.Visible;
    }

    private async Task LoadAppsAsync()
    {
        var apps = await Task.Run(() =>
        {
            var steamPath = SteamDetector.FindSteamPath();
            if (steamPath == null) return null;

            _steamPath = steamPath;

            var storagePath = Path.Combine(steamPath, "cloud_redirect", "storage");
            var blobsPath = Path.Combine(steamPath, "cloud_redirect", "blobs");

            var result = new List<AppInfo>();

            if (Directory.Exists(storagePath))
            {
                foreach (var accountDir in Directory.GetDirectories(storagePath))
                {
                    var accountId = Path.GetFileName(accountDir);

                    foreach (var appDir in Directory.GetDirectories(accountDir))
                    {
                        var appId = Path.GetFileName(appDir);
                        if (appId == "0") continue;
                        var info = new AppInfo { AppId = appId, AccountId = accountId };

                        var cnPath = Path.Combine(appDir, "cn.dat");
                        try
                        {
                            if (File.Exists(cnPath))
                                info.ChangeNumber = File.ReadAllText(cnPath).Trim();
                        }
                        catch (IOException) { /* file may be locked by the DLL */ }

                        var rtPath = Path.Combine(appDir, "root_token.dat");
                        try
                        {
                            if (File.Exists(rtPath))
                                info.RootTokens = File.ReadAllText(rtPath).Trim().Replace("\n", ", ");
                        }
                        catch (IOException) { /* file may be locked by the DLL */ }

                        // Count files from both the unified storage dir and legacy blobs dir
                        long totalBytes = 0;
                        int fileCount = 0;

                        // Unified storage (current DLL layout): blobs live alongside metadata
                        var storageFiles = Directory.GetFiles(appDir, "*", SearchOption.AllDirectories);
                        foreach (var f in storageFiles)
                        {
                            var name = Path.GetFileName(f);
                            // Skip metadata files -- only count save data
                            if (name is "cn.dat" or "root_token.dat" or "file_tokens.dat") continue;
                            fileCount++;
                            totalBytes += new FileInfo(f).Length;
                        }

                        // Legacy blobs dir (pre-unification): may still have old data
                        var appBlobDir = Path.Combine(blobsPath, accountId, appId);
                        if (Directory.Exists(appBlobDir))
                        {
                            var legacyFiles = Directory.GetFiles(appBlobDir, "*", SearchOption.AllDirectories);
                            fileCount += legacyFiles.Length;
                            foreach (var f in legacyFiles)
                                totalBytes += new FileInfo(f).Length;
                        }

                        info.FileCount = fileCount;
                        info.TotalSize = FileUtils.FormatSize(totalBytes);

                        result.Add(info);
                    }
                }
            }

            return result;
        });

        if (apps == null || apps.Count == 0)
        {
            _allApps = apps;
            AppList.ItemsSource = apps;
            return;
        }

        // Show the list immediately with app IDs while we fetch names
        _allApps = apps;
        ApplyAppFilter();

        // Fetch names + header images from Steam store API (batch, cached)
        try
        {
            var appIds = apps
                .Select(a => uint.TryParse(a.AppId, out var id) ? id : 0)
                .Where(id => id != 0)
                .Distinct()
                .ToList();

            if (appIds.Count > 0)
            {
                var storeInfo = await _storeClient.GetAppInfoAsync(appIds);

                foreach (var app in apps)
                {
                    if (uint.TryParse(app.AppId, out var id) && storeInfo.TryGetValue(id, out var info))
                    {
                        app.Name = info.Name;
                        app.HeaderUrl = info.HeaderUrl;
                    }
                }

                // Refresh the list to pick up new names/images
                ApplyAppFilter();
            }
        }
        catch
        {
            // Store API failure is non-fatal -- cards still show app IDs
        }
    }

    private void AppSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyAppFilter();
    }

    private void ApplyAppFilter()
    {
        if (_allApps == null) return;
        var query = AppSearchBox?.Text?.Trim() ?? "";

        if (string.IsNullOrEmpty(query))
        {
            AppList.ItemsSource = null;
            AppList.ItemsSource = _allApps;
            return;
        }

        var filtered = _allApps
            .Where(a => a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
                     || a.AppId.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToList();

        AppList.ItemsSource = null;
        AppList.ItemsSource = filtered;
    }

    private void RestoreSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyRestoreFilter();
    }

    private void ApplyRestoreFilter()
    {
        if (_backups == null || !_backupsLoaded) return;

        var query = RestoreSearchBox?.Text?.Trim() ?? "";
        IReadOnlyList<BackupInfo> filtered;

        if (string.IsNullOrEmpty(query))
        {
            filtered = _backups;
        }
        else
        {
            filtered = _backups
                .Where(b => MatchesBackup(b, query, _backupAppNames))
                .ToList();
        }

        BackupListPanel.Children.Clear();
        if (filtered.Count == 0)
        {
            RestoreStatus.Text = S.Get("Apps_NoDeleteBackups");
            return;
        }

        BackupListBuilder.Build(
            BackupListPanel,
            filtered,
            appId => _backupAppNames.TryGetValue(appId, out var si) ? si : null,
            FindResource,
            RunDeleteBackupPreview,
            RunDeleteBackupRestore);

        RestoreStatus.Text = S.Format("Apps_BackupCountFormat", filtered.Count);
    }

    private static bool MatchesBackup(BackupInfo b, string query, Dictionary<uint, StoreAppInfo> nameCache)
    {
        // Match against app IDs
        foreach (var id in b.AppIds)
        {
            if (id.ToString().Contains(query, StringComparison.OrdinalIgnoreCase))
                return true;
            if (nameCache.TryGetValue(id, out var info)
                && !string.IsNullOrEmpty(info.Name)
                && info.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private async void DeleteApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: AppInfo app }) return;

        var steamPath = SteamDetector.FindSteamPath();
        if (steamPath == null) return;

        // Resolve all deletion targets BEFORE showing the dialog
        var targets = await Task.Run(() => ResolveDeletionTargets(steamPath, app));

        // Build a rich-text summary of the deletion targets
        var tb = new TextBlock { TextWrapping = TextWrapping.Wrap };

        tb.Inlines.Add(new Run(S.Format("Apps_DeletePromptHeader", app.DisplayName, app.AppId)));

        tb.Inlines.Add(new Run(S.Get("Apps_DeletePromptWillDelete")));
        tb.Inlines.Add(new Bold(new Run(S.Get("Apps_DeletePromptDelete"))));
        tb.Inlines.Add(new Run(":\n"));

        tb.Inlines.Add(new Run(S.Format("Apps_DeletePromptLocalStorage", app.FileCount, app.TotalSize)));

        var providerName = CloudProviderClient.GetProviderDisplayName();
        if (providerName != null)
        {
            tb.Inlines.Add(new Run("  - "));
            tb.Inlines.Add(new Bold(new Run(S.Format("Apps_DeletePromptCloudCopies", providerName))));
            tb.Inlines.Add(new Run("\n"));
        }

        if (targets.UserdataDir != null)
            tb.Inlines.Add(new Run(S.Format("Apps_DeletePromptUserdata", targets.UserdataDir)));

        foreach (var sp in targets.GameSavePaths)
            tb.Inlines.Add(new Run(S.Format("Apps_DeletePromptGameSaves", sp)));

        if (targets.SkippedRoots.Count > 0)
            tb.Inlines.Add(new Run(S.Format("Apps_DeletePromptSkipped", targets.SkippedRoots.Count, string.Join(", ", targets.SkippedRoots))));

        tb.Inlines.Add(new Run("\n"));
        tb.Inlines.Add(new Bold(new Run(S.Get("Apps_DeletePromptWarning"))));
        tb.Inlines.Add(new Run("\n\n"));

        tb.Inlines.Add(new Run(S.Get("Apps_DeletePromptExplanation") + "\n\n"));

        tb.Inlines.Add(new Run(S.Get("Apps_DeletePromptConsequence") + "\n\n"));

        tb.Inlines.Add(new Bold(new Run(S.Get("Apps_DeletePromptBeSure"))));

        var confirmed = await Dialog.ConfirmDangerAsync(S.Get("Apps_DeleteAllSavesTitle"), tb);
        if (!confirmed) return;

        var countdown = _hasDeletedThisSession ? 0 : 3;
        var reallyConfirmed = await Dialog.ConfirmDangerCountdownAsync(
            S.Get("Apps_FinalConfirmTitle"),
            S.Format("Apps_FinalConfirmMessage", app.DisplayName, app.AppId),
            countdown);
        if (!reallyConfirmed) return;

        try
        {
            var errors = new List<string>();

            // Back up everything before deleting
            var backupTimestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var backupDir = Path.Combine(BackupPaths.GetAppDeleteRoot(steamPath),
                app.AccountId, $"{app.AppId}_{backupTimestamp}");
            var undoOps = new List<UndoOperation>();

            await Task.Run(() =>
            {
                Directory.CreateDirectory(backupDir);

                // Back up CloudRedirect local storage
                var storageDir = Path.Combine(steamPath, "cloud_redirect", "storage", app.AccountId, app.AppId);
                if (Directory.Exists(storageDir))
                    BackupDirectory(storageDir, Path.Combine(backupDir, "storage"), undoOps, uint.Parse(app.AppId));

                var blobsDir = Path.Combine(steamPath, "cloud_redirect", "blobs", app.AccountId, app.AppId);
                if (Directory.Exists(blobsDir))
                    BackupDirectory(blobsDir, Path.Combine(backupDir, "blobs"), undoOps, uint.Parse(app.AppId));

                // Back up Steam userdata
                if (targets.UserdataDir != null && Directory.Exists(targets.UserdataDir))
                    BackupDirectory(targets.UserdataDir, Path.Combine(backupDir, "userdata"), undoOps, uint.Parse(app.AppId));

                // Back up game local saves
                for (int i = 0; i < targets.GameSavePaths.Count; i++)
                {
                    var savePath = targets.GameSavePaths[i];
                    if (Directory.Exists(savePath))
                        BackupDirectory(savePath, Path.Combine(backupDir, $"game_saves_{i}"), undoOps, uint.Parse(app.AppId));
                }

                // Write undo log (compatible with existing cleanup restore system)
                var undoLog = new UndoLog
                {
                    Timestamp = DateTime.UtcNow.ToString("o"),
                    Version = 1,
                    Operations = undoOps
                };
                var json = JsonSerializer.Serialize(undoLog, CleanupJsonContext.Default.UndoLog);
                File.WriteAllText(Path.Combine(backupDir, "undo_log.json"), json);
            });

            // Now delete everything
            // 1. Delete CloudRedirect local storage (unified + legacy)
            await Task.Run(() =>
            {
                var storageDir = Path.Combine(steamPath, "cloud_redirect", "storage", app.AccountId, app.AppId);
                var blobsDir = Path.Combine(steamPath, "cloud_redirect", "blobs", app.AccountId, app.AppId);

                if (Directory.Exists(storageDir))
                    Directory.Delete(storageDir, true);
                if (Directory.Exists(blobsDir))
                    Directory.Delete(blobsDir, true);
            });

            // 2. Delete cloud storage (no local backup possible for this)
            if (providerName != null)
            {
                using var client = new CloudProviderClient();
                var result = await client.DeleteAppDataAsync(app.AccountId, app.AppId);
                if (!result.Success)
                    errors.Add($"Cloud ({providerName}): {result.Error}");
            }

            // 3. Delete Steam userdata
            if (targets.UserdataDir != null)
            {
                try
                {
                    await Task.Run(() =>
                    {
                        if (Directory.Exists(targets.UserdataDir))
                            Directory.Delete(targets.UserdataDir, true);
                    });
                }
                catch (Exception ex)
                {
                    errors.Add($"Steam userdata: {ex.Message}");
                }
            }

            // 4. Delete game local save files
            foreach (var savePath in targets.GameSavePaths)
            {
                try
                {
                    await Task.Run(() =>
                    {
                        if (Directory.Exists(savePath))
                            Directory.Delete(savePath, true);
                    });
                }
                catch (Exception ex)
                {
                    errors.Add($"Game saves ({savePath}): {ex.Message}");
                }
            }

            if (errors.Count > 0)
            {
                await Dialog.ShowWarningAsync(S.Get("Apps_PartialDeleteTitle"),
                    S.Format("Apps_PartialDeleteMessage",
                        string.Join("\n", errors.Select(err => $"  - {err}")),
                        backupDir));
            }
            else
            {
                await Dialog.ShowInfoAsync(S.Get("Apps_DeletedTitle"),
                    S.Format("Apps_DeletedMessage", app.DisplayName, app.AppId, backupDir));
            }

            _hasDeletedThisSession = true;
            _backupsLoaded = false; // invalidate backup cache
            await LoadAppsAsync();
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(S.Get("Apps_DeleteFailedTitle"), $"Error: {ex.Message}");
        }
    }

    /// <summary>Per-card Review/Collapse toggle for the orphan detail panel.</summary>
    private void OrphansToggle_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Primitives.ButtonBase btn) return;

        // Walk up to the outer DataTemplate-root StackPanel (the one whose
        // first child is the CardControl and whose second child is the
        // orphans detail StackPanel).
        DependencyObject? cur = btn;
        StackPanel? outer = null;
        while (cur != null)
        {
            cur = System.Windows.Media.VisualTreeHelper.GetParent(cur);
            if (cur is StackPanel sp &&
                sp.Children.Count == 2 &&
                sp.Children[0] is Wpf.Ui.Controls.CardControl &&
                sp.Children[1] is StackPanel)
            {
                outer = sp;
                break;
            }
        }
        if (outer == null) return;
        if (outer.Children[1] is not StackPanel detail) return;

        if (detail.Visibility == Visibility.Collapsed)
        {
            detail.Visibility = Visibility.Visible;
            btn.SetValue(System.Windows.Controls.ContentControl.ContentProperty,
                S.Get("Apps_CollapseOrphans"));
        }
        else
        {
            detail.Visibility = Visibility.Collapsed;
            btn.SetValue(System.Windows.Controls.ContentControl.ContentProperty,
                S.Get("Apps_ReviewOrphans"));
        }
    }

    /// <summary>
    /// Scan every local app's cloud blobs for orphans. Serialized to respect
    /// provider rate limits; Steam-closed gate is checked once upfront so
    /// in-flight uploads can't race the listing. Apps with incomplete or
    /// errored scans never get HasOrphans set.
    /// </summary>
    private async void ScanOrphans_Click(object sender, RoutedEventArgs e)
    {
        if (_allApps == null || _allApps.Count == 0) return;

        ScanOrphansButton.IsEnabled = false;
        var originalContent = ScanOrphansButton.Content;
        try
        {
            // Short-circuit: local-only providers have no cloud to scan.
            var providerName = CloudProviderClient.GetProviderDisplayName();
            if (providerName == null)
            {
                await Dialog.ShowInfoAsync(
                    S.Get("Apps_ScanLocalOnlyTitle"),
                    S.Get("Apps_ScanLocalOnlyMessage"));
                return;
            }

            // Explain what an orphan is up front. The button alone said nothing
            // about what would happen, so a user who clicked out of curiosity
            // got handed a "close Steam" warning with no context.
            if (!await Dialog.ConfirmAsync(
                    S.Get("Apps_ScanOrphansExplainTitle"),
                    S.Get("Apps_ScanOrphansExplainMessage")))
            {
                return;
            }

            // Single Steam-closed gate for the whole batch; no point
            // scanning the rest if the user refuses.
            if (!await SteamDetector.EnsureSteamClosedAsync()) return;

            var steamPath = SteamDetector.FindSteamPath();
            if (steamPath == null) return;

            ScanStatusText.Text = "";

            // Reuse a single CloudProviderClient across all per-app
            // listings -- one warm HttpClient, one auth refresh.
            using var client = new CloudProviderClient();
            var svc = new OrphanBlobService(client, steamPath);

            int scannedOk = 0;
            int scanFailed = 0;
            int totalOrphans = 0;
            int appsWithOrphans = 0;
            int i = 0;

            // Clear any prior scan state so stale orphans from a
            // previous scan can't linger on apps that are now clean.
            foreach (var a in _allApps)
            {
                a.HasOrphans = false;
                a.OrphanFiles = new List<string>();
                a.OrphanSummary = "";
            }

            foreach (var app in _allApps)
            {
                i++;
                ScanOrphansButton.Content = S.Format(
                    "Apps_ScanningOrphansFormat", i, _allApps.Count);

                try
                {
                    var scan = await svc.ScanAsync(app.AccountId, app.AppId);

                    if (!scan.ListingComplete || scan.Error != null)
                    {
                        scanFailed++;
                        continue;
                    }

                    scannedOk++;
                    if (scan.Orphans.Count > 0)
                    {
                        app.HasOrphans = true;
                        // Raw filenames for delete; sanitized for preview only.
                        app.OrphanFiles = scan.Orphans.ToList();
                        app.OrphanFilesPreview = scan.Orphans
                            .Select(SanitizeForPreview)
                            .ToList();
                        app.OrphanSummary = S.Format(
                            "Apps_OrphanSummaryFormat", scan.Orphans.Count);
                        totalOrphans += scan.Orphans.Count;
                        appsWithOrphans++;
                    }
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch
                {
                    scanFailed++;
                }
            }

            // Rebind so the expander visibility + summaries refresh.
            ApplyAppFilter();

            // Status text next to the button summarises the run.
            if (appsWithOrphans == 0 && scanFailed == 0)
            {
                ScanStatusText.Text = S.Format(
                    "Apps_ScanCompleteCleanFormat", scannedOk);
            }
            else
            {
                var parts = new List<string>();
                if (appsWithOrphans > 0)
                    parts.Add(S.Format("Apps_ScanCompleteFoundFormat",
                        totalOrphans, appsWithOrphans));
                if (scanFailed > 0)
                    parts.Add(S.Format("Apps_ScanCompletePartialFormat", scanFailed));
                ScanStatusText.Text = string.Join("  ", parts);
            }
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(
                S.Get("Apps_ScanFailedTitle"), ex.Message);
        }
        finally
        {
            ScanOrphansButton.IsEnabled = true;
            ScanOrphansButton.Content = originalContent;
        }
    }

    /// <summary>
    /// Prune scanned orphans for one app. Uses the scan-time snapshot
    /// (no re-scan) to avoid a TOCTOU where a newly-uploaded blob would
    /// be deleted without the user seeing it.
    /// </summary>
    private async void PruneOrphans_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: AppInfo app } fe) return;
        if (fe is not System.Windows.Controls.Primitives.ButtonBase btn) return;

        if (!app.HasOrphans || app.OrphanFiles.Count == 0) return;

        btn.IsEnabled = false;

        try
        {
            var providerName = CloudProviderClient.GetProviderDisplayName();
            if (providerName == null) return; // scan would have refused too

            if (!await SteamDetector.EnsureSteamClosedAsync()) return;

            var steamPath = SteamDetector.FindSteamPath();
            if (steamPath == null) return;

            // First prune of the session pays the 3s countdown; the flag
            // only advances on verified progress so retries still pay.
            var countdown = _hasPrunedThisSession ? 0 : 3;
            var confirmed = await Dialog.ConfirmDangerCountdownAsync(
                S.Get("Apps_PruneFinalConfirmTitle"),
                S.Format("Apps_PruneFinalConfirmMessageFormat",
                    app.OrphanFiles.Count, app.DisplayName),
                countdown);
            if (!confirmed) return;

            using var client = new CloudProviderClient();
            var svc = new OrphanBlobService(client, steamPath);

            OrphanBlobService.PruneResult result;
            try
            {
                result = await svc.PruneAsync(app.AccountId, app.AppId, app.OrphanFiles);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                await Dialog.ShowErrorAsync(
                    S.Get("Apps_PruneFailedTitle"),
                    S.Format("Apps_PruneFailedMessageFormat",
                        0, app.DisplayName, ex.Message));
                return;
            }

            if (result.Failed == 0)
            {
                // Full success: clear orphan state so the expander
                // disappears without a re-scan.
                app.HasOrphans = false;
                app.OrphanFiles = new List<string>();
                app.OrphanFilesPreview = new List<string>();
                app.OrphanSummary = "";
                ApplyAppFilter();

                await Dialog.ShowInfoAsync(
                    S.Get("Apps_PruneCompleteTitle"),
                    S.Format("Apps_PruneCompleteMessageFormat",
                        result.Deleted, app.DisplayName));
            }
            else if (result.Deleted > 0)
            {
                // Partial success: retain only failed files for retry.
                app.OrphanFiles = result.FailedFilenames.ToList();
                app.OrphanFilesPreview = app.OrphanFiles
                    .Select(SanitizeForPreview)
                    .ToList();
                app.HasOrphans = app.OrphanFiles.Count > 0;
                app.OrphanSummary = app.HasOrphans
                    ? S.Format("Apps_OrphanSummaryFormat", app.OrphanFiles.Count)
                    : "";
                ApplyAppFilter();

                var failedSample = string.Join("\n",
                    result.FailedFilenames.Take(20).Select(f => $"  {f}"));
                if (result.FailedFilenames.Count > 20)
                    failedSample += $"\n  ...and {result.FailedFilenames.Count - 20} more";

                await Dialog.ShowWarningAsync(
                    S.Get("Apps_PrunePartialTitle"),
                    S.Format("Apps_PrunePartialMessageFormat",
                        result.Deleted,
                        result.Deleted + result.Failed,
                        app.DisplayName,
                        result.Failed,
                        failedSample,
                        result.Error ?? "(no details)"));
            }
            else
            {
                await Dialog.ShowErrorAsync(
                    S.Get("Apps_PruneFailedTitle"),
                    S.Format("Apps_PruneFailedMessageFormat",
                        app.OrphanFiles.Count, app.DisplayName,
                        result.Error ?? "(no details)"));
            }

            if (result.Deleted > 0)
                _hasPrunedThisSession = true;
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(S.Get("Apps_PruneFailedTitle"), $"Error: {ex.Message}");
        }
        finally
        {
            btn.IsEnabled = true;
        }
    }

    /// <summary>
    /// Strip control chars and bidi overrides from a filename for safe
    /// preview display. Display-only; prune uses the raw filename.
    /// </summary>
    private static string SanitizeForPreview(string name)
    {
        if (string.IsNullOrEmpty(name)) return "";
        // Fast path: the common case is ASCII-printable filenames.
        bool needsSanitize = false;
        foreach (var c in name)
        {
            if (char.IsControl(c) || c == '\u202A' || c == '\u202B' ||
                c == '\u202C' || c == '\u202D' || c == '\u202E' ||
                c == '\u2066' || c == '\u2067' || c == '\u2068' || c == '\u2069')
            {
                needsSanitize = true;
                break;
            }
        }
        if (!needsSanitize) return name;
        var sb = new System.Text.StringBuilder(name.Length);
        foreach (var c in name)
        {
            if (char.IsControl(c)) { sb.Append('?'); continue; }
            // Explicit bidi overrides (LRE/RLE/PDF/LRO/RLO) and bidi
            // isolates (LRI/RLI/FSI/PDI) can reorder surrounding text
            // visually -- replace with a visible placeholder.
            if (c == '\u202A' || c == '\u202B' || c == '\u202C' ||
                c == '\u202D' || c == '\u202E' ||
                c == '\u2066' || c == '\u2067' || c == '\u2068' || c == '\u2069')
            {
                sb.Append('?');
                continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    private async void LoadBackups()
    {
        await LoadDeleteBackupsAsync();
    }

    private async void RefreshBackupsButton_Click(object sender, RoutedEventArgs e)
    {
        _backupsLoaded = false;
        await LoadDeleteBackupsAsync();
    }

    private async Task LoadDeleteBackupsAsync()
    {
        _steamPath ??= await Task.Run(() => SteamDetector.FindSteamPath());
        if (_steamPath == null)
        {
            RestoreStatus.Text = S.Get("Apps_SteamNotFound");
            return;
        }

        RefreshBackupsButton.IsEnabled = false;
        RestoreStatus.Text = "";
        BackupListPanel.Children.Clear();
        RestoreLoadingPanel.Visibility = Visibility.Visible;

        try
        {
            _backups = await Task.Run(() => BackupDiscovery.ListAppDeleteBackups(_steamPath));
            _backupsLoaded = true;

            if (_backups.Count == 0)
            {
                RestoreStatus.Text = S.Get("Apps_NoDeleteBackups");
                RestoreLoadingPanel.Visibility = Visibility.Collapsed;
                return;
            }

            // Resolve app names for backup cards
            var backupAppIds = new HashSet<uint>();
            foreach (var b in _backups)
                foreach (var id in b.AppIds)
                    backupAppIds.Add(id);

            if (backupAppIds.Count > 0)
            {
                try { _backupAppNames = await _storeClient.GetAppInfoAsync(backupAppIds.ToList()); }
                catch { _backupAppNames = new(); }
            }

            BuildDeleteBackupList();

            RestoreStatus.Text = S.Format("Apps_BackupCountFormat", _backups.Count);
        }
        catch (Exception ex)
        {
            RestoreStatus.Text = S.Format("Apps_FailedLoadBackups", ex.Message);
        }
        finally
        {
            RestoreLoadingPanel.Visibility = Visibility.Collapsed;
            RefreshBackupsButton.IsEnabled = true;
        }
    }

    private void BuildDeleteBackupList()
    {
        // If there's an active search query, apply the filter instead
        var query = RestoreSearchBox?.Text?.Trim() ?? "";
        if (!string.IsNullOrEmpty(query))
        {
            ApplyRestoreFilter();
            return;
        }

        BackupListBuilder.Build(
            BackupListPanel,
            _backups,
            appId => _backupAppNames.TryGetValue(appId, out var si) ? si : null,
            FindResource,
            RunDeleteBackupPreview,
            RunDeleteBackupRestore);
    }

    private async Task RunDeleteBackupPreview(BackupInfo backup, StackPanel detailPanel, Wpf.Ui.Controls.Button previewBtn)
    {
        if (detailPanel.Visibility == Visibility.Visible)
        {
            detailPanel.Visibility = Visibility.Collapsed;
            previewBtn.Content = S.Get("Backup_Preview");
            return;
        }

        previewBtn.IsEnabled = false;
        previewBtn.Content = S.Get("Backup_Loading");

        try
        {
            var logLines = new List<string>();
            RevertResult result = null;

            await Task.Run(() =>
            {
                var revert = new CloudCleanupRevert(_steamPath!, RevertConflictMode.Skip, msg => logLines.Add(msg));
                result = revert.RestoreFromLog(backup.UndoLogPath, dryRun: true);
            });

            detailPanel.Children.Clear();

            // Summary
            var summary = new TextBlock
            {
                Text = result != null
                    ? S.Format("Preview_SummaryFormat", result.FilesRestored, result.FilesSkipped, result.RemotecachesRestored)
                    : S.Get("Preview_Failed"),
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextFillColorSecondaryBrush"),
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            };
            detailPanel.Children.Add(summary);

            // Show log output
            if (logLines.Count > 0)
            {
                var logBorder = new Border
                {
                    Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
                    BorderBrush = (Brush)FindResource("ControlStrokeColorDefaultBrush"),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(8),
                    MaxHeight = 300
                };
                var logScroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
                var logText = new TextBlock
                {
                    Text = string.Join("\n", logLines),
                    FontFamily = new FontFamily("Cascadia Code,Consolas,Courier New"),
                    FontSize = 11,
                    Foreground = (Brush)FindResource("TextFillColorSecondaryBrush"),
                    TextWrapping = TextWrapping.Wrap
                };
                logScroll.Content = logText;
                logBorder.Child = logScroll;
                detailPanel.Children.Add(logBorder);
            }

            if (result?.Errors.Count > 0)
            {
                var errText = new TextBlock
                {
                    Text = S.Format("Preview_ErrorsHeader", string.Join("\n", result.Errors)),
                    Foreground = new SolidColorBrush(Color.FromRgb(230, 80, 80)),
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 8, 0, 0)
                };
                detailPanel.Children.Add(errText);
            }

            detailPanel.Visibility = Visibility.Visible;
            previewBtn.Content = S.Get("Backup_HidePreview");
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(S.Get("Preview_FailedTitle"), ex.Message);
            previewBtn.Content = S.Get("Backup_Preview");
        }
        finally
        {
            previewBtn.IsEnabled = true;
        }
    }

    private async Task RunDeleteBackupRestore(BackupInfo backup, Wpf.Ui.Controls.Button restoreBtn)
    {
        if (!await SteamDetector.EnsureSteamClosedAsync()) return;

        string timestampText = backup.Timestamp != DateTime.MinValue
            ? backup.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            : backup.Id;

        // Experimental warning + Steam cloud disable requirement
        bool confirmed = await Dialog.ConfirmDangerAsync(
            S.Get("Apps_RestoreSavesExperimentalTitle"),
            S.Format("Apps_RestoreConfirmMessage", timestampText, backup.FileCount, FileUtils.FormatSize(backup.TotalBytes), string.Join(", ", backup.AppIds)));

        if (!confirmed) return;

        restoreBtn.IsEnabled = false;
        restoreBtn.Content = S.Get("Apps_Restoring");

        try
        {
            RevertResult result = null!;
            await Task.Run(() =>
            {
                var revert = new CloudCleanupRevert(_steamPath!, RevertConflictMode.Skip, _ => { });
                result = revert.RestoreFromLog(backup.UndoLogPath, dryRun: false);
            });

            string msg = S.Format("Apps_RestoredFormat", result.FilesRestored);
            if (result.RemotecachesRestored > 0)
                msg += S.Format("Apps_RestoredRemotecacheFormat", result.RemotecachesRestored);
            if (result.FilesSkipped > 0)
                msg += S.Format("Apps_SkippedFormat", result.FilesSkipped);
            if (result.Errors.Count > 0)
                msg += S.Format("Apps_ErrorsFormat", result.Errors.Count, string.Join("\n", result.Errors.Take(5)));

            await Dialog.ShowInfoAsync(S.Get("Apps_RestoreCompleteTitle"), msg);
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(S.Get("Apps_RestoreFailedTitle"), ex.Message);
        }
        finally
        {
            restoreBtn.IsEnabled = true;
            restoreBtn.Content = S.Get("Apps_Restore");
        }
    }

    /// <summary>Copy sourceDir into destDir, recording each file_move in the undo log.</summary>
    private static void BackupDirectory(string sourceDir, string destDir, List<UndoOperation> ops, uint appId)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceDir, file);
            var destFile = Path.Combine(destDir, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);
            File.Copy(file, destFile, overwrite: true);

            ops.Add(new UndoOperation
            {
                Type = "file_move",
                SourcePath = file,
                DestPath = destFile,
                AppId = appId
            });
        }
    }

    /// <summary>Resolve all filesystem paths to delete for an app (background, file I/O).</summary>
    private static DeletionTargets ResolveDeletionTargets(string steamPath, AppInfo app)
    {
        var targets = new DeletionTargets();

        // Steam userdata/{accountId}/{appId}/remote/
        // Delete the whole app folder under userdata, not just /remote/,
        // because remotecache.vdf and other metadata should go too.
        var userdataAppDir = Path.Combine(steamPath, "userdata", app.AccountId, app.AppId);
        if (Directory.Exists(userdataAppDir))
            targets.UserdataDir = userdataAppDir;

        // Parse AutoCloud rules to find game save locations
        var appInfoPath = Path.Combine(steamPath, "appcache", "appinfo.vdf");
        if (!File.Exists(appInfoPath)) return targets;

        if (!uint.TryParse(app.AppId, out uint appIdNum)) return targets;

        AppCloudConfig config;
        try { config = AppInfoParser.ParseSingle(appInfoPath, appIdNum); }
        catch { return targets; }

        if (config == null || config.SaveFiles.Count == 0) return targets;

        // Resolve game install dir (needed for "gameinstall" root)
        string gameInstallDir = null;
        if (config.SaveFiles.Any(r => r.Root.Equals("gameinstall", StringComparison.OrdinalIgnoreCase)))
        {
            gameInstallDir = AppCloudConfig.FindGameInstallDir(steamPath, appIdNum);
        }

        // Collect unique save directories
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in config.SaveFiles)
        {
            // Skip default root -- those saves live in userdata/remote/ which we already handle
            if (string.IsNullOrEmpty(rule.Root)) continue;

            var rootPath = AppCloudConfig.RootToFilesystemPath(rule.Root, gameInstallDir);
            if (rootPath == null)
            {
                targets.SkippedRoots.Add(rule.Root);
                continue;
            }

            // The full save directory is rootPath + rule.Path
            var savePath = string.IsNullOrEmpty(rule.Path)
                ? rootPath
                : Path.Combine(rootPath, rule.Path.Replace('/', '\\'));

            if (Directory.Exists(savePath) && seen.Add(savePath))
                targets.GameSavePaths.Add(savePath);
        }

        return targets;
    }

    private class DeletionTargets
    {
        public string UserdataDir { get; set; }
        public List<string> GameSavePaths { get; } = new();
        public List<string> SkippedRoots { get; } = new();
    }

}

public class AppInfo
{
    public string AppId { get; set; } = "";
    public string AccountId { get; set; } = "";
    public int FileCount { get; set; }
    public string TotalSize { get; set; } = "0 B";
    public string ChangeNumber { get; set; } = "0";
    public string RootTokens { get; set; } = "";

    /// <summary>Game name from Steam store API. Falls back to "App {AppId}" if unavailable.</summary>
    public string DisplayName => !string.IsNullOrEmpty(Name) ? Name : S.Format("Apps_AppFallbackName", AppId);
    public string Name { get; set; } = "";

    /// <summary>Header image URL (292x136) from Steam CDN, or null.</summary>
    public string? HeaderUrl { get; set; }

    /// <summary>True if the last scan completed and returned orphans.</summary>
    public bool HasOrphans { get; set; }

    /// <summary>Localized summary shown in the expander header.</summary>
    public string OrphanSummary { get; set; } = "";

    /// <summary>
    /// Raw filenames from the last scan. Authoritative source for prune;
    /// never re-scan between display and prune (TOCTOU).
    /// </summary>
    public List<string> OrphanFiles { get; set; } = new();

    /// <summary>Sanitized projection of OrphanFiles for safe display.</summary>
    public List<string> OrphanFilesPreview { get; set; } = new();
}
