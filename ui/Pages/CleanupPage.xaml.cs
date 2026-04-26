using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CloudRedirect.Resources;
using CloudRedirect.Services;

namespace CloudRedirect.Pages;

internal class LastCleanupState
{
    public string Utc { get; set; } = "";
    public int FileCount { get; set; }
}

[JsonSerializable(typeof(LastCleanupState))]
internal partial class CleanupStateJsonContext : JsonSerializerContext { }

public partial class CleanupPage : Page
{
    private readonly SteamStoreClient _storeClient = SteamStoreClient.Shared;
    private Dictionary<uint, StoreAppInfo> _storeCache = new();
    private string _steamPath;
    private List<AppScanResult> _scanResults;

    // Filtered list used for display (retained for search to rebuild from)
    private List<AppScanResult> _displayedApps;

    // Track whether backups have been loaded for the restore tab
    private bool _backupsLoaded;
    private List<BackupInfo> _backups;

    // Reuse the CloudCleanup instance from the last scan (has populated _namespaceApps, _appConfigs, etc.)
    private CloudCleanup _cleanup;

    // Track whether a scan has been performed (for back button label)
    private bool _hasScanned;

    // Track the most recent cleanup for undo banner + backup highlighting
    private DateTime? _lastCleanupUtc;
    private int _lastCleanupFileCount;
    private bool _bannerChecked;

    public CleanupPage()
    {
        InitializeComponent();
        Loaded += CleanupPage_Loaded;
    }

    private async void CleanupPage_Loaded(object sender, RoutedEventArgs e)
    {
        // Restore persisted undo banner from a previous session (once)
        if (_bannerChecked) return;
        _bannerChecked = true;

        var steamPath = await Task.Run(() => SteamDetector.FindSteamPath());
        if (steamPath == null) return;
        _steamPath = steamPath;

        var saved = LoadCleanupState(steamPath);
        if (saved == null) return;

        // Verify the backup still exists on disk before showing the banner
        var backups = await Task.Run(() => BackupDiscovery.ListCleanupBackups(steamPath));
        var cutoff = saved.Value.utc.AddSeconds(-5);
        if (!backups.Any(b => b.Timestamp >= cutoff))
        {
            ClearCleanupState(steamPath); // stale state, clean up
            return;
        }

        _lastCleanupUtc = saved.Value.utc;
        ShowUndoBanner(saved.Value.fileCount);
    }

    private void RestoreButton_Click(object sender, RoutedEventArgs e)
    {
        ScanCleanPanel.Visibility = Visibility.Collapsed;
        RestorePanel.Visibility = Visibility.Visible;
        BackButton.Content = _hasScanned ? S.Get("Cleanup_BackToScan") : S.Get("Cleanup_Back");

        // Auto-load backups on first visit
        if (!_backupsLoaded)
        {
            LoadBackups();
        }
    }

    private void BackToScan_Click(object sender, RoutedEventArgs e)
    {
        RestorePanel.Visibility = Visibility.Collapsed;
        ScanCleanPanel.Visibility = Visibility.Visible;
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        _steamPath = await Task.Run(() => SteamDetector.FindSteamPath());
        if (_steamPath == null)
        {
            ScanStatus.Text = S.Get("Cleanup_SteamNotFound");
            return;
        }

        ScanButton.IsEnabled = false;
        ScanStatus.Text = "";
        GameListPanel.Visibility = Visibility.Collapsed;
        NukePanel.Visibility = Visibility.Collapsed;
        LoadingPanel.Visibility = Visibility.Visible;

        try
        {
            // Run the scan off the UI thread (store instance for reuse by nuke/per-app clean)
            _scanResults = await Task.Run(() =>
            {
                _cleanup = new CloudCleanup(_steamPath, _ => { });
                return _cleanup.ScanApps();
            });
            _hasScanned = true;

            // Filter to apps that have files (show all namespace apps with remote/ content)
            var appsWithFiles = _scanResults
                .Where(r => r.Files.Count > 0)
                .OrderByDescending(r => r.PollutedCount)
                .ThenByDescending(r => r.TotalBytes)
                .ToList();

            _displayedApps = appsWithFiles;

            if (appsWithFiles.Count == 0)
            {
                ScanStatus.Text = S.Get("Cleanup_NoNamespaceApps");
                LoadingPanel.Visibility = Visibility.Collapsed;
                ScanButton.IsEnabled = true;
                GameSearchBox.Visibility = Visibility.Collapsed;
                return;
            }

            int totalPolluted = appsWithFiles.Sum(a => a.PollutedCount);
            long totalPollutedBytes = appsWithFiles.Sum(a => a.PollutedBytes);
            int appsAffected = appsWithFiles.Count(a => a.PollutedCount > 0);
            ScanStatus.Text = S.Format("Cleanup_ScanStatusFormat", appsWithFiles.Count, totalPolluted, appsAffected);

            // Fetch game names + images in one batch
            var storeInfo = await _storeClient.GetAppInfoAsync(appsWithFiles.Select(a => a.AppId).ToList());
            foreach (var (id, info) in storeInfo)
                _storeCache[id] = info;

            // Build the game list (still hidden)
            BuildGameList(appsWithFiles);

            // Now reveal everything at once -- no bounce
            LoadingPanel.Visibility = Visibility.Collapsed;

            // Show search box now that we have results
            GameSearchBox.Text = "";
            GameSearchBox.Visibility = Visibility.Visible;

            if (totalPolluted > 0)
            {
                NukeDescription.Text = S.Format("Cleanup_NukeDescriptionFormat", totalPolluted, FileUtils.FormatSize(totalPollutedBytes), appsAffected);
                NukePanel.Visibility = Visibility.Visible;
            }
            else
            {
                NukePanel.Visibility = Visibility.Collapsed;
            }
            GameListPanel.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            ScanStatus.Text = S.Format("Cleanup_ScanFailed", ex.Message);
        }
        finally
        {
            LoadingPanel.Visibility = Visibility.Collapsed;
            ScanButton.IsEnabled = true;
        }
    }

    private async void NukeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_scanResults == null || _steamPath == null) return;

        var allSuspect = _scanResults
            .SelectMany(app => app.Files
                .Where(f => f.Classification != FileClassification.Legitimate &&
                            f.Classification != FileClassification.Unknown)
                .Select(f => (app, file: f)))
            .ToList();

        if (allSuspect.Count == 0) return;

        long totalBytes = allSuspect.Sum(x => x.file.SizeBytes);
        int appCount = allSuspect.Select(x => x.app.AppId).Distinct().Count();

        bool confirmed = await Dialog.ConfirmDangerAsync(
            S.Get("Cleanup_ConfirmCleanAllTitle"),
            S.Format("Cleanup_ConfirmCleanAllMessage", allSuspect.Count, FileUtils.FormatSize(totalBytes), appCount));

        if (!confirmed) return;

        NukeButton.IsEnabled = false;
        NukeButton.Content = S.Get("Cleanup_Cleaning");
        ScanButton.IsEnabled = false;

        try
        {
            int totalMoved = 0;
            var cleanupStartUtc = DateTime.UtcNow;

            await Task.Run(() =>
            {
                var cleanup = _cleanup ?? new CloudCleanup(_steamPath, _ => { });

                // Group by account first, then by app -- each account gets its own batch/undo log
                var byAccount = allSuspect.GroupBy(x => x.app.AccountId);

                foreach (var accountGroup in byAccount)
                {
                    cleanup.BeginBatch();
                    try
                    {
                        foreach (var appGroup in accountGroup.GroupBy(x => (x.app.AppId, x.app.RemoteDir)))
                        {
                            string appDir = Path.GetDirectoryName(appGroup.Key.RemoteDir)!;
                            var files = appGroup.Select(x => x.file).ToList();
                            totalMoved += cleanup.CleanFiles(accountGroup.Key, appGroup.Key.AppId, appDir, files);
                        }
                    }
                    finally
                    {
                        cleanup.EndBatch(accountGroup.Key);
                    }
                }
            });

            await Dialog.ShowInfoAsync(S.Get("Cleanup_CleanupCompleteTitle"),
                S.Format("Cleanup_CleanupCompleteMessage", totalMoved));

            // Track for undo banner + backup highlighting
            _lastCleanupUtc = cleanupStartUtc;
            _backupsLoaded = false;
            ShowUndoBanner(totalMoved);

            // Refresh
            ScanButton_Click(null!, null!);
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(S.Get("Cleanup_CleanupFailedTitle"), ex.Message);
        }
        finally
        {
            NukeButton.IsEnabled = true;
            NukeButton.Content = S.Get("Cleanup_CleanAllSuspectFiles");
            ScanButton.IsEnabled = true;
        }
    }

    private async void RefreshBackupsButton_Click(object sender, RoutedEventArgs e)
    {
        _backupsLoaded = false;
        await LoadBackupsAsync();
    }

    private async void LoadBackups()
    {
        await LoadBackupsAsync();
    }

    private async Task LoadBackupsAsync()
    {
        _steamPath ??= await Task.Run(() => SteamDetector.FindSteamPath());
        if (_steamPath == null)
        {
            RestoreStatus.Text = S.Get("Cleanup_SteamNotFound");
            return;
        }

        RefreshBackupsButton.IsEnabled = false;
        RestoreStatus.Text = "";
        BackupListPanel.Children.Clear();
        RestoreLoadingPanel.Visibility = Visibility.Visible;

        try
        {
            _backups = await Task.Run(() => BackupDiscovery.ListCleanupBackups(_steamPath));
            _backupsLoaded = true;

            if (_backups.Count == 0)
            {
                RestoreStatus.Text = S.Get("Cleanup_NoBackupsFound");
                RestoreLoadingPanel.Visibility = Visibility.Collapsed;
                return;
            }

            // Fetch game names + images for all apps across all backups
            var allAppIds = _backups.SelectMany(b => b.AppIds).Distinct().ToList();
            var storeInfo = await _storeClient.GetAppInfoAsync(allAppIds);
            foreach (var (id, info) in storeInfo)
                _storeCache[id] = info;

            // Build the backup list
            BuildBackupList();

            RestoreStatus.Text = S.Format("Cleanup_BackupCountFormat", _backups.Count);
        }
        catch (Exception ex)
        {
            RestoreStatus.Text = S.Format("Cleanup_FailedLoadBackups", ex.Message);
        }
        finally
        {
            RestoreLoadingPanel.Visibility = Visibility.Collapsed;
            RefreshBackupsButton.IsEnabled = true;
        }
    }

    private void BuildBackupList()
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
            appId => _storeCache.TryGetValue(appId, out var si) ? si : null,
            FindResource,
            RunBackupPreview,
            RunBackupRestore,
            _lastCleanupUtc);
    }

    private async Task RunBackupPreview(BackupInfo backup, StackPanel detailPanel, Wpf.Ui.Controls.Button previewBtn)
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

    private async Task RunBackupRestore(BackupInfo backup, Wpf.Ui.Controls.Button restoreBtn)
    {
        if (!await SteamDetector.EnsureSteamClosedAsync()) return;

        string timestampText = backup.Timestamp != DateTime.MinValue
            ? backup.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            : backup.Id;

        bool confirmed = await Dialog.ConfirmDangerAsync(
            S.Get("Cleanup_RestoreFromBackupTitle"),
            S.Format("Cleanup_RestoreConfirmMessage", timestampText, backup.AccountId, backup.FileCount, string.Join(", ", backup.AppIds)));

        if (!confirmed) return;

        restoreBtn.IsEnabled = false;
        restoreBtn.Content = S.Get("Apps_Restoring");

        try
        {
            RevertResult result = null;
            await Task.Run(() =>
            {
                var revert = new CloudCleanupRevert(_steamPath!, RevertConflictMode.Skip, _ => { });
                result = revert.RestoreFromLog(backup.UndoLogPath, dryRun: false);
            });

            if (result != null)
            {
                string msg = S.Format("Cleanup_RestoredFormat", result.FilesRestored, result.RemotecachesRestored);
                if (result.FilesSkipped > 0)
                    msg += S.Format("Cleanup_SkippedFormat", result.FilesSkipped);
                if (result.Errors.Count > 0)
                    msg += S.Format("Cleanup_ErrorsFormat", result.Errors.Count, string.Join("\n", result.Errors.Take(5)));

                await Dialog.ShowInfoAsync(S.Get("Cleanup_RestoreCompleteTitle"), msg);
            }
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(S.Get("Cleanup_RestoreFailedTitle"), ex.Message);
        }
        finally
        {
            restoreBtn.IsEnabled = true;
            restoreBtn.Content = S.Get("Apps_Restore");
        }
    }

    private void GameSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        ApplyGameFilter();
    }

    private void ApplyGameFilter()
    {
        if (_displayedApps == null) return;
        var query = GameSearchBox?.Text?.Trim() ?? "";

        List<AppScanResult> filtered;
        if (string.IsNullOrEmpty(query))
        {
            filtered = _displayedApps;
        }
        else
        {
            filtered = _displayedApps
                .Where(a => MatchesGameQuery(a, query))
                .ToList();
        }

        BuildGameList(filtered);
        GameListPanel.Visibility = filtered.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private bool MatchesGameQuery(AppScanResult app, string query)
    {
        if (app.AppId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase))
            return true;
        if (_storeCache.TryGetValue(app.AppId, out var si)
            && !string.IsNullOrEmpty(si.Name)
            && si.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
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
                .Where(b => MatchesBackupQuery(b, query))
                .ToList();
        }

        BackupListPanel.Children.Clear();
        if (filtered.Count == 0)
        {
            RestoreStatus.Text = S.Get("Cleanup_NoBackupsFound");
            return;
        }

        BackupListBuilder.Build(
            BackupListPanel,
            filtered,
            appId => _storeCache.TryGetValue(appId, out var si) ? si : null,
            FindResource,
            RunBackupPreview,
            RunBackupRestore,
            _lastCleanupUtc);

        RestoreStatus.Text = S.Format("Cleanup_BackupCountFormat", filtered.Count);
    }

    private bool MatchesBackupQuery(BackupInfo b, string query)
    {
        foreach (var id in b.AppIds)
        {
            if (id.ToString().Contains(query, StringComparison.OrdinalIgnoreCase))
                return true;
            if (_storeCache.TryGetValue(id, out var info)
                && !string.IsNullOrEmpty(info.Name)
                && info.Name.Contains(query, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string GetCleanupStatePath(string steamPath) =>
        Path.Combine(steamPath, "cloud_redirect", "last_cleanup.json");

    private void SaveCleanupState(string steamPath, DateTime utc, int fileCount)
    {
        try
        {
            var state = new LastCleanupState
            {
                Utc = utc.ToString("o"),
                FileCount = fileCount
            };
            var dir = Path.GetDirectoryName(GetCleanupStatePath(steamPath))!;
            Directory.CreateDirectory(dir);
            File.WriteAllText(GetCleanupStatePath(steamPath),
                JsonSerializer.Serialize(state, CleanupStateJsonContext.Default.LastCleanupState));
        }
        catch { }
    }

    private void ClearCleanupState(string steamPath)
    {
        try { File.Delete(GetCleanupStatePath(steamPath)); } catch { }
    }

    private (DateTime utc, int fileCount)? LoadCleanupState(string steamPath)
    {
        try
        {
            var path = GetCleanupStatePath(steamPath);
            if (!File.Exists(path)) return null;
            var json = File.ReadAllText(path);
            var state = JsonSerializer.Deserialize(json, CleanupStateJsonContext.Default.LastCleanupState);
            if (state == null || string.IsNullOrEmpty(state.Utc)) return null;
            if (!DateTime.TryParse(state.Utc, null, System.Globalization.DateTimeStyles.RoundtripKind, out var utc))
                return null;
            return (utc, state.FileCount);
        }
        catch { return null; }
    }

    private void ShowUndoBanner(int fileCount)
    {
        _lastCleanupFileCount = fileCount;
        UndoBannerText.Text = S.Format("Cleanup_CleanedBannerFormat", fileCount);
        UndoBanner.Visibility = Visibility.Visible;
        UndoButton.IsEnabled = true;
        UndoButton.Content = S.Get("Cleanup_Undo");

        // Persist so the banner survives app restart
        if (_steamPath != null && _lastCleanupUtc != null)
            SaveCleanupState(_steamPath, _lastCleanupUtc.Value, fileCount);
    }

    private void UndoDismiss_Click(object sender, RoutedEventArgs e)
    {
        UndoBanner.Visibility = Visibility.Collapsed;
    }

    private async void UndoButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastCleanupUtc == null) return;

        if (!await SteamDetector.EnsureSteamClosedAsync()) return;

        UndoButton.IsEnabled = false;
        UndoButton.Content = S.Get("Apps_Restoring");
        UndoDismissButton.IsEnabled = false;

        try
        {
            _steamPath ??= await Task.Run(() => SteamDetector.FindSteamPath());
            if (_steamPath == null)
            {
                await Dialog.ShowErrorAsync(S.Get("Cleanup_UndoFailedTitle"), S.Get("Cleanup_UndoSteamNotFound"));
                return;
            }

            // Load backups from disk and find the one(s) created by the last cleanup
            var cutoff = _lastCleanupUtc.Value.AddSeconds(-5); // small tolerance for clock skew
            var allBackups = await Task.Run(() => BackupDiscovery.ListCleanupBackups(_steamPath));
            var recentBackups = allBackups
                .Where(b => b.Timestamp >= cutoff)
                .ToList();

            if (recentBackups.Count == 0)
            {
                await Dialog.ShowErrorAsync(S.Get("Cleanup_UndoFailedTitle"),
                    S.Get("Cleanup_UndoNoBackupFound"));
                return;
            }

            int totalRestored = 0;
            int totalSkipped = 0;
            int totalRemotecaches = 0;
            var allErrors = new List<string>();

            await Task.Run(() =>
            {
                foreach (var backup in recentBackups)
                {
                    var revert = new CloudCleanupRevert(_steamPath, RevertConflictMode.Skip, _ => { });
                    var result = revert.RestoreFromLog(backup.UndoLogPath, dryRun: false);
                    if (result != null)
                    {
                        totalRestored += result.FilesRestored;
                        totalSkipped += result.FilesSkipped;
                        totalRemotecaches += result.RemotecachesRestored;
                        allErrors.AddRange(result.Errors);
                    }
                }
            });

            string msg = S.Format("Cleanup_RestoredFormat", totalRestored, totalRemotecaches);
            if (totalSkipped > 0)
                msg += S.Format("Cleanup_SkippedFormat", totalSkipped);
            if (allErrors.Count > 0)
                msg += S.Format("Cleanup_ErrorsFormat", allErrors.Count, string.Join("\n", allErrors.Take(5)));

            await Dialog.ShowInfoAsync(S.Get("Cleanup_UndoCompleteTitle"), msg);

            // Clear undo state and hide banner
            _lastCleanupUtc = null;
            UndoBanner.Visibility = Visibility.Collapsed;
            if (_steamPath != null) ClearCleanupState(_steamPath);

            // Invalidate backups cache and re-scan
            _backupsLoaded = false;
            ScanButton_Click(null!, null!);
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(S.Get("Cleanup_UndoFailedTitle"), ex.Message);
        }
        finally
        {
            UndoButton.IsEnabled = true;
            UndoButton.Content = S.Get("Cleanup_Undo");
            UndoDismissButton.IsEnabled = true;
        }
    }

    private void BuildGameList(List<AppScanResult> apps)
    {
        GameListPanel.Children.Clear();

        foreach (var app in apps)
        {
            string gameName = _storeCache.TryGetValue(app.AppId, out var si) && !string.IsNullOrEmpty(si.Name)
                ? si.Name : app.AppId.ToString();
            bool hasPollution = app.PollutedCount > 0;

            var card = new Border
            {
                Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
                CornerRadius = new CornerRadius(8),
                Margin = new Thickness(0, 0, 0, 8),
                Padding = new Thickness(16)
            };

            var cardContent = new StackPanel();
            card.Child = cardContent;

            // Header row: icon + name + stats + expand button
            var headerRow = new Grid();
            headerRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(42) });
            headerRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Game icon from SteamStoreClient
            var iconImage = new Image
            {
                Width = 32,
                Height = 32,
                Stretch = Stretch.UniformToFill,
                Margin = new Thickness(0, 0, 10, 0)
            };
            if (_storeCache.TryGetValue(app.AppId, out var storeInfo2) && SteamStoreClient.IsValidImageUrl(storeInfo2.HeaderUrl))
            {
                try
                {
                    var uri = new Uri(storeInfo2.HeaderUrl);
                    var bitmap = new BitmapImage();
                    bitmap.BeginInit();
                    if (uri.IsFile)
                    {
                        // OnLoad decodes immediately and releases the backing
                        // file handle; without it a file:// URI keeps the
                        // cached JPEG locked, blocking eviction and the
                        // File.Move(overwrite:true) that installs a refreshed
                        // asset after a Steam CDN hash rotation.
                        bitmap.CacheOption = BitmapCacheOption.OnLoad;
                    }
                    // HTTP URIs: leave CacheOption at Default so the download
                    // streams async rather than blocking the UI thread with a
                    // synchronous fetch (which was causing cold-cache renders
                    // to drop images silently).
                    bitmap.UriSource = uri;
                    bitmap.DecodePixelWidth = 64;
                    bitmap.EndInit();
                    if (uri.IsFile)
                        bitmap.Freeze();
                    iconImage.Source = bitmap;
                }
                catch { /* icon load failure is fine */ }
            }
            Grid.SetColumn(iconImage, 0);
            headerRow.Children.Add(iconImage);

            // Name + stats
            var nameStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var nameText = new TextBlock
            {
                Text = gameName,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextFillColorPrimaryBrush"),
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            nameStack.Children.Add(nameText);

            var statsWrap = new WrapPanel { Margin = new Thickness(0, 2, 0, 0) };
            statsWrap.Children.Add(MakeStatText($"AppID {app.AppId}", false));
            statsWrap.Children.Add(MakeStatText(S.Format("Cleanup_FilesCount", app.Files.Count), false));
            statsWrap.Children.Add(MakeStatText(FileUtils.FormatSize(app.TotalBytes), false));
            if (hasPollution)
            {
                statsWrap.Children.Add(MakeStatText(S.Format("Cleanup_Suspect", app.PollutedCount), true));
                statsWrap.Children.Add(MakeStatText(FileUtils.FormatSize(app.PollutedBytes), true));
            }
            else
            {
                statsWrap.Children.Add(MakeStatText(S.Get("Cleanup_Clean"), false));
            }
            nameStack.Children.Add(statsWrap);

            Grid.SetColumn(nameStack, 1);
            headerRow.Children.Add(nameStack);

            // Expand/collapse button
            var expandBtn = new Wpf.Ui.Controls.Button
            {
                Content = hasPollution ? S.Get("Cleanup_ReviewFiles") : S.Get("Cleanup_ViewFiles"),
                Appearance = hasPollution ? Wpf.Ui.Controls.ControlAppearance.Caution : Wpf.Ui.Controls.ControlAppearance.Secondary,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0)
            };
            Grid.SetColumn(expandBtn, 2);
            headerRow.Children.Add(expandBtn);

            cardContent.Children.Add(headerRow);

            // File detail panel (hidden by default)
            var detailPanel = new StackPanel
            {
                Visibility = Visibility.Collapsed,
                Margin = new Thickness(0, 12, 0, 0)
            };
            cardContent.Children.Add(detailPanel);

            // Wire expand button
            expandBtn.Click += (_, _) =>
            {
                if (detailPanel.Visibility == Visibility.Collapsed)
                {
                    detailPanel.Visibility = Visibility.Visible;
                    expandBtn.Content = S.Get("Cleanup_Collapse");
                    if (detailPanel.Children.Count == 0)
                        BuildFileList(detailPanel, app);
                }
                else
                {
                    detailPanel.Visibility = Visibility.Collapsed;
                    expandBtn.Content = hasPollution ? S.Get("Cleanup_ReviewFiles") : S.Get("Cleanup_ViewFiles");
                }
            };

            GameListPanel.Children.Add(card);
        }
    }

    private void BuildFileList(StackPanel container, AppScanResult app)
    {
        // Group files: suspect first, then unknown, then legitimate
        var suspectLabel = S.Get("Cleanup_SuspectFiles");
        var unknownLabel = S.Get("Cleanup_Unknown");
        var groups = new[]
        {
            (suspectLabel, app.Files.Where(f =>
                f.Classification != FileClassification.Legitimate &&
                f.Classification != FileClassification.Unknown).ToList()),
            (unknownLabel, app.Files.Where(f => f.Classification == FileClassification.Unknown).ToList()),
            (S.Get("Cleanup_Legitimate"), app.Files.Where(f => f.Classification == FileClassification.Legitimate).ToList())
        };

        // Track all checkboxes for this app's suspect files for the "clean selected" button
        var checkboxes = new List<(CheckBox cb, ClassifiedFile file)>();

        foreach (var (header, files) in groups)
        {
            if (files.Count == 0) continue;

            var groupHeader = new TextBlock
            {
                Text = S.Format("Cleanup_GroupHeaderFormat", header, files.Count),
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)FindResource("TextFillColorSecondaryBrush"),
                Margin = new Thickness(0, 8, 0, 4)
            };
            container.Children.Add(groupHeader);

            bool isSuspect = header == suspectLabel;

            foreach (var file in files.OrderBy(f => f.RelativePath))
            {
                var fileRow = new Grid { Margin = new Thickness(0, 1, 0, 1) };
                fileRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // checkbox
                fileRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // filename
                fileRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // classification badge
                fileRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); // size

                // Checkbox (only for suspect + unknown files)
                if (isSuspect || header == unknownLabel)
                {
                    var cb = new CheckBox
                    {
                        IsChecked = isSuspect, // pre-check suspect files
                        VerticalAlignment = VerticalAlignment.Center,
                        Margin = new Thickness(0, 0, 6, 0)
                    };
                    Grid.SetColumn(cb, 0);
                    fileRow.Children.Add(cb);
                    checkboxes.Add((cb, file));
                }

                // Filename
                var fileNameText = new TextBlock
                {
                    Text = file.RelativePath,
                    FontFamily = new FontFamily("Cascadia Code,Consolas,Courier New"),
                    FontSize = 12,
                    Foreground = (Brush)FindResource("TextFillColorPrimaryBrush"),
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    Margin = new Thickness(0, 0, 8, 0)
                };
                // Tooltip with full reason
                if (!string.IsNullOrEmpty(file.Reason))
                    fileNameText.ToolTip = file.Reason;
                Grid.SetColumn(fileNameText, 1);
                fileRow.Children.Add(fileNameText);

                // Classification badge
                var badge = new Border
                {
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(6, 2, 6, 2),
                    Margin = new Thickness(0, 0, 8, 0),
                    VerticalAlignment = VerticalAlignment.Center,
                    Background = file.Classification switch
                    {
                        FileClassification.PollutionCrossApp => new SolidColorBrush(Color.FromRgb(180, 60, 60)),
                        FileClassification.PollutionAppIdDir => new SolidColorBrush(Color.FromRgb(180, 100, 40)),
                        FileClassification.PollutionMangled => new SolidColorBrush(Color.FromRgb(180, 100, 40)),
                        FileClassification.Legitimate => new SolidColorBrush(Color.FromRgb(40, 120, 60)),
                        _ => new SolidColorBrush(Color.FromRgb(100, 100, 100))
                    }
                };
                badge.Child = new TextBlock
                {
                    Text = file.Classification switch
                    {
                        FileClassification.PollutionCrossApp => S.Get("Cleanup_Badge_CrossApp"),
                        FileClassification.PollutionAppIdDir => S.Get("Cleanup_Badge_WrongAppId"),
                        FileClassification.PollutionMangled => S.Get("Cleanup_Badge_Mangled"),
                        FileClassification.PollutionOrphan => S.Get("Cleanup_Badge_Orphan"),
                        FileClassification.Legitimate => S.Get("Cleanup_Badge_Legit"),
                        _ => S.Get("Cleanup_Badge_Unknown")
                    },
                    FontSize = 11,
                    Foreground = Brushes.White
                };
                Grid.SetColumn(badge, 2);
                fileRow.Children.Add(badge);

                // File size
                var sizeText = new TextBlock
                {
                    Text = FileUtils.FormatSize(file.SizeBytes),
                    FontSize = 12,
                    Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"),
                    VerticalAlignment = VerticalAlignment.Center,
                    MinWidth = 60,
                    TextAlignment = TextAlignment.Right
                };
                Grid.SetColumn(sizeText, 3);
                fileRow.Children.Add(sizeText);

                container.Children.Add(fileRow);
            }
        }

        // Action buttons
        if (checkboxes.Count > 0)
        {
            var actionBar = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };

            var selectAllBtn = new Wpf.Ui.Controls.Button
            {
                Content = S.Get("Cleanup_SelectAllSuspect"),
                Appearance = Wpf.Ui.Controls.ControlAppearance.Secondary,
                Margin = new Thickness(0, 0, 8, 0)
            };
            selectAllBtn.Click += (_, _) =>
            {
                foreach (var (cb, _) in checkboxes)
                    cb.IsChecked = true;
            };
            actionBar.Children.Add(selectAllBtn);

            var selectNoneBtn = new Wpf.Ui.Controls.Button
            {
                Content = S.Get("Cleanup_DeselectAll"),
                Appearance = Wpf.Ui.Controls.ControlAppearance.Secondary,
                Margin = new Thickness(0, 0, 8, 0)
            };
            selectNoneBtn.Click += (_, _) =>
            {
                foreach (var (cb, _) in checkboxes)
                    cb.IsChecked = false;
            };
            actionBar.Children.Add(selectNoneBtn);

            var cleanBtn = new Wpf.Ui.Controls.Button
            {
                Content = S.Get("Cleanup_CleanSelected"),
                Icon = new Wpf.Ui.Controls.SymbolIcon { Symbol = Wpf.Ui.Controls.SymbolRegular.Delete24 },
                Appearance = Wpf.Ui.Controls.ControlAppearance.Danger,
                Margin = new Thickness(0, 0, 0, 0)
            };

            // Capture app reference for the closure
            var capturedApp = app;
            var capturedCheckboxes = checkboxes;

            cleanBtn.Click += async (_, _) =>
            {
                var selected = capturedCheckboxes
                    .Where(x => x.cb.IsChecked == true)
                    .Select(x => x.file)
                    .ToList();

                if (selected.Count == 0)
                {
                    await Dialog.ShowInfoAsync(S.Get("Cleanup_NothingSelectedTitle"), S.Get("Cleanup_NothingSelectedMessage"));
                    return;
                }

                long totalBytes = selected.Sum(f => f.SizeBytes);
                bool confirmed = await Dialog.ConfirmDangerAsync(
                    S.Get("Cleanup_ConfirmCleanupTitle"),
                    S.Format("Cleanup_ConfirmCleanupMessage", selected.Count, FileUtils.FormatSize(totalBytes), capturedApp.AccountId));

                if (!confirmed) return;

                cleanBtn.IsEnabled = false;
                cleanBtn.Content = S.Get("Cleanup_CleaningButton");

                try
                {
                    string appDir = Path.GetDirectoryName(capturedApp.RemoteDir)!;
                    var cleanupStartUtc = DateTime.UtcNow;
                    int moved = await Task.Run(() =>
                    {
                        var cleanup = _cleanup ?? new CloudCleanup(_steamPath!, _ => { });
                        return cleanup.CleanFiles(capturedApp.AccountId, capturedApp.AppId, appDir, selected);
                    });

                    await Dialog.ShowInfoAsync(S.Get("Cleanup_CleanupCompleteTitle"),
                        S.Format("Cleanup_CleanupCompleteMessage", moved));

                    // Track for undo banner + backup highlighting
                    _lastCleanupUtc = cleanupStartUtc;
                    _backupsLoaded = false;
                    ShowUndoBanner(moved);

                    // Refresh the scan
                    ScanButton_Click(null!, null!);
                }
                catch (Exception ex)
                {
            await Dialog.ShowErrorAsync(S.Get("Cleanup_CleanupFailedTitle"), ex.Message);
                }
                finally
                {
                    cleanBtn.IsEnabled = true;
                    cleanBtn.Content = S.Get("Cleanup_CleanSelected");
                }
            };

            actionBar.Children.Add(cleanBtn);
            container.Children.Add(actionBar);
        }
    }

    private TextBlock MakeStatText(string text, bool isWarning)
    {
        return new TextBlock
        {
            Text = text,
            FontSize = 12,
            Foreground = isWarning
                ? new SolidColorBrush(Color.FromRgb(230, 150, 50))
                : (Brush)FindResource("TextFillColorTertiaryBrush"),
            Margin = new Thickness(0, 0, 12, 0)
        };
    }
}
