using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;
using TextBlock = System.Windows.Controls.TextBlock;

namespace CloudRedirect;

public partial class MainWindow : FluentWindow
{
    private Services.AppUpdater.CheckResult? _pendingUpdate;
    public bool AppUpdateAvailable { get; private set; }
    private readonly DispatcherTimer _steamStateTimer = new() { Interval = TimeSpan.FromSeconds(5) };

    public MainWindow()
    {
        InitializeComponent();

        Loaded += async (_, _) =>
        {
            try
            {
                SystemThemeWatcher.Watch(this);

                _ = CheckForAutoUpdateAsync();

                var mode = await Task.Run(() => Services.SteamDetector.ReadModeSetting());
                ApplyMode(mode);

                bool needsSetup = await Task.Run(() => NeedsSetup());

                if (mode == null)
                    RootNavigation.Navigate(typeof(Pages.ChoiceModePage));
                else if (needsSetup)
                    RootNavigation.Navigate(typeof(Pages.SetupPage));
                else
                    RootNavigation.Navigate(typeof(Pages.DashboardPage));
            }
            catch { }

            UpdateSteamNavItem();
            _steamStateTimer.Tick += (_, _) => UpdateSteamNavItem();
            _steamStateTimer.Start();
        };
    }

    public void ApplyMode(string? mode)
    {
        var cloudOnly = mode == "cloud_redirect";
        var vis = cloudOnly ? Visibility.Visible : Visibility.Collapsed;
        NavCloudProvider.Visibility = vis;
        NavApps.Visibility = vis;
        NavCleanup.Visibility = vis;
        NavCloud760.Visibility = vis;

        // In cloud_redirect the mode chooser is hidden from the sidebar; the
        // switch-back lives under Settings. In STFixer it stays visible.
        NavChoiceMode.Visibility = cloudOnly ? Visibility.Collapsed : Visibility.Visible;

        RootNavigation.UpdateLayout();
    }

    /// <summary>
    /// Returns true if the DLL isn't deployed or config.json doesn't exist yet.
    /// </summary>
    private static bool NeedsSetup()
    {
        var steamPath = Services.SteamDetector.FindSteamPath();
        if (steamPath == null) return true;

        if (!File.Exists(Path.Combine(steamPath, "cloud_redirect.dll")))
            return true;

        var configPath = Services.SteamDetector.GetConfigFilePath();
        if (!File.Exists(configPath))
            return true;

        return false;
    }

    /// <summary>
    /// Checks GitHub for a newer version. If found, shows an inline banner
    /// with changelog and Update/Skip buttons.
    /// </summary>
    private async Task CheckForAutoUpdateAsync()
    {
        try
        {
            var result = await Services.AppUpdater.CheckAsync();
            if (result == null || !result.UpdateAvailable || result.DownloadUrl == null)
                return;

            _pendingUpdate = result;
            var versionStr = result.TagName?.TrimStart('v') ?? result.TagName ?? "unknown";
            var body = result.Body?.Trim() ?? "";

            UpdateBannerTitle.Text = $"Update available -- v{versionStr}";
            UpdateBannerStatus.Text = "A new version of CloudRedirect is ready to install.";

            if (!string.IsNullOrEmpty(body))
            {
                UpdateChangelogText.Text = body;
                UpdateChangelogScroll.Visibility = Visibility.Visible;
            }

            if (!string.IsNullOrEmpty(result.HtmlUrl))
                UpdateReleaseNotesButton.Visibility = Visibility.Visible;

            AppUpdateAvailable = true;
            UpdateBanner.Visibility = Visibility.Visible;
        }
        catch
        {
            // Auto-update check failures are non-fatal
        }
    }

    private async void UpdateNow_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdate?.DownloadUrl == null) return;

        var versionStr = _pendingUpdate.TagName?.TrimStart('v') ?? "unknown";

        // Switch banner to download mode
        UpdateNowButton.Visibility = Visibility.Collapsed;
        UpdateSkipButton.Visibility = Visibility.Collapsed;
        UpdateReleaseNotesButton.Visibility = Visibility.Collapsed;
        UpdateChangelogScroll.Visibility = Visibility.Collapsed;
        UpdateBannerStatus.Text = $"Downloading v{versionStr}...";
        UpdateProgressBar.Visibility = Visibility.Visible;
        UpdateProgressBar.IsIndeterminate = true;

        var error = await Services.AppUpdater.DownloadAndApplyAsync(
            _pendingUpdate.DownloadUrl,
            (pct, status) => Dispatcher.Invoke(() =>
            {
                UpdateBannerStatus.Text = status;
                if (pct >= 0)
                {
                    UpdateProgressBar.IsIndeterminate = false;
                    UpdateProgressBar.Value = pct;
                }
                else
                {
                    UpdateProgressBar.IsIndeterminate = true;
                }
            }));

        if (error != null)
        {
            // Show error, restore buttons so user can retry
            UpdateBannerTitle.Text = "Update failed";
            UpdateBannerStatus.Text = error;
            UpdateProgressBar.Visibility = Visibility.Collapsed;
            UpdateBanner.Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromArgb(0x33, 0xC4, 0x2B, 0x1C));
            UpdateBanner.BorderBrush = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xC4, 0x2B, 0x1C));
            UpdateNowButton.Visibility = Visibility.Visible;
            UpdateSkipButton.Visibility = Visibility.Visible;
        }
        // If successful, the process will have exited already
    }

    private void UpdateReleaseNotes_Click(object sender, RoutedEventArgs e)
    {
        if (_pendingUpdate?.HtmlUrl != null)
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = _pendingUpdate.HtmlUrl,
                UseShellExecute = true
            });
        }
    }

    private void UpdateSkip_Click(object sender, RoutedEventArgs e)
    {
        UpdateBanner.Visibility = Visibility.Collapsed;
        _pendingUpdate = null;
    }

    public void ShowRestartSteam()
    {
        UpdateSteamNavItem();
    }

    private void UpdateSteamNavItem()
    {
        var running = Services.SteamDetector.IsSteamRunning();
        RestartSteamItem.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        CloseSteamItem.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        StartSteamItem.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
    }

    private async void SteamNav_Click(object sender, RoutedEventArgs e)
    {
        var tag = (sender as FrameworkElement)?.Tag as string;

        var steamPath = Services.SteamDetector.FindSteamPath();
        if (steamPath == null) return;

        var steamExe = Path.Combine(steamPath, "steam.exe");
        if (!File.Exists(steamExe)) return;

        if (tag == "start")
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = steamExe,
                    UseShellExecute = true
                })?.Dispose();
            }
            catch { }
            return;
        }

        // restart or close — shut down Steam first
        var procs = Process.GetProcessesByName("steam");
        bool wasRunning = procs.Length > 0;
        foreach (var p in procs) p.Dispose();

        if (wasRunning)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = steamExe,
                Arguments = "-shutdown",
                UseShellExecute = true
            })?.Dispose();

            for (int i = 0; i < 30; i++)
            {
                await Task.Delay(500);
                var check = Process.GetProcessesByName("steam");
                bool still = check.Length > 0;
                foreach (var p in check) p.Dispose();
                if (!still) break;
            }
        }

        if (tag == "restart")
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = steamExe,
                    UseShellExecute = true
                })?.Dispose();
            }
            catch { }
        }

        UpdateSteamNavItem();
    }
}
