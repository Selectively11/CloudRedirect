using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;
using CloudRedirect.Services;
namespace CloudRedirect.Pages;

public partial class SetupPage : Page
{
    private string? _steamPath;
    private readonly StringBuilder _logBuffer = new();
    private readonly object _logLock = new();
    private bool _isRunning;

    // Bumped on every refresh; stale results are discarded.
    private int _refreshGeneration;

    public SetupPage()
    {
        InitializeComponent();

        Loaded += async (_, _) =>
        {
            try
            {
                _steamPath = await Task.Run(() => SteamDetector.FindSteamPath());

                ModeService.SaveClientType("thirdparty");
                RunAllButton.Content = S.Get("Setup_DeployDll");
                RunAllButton.IsEnabled = !_isRunning;

                await RefreshStatuses();
            }
            catch { }
        };
    }

    private Wpf.Ui.Controls.NavigationView? FindNavigationView()
    {
        var window = Window.GetWindow(this);
        if (window is MainWindow mw)
            return mw.RootNavigation;
        return null;
    }

    private void DiagnosticsToggle_Click(object sender, RoutedEventArgs e)
    {
        DiagnosticsPanel.Visibility = DiagnosticsToggle.IsChecked == true
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private async void BrowseSteamDir_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog
        {
            Title = S.Get("Setup_BrowseSteamFolderTitle")
        };

        if (_steamPath != null && System.IO.Directory.Exists(_steamPath))
            dlg.InitialDirectory = _steamPath;

        if (dlg.ShowDialog() != true)
            return;

        var selected = dlg.FolderName;

        if (!System.IO.File.Exists(System.IO.Path.Combine(selected, "steam.exe")))
        {
            await Services.Dialog.ShowWarningAsync(S.Get("Setup_InvalidSteamFolder"),
                S.Get("Setup_InvalidSteamFolderMessage"));
            return;
        }

        SteamDetector.SetSteamPath(selected);
        _steamPath = selected;
        await RefreshStatuses();
    }

    private void Log(string message)
    {
        string snapshot;
        lock (_logLock)
        {
            _logBuffer.AppendLine(message);
            snapshot = _logBuffer.ToString();
        }
        Dispatcher.BeginInvoke(() =>
        {
            LogOutput.Text = snapshot;
            LogScrollViewer.ScrollToEnd();
        });
    }

    private void ClearLog()
    {
        lock (_logLock)
        {
            _logBuffer.Clear();
        }
        Dispatcher.BeginInvoke(() => LogOutput.Text = "");
    }

    private void SetBusy(bool busy)
    {
        _isRunning = busy;
        Dispatcher.BeginInvoke(() =>
        {
            RunAllButton.IsEnabled = !busy;
            DeployButton.IsEnabled = !busy;
            UninstallDllButton.IsEnabled = !busy;
        });
    }

    /// <summary>Graceful Steam shutdown, falling back to Kill after 15s.</summary>
    private async Task EnsureSteamClosed()
    {
        var running = await Task.Run(() =>
        {
            var procs = System.Diagnostics.Process.GetProcessesByName("steam");
            bool any = procs.Length > 0;
            foreach (var p in procs) p.Dispose();
            return any;
        });

        if (!running) return;

        Log("Steam is running - shutting it down...");

        await Task.Run(() =>
        {
            var steamExe = Path.Combine(_steamPath ?? "", "steam.exe");
            if (File.Exists(steamExe))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = steamExe,
                    Arguments = "-shutdown",
                    UseShellExecute = true
                })?.Dispose();
            }

            for (int i = 0; i < 30; i++) // 15s
            {
                System.Threading.Thread.Sleep(500);
                var check = System.Diagnostics.Process.GetProcessesByName("steam");
                bool any = check.Length > 0;
                foreach (var p in check) p.Dispose();
                if (!any) return;
            }

            foreach (var p in System.Diagnostics.Process.GetProcessesByName("steam"))
            {
                try { p.Kill(); } catch { }
                finally { p.Dispose(); }
            }
        });

        Log("Steam closed.");
    }

    private sealed record StatusSnapshot(
        ThirdPartyDetector.DetectionResult Detection,
        bool DllExists,
        long DllLength,
        DateTime DllLastWrite,
        bool? DllIsCurrent,
        bool EmbeddedAvailable);

    private static StatusSnapshot ComputeStatusSnapshot(string steamPath)
    {
        var detection = ThirdPartyDetector.Detect(steamPath);

        var dllExists = false;
        long dllLength = 0;
        var dllLastWrite = default(DateTime);
        bool? dllIsCurrent = null;

        var dllPath = Path.Combine(steamPath, "cloud_redirect.dll");
        if (File.Exists(dllPath))
        {
            try
            {
                var info = new FileInfo(dllPath);
                dllExists = true;
                dllLength = info.Length;
                dllLastWrite = info.LastWriteTime;
                dllIsCurrent = EmbeddedDll.IsDeployedCurrent(dllPath);
            }
            catch
            {
                // Unreadable: exists, state unknown.
                dllExists = true;
                dllIsCurrent = null;
            }
        }

        return new StatusSnapshot(
            Detection: detection,
            DllExists: dllExists,
            DllLength: dllLength,
            DllLastWrite: dllLastWrite,
            DllIsCurrent: dllIsCurrent,
            EmbeddedAvailable: EmbeddedDll.IsAvailable());
    }

    private async Task RefreshStatuses()
    {
        var gen = System.Threading.Interlocked.Increment(ref _refreshGeneration);

        // Sync prefix: instant "no Steam" feedback is worth a tiny order race.
        SteamPathText.Text = _steamPath ?? S.Get("Setup_SteamNotFoundManual");
        if (_steamPath == null)
        {
            DeployStatusText.Text = S.Get("Setup_SteamNotFound");
            DetectionStatusText.Text = S.Get("Setup_SteamNotFound");
            RunAllButton.IsEnabled = false;
            return;
        }

        // Capture path so a racing path-flip can't apply a stale result.
        var capturedPath = _steamPath;
        StatusSnapshot snap;
        try
        {
            snap = await Task.Run(() => ComputeStatusSnapshot(capturedPath));
        }
        catch
        {
            // Unexpected (snapshot already swallows the expected ones).
            return;
        }

        // Discard if newer refresh started or path changed (covers ABA).
        if (gen != _refreshGeneration || capturedPath != _steamPath)
            return;

        try
        {
            ApplyStatusSnapshot(snap);
        }
        catch
        {
            // Control writes can throw on a navigated-away page.
        }
    }

    private void ApplyStatusSnapshot(StatusSnapshot snap)
    {
        // Detection gating: block deploy for incompatible tools, grey out when none found.
        switch (snap.Detection.Status)
        {
            case ThirdPartyDetector.DetectionStatus.Blocked:
                DetectionStatusText.Text = S.Get("Setup_BlockedSFF");
                DetectionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0xFF, 0x44, 0x44));
                RunAllButton.IsEnabled = false;
                break;

            case ThirdPartyDetector.DetectionStatus.Compatible:
                DetectionStatusText.Text = S.Format("Setup_CompatibleDetected", snap.Detection.DetectedTool);
                DetectionStatusText.Foreground = (System.Windows.Media.Brush)FindResource("TextFillColorSecondaryBrush");
                RunAllButton.IsEnabled = !_isRunning;
                break;

            case ThirdPartyDetector.DetectionStatus.NotFound:
            default:
                DetectionStatusText.Text = S.Get("Setup_NoUnlockSolution");
                DetectionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0xFF, 0xAA, 0x00));
                RunAllButton.IsEnabled = false;
                break;
        }

        // DLL status in diagnostics panel.
        if (snap.DllExists)
        {
            if (snap.DllIsCurrent == false)
            {
                DeployStatusText.Text = S.Format("Setup_DllInstalledOutdated", snap.DllLastWrite.ToString("g"));
                DeployStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0xFF, 0xAA, 0x00));
                DeployButton.Content = S.Get("Setup_UpdateDll");
                DeployButton.Visibility = Visibility.Visible;
            }
            else
            {
                DeployStatusText.Text = S.Format("Setup_DllInstalled", snap.DllLength.ToString("N0"), snap.DllLastWrite.ToString("g"));
                DeployButton.Content = S.Get("Setup_Deploy");
                DeployButton.Visibility = Visibility.Collapsed;
            }
            UninstallDllButton.Visibility = Visibility.Visible;
        }
        else if (snap.EmbeddedAvailable)
        {
            DeployStatusText.Text = S.Get("Setup_DllNotInstalledReady");
            DeployButton.Content = S.Get("Setup_Deploy");
            UninstallDllButton.Visibility = Visibility.Collapsed;
        }
        else
        {
            DeployStatusText.Text = S.Get("Setup_DllNotInstalledNoEmbed");
            DeployButton.Content = S.Get("Setup_Deploy");
            UninstallDllButton.Visibility = Visibility.Collapsed;
        }
    }

    /// <summary>
    /// Writes a default config.json that uses the folder provider with
    /// &lt;steamdir&gt;/localcloud as the sync path.
    /// </summary>
    private async Task WriteDefaultLocalConfig()
    {
        var configDir = Services.SteamDetector.GetConfigDir();

        try
        {
            Directory.CreateDirectory(configDir);

            var localCloudPath = Path.Combine(_steamPath ?? "", "localcloud");
            Directory.CreateDirectory(localCloudPath);

            var configPath = Path.Combine(configDir, "config.json");

            await Task.Run(() => Services.ConfigHelper.SaveConfig(configPath,
                new[] { "provider", "sync_path" },
                writer =>
                {
                    writer.WriteString("provider", "folder");
                    writer.WriteString("sync_path", localCloudPath);
                }));

            Log($"Default config written - saves will sync to: {localCloudPath}");
            Log("You can change this later on the Cloud Provider page.");
        }
        catch (Exception ex)
        {
            Log($"WARNING: Failed to write default config: {ex.Message}");
        }
    }

    private async void RunAll_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        // Hard block: refuse to deploy alongside StealIdra.
        var detection = await Task.Run(() => ThirdPartyDetector.Detect(_steamPath));
        if (detection.Status == ThirdPartyDetector.DetectionStatus.Blocked)
        {
            await Services.Dialog.ShowWarningAsync(S.Get("Setup_BlockedSFF_Title"),
                S.Get("Setup_BlockedSFF"));
            return;
        }

        await RunAllThirdParty();
    }

    private async Task RunAllThirdParty()
    {
        if (!EmbeddedDll.IsAvailable())
        {
            await Services.Dialog.ShowWarningAsync(S.Get("Setup_DllNotEmbedded"),
                S.Get("Setup_DllNotEmbeddedMessage"));
            return;
        }

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("═══ Deploy cloud_redirect.dll ═══");

        bool succeeded = false;
        try
        {
            var destPath = Path.Combine(_steamPath!, "cloud_redirect.dll");
            var deployError = await Task.Run(() => EmbeddedDll.DeployTo(destPath));

            if (deployError != null)
            {
                Log($"FAILED: {deployError}");
                DeployStatusText.Text = S.Get("Setup_DeployFailed");
            }
            else
            {
                var info = new FileInfo(destPath);
                DeployStatusText.Text = S.Format("Setup_DllInstalled", info.Length.ToString("N0"), info.LastWriteTime.ToString("g"));
                Log($"Deployed to {destPath}");
                Log("OK");
                succeeded = true;
            }
        }
        catch (Exception ex)
        {
            Log($"FAILED: {ex.Message}");
            DeployStatusText.Text = S.Get("Setup_DeployFailed");
        }

        Log("");

        // If OpenSteamTool is the detected host, auto-configure its cloud setting.
        if (succeeded)
        {
            var detection = await Task.Run(() => ThirdPartyDetector.Detect(_steamPath!));
            if (detection.DetectedTool == "OpenSteamTool")
            {
                Log("═══ Configure OpenSteamTool ═══");
                try
                {
                    var result = await Task.Run(() =>
                        OpenSteamToolIntegration.EnsureCloudEnabled(_steamPath!));

                    Log(result.Change switch
                    {
                        OpenSteamToolIntegration.ChangeKind.AlreadyEnabled =>
                            "[cloud].enabled is already true.",
                        OpenSteamToolIntegration.ChangeKind.Created =>
                            $"Created {result.ConfigPath} with [cloud].enabled = true.",
                        _ =>
                            $"Enabled [cloud] in {result.ConfigPath}.",
                    });
                    if (result.BackupPath != null && File.Exists(result.BackupPath))
                        Log($"Configuration backup: {result.BackupPath}");
                    Log("OK");
                }
                catch (Exception ex)
                {
                    Log($"WARNING: OpenSteamTool config failed: {ex.Message}");
                    Log("Enable [cloud].enabled = true manually in opensteamtool.toml before starting Steam.");
                }
                Log("");
            }
        }

        if (succeeded)
        {
            Log("DLL deployed. Your third-party client will load it on next Steam launch.");

            bool providerReady = false;
            var existingConfig = Services.SteamDetector.ReadConfig();
            if (existingConfig != null &&
                existingConfig.Provider is "gdrive" or "onedrive" &&
                !string.IsNullOrEmpty(existingConfig.TokenPath))
            {
                var tokenStatus = Services.OAuthService.CheckTokenStatus(existingConfig.TokenPath);
                providerReady = tokenStatus.IsAuthenticated;
            }
            else if (existingConfig != null &&
                     existingConfig.Provider is "r2" or "s3" &&
                     !string.IsNullOrEmpty(existingConfig.TokenPath) &&
                     File.Exists(existingConfig.TokenPath))
            {
                providerReady = true;
            }

            if (!providerReady)
            {
                var statusText = S.Get("Setup_AllPatchesApplied");
                string message = existingConfig != null
                    ? S.Format("Setup_ConfigureProviderExisting", statusText, existingConfig.DisplayName)
                    : S.Format("Setup_ConfigureProviderNew", statusText);

                var wantsConfigure = await Services.Dialog.ChoiceAsync(
                    S.Get("Setup_ConfigureProviderTitle"),
                    message,
                    S.Get("Setup_ConfigureProvider"),
                    S.Get("Setup_UseLocalStorage"));

                if (wantsConfigure)
                {
                    var nav = FindNavigationView();
                    nav?.Navigate(typeof(CloudProviderPage));
                }
                else if (existingConfig == null)
                {
                    await WriteDefaultLocalConfig();
                }
            }

            if (!HasBeenPromptedForAutoUpdate())
                await PromptAutoUpdateAsync();
        }

        SetBusy(false);
    }

    private static bool HasBeenPromptedForAutoUpdate()
    {
        try
        {
            var configPath = Services.SteamDetector.GetConfigFilePath();
            if (!File.Exists(configPath)) return false;
            var json = File.ReadAllText(configPath);
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("auto_update_prompted", out _);
        }
        catch { return false; }
    }

    private async Task PromptAutoUpdateAsync()
    {
        try
        {
            var enable = await Services.Dialog.ChoiceAsync(
                "Automatic Updates",
                "Would you like CloudRedirect to check for and install updates during Steam startup?\n\n" +
                "You can change this behavior in the Settings tab in this app.",
                "Enable",
                "No thanks");

            var configPath = Services.SteamDetector.GetConfigFilePath();
            await Task.Run(() => Services.ConfigHelper.SaveConfig(configPath,
                new[] { "auto_update_dll", "auto_update_prompted" },
                writer =>
                {
                    writer.WriteBoolean("auto_update_dll", enable);
                    writer.WriteBoolean("auto_update_prompted", true);
                }));
        }
        catch { }
    }

    private async void Deploy_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        // Hard block: refuse to deploy alongside StealIdra.
        var detection = await Task.Run(() => ThirdPartyDetector.Detect(_steamPath));
        if (detection.Status == ThirdPartyDetector.DetectionStatus.Blocked)
        {
            await Services.Dialog.ShowWarningAsync(S.Get("Setup_BlockedSFF_Title"),
                S.Get("Setup_BlockedSFF"));
            return;
        }

        if (!EmbeddedDll.IsAvailable())
        {
            await Services.Dialog.ShowWarningAsync(S.Get("Setup_DllNotEmbedded"),
                S.Get("Setup_DllNotEmbeddedMessage"));
            return;
        }

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Source: embedded resource");

        try
        {
            var destPath = Path.Combine(_steamPath, "cloud_redirect.dll");
            var error = await Task.Run(() => EmbeddedDll.DeployTo(destPath));

            if (error != null)
            {
                Log($"ERROR: {error}");
                DeployStatusText.Text = S.Get("Setup_DeployFailed");
            }
            else
            {
                var info = new FileInfo(destPath);
                Log($"Deployed to: {destPath}");
                Log($"Size: {info.Length:N0} bytes");
                DeployStatusText.Text = S.Format("Setup_DllInstalled", info.Length.ToString("N0"), info.LastWriteTime.ToString("g"));
                Log("");
                Log("DLL deployed successfully.");
            }
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            DeployStatusText.Text = S.Get("Setup_DeployFailed");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void UninstallDll_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        var dllPath = Path.Combine(_steamPath, "cloud_redirect.dll");
        if (!File.Exists(dllPath))
        {
            DeployStatusText.Text = S.Get("Setup_NotInstalled");
            UninstallDllButton.Visibility = Visibility.Collapsed;
            return;
        }

        var confirm = await Services.Dialog.ConfirmDangerAsync(S.Get("Setup_UninstallDllTitle"),
            S.Get("Setup_ConfirmUninstall"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Removing cloud_redirect.dll...");

        try
        {
            await Task.Run(() => File.Delete(dllPath));
            DeployStatusText.Text = S.Get("Setup_NotInstalled");
            UninstallDllButton.Visibility = Visibility.Collapsed;
            Log($"Deleted {dllPath}");
            Log("");
            Log("DLL uninstalled.");
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            DeployStatusText.Text = S.Get("Setup_UninstallFailedSteam");
        }
        finally
        {
            SetBusy(false);
        }
    }

}
