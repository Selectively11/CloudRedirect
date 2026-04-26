using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;
using CloudRedirect.Services;
using CloudRedirect.Services.Patching;

namespace CloudRedirect.Pages;

public partial class SetupPage : Page
{
    private string _steamPath;
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

                var mode = SteamDetector.ReadModeSetting();
                if (mode == "stfixer")
                {
                    DescriptionText.Text = S.Get("Setup_Description_STFixer");
                    CloudRedirectPatchHeaderText.Text = S.Get("Setup_CloudRedirectPatchHeader_STFixer");
                    CloudRedirectPatchDescriptionText.Text = S.Get("Setup_CloudRedirectPatchDescription_STFixer");
                }

                await RefreshStatuses();
            }
            catch { }
        };
    }

    private Wpf.Ui.Controls.NavigationView FindNavigationView()
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
            OfflineSetupButton.IsEnabled = !busy;
            OfflineRevertButton.IsEnabled = !busy;
            RunAllButton.IsEnabled = !busy;
            StExePatchButton.IsEnabled = !busy;
            StExeUnpatchButton.IsEnabled = !busy;
            PatchButton.IsEnabled = !busy;
            PatchRevertButton.IsEnabled = !busy;
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

        Log("Steam is running -- shutting it down...");

        await Task.Run(() =>
        {
            var steamExe = Path.Combine(_steamPath, "steam.exe");
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

    /// <summary>Starts Steam, waits up to 90s for the payload cache, then closes it.</summary>
    private async Task<bool> BootstrapSteamForPayload()
    {
        var steamExe = Path.Combine(_steamPath, "steam.exe");
        if (!File.Exists(steamExe))
        {
            Log("steam.exe not found");
            return false;
        }

        Log("Starting Steam to download payload cache...");

        await Task.Run(() =>
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = steamExe,
                UseShellExecute = true
            })?.Dispose();
        });

        Log("Waiting for payload to appear (up to 90 seconds)...");

        bool found = await Task.Run(() =>
        {
            for (int i = 0; i < 180; i++) // 90s at 500ms intervals
            {
                System.Threading.Thread.Sleep(500);
                if (Fingerprint.FindCachePath(_steamPath, verbose: false) != null)
                    return true;
            }
            return false;
        });

        if (found)
            Log("Payload cache found.");
        else
            Log("Timed out waiting for payload cache.");

        await EnsureSteamClosed();
        return found;
    }

    // Computed off-thread by ComputeStatusSnapshot, applied by ApplyStatusSnapshot.
    private sealed record StatusSnapshot(
        long? Version,
        PatchState OfflineState,
        PatchState PatchState,
        int StExeState,
        bool ProbeFailed,
        string? ProbeError,
        bool DllExists,
        long DllLength,
        DateTime DllLastWrite,
        bool? DllIsCurrent,
        bool EmbeddedAvailable);

    private static StatusSnapshot ComputeStatusSnapshot(string steamPath)
    {
        var version = SteamDetector.GetSteamVersion(steamPath);
        var offline = PatchState.NotInstalled;
        var patchState = PatchState.NotInstalled;
        var stExe = -1;
        var probeFailed = false;
        string? probeError = null;

        try
        {
            // One Patcher instance so the AES-decrypted payload cache is reused.
            var patcher = new Patcher(steamPath, _ => { });
            offline = patcher.GetOfflinePatchState();
            stExe = patcher.GetSteamToolsExePatchState();
            patchState = patcher.GetPatchState();
        }
        catch (Exception ex)
        {
            probeFailed = true;
            probeError = ex.Message;
        }

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
            Version: version,
            OfflineState: offline,
            PatchState: patchState,
            StExeState: stExe,
            ProbeFailed: probeFailed,
            ProbeError: probeError,
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
            OfflineStatusText.Text = S.Get("Setup_SteamNotFound");
            StExeStatusText.Text = S.Get("Setup_SteamNotFound");
            PatchStatusText.Text = S.Get("Setup_SteamNotFound");
            DeployStatusText.Text = S.Get("Setup_SteamNotFound");
            VersionStatusText.Text = S.Get("Setup_VersionCouldNotDetermine");
            VersionIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.Warning24;
            return;
        }

        // Capture path so a racing path-flip can't apply a stale result.
        var capturedPath = _steamPath;
        StatusSnapshot snap;
        try
        {
            snap = await Task.Run(() => ComputeStatusSnapshot(capturedPath));
        }
        catch (Exception ex)
        {
            // Unexpected (snapshot already swallows the expected ones).
            if (gen != _refreshGeneration) return;
            OfflineStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
            StExeStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
            PatchStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
            return;
        }

        // Discard if newer refresh started or path changed (covers ABA).
        if (gen != _refreshGeneration || capturedPath != _steamPath)
            return;

        try
        {
            ApplyStatusSnapshot(snap);
        }
        catch (Exception ex)
        {
            // S.Format / brush / control writes can throw on a navigated-away page.
            try
            {
                OfflineStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
                StExeStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
                PatchStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
            }
            catch { }
        }
    }

    private void ApplyStatusSnapshot(StatusSnapshot snap)
    {
        ApplyVersionStatus(snap.Version);

        if (snap.ProbeFailed)
        {
            OfflineStatusText.Text = S.Format("Setup_CouldNotCheck", snap.ProbeError);
            StExeStatusText.Text = S.Format("Setup_CouldNotCheck", snap.ProbeError);
            PatchStatusText.Text = S.Format("Setup_CouldNotCheck", snap.ProbeError);
        }
        else
        {
            ApplyOfflineStatus(snap.OfflineState);
            ApplyStExeStatus(snap.StExeState);
            ApplyPatchStatus(snap.PatchState);
        }

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

    private void ApplyVersionStatus(long? version)
    {
        if (version == null)
        {
            VersionStatusText.Text = S.Get("Setup_VersionCouldNotDetermine");
            VersionIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.Warning24;
            return;
        }

        if (version.Value == SteamDetector.ExpectedSteamVersion)
        {
            VersionStatusText.Text = S.Format("Setup_VersionSupported", version.Value);
            VersionIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.CheckmarkCircle24;
        }
        else
        {
            var direction = version.Value > SteamDetector.ExpectedSteamVersion
                ? S.Get("Setup_DirectionNewer") : S.Get("Setup_DirectionOlder");
            VersionStatusText.Text = S.Format("Setup_VersionUnsupported", version.Value, direction, SteamDetector.ExpectedSteamVersion);
            VersionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xFF, 0x44, 0x44));
            VersionIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ErrorCircle24;

            // Disable all patching buttons -- they will fail or cause damage
            PatchButton.IsEnabled = false;
            DeployButton.IsEnabled = false;
            OfflineSetupButton.IsEnabled = false;
            StExePatchButton.IsEnabled = false;
            RunAllButton.IsEnabled = false;
        }
    }

    private void ApplyPatchStatus(PatchState state)
    {
        PatchStatusText.Text = state switch
        {
            PatchState.Patched => S.Get("Setup_PatchState_Patched"),
            PatchState.Unpatched => S.Get("Setup_PatchState_Unpatched"),
            PatchState.PartiallyPatched => S.Get("Setup_PatchState_PartiallyPatched"),
            PatchState.NotInstalled => S.Get("Setup_PatchState_NotInstalled"),
            PatchState.UnknownVersion => S.Get("Setup_PatchState_UnknownVersion"),
            PatchState.OutOfDate => S.Get("Setup_PatchState_OutOfDate"),
            _ => S.Get("Setup_PatchState_Unknown")
        };
        PatchRevertButton.Visibility = (state == PatchState.Patched || state == PatchState.PartiallyPatched)
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void ApplyOfflineStatus(PatchState state)
    {
        OfflineStatusText.Text = state switch
        {
            PatchState.Patched => S.Get("Setup_OfflinePatched"),
            PatchState.Unpatched => S.Get("Setup_PatchState_Unpatched"),
            PatchState.PartiallyPatched => S.Get("Setup_PatchState_PartiallyPatched"),
            PatchState.NotInstalled => S.Get("Setup_PatchState_NotInstalled"),
            PatchState.UnknownVersion => S.Get("Setup_PatchState_UnknownVersion"),
            PatchState.OutOfDate => S.Get("Setup_PatchState_OutOfDate"),
            _ => S.Get("Setup_PatchState_Unknown")
        };
        OfflineRevertButton.Visibility = (state == PatchState.Patched || state == PatchState.PartiallyPatched)
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private void ApplyStExeStatus(int state)
    {
        StExeStatusText.Text = state switch
        {
            0 => S.Get("Setup_StExePatched"),
            1 => S.Get("Setup_StExeActive"),
            _ => S.Get("Setup_StExeNotFound")
        };
        StExeUnpatchButton.Visibility = state == 0
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    // Per-button post-action refreshers; off-thread to avoid stalling the UI.
    private async Task RefreshPatchStatusAsync()
    {
        var gen = System.Threading.Interlocked.Increment(ref _refreshGeneration);
        var capturedPath = _steamPath;
        if (capturedPath == null) return;
        try
        {
            var state = await Task.Run(() => new Patcher(capturedPath, _ => { }).GetPatchState());
            if (gen != _refreshGeneration || capturedPath != _steamPath) return;
            ApplyPatchStatus(state);
        }
        catch (Exception ex)
        {
            if (gen != _refreshGeneration) return;
            PatchStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
            PatchRevertButton.Visibility = Visibility.Collapsed;
        }
    }

    private async Task RefreshOfflineStatusAsync()
    {
        var gen = System.Threading.Interlocked.Increment(ref _refreshGeneration);
        var capturedPath = _steamPath;
        if (capturedPath == null) return;
        try
        {
            var state = await Task.Run(() => new Patcher(capturedPath, _ => { }).GetOfflinePatchState());
            if (gen != _refreshGeneration || capturedPath != _steamPath) return;
            ApplyOfflineStatus(state);
        }
        catch (Exception ex)
        {
            if (gen != _refreshGeneration) return;
            OfflineStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
            OfflineRevertButton.Visibility = Visibility.Collapsed;
        }
    }

    private async Task RefreshStExeStatusAsync()
    {
        var gen = System.Threading.Interlocked.Increment(ref _refreshGeneration);
        var capturedPath = _steamPath;
        if (capturedPath == null) return;
        try
        {
            var state = await Task.Run(() => new Patcher(capturedPath, _ => { }).GetSteamToolsExePatchState());
            if (gen != _refreshGeneration || capturedPath != _steamPath) return;
            ApplyStExeStatus(state);
        }
        catch (Exception ex)
        {
            if (gen != _refreshGeneration) return;
            StExeStatusText.Text = S.Format("Setup_CouldNotCheck", ex.Message);
            StExeUnpatchButton.Visibility = Visibility.Collapsed;
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

            var localCloudPath = Path.Combine(_steamPath, "localcloud");
            Directory.CreateDirectory(localCloudPath);

            var configPath = Path.Combine(configDir, "config.json");

            await Task.Run(() => Services.ConfigHelper.SaveConfig(configPath,
                new[] { "provider", "sync_path" },
                writer =>
                {
                    writer.WriteString("provider", "folder");
                    writer.WriteString("sync_path", localCloudPath);
                }));

            Log($"Default config written -- saves will sync to: {localCloudPath}");
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

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_RunAllPatches"),
            S.Get("Setup_ConfirmRunAll"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        bool allSucceeded = true;

        // Pre-step: if core DLLs are missing, download them and bootstrap Steam
        bool needsCoreDlls = await Task.Run(() => !new Patcher(_steamPath, Log).HasCoreDll());
        if (needsCoreDlls)
        {
            Log("═══ Pre-step: Download SteamTools Core DLLs ═══");
            try
            {
                var patcher = new Patcher(_steamPath, Log);
                PatchResult repairResult = await patcher.RepairCoreDllsAsync();

                if (repairResult?.Succeeded != true)
                {
                    Log($"FAILED: {repairResult?.Error ?? "Unknown error"}");
                    Log("");
                    Log("Cannot proceed without core DLLs.");
                    SetBusy(false);
                    return;
                }
                Log("OK");
            }
            catch (Exception ex)
            {
                Log($"FAILED: {ex.Message}");
                Log("");
                Log("Cannot proceed without core DLLs.");
                SetBusy(false);
                return;
            }
            Log("");
        }

        bool needsPayload = await Task.Run(() => !new Patcher(_steamPath, Log).HasPayloadCache());
        if (needsPayload)
        {
            Log("═══ Pre-step: Bootstrap Steam for Payload ═══");
            bool payloadFound = await BootstrapSteamForPayload();
            if (!payloadFound)
            {
                Log("FAILED: Payload cache did not appear.");
                Log("Try running Steam manually, wait for it to fully load, then close it and try again.");
                Log("");
                SetBusy(false);
                return;
            }
            Log("OK");
            Log("");
        }

        Log("═══ Step 1/4: SteamTools Offline Setup ═══");
        try
        {
            PatchResult result = null;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                result = patcher.ApplyOfflineSetup();
            });

            if (result?.Succeeded == true)
            {
                OfflineStatusText.Text = S.Get("Setup_OfflinePatched");
                Log("OK");
            }
            else
            {
                OfflineStatusText.Text = S.Get("Setup_FailedSeeLog");
                Log($"FAILED: {result?.Error ?? "Unknown error"}");
                allSucceeded = false;
            }
        }
        catch (Exception ex)
        {
            Log($"FAILED: {ex.Message}");
            allSucceeded = false;
        }

        Log("");

        Log("═══ Step 2/4: Patch SteamTools.exe ═══");
        try
        {
            int stResult = 0;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                stResult = patcher.PatchSteamToolsExe();
            });

            await RefreshStExeStatusAsync();
            if (stResult == 0)
                Log("Skipped (not installed)");
            else if (stResult == 1)
                Log("OK");
            else
            {
                Log("FAILED -- see detail above");
                allSucceeded = false;
            }
        }
        catch (Exception ex)
        {
            Log($"FAILED: {ex.Message}");
            allSucceeded = false;
        }

        Log("");

        Log("═══ Step 3/4: Cloud Redirect Patch ═══");
        try
        {
            PatchResult patchResult = null;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                patchResult = patcher.ApplyCloudRedirectNamespace();
            });

            if (patchResult?.Succeeded == true)
            {
                PatchStatusText.Text = S.Get("Setup_PatchAppliedSuccessfully");
                Log("OK");
            }
            else
            {
                PatchStatusText.Text = S.Get("Setup_PatchFailedSeeLog");
                Log($"FAILED: {patchResult?.Error ?? "Unknown error"}");
                allSucceeded = false;
            }
        }
        catch (Exception ex)
        {
            Log($"FAILED: {ex.Message}");
            PatchStatusText.Text = S.Get("Setup_PatchFailedSeeLog");
            allSucceeded = false;
        }

        Log("");

        Log("═══ Step 4/4: Deploy cloud_redirect.dll ═══");
        try
        {
            var destPath = Path.Combine(_steamPath, "cloud_redirect.dll");
            var deployError = await Task.Run(() => EmbeddedDll.DeployTo(destPath));

            if (deployError != null)
            {
                Log($"FAILED: {deployError}");
                DeployStatusText.Text = S.Get("Setup_DeployFailed");
                allSucceeded = false;
            }
            else
            {
                var info = new FileInfo(destPath);
                DeployStatusText.Text = S.Format("Setup_DllInstalled", info.Length.ToString("N0"), info.LastWriteTime.ToString("g"));
                Log($"Deployed to {destPath}");
                Log("OK");
            }
        }
        catch (Exception ex)
        {
            Log($"FAILED: {ex.Message}");
            DeployStatusText.Text = S.Get("Setup_DeployFailed");
            allSucceeded = false;
        }

        Log("");

        // Refresh all statuses (off-thread; both methods swallow their own errors)
        await RefreshOfflineStatusAsync();
        await RefreshStExeStatusAsync();

        if (!allSucceeded)
        {
            Log("Some steps failed -- review the log above.");
        }
        else
        {
            Log("All patches applied successfully.");
        }

        // Only prompt for cloud provider config in cloud_redirect mode
        var mode = SteamDetector.ReadModeSetting();
        if (mode == "cloud_redirect")
        {
            var existingConfig = Services.SteamDetector.ReadConfig();
            var statusText = allSucceeded ? S.Get("Setup_AllPatchesApplied") : S.Get("Setup_PatchingFinishedWithErrors");
            string message;
            if (existingConfig != null)
            {
                message = S.Format("Setup_ConfigureProviderExisting", statusText, existingConfig.DisplayName);
            }
            else
            {
                message = S.Format("Setup_ConfigureProviderNew", statusText);
            }

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

        SetBusy(false);
    }

    private async void OfflineSetup_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_ConfirmOfflineSetupTitle"),
            S.Get("Setup_ConfirmOfflineSetup"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Applying SteamTools offline setup patch...");

        try
        {
            PatchResult result = null;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                result = patcher.ApplyOfflineSetup();
            });

            if (result?.Succeeded == true)
            {
                OfflineStatusText.Text = S.Get("Setup_OfflinePatched");
                Log("");
                Log("Offline setup complete.");
            }
            else
            {
                OfflineStatusText.Text = S.Get("Setup_FailedSeeLog");
                Log("");
                Log($"ERROR: {result?.Error ?? "Unknown error"}");
            }
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            OfflineStatusText.Text = S.Get("Setup_FailedSeeLog");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void OfflineRevert_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_RevertOfflineSetupTitle"),
            S.Get("Setup_ConfirmRevertOffline"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Reverting SteamTools offline setup patch...");

        try
        {
            PatchResult result = null;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                result = patcher.RevertOfflineSetup();
            });

            await RefreshOfflineStatusAsync();

            if (result?.Succeeded == true)
            {
                Log("");
                Log("Offline setup reverted.");
            }
            else
            {
                OfflineStatusText.Text = S.Get("Setup_FailedSeeLog");
                Log("");
                Log($"ERROR: {result?.Error ?? "Unknown error"}");
            }
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            OfflineStatusText.Text = S.Get("Setup_FailedSeeLog");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void StExePatch_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_PatchSteamToolsExeTitle"),
            S.Get("Setup_ConfirmPatchStExe"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Patching SteamTools.exe to disable DLL deployment...");

        try
        {
            int stResult = 0;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                stResult = patcher.PatchSteamToolsExe();
            });

            await RefreshStExeStatusAsync();
            Log("");
            Log(stResult == 1 ? "SteamTools.exe patched."
              : stResult == 0 ? "SteamTools.exe not found -- nothing to patch."
              : "Patch failed -- see log above.");
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            StExeStatusText.Text = S.Get("Setup_FailedSeeLog");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void StExeUnpatch_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_RevertStExeTitle"),
            S.Get("Setup_ConfirmRevertStExe"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Restoring SteamTools.exe to original...");

        try
        {
            bool success = false;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                success = patcher.UnpatchSteamToolsExe();
            });

            await RefreshStExeStatusAsync();
            Log("");
            Log(success ? "SteamTools.exe restored." : "Restore failed -- see log above.");
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            StExeStatusText.Text = S.Get("Setup_FailedSeeLog");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void Patch_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_ApplyPatchTitle"),
            S.Get("Setup_ConfirmApplyPatch"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Applying cloud redirect patch...");

        try
        {
            PatchResult patchResult = null;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                patchResult = patcher.ApplyCloudRedirectNamespace();
            });

            if (patchResult?.Succeeded == true)
            {
                PatchStatusText.Text = S.Get("Setup_PatchAppliedSuccessfully");
                Log("");
                Log("Patch complete. Remember to deploy cloud_redirect.dll next.");
            }
            else
            {
                PatchStatusText.Text = S.Get("Setup_PatchFailedSeeLog");
                Log($"FAILED: {patchResult?.Error ?? "Unknown error"}");
            }
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            PatchStatusText.Text = S.Get("Setup_PatchFailedSeeLog");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void PatchRevert_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_RevertCloudRedirectTitle"),
            S.Get("Setup_ConfirmRevertPatch"));

        if (!confirm) return;

        SetBusy(true);
        ClearLog();

        await EnsureSteamClosed();

        Log("Reverting cloud redirect patch...");

        try
        {
            PatchResult result = null;
            await Task.Run(() =>
            {
                var patcher = new Patcher(_steamPath, Log);
                result = patcher.RevertCloudRedirectNamespace();
            });

            await RefreshPatchStatusAsync();

            if (result?.Succeeded == true)
            {
                Log("");
                Log("Cloud redirect patch reverted.");
            }
            else
            {
                PatchStatusText.Text = S.Get("Setup_FailedSeeLog");
                Log("");
                Log($"ERROR: {result?.Error ?? "Unknown error"}");
            }
        }
        catch (Exception ex)
        {
            Log($"ERROR: {ex.Message}");
            PatchStatusText.Text = S.Get("Setup_FailedSeeLog");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void Deploy_Click(object sender, RoutedEventArgs e)
    {
        if (_isRunning || _steamPath == null) return;

        if (!EmbeddedDll.IsAvailable())
        {
            await Services.Dialog.ShowWarningAsync(S.Get("Setup_DllNotEmbedded"),
                S.Get("Setup_DllNotEmbeddedMessage"));
            return;
        }

        var confirm = await Services.Dialog.ConfirmAsync(S.Get("Setup_DeployDllTitle"),
            S.Get("Setup_ConfirmDeploy"));

        if (!confirm) return;

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
