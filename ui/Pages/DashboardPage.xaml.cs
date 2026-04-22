using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;

namespace CloudRedirect.Pages;

public partial class DashboardPage : Page
{
    private string? _steamPath;

    public DashboardPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try { await LoadStatusAsync(); }
            catch { }
        };
    }

    // M16: Gather data off the UI thread, update controls on dispatcher
    private async Task LoadStatusAsync()
    {
        var data = await Task.Run(() =>
        {
            var steamPath = Services.SteamDetector.FindSteamPath();
            bool dllExists = false;
            bool? dllCurrent = null;
            Services.CloudConfig config = null;
            int appCount = 0;
            Services.TokenStatus tokenStatus = null;

            if (steamPath != null)
            {
                var dllPath = Path.Combine(steamPath, "cloud_redirect.dll");
                dllExists = File.Exists(dllPath);
                if (dllExists)
                    dllCurrent = Services.EmbeddedDll.IsDeployedCurrent(dllPath);
                config = Services.SteamDetector.ReadConfig();

                var storagePath = Path.Combine(steamPath, "cloud_redirect", "storage");
                if (Directory.Exists(storagePath))
                {
                    foreach (var accountDir in Directory.GetDirectories(storagePath))
                        appCount += Directory.GetDirectories(accountDir).Length;
                }

                // M9: Check OAuth token status off the UI thread (DPAPI + file I/O)
                if (config?.TokenPath != null)
                    tokenStatus = Services.OAuthService.CheckTokenStatus(config.TokenPath);
            }

            return (steamPath, dllExists, dllCurrent, config, appCount, tokenStatus);
        });

        _steamPath = data.steamPath;

        // Update UI on dispatcher thread
        SteamStatus.Text = data.steamPath ?? S.Get("Dashboard_NotFound");

        if (data.steamPath != null)
        {
            if (!data.dllExists)
            {
                DllStatus.Text = S.Get("Dashboard_DllNotInstalled");
                DllIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.PlugDisconnected24;
            }
            else if (data.dllCurrent == false)
            {
                DllStatus.Text = S.Get("Dashboard_DllInstalledUpdateAvailable");
                DllIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ArrowSync24;
                UpdateBanner.Visibility = Visibility.Visible;
            }
            else
            {
                DllStatus.Text = S.Get("Dashboard_DllInstalled");
                DllIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.PlugConnected24;
            }

            if (data.config != null)
                UpdateProviderAuthStatus(data.config, data.tokenStatus);

            AppCount.Text = S.Format("Dashboard_AppCountFormat", data.appCount);
        }
    }

    private void UpdateProviderAuthStatus(Services.CloudConfig config, Services.TokenStatus preCheckedStatus)
    {
        if (config.IsLocal)
        {
            ProviderStatus.Text = config.DisplayName;
            ProviderIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.CloudCheckmark24;
            return;
        }

        if (config.IsFolder)
        {
            if (config.SyncPath != null)
            {
                if (Directory.Exists(config.SyncPath))
                {
                    ProviderStatus.Text = S.Format("Dashboard_FolderAccessible", config.DisplayName);
                    ProviderIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.CloudCheckmark24;
                }
                else
                {
                    ProviderStatus.Text = S.Format("Dashboard_FolderNotFound", config.DisplayName);
                    ProviderIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.CloudDismiss24;
                }
            }
            else
            {
                ProviderStatus.Text = S.Format("Dashboard_NoSyncFolder", config.DisplayName);
                ProviderIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.CloudOff24;
            }
            return;
        }

        // OAuth providers (gdrive, onedrive)
        if (config.TokenPath != null && preCheckedStatus != null)
        {
            ProviderStatus.Text = preCheckedStatus.IsAuthenticated
                ? S.Format("Dashboard_Authenticated", config.DisplayName)
                : S.Format("Dashboard_AuthStatus", config.DisplayName, preCheckedStatus.Message);
            ProviderIcon.Symbol = preCheckedStatus.IsAuthenticated
                ? Wpf.Ui.Controls.SymbolRegular.CloudCheckmark24
                : Wpf.Ui.Controls.SymbolRegular.CloudOff24;
        }
        else
        {
            ProviderStatus.Text = S.Format("Dashboard_NoTokenPath", config.DisplayName);
            ProviderIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.CloudOff24;
        }
    }

    private async void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        var logPath = Services.SteamDetector.GetLogPath();
        if (logPath != null && File.Exists(logPath))
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = logPath,
                UseShellExecute = true
            })?.Dispose();
        }
        else
        {
            await Services.Dialog.ShowInfoAsync(S.Get("Common_Info"),
                S.Get("Dashboard_LogNotFound"));
        }
    }

    private async void RestartSteam_Click(object sender, RoutedEventArgs e)
    {
        var steamPath = Services.SteamDetector.FindSteamPath();
        if (steamPath == null)
        {
            await Services.Dialog.ShowErrorAsync(S.Get("Common_Error"), S.Get("Dashboard_CouldNotFindSteam"));
            return;
        }

        var steamExe = Path.Combine(steamPath, "steam.exe");
        if (!File.Exists(steamExe))
        {
            await Services.Dialog.ShowErrorAsync(S.Get("Common_Error"), S.Get("Dashboard_SteamExeNotFound"));
            return;
        }

        if (!Services.SteamDetector.IsSteamRunning())
        {
            return;
        }

        var confirmed = await Services.Dialog.ConfirmAsync(S.Get("Dashboard_RestartSteam"),
            S.Get("Dashboard_RestartSteamPrompt"));

        if (!confirmed) return;

        var button = (Wpf.Ui.Controls.Button)sender;
        button.IsEnabled = false;
        var originalContent = button.Content;
        button.Content = S.Get("Dashboard_ShuttingDownSteam");

        try
        {
            // Ask Steam to shut down gracefully
            Process.Start(new ProcessStartInfo
            {
                FileName = steamExe,
                Arguments = "-shutdown",
                UseShellExecute = true
            })?.Dispose();

            // Poll until Steam processes exit (up to 15 seconds)
            bool exited = await Task.Run(async () =>
            {
                for (int i = 0; i < 30; i++) // 30 x 500ms = 15s
                {
                    await Task.Delay(500);
                    var procs = Process.GetProcessesByName("steam");
                    bool any = procs.Length > 0;
                    foreach (var p in procs) p.Dispose();
                    if (!any) return true;
                }
                return false;
            });

            if (!exited)
            {
                // Graceful shutdown didn't work -- offer force-kill
                var forceKill = await Services.Dialog.ConfirmAsync(S.Get("Dashboard_SteamStillRunning"),
                    S.Get("Dashboard_SteamStillRunningPrompt"));

                if (forceKill)
                {
                    button.Content = S.Get("Dashboard_ForceKilling");
                    await Task.Run(() =>
                    {
                        foreach (var proc in Process.GetProcessesByName("steam"))
                        {
                            try { proc.Kill(); }
                            catch { /* already exited */ }
                            finally { proc.Dispose(); }
                        }
                    });

                    // Brief wait for process table cleanup
                    await Task.Delay(1000);
                }
                else
                {
                    return; // User cancelled
                }
            }

            // Start Steam
            button.Content = S.Get("Dashboard_StartingSteam");
            Process.Start(new ProcessStartInfo
            {
                FileName = steamExe,
                UseShellExecute = true
            })?.Dispose();
        }
        catch (Exception ex)
        {
            await Services.Dialog.ShowErrorAsync(S.Get("Common_Error"), S.Format("Dashboard_FailedRestartSteam", ex.Message));
        }
        finally
        {
            button.Content = originalContent;
            button.IsEnabled = true;
        }
    }

    private async void UpdateDll_Click(object sender, RoutedEventArgs e)
    {
        if (_steamPath == null) return;

        UpdateBanner.Visibility = Visibility.Collapsed;

        try
        {
            // Shut down Steam if it's running
            var steamRunning = await Task.Run(() =>
            {
                var procs = Process.GetProcessesByName("steam");
                bool running = procs.Length > 0;
                foreach (var p in procs) p.Dispose();
                return running;
            });

            if (steamRunning)
            {
                DllStatus.Text = S.Get("Dashboard_ClosingSteam");

                await Task.Run(() =>
                {
                    var steamExe = Path.Combine(_steamPath, "steam.exe");
                    if (File.Exists(steamExe))
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = steamExe,
                            Arguments = "-shutdown",
                            UseShellExecute = true
                        })?.Dispose();
                    }

                    // Wait up to 15s for graceful exit
                    for (int i = 0; i < 30; i++)
                    {
                        System.Threading.Thread.Sleep(500);
                        var check = Process.GetProcessesByName("steam");
                        bool any = check.Length > 0;
                        foreach (var p in check) p.Dispose();
                        if (!any) return;
                    }

                    // Force-kill stragglers
                    foreach (var p in Process.GetProcessesByName("steam"))
                    {
                        try { p.Kill(); } catch { }
                        finally { p.Dispose(); }
                    }
                });
            }

            DllStatus.Text = S.Get("Dashboard_Updating");

            var destPath = Path.Combine(_steamPath, "cloud_redirect.dll");
            var error = await Task.Run(() => Services.EmbeddedDll.DeployTo(destPath));

            if (error != null)
            {
                DllStatus.Text = S.Get("Dashboard_UpdateFailed");
                await Services.Dialog.ShowErrorAsync(S.Get("Common_UpdateFailed"), error);
                UpdateBanner.Visibility = Visibility.Visible;
            }
            else
            {
                DllStatus.Text = S.Get("Dashboard_DllInstalledUpdated");
                DllIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.PlugConnected24;

                if (steamRunning)
                {
                    var restart = await Services.Dialog.ConfirmAsync(S.Get("Dashboard_DllUpdatedTitle"),
                        S.Get("Dashboard_DllUpdatedRestartPrompt"));
                    if (restart)
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = Path.Combine(_steamPath, "steam.exe"),
                            UseShellExecute = true
                        })?.Dispose();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            await Services.Dialog.ShowErrorAsync(S.Get("Common_Error"), S.Format("Dashboard_FailedUpdateDll", ex.Message));
            UpdateBanner.Visibility = Visibility.Visible;
        }
    }
}
