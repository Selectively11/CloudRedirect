using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;

namespace CloudRedirect.Pages;

public partial class NewsPage : Page
{
    private string? _steamPath;

    public NewsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try { await CheckDllUpdateAsync(); }
            catch { }
        };
    }

    private async Task CheckDllUpdateAsync()
    {
        var data = await Task.Run(() =>
        {
            var steamPath = Services.SteamDetector.FindSteamPath();
            if (steamPath == null) return (steamPath: (string?)null, needsUpdate: false);
            var dllPath = Path.Combine(steamPath, "cloud_redirect.dll");
            if (!File.Exists(dllPath)) return (steamPath, needsUpdate: false);
            return (steamPath, needsUpdate: Services.EmbeddedDll.IsDeployedCurrent(dllPath) == false);
        });

        _steamPath = data.steamPath;

        if (data.needsUpdate)
            UpdateBanner.Visibility = Visibility.Visible;
    }

    private async void UpdateDll_Click(object sender, RoutedEventArgs e)
    {
        if (_steamPath == null) return;

        UpdateBanner.Visibility = Visibility.Collapsed;

        try
        {
            var steamRunning = await Task.Run(() =>
            {
                var procs = Process.GetProcessesByName("steam");
                bool running = procs.Length > 0;
                foreach (var p in procs) p.Dispose();
                return running;
            });

            if (steamRunning)
            {
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

                    for (int i = 0; i < 30; i++)
                    {
                        System.Threading.Thread.Sleep(500);
                        var check = Process.GetProcessesByName("steam");
                        bool any = check.Length > 0;
                        foreach (var p in check) p.Dispose();
                        if (!any) return;
                    }

                    foreach (var p in Process.GetProcessesByName("steam"))
                    {
                        try { p.Kill(); } catch { }
                        finally { p.Dispose(); }
                    }
                });
            }

            var destPath = Path.Combine(_steamPath, "cloud_redirect.dll");
            var error = await Task.Run(() => Services.EmbeddedDll.DeployTo(destPath));

            if (error != null)
            {
                await Services.Dialog.ShowErrorAsync(S.Get("Common_UpdateFailed"), error);
                UpdateBanner.Visibility = Visibility.Visible;
            }
            else
            {
                UpdateBanner.Visibility = Visibility.Collapsed;

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
