using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;

namespace CloudRedirect.Pages;

public partial class CloudProviderPage : Page
{
    private Services.OAuthService? _oauth;
    private CancellationTokenSource? _authCts;
    private bool _isAuthenticating;
    private bool _loading;
    private readonly StringBuilder _logBuffer = new();

    public CloudProviderPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try { await LoadCurrentConfigAsync(); }
            catch { }
        };
        // Cancel in-flight OAuth when the user navigates away mid-auth.
        // Without this, the loopback HTTP listener in OAuthService keeps
        // running until the user closes their browser tab (or forever if
        // they don't), the auth state machine continuation keeps `this`
        // alive via the closure, and the per-message log callback
        // (msg => Dispatcher.BeginInvoke(...)) keeps marshaling work onto
        // a detached LogOutput. Cancelling _authCts triggers the existing
        // finally block in SignIn_Click which disposes _oauth + _authCts
        // and resets the UI state.
        Unloaded += (_, _) =>
        {
            if (_isAuthenticating)
                _authCts?.Cancel();
        };
    }

    /// <summary>
    /// Snapshot of everything LoadCurrentConfigAsync gathers off the UI
    /// thread. Pre-resolving the default local path here means the
    /// dispatcher continuation never has to fall back to a synchronous
    /// FindSteamPath() (registry + file probes) on Loaded.
    /// </summary>
    private sealed record LoadedConfigSnapshot(
        Services.CloudConfig? Config,
        string DefaultLocalPath,
        string PathTextOverride,
        Services.TokenStatus? TokenStatus);

    // M14: Move SteamDetector.ReadConfig + FindSteamPath + OAuth token
    // status check off the UI thread. Loaded used to call them
    // synchronously; on a slow disk or stalled DPAPI prompt that froze
    // the dispatcher long enough for the page to render with a blank
    // status line. We now resolve the snapshot in Task.Run and apply it
    // to controls in the dispatcher continuation, mirroring
    // DashboardPage.LoadStatusAsync.
    private async Task LoadCurrentConfigAsync()
    {
        // _loading must be true the entire time we touch ProviderCombo /
        // TokenPathBox so the SelectionChanged handler doesn't fire
        // user-gesture branches against a partially-initialized UI. Set
        // it on the UI thread before launching the I/O.
        _loading = true;
        try
        {
            var snapshot = await Task.Run(() =>
            {
                var config = Services.SteamDetector.ReadConfig();
                var steamPath = Services.SteamDetector.FindSteamPath();
                var defaultLocal = steamPath != null
                    ? Path.Combine(steamPath, "localcloud")
                    : "";

                string pathOverride = "";
                if (config != null)
                {
                    if (config.TokenPath != null)
                        pathOverride = config.TokenPath;
                    else if (config.SyncPath != null)
                        pathOverride = config.SyncPath;
                }

                Services.TokenStatus? tokenStatus = null;
                if (config?.TokenPath != null)
                    tokenStatus = Services.OAuthService.CheckTokenStatus(config.TokenPath);

                return new LoadedConfigSnapshot(config, defaultLocal, pathOverride, tokenStatus);
            });

            ApplyLoadedSnapshot(snapshot);
        }
        catch (Exception ex)
        {
            AuthStatus.Text = S.Format("CloudProvider_ErrorReadingConfig", ex.Message);
        }
        finally
        {
            _loading = false;
        }
    }

    private void ApplyLoadedSnapshot(LoadedConfigSnapshot snap)
    {
        if (snap.Config == null)
        {
            AuthStatus.Text = S.Get("CloudProvider_NoConfigFound");
            ProviderCombo.SelectedIndex = 3; // Local only
            if (!string.IsNullOrEmpty(snap.DefaultLocalPath))
                TokenPathBox.Text = snap.DefaultLocalPath;
            return;
        }

        for (int i = 0; i < ProviderCombo.Items.Count; i++)
        {
            if (ProviderCombo.Items[i] is ComboBoxItem item && item.Tag as string == snap.Config.Provider)
            {
                ProviderCombo.SelectedIndex = i;
                break;
            }
        }

        if (!string.IsNullOrEmpty(snap.PathTextOverride))
            TokenPathBox.Text = snap.PathTextOverride;
        else if (snap.Config.IsLocal || snap.Config.IsFolder)
        {
            if (!string.IsNullOrEmpty(snap.DefaultLocalPath))
                TokenPathBox.Text = snap.DefaultLocalPath;
        }

        UpdateProviderUI();
        // Use the pre-resolved token status so the dispatcher path never
        // re-enters CheckTokenStatus synchronously on Loaded. Only reach
        // the slow path on later user gestures (Provider change, Browse).
        UpdateAuthStatus(snap.TokenStatus);
    }

    /// <summary>
    /// Sets the path box to the default local storage path: &lt;steamdir&gt;/localcloud.
    /// Synchronous fallback for non-Loaded callers (BrowseToken, provider switch);
    /// the Loaded path uses the pre-resolved snapshot instead.
    /// </summary>
    private void SetDefaultLocalPath()
    {
        var steamPath = Services.SteamDetector.FindSteamPath();
        if (steamPath != null)
            TokenPathBox.Text = Path.Combine(steamPath, "localcloud");
    }

    private void ProviderCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;

        UpdateProviderUI();

        if (ProviderCombo.SelectedItem is ComboBoxItem item)
        {
            var tag = item.Tag as string;
            if (tag == "gdrive")
            {
                TokenPathBox.Text = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CloudRedirect", "google_tokens.json");
            }
            else if (tag == "onedrive")
            {
                TokenPathBox.Text = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CloudRedirect", "onedrive_tokens.json");
            }
            else if (tag is "local" or "folder")
            {
                SetDefaultLocalPath();
            }
        }

        UpdateAuthStatus();
    }

    /// <summary>
    /// Updates labels, enabled state, and hints for the selected provider.
    /// </summary>
    private void UpdateProviderUI()
    {
        if (ProviderCombo.SelectedItem is not ComboBoxItem item) return;

        var tag = item.Tag as string;
        bool needsTokens = tag is "gdrive" or "onedrive";
        bool isFolder = tag == "folder";
        bool isLocal = tag == "local";
        bool needsPath = needsTokens || isFolder;

        TokenPathBox.IsEnabled = needsPath;
        BrowseButton.IsEnabled = needsPath;
        SignInButton.Visibility = needsTokens ? Visibility.Visible : Visibility.Collapsed;

        // Update labels based on provider type
        if (isFolder)
        {
            PathLabel.Text = S.Get("CloudProvider_SyncFolderPath");
            TokenPathBox.PlaceholderText = S.Get("CloudProvider_SyncFolderPlaceholder");
            PathHint.Text = S.Get("CloudProvider_SyncFolderHint");
        }
        else if (isLocal)
        {
            PathLabel.Text = S.Get("CloudProvider_LocalStoragePath");
            TokenPathBox.PlaceholderText = "";
            PathHint.Text = S.Get("CloudProvider_LocalStorageHint");
            TokenPathBox.IsEnabled = false;
            BrowseButton.IsEnabled = false;
        }
        else if (needsTokens)
        {
            PathLabel.Text = S.Get("CloudProvider_TokenFilePath");
            TokenPathBox.PlaceholderText = S.Get("CloudProvider_TokenPlaceholder");
            PathHint.Text = "";
        }
        else
        {
            PathLabel.Text = S.Get("CloudProvider_TokenFilePath");
            TokenPathBox.PlaceholderText = "";
            PathHint.Text = "";
        }
    }

    private void BrowseToken_Click(object sender, RoutedEventArgs e)
    {
        var provider = GetSelectedProvider();

        if (provider == "folder")
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = S.Get("CloudProvider_SelectSyncFolder"),
                Multiselect = false
            };

            if (!string.IsNullOrEmpty(TokenPathBox.Text) && Directory.Exists(TokenPathBox.Text))
                dialog.InitialDirectory = TokenPathBox.Text;

            if (dialog.ShowDialog() == true)
            {
                TokenPathBox.Text = dialog.FolderName;
                UpdateAuthStatus();
            }
        }
        else
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = S.Get("CloudProvider_SelectTokenFile"),
                Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
                CheckFileExists = false
            };

            if (dialog.ShowDialog() == true)
            {
                TokenPathBox.Text = dialog.FileName;
                UpdateAuthStatus();
            }
        }
    }

    private async void SignIn_Click(object sender, RoutedEventArgs e)
    {
        if (_isAuthenticating) return;

        var provider = GetSelectedProvider();
        if (provider is "local" or "folder") return;

        var tokenPath = TokenPathBox.Text?.Trim();
        if (string.IsNullOrEmpty(tokenPath))
        {
            await Services.Dialog.ShowWarningAsync(S.Get("CloudProvider_MissingPath"),
                S.Get("CloudProvider_MissingPathMessage"));
            return;
        }

        _isAuthenticating = true;
        _authCts = new CancellationTokenSource();
        _oauth = new Services.OAuthService();

        // Update UI state
        SignInButton.IsEnabled = false;
        CancelAuthButton.Visibility = Visibility.Visible;
        ProviderCombo.IsEnabled = false;
        LogBorder.Visibility = Visibility.Visible;
        _logBuffer.Clear();
        LogOutput.Text = "";

        try
        {
            bool success = await _oauth.AuthorizeAsync(
                provider,
                tokenPath,
                msg => Dispatcher.BeginInvoke(() => AppendLog(msg)),
                _authCts.Token);

            if (success)
            {
                // Also save the config so the DLL picks up the new provider + token path
                await SaveConfigSilent();
            }
        }
        catch (OperationCanceledException)
        {
            AppendLog("Authentication cancelled.");
        }
        catch (Exception ex)
        {
            AppendLog($"ERROR: {ex.Message}");
        }
        finally
        {
            _oauth?.Dispose();
            _oauth = null;
            _authCts?.Dispose();
            _authCts = null;
            _isAuthenticating = false;

            SignInButton.IsEnabled = true;
            CancelAuthButton.Visibility = Visibility.Collapsed;
            ProviderCombo.IsEnabled = true;

            UpdateAuthStatus();
        }
    }

    private void CancelAuth_Click(object sender, RoutedEventArgs e)
    {
        _authCts?.Cancel();
        // Don't dispose _oauth here -- the SignIn_Click finally block handles cleanup
        // after the async operation observes cancellation.
    }

    private async void SaveConfig_Click(object sender, RoutedEventArgs e)
    {
        if (await SaveConfigSilent())
        {
            await Services.Dialog.ShowInfoAsync(S.Get("CloudProvider_Saved"), S.Get("CloudProvider_SavedMessage"));
        }
    }

    /// <summary>
    /// Writes config.json without showing a dialog. Returns true on success.
    /// </summary>
    private async Task<bool> SaveConfigSilent()
    {
        var configDir = Services.SteamDetector.GetConfigDir();

        Directory.CreateDirectory(configDir);

        var provider = GetSelectedProvider();
        var tokenPath = TokenPathBox.Text?.Trim() ?? "";

        // "local" in the UI maps to "folder" provider in the DLL with the
        // default localcloud path, so the DLL has a concrete storage location.
        var configProvider = provider;
        if (provider == "local")
            configProvider = "folder";

        var configPath = Path.Combine(configDir, "config.json");

        try
        {
            Services.ConfigHelper.SaveConfig(configPath,
                new[] { "provider", "sync_path", "token_path" },
                writer =>
                {
                    writer.WriteString("provider", configProvider);
                    if (configProvider == "folder")
                        writer.WriteString("sync_path", tokenPath);
                    else if (configProvider is not "local")
                        writer.WriteString("token_path", tokenPath);
                });
            return true;
        }
        catch (Exception ex)
        {
            await Services.Dialog.ShowErrorAsync(S.Get("Common_Error"), S.Format("CloudProvider_FailedSaveConfig", ex.Message));
            return false;
        }
    }

    private string GetSelectedProvider()
    {
        if (ProviderCombo.SelectedItem is ComboBoxItem item)
            return item.Tag as string ?? "local";
        return "local";
    }

    private void UpdateAuthStatus(Services.TokenStatus? preCheckedStatus = null)
    {
        if (ProviderCombo.SelectedItem is not ComboBoxItem item) return;

        var tag = item.Tag as string;

        if (tag == "local")
        {
            var localPath = TokenPathBox.Text?.Trim();
            if (!string.IsNullOrEmpty(localPath))
                AuthStatus.Text = S.Format("CloudProvider_LocalModeStored", localPath);
            else
                AuthStatus.Text = S.Get("CloudProvider_LocalModeNoSync");
            AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24;
            return;
        }

        if (tag == "folder")
        {
            var folderPath = TokenPathBox.Text?.Trim();
            if (string.IsNullOrEmpty(folderPath))
            {
                AuthStatus.Text = S.Get("CloudProvider_NoSyncFolder");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldKeyhole24;
            }
            else if (Directory.Exists(folderPath))
            {
                AuthStatus.Text = S.Format("CloudProvider_FolderAccessible", folderPath);
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24;
            }
            else
            {
                AuthStatus.Text = S.Format("CloudProvider_FolderNotFound", folderPath);
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldDismiss24;
            }
            return;
        }

        var tokenPath = TokenPathBox.Text?.Trim();
        if (string.IsNullOrEmpty(tokenPath))
        {
            AuthStatus.Text = S.Get("CloudProvider_NoTokenFilePath");
            AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldKeyhole24;
            return;
        }

        // Caller (the Loaded path) may pass a status that was already
        // resolved off the UI thread; otherwise we hit DPAPI + file I/O
        // synchronously. The user-gesture callers (Browse, provider
        // switch, post-OAuth) accept the synchronous cost in exchange
        // for keeping their flow simple -- those events are already
        // tied to a click and the user has paid attention.
        var status = preCheckedStatus ?? Services.OAuthService.CheckTokenStatus(tokenPath);
        AuthStatus.Text = status.Message;
        AuthIcon.Symbol = status.IsAuthenticated
            ? Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24
            : Wpf.Ui.Controls.SymbolRegular.ShieldKeyhole24;
    }

    private void AppendLog(string message)
    {
        if (_logBuffer.Length > 0)
            _logBuffer.AppendLine();
        _logBuffer.Append(message);
        LogOutput.Text = _logBuffer.ToString();
        LogScroll.ScrollToEnd();
    }
}
