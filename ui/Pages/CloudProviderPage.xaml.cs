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
        Loaded += (_, _) => LoadCurrentConfig();
    }

    private void LoadCurrentConfig()
    {
        var config = Services.SteamDetector.ReadConfig();
        if (config == null)
        {
            AuthStatus.Text = S.Get("CloudProvider_NoConfigFound");
            ProviderCombo.SelectedIndex = 3; // Local only
            SetDefaultLocalPath();
            return;
        }

        try
        {
            _loading = true;

            for (int i = 0; i < ProviderCombo.Items.Count; i++)
            {
                if (ProviderCombo.Items[i] is ComboBoxItem item && item.Tag as string == config.Provider)
                {
                    ProviderCombo.SelectedIndex = i;
                    break;
                }
            }

            if (config.TokenPath != null)
                TokenPathBox.Text = config.TokenPath;
            else if (config.SyncPath != null)
                TokenPathBox.Text = config.SyncPath;
            else if (config.IsLocal || config.IsFolder)
                SetDefaultLocalPath();

            UpdateProviderUI();
            UpdateAuthStatus();
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

    /// <summary>
    /// Sets the path box to the default local storage path: &lt;steamdir&gt;/localcloud.
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
        // Don't dispose _oauth here — the SignIn_Click finally block handles cleanup
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

    private void UpdateAuthStatus()
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

        var status = Services.OAuthService.CheckTokenStatus(tokenPath);
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
