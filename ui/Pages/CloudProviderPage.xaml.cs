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

    // Upload in-flight cap (MB). Only shown/saved for Google Drive.
    private const int InFlightDefaultMb = 24;
    private const int InFlightMinMb = 24;
    private const int InFlightMaxMb = 64;
    // Suppresses the slider ValueChanged handler during programmatic load.
    private bool _inFlightLoading;

    public CloudProviderPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try { await LoadCurrentConfigAsync(); }
            catch { }
        };
        // Cancel in-flight OAuth on Unloaded to stop the loopback listener and prevent leaked references.
        Unloaded += (_, _) =>
        {
            if (_isAuthenticating)
                _authCts?.Cancel();
        };
    }

    /// <summary>Off-thread config snapshot for LoadCurrentConfigAsync.</summary>
    private sealed record LoadedConfigSnapshot(
        Services.CloudConfig? Config,
        string DefaultLocalPath,
        string PathTextOverride,
        Services.TokenStatus? TokenStatus,
        int UploadInFlightMb);

    // M14: Read config + token status off UI thread to avoid disk/DPAPI stall.
    private async Task LoadCurrentConfigAsync()
    {
        // Set _loading before I/O to suppress SelectionChanged during init.
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
                if (config?.TokenPath != null && config.Provider is not "r2" and not "s3")
                    tokenStatus = Services.OAuthService.CheckTokenStatus(config.TokenPath);

                return new LoadedConfigSnapshot(config, defaultLocal, pathOverride, tokenStatus, ReadUploadInFlightMb());
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
        ApplyUploadInFlight(snap.UploadInFlightMb);

        if (snap.Config == null)
        {
            AuthStatus.Text = S.Get("CloudProvider_NoConfigFound");
            ProviderCombo.SelectedIndex = 2; // Folder / Mapped Drive (default local path)
            if (!string.IsNullOrEmpty(snap.DefaultLocalPath))
                TokenPathBox.Text = snap.DefaultLocalPath;
            UpdateProviderUI();
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
            else if (tag == "r2")
            {
                TokenPathBox.Text = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CloudRedirect", "r2_credentials.json");
            }
            else if (tag == "s3")
            {
                TokenPathBox.Text = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CloudRedirect", "s3_credentials.json");
            }
            else if (tag == "folder")
            {
                SetDefaultLocalPath();
            }
        }

        UpdateAuthStatus();
        // Persist the provider switch (and the path it just set).
        _ = SaveConfigSilent();
    }

    // Auto-save manual path edits when the field loses focus, rather than on
    // every keystroke.
    private void TokenPathBox_LostFocus(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        _ = SaveConfigSilent();
    }

    /// <summary>
    /// Updates labels, enabled state, and hints for the selected provider.
    /// </summary>
    private void UpdateProviderUI()
    {
        if (ProviderCombo.SelectedItem is not ComboBoxItem item) return;

        var tag = item.Tag as string;
        bool needsOAuth = tag is "gdrive" or "onedrive";
        bool isR2 = tag == "r2";
        bool isS3 = tag == "s3";
        bool isFolder = tag == "folder";
        bool needsPathRow = needsOAuth || isFolder; // R2/S3 hide the path row

        // Token path row: visible for OAuth/folder, hidden for R2.
        PathLabel.Visibility = needsPathRow ? Visibility.Visible : Visibility.Collapsed;
        TokenPathGrid.Visibility = needsPathRow ? Visibility.Visible : Visibility.Collapsed;
        TokenPathBox.Visibility = needsPathRow ? Visibility.Visible : Visibility.Collapsed;
        BrowseButton.Visibility = needsPathRow ? Visibility.Visible : Visibility.Collapsed;
        TokenPathBox.IsEnabled = needsPathRow;
        BrowseButton.IsEnabled = needsPathRow;

        // R2 uses static credentials (no OAuth sign-in flow).
        SignInButton.Visibility = needsOAuth ? Visibility.Visible : Visibility.Collapsed;
        // Upload in-flight cap is a Google Drive-only throttle.
        UploadInFlightSection.Visibility = tag == "gdrive" ? Visibility.Visible : Visibility.Collapsed;
        // R2 credential entry panel.
        R2CredentialsPanel.Visibility = isR2 ? Visibility.Visible : Visibility.Collapsed;
        // S3-compatible credential entry panel.
        S3CredentialsPanel.Visibility = isS3 ? Visibility.Visible : Visibility.Collapsed;

        // Update labels based on provider type
        if (isFolder)
        {
            PathLabel.Text = S.Get("CloudProvider_SyncFolderPath");
            TokenPathBox.PlaceholderText = S.Get("CloudProvider_SyncFolderPlaceholder");
            PathHint.Text = S.Get("CloudProvider_SyncFolderHint");
        }
        else if (isR2)
        {
            PathHint.Text = "";
            // Load existing creds into the fields if the file exists.
            LoadR2CredentialFields();
        }
        else if (isS3)
        {
            PathHint.Text = "";
            // Load existing creds into the fields if the file exists.
            LoadS3CredentialFields();
        }
        else if (needsOAuth)
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

        // Only reserve space for the hint when it actually has text.
        PathHint.Visibility = string.IsNullOrEmpty(PathHint.Text)
            ? Visibility.Collapsed : Visibility.Visible;
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
                _ = SaveConfigSilent();
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
                _ = SaveConfigSilent();
            }
        }
    }

    private void S3BrowseCaCert_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select CA Certificate",
            Filter = "PEM files (*.pem)|*.pem|Certificate files (*.crt;*.cer)|*.crt;*.cer|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (!string.IsNullOrEmpty(S3CaCertBox.Text) && File.Exists(S3CaCertBox.Text))
            dialog.InitialDirectory = Path.GetDirectoryName(S3CaCertBox.Text);

        if (dialog.ShowDialog() == true)
            S3CaCertBox.Text = dialog.FileName;
    }

    private async void SignIn_Click(object sender, RoutedEventArgs e)
    {
        if (_isAuthenticating) return;

        var provider = GetSelectedProvider();
        if (provider == "folder") return;

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

    private async Task<bool> SaveConfigSilent()
    {
        var configDir = Services.SteamDetector.GetConfigDir();

        Directory.CreateDirectory(configDir);

        var provider = GetSelectedProvider();
        var tokenPath = TokenPathBox.Text?.Trim() ?? "";

        var configPath = Path.Combine(configDir, "config.json");

        // Read existing token_paths to merge the new entry.
        var tokenPaths = new Dictionary<string, string>();
        if (File.Exists(configPath))
        {
            try
            {
                var existingJson = File.ReadAllText(configPath);
                using var existingDoc = System.Text.Json.JsonDocument.Parse(existingJson);
                if (existingDoc.RootElement.TryGetProperty("token_paths", out var tps) &&
                    tps.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    foreach (var prop in tps.EnumerateObject())
                    {
                        if (prop.Value.ValueKind == System.Text.Json.JsonValueKind.String)
                            tokenPaths[prop.Name] = prop.Value.GetString() ?? "";
                    }
                }
            }
            catch { }
        }

        // Register this provider's path (skip folder/local — they use sync_path).
        if (provider != "folder" && provider != "local" && !string.IsNullOrEmpty(tokenPath))
            tokenPaths[provider] = tokenPath;

        try
        {
            Services.ConfigHelper.SaveConfig(configPath,
                new[] { "provider", "sync_path", "token_path", "token_paths" },
                writer =>
                {
                    writer.WriteString("provider", provider);
                    if (provider == "folder")
                        writer.WriteString("sync_path", tokenPath);
                    else
                        writer.WriteString("token_path", tokenPath);

                    // Persist per-provider token path registry.
                    writer.WritePropertyName("token_paths");
                    writer.WriteStartObject();
                    foreach (var (key, value) in tokenPaths)
                        writer.WriteString(key, value);
                    writer.WriteEndObject();
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
            return item.Tag as string ?? "folder";
        return "folder";
    }

    private void UpdateAuthStatus(Services.TokenStatus? preCheckedStatus = null)
    {
        if (ProviderCombo.SelectedItem is not ComboBoxItem item) return;

        var tag = item.Tag as string;

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

        if (tag == "r2")
        {
            var credPath = TokenPathBox.Text?.Trim();
            if (string.IsNullOrEmpty(credPath))
            {
                AuthStatus.Text = S.Get("CloudProvider_NoTokenFilePath");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldKeyhole24;
            }
            else if (!File.Exists(credPath))
            {
                AuthStatus.Text = S.Get("CloudProvider_R2CredMissing");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldDismiss24;
            }
            else if (!CheckR2CredentialFields(credPath))
            {
                AuthStatus.Text = S.Get("CloudProvider_R2CredInvalid");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldDismiss24;
            }
            else
            {
                AuthStatus.Text = S.Get("CloudProvider_R2CredFound");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24;
            }
            return;
        }

        if (tag == "s3")
        {
            var credPath = TokenPathBox.Text?.Trim();
            if (string.IsNullOrEmpty(credPath))
            {
                AuthStatus.Text = S.Get("CloudProvider_NoTokenFilePath");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldKeyhole24;
            }
            else if (!File.Exists(credPath))
            {
                AuthStatus.Text = S.Get("CloudProvider_S3CredMissing");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldDismiss24;
            }
            else if (!CheckS3CredentialFields(credPath))
            {
                AuthStatus.Text = S.Get("CloudProvider_S3CredInvalid");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldDismiss24;
            }
            else
            {
                AuthStatus.Text = S.Get("CloudProvider_S3CredFound");
                AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24;
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

        // preCheckedStatus avoids sync DPAPI/file I/O on Loaded; user-gesture callers accept sync cost.
        var status = preCheckedStatus ?? Services.OAuthService.CheckTokenStatus(tokenPath);
        AuthStatus.Text = status.Message;
        AuthIcon.Symbol = status.IsAuthenticated
            ? Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24
            : Wpf.Ui.Controls.SymbolRegular.ShieldKeyhole24;
    }

    /// <summary>
    /// Quick check that the R2 credentials file contains the four required fields.
    /// Does not validate the credential values (that happens at runtime via the DLL).
    /// </summary>
    private static bool CheckR2CredentialFields(string path)
    {
        try
        {
            var json = File.ReadAllText(path);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;
            return root.TryGetProperty("account_id", out var a) && a.GetString()?.Length > 0
                && root.TryGetProperty("access_key_id", out var b) && b.GetString()?.Length > 0
                && root.TryGetProperty("secret_access_key", out var c) && c.GetString()?.Length > 0
                && root.TryGetProperty("bucket", out var d) && d.GetString()?.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the default R2 credentials file path.
    /// </summary>
    private static string GetR2CredentialPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "CloudRedirect", "r2_credentials.json");
    }

    /// <summary>
    /// Populate the R2 credential text fields from the existing file (if any).
    /// Only fills non-sensitive fields (account_id, access_key_id, bucket);
    /// the secret key is shown as masked/empty.
    /// </summary>
    private void LoadR2CredentialFields()
    {
        R2AccountIdBox.Text = "";
        R2AccessKeyBox.Text = "";
        R2SecretKeyBox.Password = "";
        R2BucketBox.Text = "";
        R2KeyPrefixBox.Text = "";
        R2EndpointBox.Text = "";

        var path = GetR2CredentialPath();
        if (!File.Exists(path)) return;

        try
        {
            var json = File.ReadAllText(path);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("account_id", out var a))
                R2AccountIdBox.Text = a.GetString() ?? "";
            if (root.TryGetProperty("access_key_id", out var b))
                R2AccessKeyBox.Text = b.GetString() ?? "";
            if (root.TryGetProperty("bucket", out var d))
                R2BucketBox.Text = d.GetString() ?? "";
            if (root.TryGetProperty("key_prefix", out var kp))
                R2KeyPrefixBox.Text = kp.GetString() ?? "";
            if (root.TryGetProperty("endpoint", out var ep))
                R2EndpointBox.Text = ep.GetString() ?? "";
            if (root.TryGetProperty("secret_access_key", out var c) && (c.GetString()?.Length ?? 0) > 0)
                R2SecretKeyBox.Password = c.GetString() ?? "";
        }
        catch { }
    }

    private async void R2SaveCreds_Click(object sender, RoutedEventArgs e)
    {
        var accountId = R2AccountIdBox.Text?.Trim() ?? "";
        var accessKey = R2AccessKeyBox.Text?.Trim() ?? "";
        var secretKey = R2SecretKeyBox.Password?.Trim() ?? "";
        var bucket = R2BucketBox.Text?.Trim() ?? "";
        var keyPrefix = R2KeyPrefixBox.Text?.Trim() ?? "";
        var endpoint = R2EndpointBox.Text?.Trim() ?? "";

        if (string.IsNullOrEmpty(accountId) || string.IsNullOrEmpty(accessKey) ||
            string.IsNullOrEmpty(secretKey) || string.IsNullOrEmpty(bucket))
        {
            await Services.Dialog.ShowWarningAsync(S.Get("CloudProvider_R2CredTitle"),
                S.Get("CloudProvider_R2FieldsRequired"));
            return;
        }

        var credPath = GetR2CredentialPath();
        var dir = Path.GetDirectoryName(credPath)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        // Write the credentials as a simple JSON file. key_prefix and endpoint
        // are optional and only written when non-empty (matches the Linux UI).
        var cred = new Dictionary<string, string>
        {
            ["account_id"] = accountId,
            ["access_key_id"] = accessKey,
            ["secret_access_key"] = secretKey,
            ["bucket"] = bucket
        };
        if (!string.IsNullOrEmpty(keyPrefix))
            cred["key_prefix"] = keyPrefix;
        if (!string.IsNullOrEmpty(endpoint))
            cred["endpoint"] = endpoint;

        var json = System.Text.Json.JsonSerializer.Serialize(cred,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

        Services.FileUtils.AtomicWriteAllText(credPath, json);

        // Point the config at this credentials file.
        TokenPathBox.Text = credPath;
        await SaveConfigSilent();

        // Update status to reflect the saved credentials.
        UpdateAuthStatus();
        AuthStatus.Text = S.Get("CloudProvider_R2CredSaved");
        AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24;
    }

    /// <summary>
    /// Quick check that the S3 credentials file contains the required fields.
    /// Generic S3 needs an explicit endpoint + region (no account-derived host).
    /// </summary>
    private static bool CheckS3CredentialFields(string path)
    {
        try
        {
            var json = File.ReadAllText(path);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;
            return root.TryGetProperty("access_key_id", out var a) && a.GetString()?.Length > 0
                && root.TryGetProperty("secret_access_key", out var b) && b.GetString()?.Length > 0
                && root.TryGetProperty("bucket", out var c) && c.GetString()?.Length > 0
                && root.TryGetProperty("endpoint", out var d) && d.GetString()?.Length > 0
                && root.TryGetProperty("region", out var e) && e.GetString()?.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the default S3 credentials file path.
    /// </summary>
    private static string GetS3CredentialPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "CloudRedirect", "s3_credentials.json");
    }

    /// <summary>
    /// Populate the S3 credential fields from the existing file (if any).
    /// Only fills non-sensitive fields; the secret key is left blank.
    /// </summary>
    private void LoadS3CredentialFields()
    {
        S3EndpointBox.Text = "";
        S3AccessKeyBox.Text = "";
        S3SecretKeyBox.Password = "";
        S3BucketBox.Text = "";
        S3RegionBox.Text = "";
        S3KeyPrefixBox.Text = "";
        S3CaCertBox.Text = "";
        S3SignPayloadCheck.IsChecked = false;
        S3InsecureHttpCheck.IsChecked = false;
        S3InsecureTlsCheck.IsChecked = false;

        var path = GetS3CredentialPath();
        if (!File.Exists(path)) return;

        try
        {
            var json = File.ReadAllText(path);
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("access_key_id", out var a))
                S3AccessKeyBox.Text = a.GetString() ?? "";
            if (root.TryGetProperty("bucket", out var b))
                S3BucketBox.Text = b.GetString() ?? "";
            if (root.TryGetProperty("endpoint", out var c))
                S3EndpointBox.Text = c.GetString() ?? "";
            if (root.TryGetProperty("region", out var d))
                S3RegionBox.Text = d.GetString() ?? "";
            if (root.TryGetProperty("key_prefix", out var kp))
                S3KeyPrefixBox.Text = kp.GetString() ?? "";
            if (root.TryGetProperty("ca_cert_path", out var ca))
                S3CaCertBox.Text = ca.GetString() ?? "";
            S3SignPayloadCheck.IsChecked =
                root.TryGetProperty("sign_payload", out var sp) && sp.ValueKind == System.Text.Json.JsonValueKind.True;
            S3InsecureHttpCheck.IsChecked =
                root.TryGetProperty("allow_insecure_http", out var ih) && ih.ValueKind == System.Text.Json.JsonValueKind.True;
            S3InsecureTlsCheck.IsChecked =
                root.TryGetProperty("allow_insecure_tls", out var it) && it.ValueKind == System.Text.Json.JsonValueKind.True;
            if (root.TryGetProperty("secret_access_key", out var s) && (s.GetString()?.Length ?? 0) > 0)
                S3SecretKeyBox.Password = s.GetString() ?? "";
        }
        catch { }
    }

    private async void S3SaveCreds_Click(object sender, RoutedEventArgs e)
    {
        var accessKey = S3AccessKeyBox.Text?.Trim() ?? "";
        var secretKey = S3SecretKeyBox.Password?.Trim() ?? "";
        var bucket = S3BucketBox.Text?.Trim() ?? "";
        var endpoint = S3EndpointBox.Text?.Trim() ?? "";
        var region = S3RegionBox.Text?.Trim() ?? "";
        var keyPrefix = S3KeyPrefixBox.Text?.Trim() ?? "";
        var caCertPath = S3CaCertBox.Text?.Trim() ?? "";

        if (string.IsNullOrEmpty(accessKey) || string.IsNullOrEmpty(secretKey) ||
            string.IsNullOrEmpty(bucket) || string.IsNullOrEmpty(endpoint) ||
            string.IsNullOrEmpty(region))
        {
            await Services.Dialog.ShowWarningAsync(S.Get("CloudProvider_S3CredTitle"),
                S.Get("CloudProvider_S3FieldsRequired"));
            return;
        }

        var credPath = GetS3CredentialPath();
        var dir = Path.GetDirectoryName(credPath)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        // Build the credentials object. String fields go in a dictionary; the
        // boolean transport/signing flags are added via a JsonObject so their
        // JSON type is a real bool (matching the native S3Provider parser).
        var cred = new System.Text.Json.Nodes.JsonObject
        {
            ["access_key_id"] = accessKey,
            ["secret_access_key"] = secretKey,
            ["bucket"] = bucket,
            ["endpoint"] = endpoint,
            ["region"] = region
        };
        if (!string.IsNullOrEmpty(keyPrefix))
            cred["key_prefix"] = keyPrefix;
        // Only emit the optional flags when set, to keep the file minimal.
        if (S3SignPayloadCheck.IsChecked == true)
            cred["sign_payload"] = true;
        if (S3InsecureHttpCheck.IsChecked == true)
            cred["allow_insecure_http"] = true;
        if (S3InsecureTlsCheck.IsChecked == true)
            cred["allow_insecure_tls"] = true;
        if (!string.IsNullOrEmpty(caCertPath))
            cred["ca_cert_path"] = caCertPath;

        var json = cred.ToJsonString(
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

        Services.FileUtils.AtomicWriteAllText(credPath, json);

        // Point the config at this credentials file.
        TokenPathBox.Text = credPath;
        await SaveConfigSilent();

        // Update status to reflect the saved credentials.
        UpdateAuthStatus();
        AuthStatus.Text = S.Get("CloudProvider_S3CredSaved");
        AuthIcon.Symbol = Wpf.Ui.Controls.SymbolRegular.ShieldCheckmark24;
    }

    /// <summary>Reads upload_inflight_mb from config.json, clamped 24..64.
    /// Absent/invalid -> the 24 MB default. Off the UI thread.</summary>
    private static int ReadUploadInFlightMb()
    {
        try
        {
            var path = Services.SteamDetector.GetConfigFilePath();
            if (!File.Exists(path)) return InFlightDefaultMb;

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.TryGetProperty("upload_inflight_mb", out var inf) && inf.TryGetInt32(out var mb))
                return Math.Clamp(mb, InFlightMinMb, InFlightMaxMb);
        }
        catch { }
        return InFlightDefaultMb;
    }

    private void ApplyUploadInFlight(int mb)
    {
        _inFlightLoading = true;
        try
        {
            UploadInFlightSlider.Value = Math.Clamp(mb, InFlightMinMb, InFlightMaxMb);
            UpdateUploadInFlightValueLabel();
        }
        finally { _inFlightLoading = false; }
    }

    private void UploadInFlightSlider_Changed(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        UpdateUploadInFlightValueLabel();
        if (_inFlightLoading) return;
        SaveUploadInFlight();
    }

    private void UpdateUploadInFlightValueLabel()
    {
        if (UploadInFlightValue != null)
            UploadInFlightValue.Text = S.Format("CloudProvider_UploadInFlightValue", (int)UploadInFlightSlider.Value);
    }

    /// <summary>Persists upload_inflight_mb (clamped 24..64) into config.json.</summary>
    private void SaveUploadInFlight()
    {
        int mb = Math.Clamp((int)Math.Round(UploadInFlightSlider.Value), InFlightMinMb, InFlightMaxMb);
        Services.ConfigHelper.SaveConfig(Services.SteamDetector.GetConfigFilePath(),
            new[] { "upload_inflight_mb" },
            writer => writer.WriteNumber("upload_inflight_mb", mb));
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
