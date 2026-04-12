using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;
using CloudRedirect.Services;

namespace CloudRedirect.Pages;

public partial class SettingsPage : Page
{
    private const string ReleasesUrl = "https://github.com/Selectively11/CloudRedirect/releases";

    private string? _latestDownloadUrl;
    private bool _languageLoading;
    private bool _syncLoading;
    /// <summary>
    /// Language options: display key -> culture code (or "system").
    /// </summary>
    private static readonly (string ResourceKey, string Code)[] LanguageOptions =
    [
        ("Settings_SystemDefault", "system"),
        ("Settings_LanguageEnglish", "en"),
        ("Settings_LanguageSpanish", "es"),
        ("Settings_LanguagePortuguese", "pt-BR"),
    ];

    public SettingsPage()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            LoadAbout();
            LoadLanguageSelector();

            var mode = Services.SteamDetector.ReadModeSetting();
            if (mode == "cloud_redirect")
            {
                SyncSection.Visibility = Visibility.Visible;
                LoadSyncToggles();
            }
            else
            {
                SyncSection.Visibility = Visibility.Collapsed;
            }
        };
    }

    private void LoadAbout()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = version != null
            ? S.Format("Settings_VersionFormat", version.Major, version.Minor, version.Build)
            : S.Get("Settings_CloudRedirect");
    }

    private void LoadLanguageSelector()
    {
        _languageLoading = true;
        try
        {
            var saved = ReadLanguageSetting();
            LanguageComboBox.Items.Clear();

            int selectedIndex = 0;
            for (int i = 0; i < LanguageOptions.Length; i++)
            {
                var (resKey, code) = LanguageOptions[i];
                LanguageComboBox.Items.Add(S.Get(resKey));
                if (code == saved)
                    selectedIndex = i;
            }

            LanguageComboBox.SelectedIndex = selectedIndex;
        }
        finally
        {
            _languageLoading = false;
        }
    }

    private void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_languageLoading) return;

        var idx = LanguageComboBox.SelectedIndex;
        if (idx < 0 || idx >= LanguageOptions.Length) return;

        var code = LanguageOptions[idx].Code;
        SaveLanguageSetting(code);
        LanguageHintText.Text = S.Get("Settings_RestartRequired");
        RestartButton.Visibility = Visibility.Visible;
    }

    private void RestartApp_Click(object sender, RoutedEventArgs e)
    {
        var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
        if (exePath != null)
            Process.Start(exePath);
        Application.Current.Shutdown();
    }

    private static string GetSettingsPath()
    {
        return Path.Combine(Services.SteamDetector.GetConfigDir(), "settings.json");
    }

    private static string ReadLanguageSetting()
    {
        try
        {
            var path = GetSettingsPath();
            if (!File.Exists(path)) return "system";

            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("language", out var prop))
                return prop.GetString() ?? "system";
        }
        catch { }
        return "system";
    }

    private static void SaveLanguageSetting(string code)
    {
        try
        {
            var path = GetSettingsPath();
            var dir = Path.GetDirectoryName(path)!;
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            // Read existing settings to preserve other fields
            JsonElement existing = default;
            if (File.Exists(path))
            {
                try
                {
                    var oldJson = File.ReadAllText(path);
                    using var oldDoc = JsonDocument.Parse(oldJson);
                    existing = oldDoc.RootElement.Clone();
                }
                catch { }
            }

            using var ms = new System.IO.MemoryStream();
            using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WriteString("language", code);

                // Copy any other properties from the existing file
                if (existing.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in existing.EnumerateObject())
                    {
                        if (prop.Name == "language") continue;
                        prop.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
            }

            var newJson = System.Text.Encoding.UTF8.GetString(ms.ToArray());
            Services.FileUtils.AtomicWriteAllText(path, newJson);
        }
        catch { }
    }

    private static string GetConfigPath()
    {
        return Services.SteamDetector.GetConfigFilePath();
    }

    private void LoadSyncToggles()
    {
        _syncLoading = true;
        try
        {
            var path = GetConfigPath();
            if (!File.Exists(path)) return;

            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("sync_achievements", out var a) && a.ValueKind == JsonValueKind.True)
                SyncAchievementsToggle.IsChecked = true;
            if (root.TryGetProperty("sync_playtime", out var p) && p.ValueKind == JsonValueKind.True)
                SyncPlaytimeToggle.IsChecked = true;
            if (root.TryGetProperty("sync_luas", out var l) && l.ValueKind == JsonValueKind.True)
                SyncLuasToggle.IsChecked = true;
        }
        catch { }
        finally
        {
            _syncLoading = false;
        }
    }

    private void SyncToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncLoading) return;
        SaveSyncToggles();
    }

    private void SaveSyncToggles()
    {
        try
        {
            var path = GetConfigPath();
            Services.ConfigHelper.SaveConfig(path,
                new[] { "sync_achievements", "sync_playtime", "sync_luas" },
                writer =>
                {
                    writer.WriteBoolean("sync_achievements", SyncAchievementsToggle.IsChecked == true);
                    writer.WriteBoolean("sync_playtime", SyncPlaytimeToggle.IsChecked == true);
                    writer.WriteBoolean("sync_luas", SyncLuasToggle.IsChecked == true);
                });
        }
        catch { }
    }

    private async void CheckForUpdates_Click(object sender, RoutedEventArgs e)
    {
        UpdateButton.IsEnabled = false;
        UpdateButton.Content = S.Get("Settings_Checking");
        UpdateStatusText.Text = S.Get("Settings_ContactingGitHub");
        DownloadButton.Visibility = Visibility.Collapsed;
        _latestDownloadUrl = null;

        try
        {
            var result = await AppUpdater.CheckAsync();

            if (result == null)
            {
                UpdateHeaderText.Text = S.Get("Settings_CheckForUpdates");
                UpdateStatusText.Text = S.Format("Settings_FailedToCheck", "no response from GitHub");
                return;
            }

            var localVersion = Assembly.GetExecutingAssembly().GetName().Version;
            var local3 = localVersion != null
                ? new Version(localVersion.Major, localVersion.Minor, localVersion.Build)
                : new Version(0, 0, 0);

            if (result.UpdateAvailable)
            {
                UpdateHeaderText.Text = S.Format("Settings_UpdateAvailableFormat", result.TagName ?? "");
                UpdateStatusText.Text = S.Format("Settings_NewerVersionAvailable", local3);
                _latestDownloadUrl = ReleasesUrl;
                DownloadButton.Visibility = Visibility.Visible;
            }
            else
            {
                UpdateHeaderText.Text = S.Get("Settings_UpToDate");
                UpdateStatusText.Text = S.Format("Settings_LatestVersionFormat", local3);
            }
        }
        catch (Exception ex)
        {
            UpdateHeaderText.Text = S.Get("Settings_CheckForUpdates");
            UpdateStatusText.Text = S.Format("Settings_FailedToCheck", ex.Message);
        }
        finally
        {
            UpdateButton.IsEnabled = true;
            UpdateButton.Content = S.Get("Settings_Check");
        }
    }

    private void DownloadUpdate_Click(object sender, RoutedEventArgs e)
    {
        var url = _latestDownloadUrl ?? ReleasesUrl;
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
    }

    private async void ResetData_Click(object sender, RoutedEventArgs e)
    {
        var confirmed = await Services.Dialog.ConfirmDangerAsync(S.Get("Settings_ConfirmResetTitle"),
            S.Get("Settings_ConfirmResetMessage"));

        if (!confirmed) return;

        var steamPath = Services.SteamDetector.FindSteamPath();
        if (steamPath == null) return;

        try
        {
            var dataRoot = Path.Combine(steamPath, "cloud_redirect");
            var storagePath = Path.Combine(dataRoot, "storage");

            // Legacy/unused folders from older versions
            var blobsPath = Path.Combine(dataRoot, "blobs");
            var savesPath = Path.Combine(dataRoot, "saves");

            if (Directory.Exists(storagePath))
                Directory.Delete(storagePath, true);
            if (Directory.Exists(blobsPath))
                Directory.Delete(blobsPath, true);
            if (Directory.Exists(savesPath))
                Directory.Delete(savesPath, true);

            await Services.Dialog.ShowInfoAsync(S.Get("Settings_Done"), S.Get("Settings_ResetDoneMessage"));
        }
        catch (Exception ex)
        {
            await Services.Dialog.ShowErrorAsync(S.Get("Common_Error"), S.Format("Settings_FailedReset", ex.Message));
        }
    }

    private void OpenGitHub_Click(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo(ReleasesUrl) { UseShellExecute = true })?.Dispose();
    }
}
