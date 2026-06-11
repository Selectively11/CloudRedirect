using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;
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
    /// Index of the last LanguageOptions entry that was successfully
    /// persisted to settings.json. Used to roll back the combo if a
    /// later selection-change save fails so the UI never shows a
    /// language different from what's actually on disk.
    /// </summary>
    private int _lastSavedLanguageIndex;
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
        Loaded += async (_, _) =>
        {
            LoadAbout();
            try { await LoadSettingsAsync(); }
            catch { }
        };
    }

    /// <summary>
    /// Snapshot of everything LoadSettingsAsync gathers off the UI thread.
    /// All disk reads (settings.json language, settings.json mode,
    /// config.json sync toggles) happen in Task.Run; the dispatcher
    /// continuation only mutates controls.
    /// </summary>
    private sealed record SettingsSnapshot(
        string Language,
        string? Mode,
        bool? SyncAchievements,
        bool? SyncPlaytime,
        bool? SyncLuas,
        bool? AutoUpdateDll,
        bool? ShowNonSteamGame,
        bool? ParentalIgnorePlaytime,
        bool? ParentalBypassPlaytime,
        bool? SchemaFetch,
        bool? OverrideNonStGate);

    // M15: Move language/mode/sync-toggle config reads off the UI thread.
    // Loaded used to call ReadLanguageSetting + ReadModeSetting +
    // LoadSyncToggles synchronously, which can stall on a slow disk
    // (network drive, AV scan). Mirror DashboardPage.LoadStatusAsync:
    // gather a snapshot in Task.Run, apply controls afterward.
    private async Task LoadSettingsAsync()
    {
        var snapshot = await Task.Run(() =>
        {
            var lang = ReadLanguageSetting();
            var mode = Services.SteamDetector.ReadModeSetting();

            bool? a = null, p = null, l = null, u = null, nsg = null, pip = null, pbp = null, sf = null, ovr = null;
            if (mode == "cloud_redirect")
                ReadSyncTogglesInto(ref a, ref p, ref l, ref u, ref nsg, ref pip, ref pbp, ref sf, ref ovr);

            return new SettingsSnapshot(lang, mode, a, p, l, u, nsg, pip, pbp, sf, ovr);
        });

        ApplySettingsSnapshot(snapshot);
    }

    private void ApplySettingsSnapshot(SettingsSnapshot snap)
    {
        ApplyLanguageSelector(snap.Language);

        ParentalSection.Visibility = Visibility.Visible;
        if (snap.Mode == "cloud_redirect")
        {
            ExperimentalSection.Visibility = Visibility.Visible;
            ExtraSection.Visibility = Visibility.Visible;
            ApplySyncToggles(snap.SyncAchievements, snap.SyncPlaytime, snap.SyncLuas, snap.AutoUpdateDll,
                             snap.ShowNonSteamGame, snap.ParentalIgnorePlaytime, snap.ParentalBypassPlaytime,
                             snap.SchemaFetch, snap.OverrideNonStGate);
        }
        else
        {
            ExperimentalSection.Visibility = Visibility.Collapsed;
            ExtraSection.Visibility = Visibility.Collapsed;
            // Auto-update DLL lives in the always-visible Updates section, so it
            // reflects the real setting even when the sync/extra sections are hidden.
            ApplySyncToggles(false, false, false, snap.AutoUpdateDll, false,
                             snap.ParentalIgnorePlaytime, snap.ParentalBypassPlaytime, false, false);
        }
    }

    private void ApplyLanguageSelector(string saved)
    {
        _languageLoading = true;
        try
        {
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
            _lastSavedLanguageIndex = selectedIndex;
        }
        finally
        {
            _languageLoading = false;
        }
    }

    private void ApplySyncToggles(bool? achievements, bool? playtime, bool? luas, bool? autoUpdateDll,
                                   bool? showNonSteamGame, bool? parentalIgnorePlaytime, bool? parentalBypassPlaytime,
                                   bool? schemaFetch, bool? overrideNonStGate)
    {
        _syncLoading = true;
        try
        {
            if (achievements == true) SyncAchievementsToggle.IsChecked = true;
            if (playtime == true) SyncPlaytimeToggle.IsChecked = true;
            if (luas == true) SyncLuasToggle.IsChecked = true;
            if (autoUpdateDll == true) AutoUpdateDllToggle.IsChecked = true;
            if (showNonSteamGame == true) ShowNonSteamGameToggle.IsChecked = true;
            if (parentalIgnorePlaytime == true) ParentalIgnorePlaytimeToggle.IsChecked = true;
            if (parentalBypassPlaytime == true) ParentalBypassPlaytimeToggle.IsChecked = true;
            if (schemaFetch == true) GetAchievementDataToggle.IsChecked = true;
            if (overrideNonStGate == true) OverrideNonStGateToggle.IsChecked = true;
        }
        finally
        {
            _syncLoading = false;
        }
    }

    /// <summary>
    /// Reads the sync toggle booleans from config.json on the calling
    /// thread. Used by LoadSettingsAsync inside Task.Run so the dispatcher
    /// path never opens config.json synchronously.
    /// </summary>
    private static void ReadSyncTogglesInto(ref bool? achievements, ref bool? playtime, ref bool? luas, ref bool? autoUpdateDll,
                                              ref bool? showNonSteamGame, ref bool? parentalIgnorePlaytime, ref bool? parentalBypassPlaytime,
                                              ref bool? schemaFetch, ref bool? overrideNonStGate)
    {
        try
        {
            var path = GetConfigPath();
            if (!File.Exists(path)) return;

            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("sync_achievements", out var a) && a.ValueKind == JsonValueKind.True)
                achievements = true;
            if (root.TryGetProperty("sync_playtime", out var p) && p.ValueKind == JsonValueKind.True)
                playtime = true;
            if (root.TryGetProperty("sync_luas", out var l) && l.ValueKind == JsonValueKind.True)
                luas = true;
            if (root.TryGetProperty("auto_update_dll", out var u))
                autoUpdateDll = u.ValueKind == JsonValueKind.True;
            else
                autoUpdateDll = true; // default on when key absent
            if (root.TryGetProperty("show_non_steam_game", out var nsg))
                showNonSteamGame = nsg.ValueKind == JsonValueKind.True;
            else
                showNonSteamGame = true; // default on when key absent
            if (root.TryGetProperty("parental_ignore_playtime", out var pip) && pip.ValueKind == JsonValueKind.True)
                parentalIgnorePlaytime = true;
            if (root.TryGetProperty("parental_bypass_playtime", out var pbp) && pbp.ValueKind == JsonValueKind.True)
                parentalBypassPlaytime = true;
            // Experimental schema fetch: default off when key absent.
            if (root.TryGetProperty("experimental_schema_fetch", out var sf) && sf.ValueKind == JsonValueKind.True)
                schemaFetch = true;
            // UNSUPPORTED WIP OVERRIDE NON-ST CLIENT GATE: default off when absent.
            if (root.TryGetProperty("override_non_st_client_gate", out var ovr) && ovr.ValueKind == JsonValueKind.True)
                overrideNonStGate = true;
        }
        catch { }
    }

    private void LoadAbout()
    {
        // Prefer the informational version (carries any pre-release suffix like
        // "-TEST1"); strip build metadata after '+'. Fall back to the numeric
        // assembly version formatted as X.Y.Z.
        var informational = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrEmpty(informational))
        {
            var plus = informational.IndexOf('+');
            VersionText.Text = plus >= 0 ? informational.Substring(0, plus) : informational;
            return;
        }

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        VersionText.Text = version != null
            ? S.Format("Settings_VersionFormat", version.Major, version.Minor, version.Build)
            : S.Get("Settings_CloudRedirect");
    }

    private async void LanguageComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_languageLoading) return;

        var idx = LanguageComboBox.SelectedIndex;
        if (idx < 0 || idx >= LanguageOptions.Length) return;

        var code = LanguageOptions[idx].Code;
        try
        {
            SaveLanguageSetting(code);
        }
        catch (Exception ex)
        {
            // Revert the combo to the last successfully-persisted index so
            // the user doesn't see a fake selection that won't survive
            // restart. Suppress the re-fire via _languageLoading.
            _languageLoading = true;
            try { LanguageComboBox.SelectedIndex = _lastSavedLanguageIndex; }
            finally { _languageLoading = false; }

            await Services.Dialog.ShowErrorAsync(
                S.Get("Common_Error"),
                S.Format("Settings_FailedSaveLanguage", ex.Message));
            return;
        }

        _lastSavedLanguageIndex = idx;
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

    /// <summary>
    /// Writes the language preference to settings.json. Throws on real
    /// I/O failure so the caller can revert the combo and surface the
    /// error; the inner old-file parse catch is intentional (corrupt
    /// settings → write fresh, preserving language only).
    /// </summary>
    private static void SaveLanguageSetting(string code)
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

    private static string GetConfigPath()
    {
        return Services.SteamDetector.GetConfigFilePath();
    }

    private async void SyncToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncLoading) return;

        try
        {
            SaveSyncToggles();
        }
        catch (Exception ex)
        {
            // Only the toggle that just fired diverges from the on-disk
            // value — flip it back and surface the error. The
            // _syncLoading guard suppresses the recursive Changed event
            // that the programmatic IsChecked set will trigger.
            if (sender is Wpf.Ui.Controls.ToggleSwitch toggle)
            {
                _syncLoading = true;
                try { toggle.IsChecked = !(toggle.IsChecked == true); }
                finally { _syncLoading = false; }
            }

            await Services.Dialog.ShowErrorAsync(
                S.Get("Common_Error"),
                S.Format("Settings_FailedSaveSync", ex.Message));
        }
    }

    /// <summary>
    /// Persists the three sync toggles into config.json via ConfigHelper
    /// (which preserves caller-unowned keys and atomic-writes). Throws on
    /// real I/O failure so the caller can revert UI state and surface
    /// the error.
    /// </summary>
    private void SaveSyncToggles()
    {
        var path = GetConfigPath();
        Services.ConfigHelper.SaveConfig(path,
            new[] { "sync_achievements", "sync_playtime", "sync_luas", "auto_update_dll",
                    "show_non_steam_game", "parental_ignore_playtime", "parental_bypass_playtime",
                    "experimental_schema_fetch", "override_non_st_client_gate" },
            writer =>
            {
                writer.WriteBoolean("sync_achievements", SyncAchievementsToggle.IsChecked == true);
                writer.WriteBoolean("sync_playtime", SyncPlaytimeToggle.IsChecked == true);
                writer.WriteBoolean("sync_luas", SyncLuasToggle.IsChecked == true);
                writer.WriteBoolean("auto_update_dll", AutoUpdateDllToggle.IsChecked == true);
                writer.WriteBoolean("show_non_steam_game", ShowNonSteamGameToggle.IsChecked == true);
                writer.WriteBoolean("parental_ignore_playtime", ParentalIgnorePlaytimeToggle.IsChecked == true);
                writer.WriteBoolean("parental_bypass_playtime", ParentalBypassPlaytimeToggle.IsChecked == true);
                writer.WriteBoolean("experimental_schema_fetch", GetAchievementDataToggle.IsChecked == true);
                writer.WriteBoolean("override_non_st_client_gate", OverrideNonStGateToggle.IsChecked == true);
            });
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
