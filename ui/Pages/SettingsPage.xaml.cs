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

    private bool _languageLoading;
    private bool _syncLoading;
    /// <summary>
    /// Index of the last LanguageOptions entry that was successfully
    /// persisted to settings.json. Used to roll back the combo if a
    /// later selection-change save fails so the UI never shows a
    /// language different from what's actually on disk.
    /// </summary>
    private int _lastSavedLanguageIndex;
    private static readonly (string ResourceKey, string Code)[] LanguageOptions =
    [
        ("Settings_SystemDefault", "system"),
        ("Settings_LanguageEnglish", "en"),
        ("Settings_LanguageSpanish", "es"),
        ("Settings_LanguagePortuguese", "pt-BR"),
        ("Settings_LanguageSimplifiedChinese", "zh-CN"),
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

    /// <summary>Off-thread snapshot of settings.json + config.json state.</summary>
    private sealed record SettingsSnapshot(
        string Language,
        bool? SyncAchievements,
        bool? SyncPlaytime,
        bool? SyncLuas,
        bool? AutoUpdateDll,
        bool? ShowNonSteamGame,
        bool? ParentalIgnorePlaytime,
        bool? ParentalBypassPlaytime);

    // M15: Read config off UI thread to avoid slow-disk stall.
    private async Task LoadSettingsAsync()
    {
        var snapshot = await Task.Run(() =>
        {
            var lang = ReadLanguageSetting();

            bool? a = null, p = null, l = null, u = null, nsg = null, pip = null, pbp = null;
            ReadSyncTogglesInto(ref a, ref p, ref l, ref u, ref nsg, ref pip, ref pbp);

            return new SettingsSnapshot(lang, a, p, l, u, nsg, pip, pbp);
        });

        ApplySettingsSnapshot(snapshot);
    }

    private void ApplySettingsSnapshot(SettingsSnapshot snap)
    {
        ApplyLanguageSelector(snap.Language);

        ShowNonSteamGameCard.Visibility = Visibility.Collapsed;
        SyncLuasCard.Visibility = Visibility.Collapsed;

        ExtraSection.Visibility = Visibility.Visible;
        ExperimentalSection.Visibility = Visibility.Visible;

        ApplySyncToggles(snap.SyncAchievements, snap.SyncPlaytime, snap.SyncLuas, snap.AutoUpdateDll,
                         snap.ShowNonSteamGame, snap.ParentalIgnorePlaytime, snap.ParentalBypassPlaytime);
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
                                   bool? showNonSteamGame, bool? parentalIgnorePlaytime, bool? parentalBypassPlaytime)
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
        }
        finally
        {
            _syncLoading = false;
        }
    }

    /// <summary>Reads sync toggles from config.json (called inside Task.Run).</summary>
    private static void ReadSyncTogglesInto(ref bool? achievements, ref bool? playtime, ref bool? luas, ref bool? autoUpdateDll,
                                              ref bool? showNonSteamGame, ref bool? parentalIgnorePlaytime, ref bool? parentalBypassPlaytime)
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
        }
        catch { }
    }

    private void LoadAbout()
    {
        // Use informational version (has pre-release suffix); strip build metadata; fall back to assembly version.
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

    /// <summary>Persists sync toggles to config.json; throws on I/O failure for caller to revert.</summary>
    private void SaveSyncToggles()
    {
        var path = GetConfigPath();

        // schema_fetch / experimental_schema_fetch are retired: stay in the strip list so a
        // saved config drops the stale keys, but no longer written back.
        Services.ConfigHelper.SaveConfig(path,
            new[] { "sync_achievements", "sync_playtime", "sync_luas", "auto_update_dll",
                    "show_non_steam_game", "parental_ignore_playtime", "parental_bypass_playtime",
                    "schema_fetch", "experimental_schema_fetch" },
            writer =>
            {
                writer.WriteBoolean("sync_achievements", SyncAchievementsToggle.IsChecked == true);
                writer.WriteBoolean("sync_playtime", SyncPlaytimeToggle.IsChecked == true);
                writer.WriteBoolean("sync_luas", SyncLuasToggle.IsChecked == true);
                writer.WriteBoolean("auto_update_dll", AutoUpdateDllToggle.IsChecked == true);
                writer.WriteBoolean("show_non_steam_game", ShowNonSteamGameToggle.IsChecked == true);
                writer.WriteBoolean("parental_ignore_playtime", ParentalIgnorePlaytimeToggle.IsChecked == true);
                writer.WriteBoolean("parental_bypass_playtime", ParentalBypassPlaytimeToggle.IsChecked == true);
            });
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
