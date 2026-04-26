using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using CloudRedirect.Resources;
using CloudRedirect.Services;
using CloudRedirect.Windows;

namespace CloudRedirect.Pages;

public partial class ChoiceModePage : Page
{
    private string? _currentMode;

    public ChoiceModePage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            try { await RefreshStateAsync(); }
            catch { }
        };
    }

    // M16: Move SteamDetector.ReadModeSetting() off the UI thread.
    // It opens settings.json synchronously, so a slow disk would
    // block Loaded long enough for the page to flash unconfigured
    // state. Resolve the mode in Task.Run, then apply visibility.
    private async Task RefreshStateAsync()
    {
        var mode = await Task.Run(() => SteamDetector.ReadModeSetting());
        ApplyMode(mode);
    }

    private void ApplyMode(string? mode)
    {
        _currentMode = mode;

        if (_currentMode != null)
        {
            CurrentModeBanner.Visibility = Visibility.Visible;

            if (_currentMode == "cloud_redirect")
            {
                CurrentModeText.Text = S.Get("Choice_CurrentMode_CloudRedirect");
                CurrentModeDescription.Text = S.Get("Choice_CurrentMode_CloudRedirect_Desc");
                STFixerCard.Visibility = Visibility.Collapsed;
                CloudRedirectCard.Visibility = Visibility.Collapsed;
            }
            else
            {
                CurrentModeText.Text = S.Get("Choice_CurrentMode_STFixer");
                CurrentModeDescription.Text = S.Get("Choice_CurrentMode_STFixer_Desc");
                STFixerCard.Visibility = Visibility.Collapsed;
                CloudRedirectCard.Visibility = Visibility.Visible;
            }
        }
        else
        {
            CurrentModeBanner.Visibility = Visibility.Collapsed;
            STFixerCard.Visibility = Visibility.Visible;
            CloudRedirectCard.Visibility = Visibility.Visible;
        }
    }

    private async void STFixerCard_Click(object sender, MouseButtonEventArgs e)
    {
        if (_currentMode == "cloud_redirect") return;

        if (!await TryPersistModeAsync("stfixer", cloudRedirectEnabled: false))
            return;

        var mw = Window.GetWindow(this) as MainWindow;
        mw?.ApplyMode("stfixer");
        mw?.RootNavigation.Navigate(typeof(SetupPage));
    }

    private async void CloudRedirectCard_Click(object sender, MouseButtonEventArgs e)
    {
        var disclaimer = new DisclaimerWindow
        {
            Owner = Window.GetWindow(this)
        };

        var result = disclaimer.ShowDialog();

        if (result != true || !disclaimer.Accepted)
            return;

        if (!await TryPersistModeAsync("cloud_redirect", cloudRedirectEnabled: true))
            return;

        var mw = Window.GetWindow(this) as MainWindow;
        mw?.ApplyMode("cloud_redirect");
        mw?.RootNavigation.Navigate(typeof(SetupPage));
    }

    // Persists both settings.json (mode) and the pin config (cloud_redirect).
    // Surfaces failure to the user so a silent disk/permissions error doesn't
    // leave the UI looking like the choice was saved when it wasn't.
    //
    // The two writes are not atomic: if SaveModeSetting succeeds and
    // SetDllCloudRedirect fails, settings.json would advertise a mode the
    // DLL never agreed to, and the next launch's banner would lie. Snapshot
    // settings.json before the first write and restore it on failure so the
    // file system view stays consistent with whatever the DLL is doing.
    private static async Task<bool> TryPersistModeAsync(string mode, bool cloudRedirectEnabled)
    {
        var settingsPath = GetSettingsPath();
        byte[]? settingsBackup = null;
        if (File.Exists(settingsPath))
        {
            try { settingsBackup = File.ReadAllBytes(settingsPath); }
            catch { /* unreadable; rollback won't be possible, but the
                       initial write below will likely fail for the same
                       reason and rollback won't be needed */ }
        }

        try
        {
            SaveModeSetting(mode);
            try
            {
                SetDllCloudRedirect(cloudRedirectEnabled);
            }
            catch
            {
                RestoreSettingsBackup(settingsPath, settingsBackup);
                throw;
            }
            return true;
        }
        catch (Exception ex)
        {
            await Dialog.ShowErrorAsync(
                S.Get("Common_Error"),
                S.Format("Choice_FailedSaveMode", ex.Message));
            return false;
        }
    }

    private static void RestoreSettingsBackup(string path, byte[]? backup)
    {
        try
        {
            if (backup != null)
                FileUtils.AtomicWriteAllBytes(path, backup);
            else if (File.Exists(path))
                File.Delete(path); // No prior file → undo our creation.
        }
        catch { /* best-effort; the user's already seeing an error */ }
    }

    private static void SaveModeSetting(string mode)
    {
        var path = GetSettingsPath();
        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        // A corrupt existing file is treated as empty and rewritten; any
        // other failure (I/O, permissions) propagates so the caller can
        // surface it instead of silently dropping the user's choice.
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

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("mode", mode);

            if (existing.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in existing.EnumerateObject())
                {
                    if (prop.Name == "mode") continue;
                    prop.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        var newJson = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        FileUtils.AtomicWriteAllText(path, newJson);
    }

    private static void SetDllCloudRedirect(bool enabled)
    {
        var path = SteamDetector.GetPinConfigPath();
        if (path == null) return;

        // Same policy as SaveModeSetting: corrupt-old-file is best-effort,
        // but real write failures must surface instead of being swallowed.
        JsonElement existing = default;
        if (File.Exists(path))
        {
            try
            {
                var oldJson = File.ReadAllText(path);
                using var oldDoc = JsonDocument.Parse(oldJson, new JsonDocumentOptions
                {
                    CommentHandling = JsonCommentHandling.Skip
                });
                existing = oldDoc.RootElement.Clone();
            }
            catch { }
        }

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("cloud_redirect", enabled);

            if (existing.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in existing.EnumerateObject())
                {
                    if (prop.Name == "cloud_redirect") continue;
                    prop.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var newJson = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        FileUtils.AtomicWriteAllText(path, newJson);
    }

    private static string GetSettingsPath()
    {
        return Path.Combine(SteamDetector.GetConfigDir(), "settings.json");
    }
}
