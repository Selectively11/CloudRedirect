using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;
using CloudRedirect.Services;
using Wpf.Ui.Controls;

namespace CloudRedirect.Pages;

public partial class ManifestPinningPage : Page
{
    private bool _loading;
    private readonly List<LuaApp> _apps = new();
    private readonly HashSet<uint> _pinnedApps = new();
    private readonly SteamStoreClient _storeClient = SteamStoreClient.Shared;

    public ManifestPinningPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            _loading = true;
            try
            {
                await LoadInitialDataAsync();
                await ResolveAppNamesAsync();
            }
            finally
            {
                _loading = false;
            }
        };
    }

    /// <summary>
    /// Snapshot gathered off the UI thread so Loaded never blocks on
    /// JsonDocument.Parse(pin config) or the lua dir walk.
    /// </summary>
    private sealed record InitialDataSnapshot(
        bool ManifestPinning,
        bool AutoComment,
        HashSet<uint> PinnedApps,
        List<LuaApp> Apps);

    // M17: Move pin-config read + lua dir scan off the UI thread.
    // Loaded used to call LoadConfig + ScanLuaFiles synchronously,
    // which can stall if the Steam dir is on a network drive or AV
    // is scanning *.lua. Gather everything in Task.Run and only
    // mutate controls / collections in the dispatcher continuation.
    private async Task LoadInitialDataAsync()
    {
        var snapshot = await Task.Run(() =>
        {
            var (mp, ac, pinned) = ReadPinConfig();
            var apps = ScanLuaFilesOffThread();
            return new InitialDataSnapshot(mp, ac, pinned, apps);
        });

        ManifestPinningToggle.IsChecked = snapshot.ManifestPinning;
        AutoCommentToggle.IsChecked = snapshot.AutoComment;

        _pinnedApps.Clear();
        foreach (var id in snapshot.PinnedApps)
            _pinnedApps.Add(id);

        _apps.Clear();
        _apps.AddRange(snapshot.Apps);

        ApplyPinnedState();
        RefreshList();
    }

    /// <summary>
    /// Reads the pin config off-thread. Returns defaults on any error
    /// so the UI never sees a half-applied state.
    /// </summary>
    private static (bool ManifestPinning, bool AutoComment, HashSet<uint> Pinned) ReadPinConfig()
    {
        var pinned = new HashSet<uint>();
        bool mp = false, ac = false;
        try
        {
            var path = SteamDetector.GetPinConfigPath();
            if (path == null || !File.Exists(path))
                return (mp, ac, pinned);

            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip
            });
            var root = doc.RootElement;

            if (root.TryGetProperty("manifest_pinning", out var mpEl) && mpEl.ValueKind == JsonValueKind.True)
                mp = true;
            if (root.TryGetProperty("auto_comment", out var acEl) && acEl.ValueKind == JsonValueKind.True)
                ac = true;

            if (root.TryGetProperty("pinned_apps", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in arr.EnumerateArray())
                {
                    if (el.TryGetUInt32(out var appId))
                        pinned.Add(appId);
                }
            }
        }
        catch { }
        return (mp, ac, pinned);
    }

    private static readonly Regex ManifestIdRegex = new(
        @"setManifestid\s*\(\s*(\d+)\s*,\s*""(\d+)""",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Off-thread version of the lua scan. Returns a fresh list rather
    /// than mutating <see cref="_apps"/> so the dispatcher path owns
    /// the only writer of that collection.
    /// </summary>
    private static List<LuaApp> ScanLuaFilesOffThread()
    {
        var result = new List<LuaApp>();
        try
        {
            var steamPath = SteamDetector.FindSteamPath();
            if (steamPath == null) return result;

            var luaDir = Path.Combine(steamPath, "config", "stplug-in");
            if (!Directory.Exists(luaDir)) return result;

            foreach (var file in Directory.GetFiles(luaDir, "*.lua"))
            {
                var fileName = Path.GetFileNameWithoutExtension(file);
                if (!uint.TryParse(fileName, out var appId) || appId == 0) continue;

                var depots = new List<DepotEntry>();
                foreach (var line in File.ReadLines(file))
                {
                    var trimmed = line.TrimStart();
                    if (trimmed.StartsWith("--")) continue;

                    var match = ManifestIdRegex.Match(line);
                    if (!match.Success) continue;

                    if (uint.TryParse(match.Groups[1].Value, out _) &&
                        ulong.TryParse(match.Groups[2].Value, out _))
                    {
                        depots.Add(new DepotEntry
                        {
                            DepotId = match.Groups[1].Value,
                            ManifestId = match.Groups[2].Value
                        });
                    }
                }

                if (depots.Count == 0) continue;

                result.Add(new LuaApp
                {
                    AppId = appId,
                    DisplayName = S.Format("Pin_AppFallbackName", appId),
                    Depots = depots
                });
            }

            result.Sort((a, b) => a.AppId.CompareTo(b.AppId));
        }
        catch { }
        return result;
    }

    private void ApplyPinnedState()
    {
        foreach (var app in _apps)
            app.IsPinned = _pinnedApps.Contains(app.AppId);
    }

    private void RefreshList()
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        var filtered = string.IsNullOrEmpty(query)
            ? _apps.ToList()
            : _apps.Where(a =>
                a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                a.AppId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase))
              .ToList();

        NoPinsText.Visibility = _apps.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        AppList.ItemsSource = null;
        AppList.ItemsSource = filtered;
    }

    private async System.Threading.Tasks.Task ResolveAppNamesAsync()
    {
        var ids = _apps.Select(a => a.AppId).Distinct().ToList();
        if (ids.Count == 0) return;

        try
        {
            var infos = await _storeClient.GetAppInfoAsync(ids);
            foreach (var app in _apps)
            {
                if (infos.TryGetValue(app.AppId, out var info))
                {
                    if (!string.IsNullOrEmpty(info.Name))
                        app.Name = info.Name;
                    app.HeaderUrl = info.HeaderUrl;
                }
            }
            RefreshList();
        }
        catch { }
    }

    private async void PinToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;

        // The toggle state has already flipped by the time this handler
        // runs. If SaveConfig throws (disk full, AV lock, etc.) we revert
        // to the previous state so the UI doesn't lie about what's on disk.
        var toggle = sender as Wpf.Ui.Controls.ToggleSwitch;
        var prev = toggle?.IsChecked != true;

        try
        {
            SaveConfig();
        }
        catch (Exception ex)
        {
            if (toggle != null)
            {
                _loading = true;
                try { toggle.IsChecked = prev; }
                finally { _loading = false; }
            }
            await Dialog.ShowErrorAsync(
                S.Get("Common_Error"),
                S.Format("Pin_FailedSavePinConfig", ex.Message));
            return;
        }

        NotifyRestartNeeded();
    }

    private async void AppPin_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading) return;

        // Two-way binding has already mutated app.IsPinned. Snapshot the
        // pre-write pinned set so we can roll back the LuaApp + UI state
        // if SaveConfig fails (atomic write means disk is intact either
        // way; we only need to revert what we changed in-process).
        var prevPinned = new HashSet<uint>(_pinnedApps);

        _pinnedApps.Clear();
        foreach (var app in _apps)
        {
            if (app.IsPinned)
                _pinnedApps.Add(app.AppId);
        }

        try
        {
            SaveConfig();
        }
        catch (Exception ex)
        {
            // Restore _pinnedApps and the per-app IsPinned flags, then
            // re-bind the list so the toggle switch reflects the
            // reverted state (LuaApp doesn't implement INPC).
            _pinnedApps.Clear();
            foreach (var id in prevPinned) _pinnedApps.Add(id);
            foreach (var app in _apps)
                app.IsPinned = _pinnedApps.Contains(app.AppId);

            _loading = true;
            try { RefreshList(); }
            finally { _loading = false; }

            await Dialog.ShowErrorAsync(
                S.Get("Common_Error"),
                S.Format("Pin_FailedSavePinConfig", ex.Message));
            return;
        }

        NotifyRestartNeeded();
    }

    private void ExpandCollapse_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: LuaApp app }) return;
        app.IsExpanded = !app.IsExpanded;
        RefreshList();
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        RefreshList();
    }

    private void NotifyRestartNeeded()
    {
        if (Window.GetWindow(this) is MainWindow mainWindow)
            mainWindow.ShowRestartSteam();
    }

    private static readonly HashSet<string> _ownedKeys = new()
    {
        "manifest_pinning", "auto_comment", "pinned_apps"
    };

    /// <summary>
    /// Writes the current pin config to disk. Throws on real I/O failure
    /// so callers can surface the error instead of silently dropping the
    /// user's toggle action; the inner old-file parse catch is kept (corrupt
    /// existing file → write fresh, intentional).
    /// </summary>
    private void SaveConfig()
    {
        var path = SteamDetector.GetPinConfigPath();
        if (path == null) return;

        JsonElement existing = default;
        if (File.Exists(path))
        {
            try
            {
                var raw = File.ReadAllText(path);
                using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions
                {
                    CommentHandling = JsonCommentHandling.Skip
                });
                existing = doc.RootElement.Clone();
            }
            catch { }
        }

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("manifest_pinning", ManifestPinningToggle.IsChecked == true);
            writer.WriteBoolean("auto_comment", AutoCommentToggle.IsChecked == true);

            writer.WriteStartArray("pinned_apps");
            foreach (var appId in _pinnedApps.OrderBy(x => x))
                writer.WriteNumberValue(appId);
            writer.WriteEndArray();

            if (existing.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in existing.EnumerateObject())
                {
                    if (_ownedKeys.Contains(prop.Name)) continue;
                    prop.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var json = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        FileUtils.AtomicWriteAllText(path, json);
    }

    internal class LuaApp
    {
        public uint AppId { get; set; }
        public string Name { get; set; } = "";
        public string? HeaderUrl { get; set; }
        public bool IsPinned { get; set; }
        public bool IsExpanded { get; set; }
        public List<DepotEntry> Depots { get; set; } = new();

        public string DisplayName
        {
            get => !string.IsNullOrEmpty(Name) ? Name : _displayName;
            set => _displayName = value;
        }
        private string _displayName = "";

        public string DepotSummary => $"{Depots.Count} depot{(Depots.Count != 1 ? "s" : "")}";

        public SymbolRegular ChevronSymbol =>
            IsExpanded ? SymbolRegular.ChevronDown24 : SymbolRegular.ChevronRight24;

        public Visibility DepotsVisibility =>
            IsExpanded ? Visibility.Visible : Visibility.Collapsed;
    }

    internal class DepotEntry
    {
        public string DepotId { get; set; } = "";
        public string ManifestId { get; set; } = "";
    }
}
