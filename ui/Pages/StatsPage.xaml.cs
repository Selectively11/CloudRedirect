using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;
using CloudRedirect.Services;
using Wpf.Ui.Controls;

namespace CloudRedirect.Pages;

/// <summary>
/// Diagnostics view for the native stats/playtime store. Reads each app's
/// stats.json directly from the configured CLOUD provider (Google Drive /
/// OneDrive / folder) via <see cref="CloudProviderClient"/>, so it shows what is
/// actually synced rather than the local on-disk copy. Read-only.
/// </summary>
public partial class StatsPage : Page
{
    private bool _loading;
    private readonly List<StatApp> _apps = new();
    private readonly SteamStoreClient _storeClient = SteamStoreClient.Shared;
    private static readonly string LogPath = Path.Combine(
        SteamDetector.GetConfigDir(), "stats_page.log");
    private readonly CloudProviderClient _cloud = new(Log);
    private System.Windows.Data.ListCollectionView? _appsView;

    private static void Log(string msg)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
            File.AppendAllText(LogPath, $"[{DateTime.Now:HH:mm:ss}] {msg}{Environment.NewLine}");
        }
        catch { }
    }

    public StatsPage()
    {
        InitializeComponent();

        Loaded += async (_, _) =>
        {
            _loading = true;
            try
            {
                await LoadStatsAsync();
                await ResolveAppNamesAsync();
            }
            catch (Exception ex)
            {
                Log($"FATAL in load: {ex}");
                ShowStatus($"Error loading stats: {ex.Message}");
            }
            finally
            {
                _loading = false;
            }
        };
    }

    private void ShowStatus(string text)
    {
        StatusText.Text = text;
        StatusText.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
    }

    private async Task LoadStatsAsync()
    {
        ShowStatus("Reading stats from cloud…");
        CloudUnavailableText.Visibility = Visibility.Collapsed;
        EmptyText.Visibility = Visibility.Collapsed;

        // Discover the synced account ids (folders under cloud_redirect\storage).
        // Everything else -- which apps have stats, and their content -- comes
        // from the cloud via the native CLI in a single call.
        var cfg = SteamDetector.ReadConfig();
        Log($"Provider config: provider={cfg?.Provider ?? "(null)"} tokenPath={cfg?.TokenPath ?? "(null)"}");

        if (!IsCloudConfigured())
        {
            Log("No cloud provider configured.");
            ShowStatus("");
            _apps.Clear();
            RefreshList();
            CloudUnavailableText.Visibility = Visibility.Visible;
            return;
        }

        // The native CLI searches the cloud directly for every stats.json.
        var result = await _cloud.ListAllStatsAsync();
        Log($"ListAllStats returned {result.Entries.Count} entr(ies); error={result.Error ?? "(none)"}");
        if (!string.IsNullOrEmpty(result.Error))
            Log($"  error detail: {result.Error}");

        var apps = new List<StatApp>();
        foreach (var entry in result.Entries)
        {
            if (!uint.TryParse(entry.AppId, out var appId)) continue;
            var app = TryParse(appId, entry.Content);
            if (app == null) { Log($"  parse failed for {entry.AccountId}/{entry.AppId}"); continue; }
            app.AccountId = entry.AccountId;
            apps.Add(app);
        }
        Log($"Parsed {apps.Count} app(s) into view.");

        // Group/sort by account, then most-recently-played, then appId.
        apps.Sort((a, b) =>
        {
            int c = string.CompareOrdinal(a.AccountId, b.AccountId);
            if (c != 0) return c;
            c = b.LastPlayedUnix.CompareTo(a.LastPlayedUnix);
            return c != 0 ? c : a.AppId.CompareTo(b.AppId);
        });

        _apps.Clear();
        _apps.AddRange(apps);
        RefreshList();

        ShowStatus("");
        if (_apps.Count == 0)
        {
            if (!string.IsNullOrEmpty(result.Error))
                ShowStatus($"Cloud error: {result.Error}");
            else
                CloudUnavailableText.Visibility =
                    !IsCloudConfigured() ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private static bool IsCloudConfigured()
    {
        try
        {
            var cfg = SteamDetector.ReadConfig();
            var p = cfg?.Provider;
            return !string.IsNullOrEmpty(p) && p != "local" && p != "none";
        }
        catch { return false; }
    }

    private static StatApp? TryParse(uint appId, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var app = new StatApp
            {
                AppId = appId,
                DisplayName = S.Format("Stats_AppFallbackName", appId),
                CrcStats = root.TryGetProperty("crc_stats", out var crcEl) && crcEl.TryGetUInt32(out var crc) ? crc : 0,
            };

            if (root.TryGetProperty("playtime", out var pt) && pt.ValueKind == JsonValueKind.Object)
            {
                app.MinutesForever = GetU32(pt, "minutes_forever");
                app.Minutes2Weeks = GetU32(pt, "minutes_2weeks");
                app.LastPlayedUnix = GetU32(pt, "last_played");
            }

            // Local schema names (read from appcache\stats) take precedence over
            // any names baked into the cloud blob, so real achievement titles
            // show immediately without waiting for the DLL to re-import.
            var schemaNames = AchievementSchema.LoadNames(appId);

            // Achievements (each block = one achievement-typed stat whose "value"
            // is a bitfield of unlocked achievements, with per-bit unlock times).
            // Collect these stat ids so we can hide them from the raw Stats list
            // below -- a bitfield int (e.g. 1832827) is meaningless as a "stat".
            var achievementStatIds = new HashSet<uint>();
            if (root.TryGetProperty("achievements", out var achs) && achs.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in achs.EnumerateArray())
                {
                    uint statId = GetU32(a, "stat_id");
                    achievementStatIds.Add(statId);

                    uint bits = GetU32(a, "bits");
                    var unlockTimes = new uint[32];
                    if (a.TryGetProperty("unlock_times", out var times) && times.ValueKind == JsonValueKind.Array)
                    {
                        int i = 0;
                        foreach (var t in times.EnumerateArray())
                        {
                            if (i >= 32) break;
                            unlockTimes[i++] = t.TryGetUInt32(out var v) ? v : 0;
                        }
                    }

                    // Human-readable per-bit names from the schema (optional).
                    var names = new string[32];
                    if (a.TryGetProperty("names", out var nameArr) && nameArr.ValueKind == JsonValueKind.Array)
                    {
                        int i = 0;
                        foreach (var n in nameArr.EnumerateArray())
                        {
                            if (i >= 32) break;
                            names[i++] = n.GetString() ?? "";
                        }
                    }

                    for (int bit = 0; bit < 32; bit++)
                    {
                        bool unlocked = (bits & (1u << bit)) != 0;
                        if (!unlocked && unlockTimes[bit] == 0) continue;

                        // Prefer the local schema name; fall back to the cloud
                        // blob's baked-in name, then to the bit identifier.
                        string name = "";
                        if (schemaNames.TryGetValue(((ulong)statId << 32) | (uint)bit, out var sn))
                            name = sn;
                        if (string.IsNullOrEmpty(name)) name = names[bit] ?? "";

                        app.Achievements.Add(new AchievementEntry
                        {
                            StatId = statId,
                            Bit = bit,
                            Unlocked = unlocked,
                            UnlockUnix = unlockTimes[bit],
                            Name = name,
                        });
                    }
                }
                app.Achievements.Sort((x, y) => y.UnlockUnix.CompareTo(x.UnlockUnix));
            }

            // Stats -- the real gameplay stats only. Skip ids that are actually
            // achievement bitfields (already shown in the Achievements section).
            if (root.TryGetProperty("stats", out var stats) && stats.ValueKind == JsonValueKind.Array)
            {
                foreach (var s in stats.EnumerateArray())
                {
                    uint id = GetU32(s, "id");
                    if (achievementStatIds.Contains(id)) continue;
                    app.Stats.Add(new StatEntry
                    {
                        Id = id,
                        Value = GetU32(s, "value"),
                    });
                }
            }

            return app;
        }
        catch
        {
            return null;
        }
    }

    private static uint GetU32(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var el) && el.TryGetUInt32(out var v) ? v : 0;

    private void RefreshList()
    {
        if (_appsView == null)
        {
            _appsView = (System.Windows.Data.ListCollectionView)
                System.Windows.Data.CollectionViewSource.GetDefaultView(_apps);
            _appsView.Filter = AppFilter;
            // Group by account so each account's apps are shown together under
            // an account header.
            _appsView.GroupDescriptions.Add(
                new System.Windows.Data.PropertyGroupDescription(nameof(StatApp.AccountLabel)));
            AppList.ItemsSource = _appsView;
        }
        else
        {
            _appsView.Refresh();
        }

        EmptyText.Visibility = _apps.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private bool AppFilter(object item)
    {
        var query = SearchBox?.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(query)) return true;
        if (item is not StatApp a) return false;
        return a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || a.AppId.ToString().Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private async Task ResolveAppNamesAsync()
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

    private void ExpandCollapse_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: StatApp app }) return;
        app.IsExpanded = !app.IsExpanded;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => RefreshList();

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        _loading = true;
        try
        {
            await LoadStatsAsync();
            await ResolveAppNamesAsync();
        }
        finally { _loading = false; }
    }

    // ── View models ──────────────────────────────────────────────────────

    internal static string FormatPlaytime(uint minutes)
    {
        if (minutes == 0) return S.Get("Stats_NoPlaytime");
        if (minutes < 60) return S.Format("Stats_Minutes", minutes);
        double hours = minutes / 60.0;
        return S.Format("Stats_Hours", hours.ToString("0.#", CultureInfo.CurrentCulture));
    }

    internal static string FormatUnixTime(uint unix)
    {
        if (unix == 0) return S.Get("Stats_Never");
        try
        {
            var dt = DateTimeOffset.FromUnixTimeSeconds(unix).ToLocalTime();
            return dt.ToString("g", CultureInfo.CurrentCulture);
        }
        catch { return S.Get("Stats_Never"); }
    }

    internal class StatApp : INotifyPropertyChanged
    {
        public uint AppId { get; set; }
        public string AccountId { get; set; } = "";
        public string AccountLabel => S.Format("Stats_AccountHeader", AccountId);
        public uint CrcStats { get; set; }

        public uint MinutesForever { get; set; }
        public uint Minutes2Weeks { get; set; }
        public uint LastPlayedUnix { get; set; }

        public List<StatEntry> Stats { get; } = new();
        public List<AchievementEntry> Achievements { get; } = new();

        private string _name = "";
        public string Name
        {
            get => _name;
            set { _name = value; Notify(nameof(Name)); Notify(nameof(DisplayName)); }
        }

        private string? _headerUrl;
        public string? HeaderUrl
        {
            get => _headerUrl;
            set { _headerUrl = value; Notify(nameof(HeaderUrl)); }
        }

        private bool _isExpanded;
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                _isExpanded = value;
                Notify(nameof(IsExpanded));
                Notify(nameof(ChevronSymbol));
                Notify(nameof(DetailsVisibility));
            }
        }

        public string DisplayName
        {
            get => !string.IsNullOrEmpty(Name) ? Name : _displayName;
            set => _displayName = value;
        }
        private string _displayName = "";

        public int UnlockedAchievements => Achievements.Count(a => a.Unlocked);
        public int TotalAchievementsSeen => Achievements.Count;

        public string PlaytimeForeverText => FormatPlaytime(MinutesForever);
        public string Playtime2WeeksText => FormatPlaytime(Minutes2Weeks);
        public string LastPlayedText => FormatUnixTime(LastPlayedUnix);

        public string Summary
        {
            get
            {
                var parts = new List<string>
                {
                    S.Format("Stats_SummaryPlaytime", PlaytimeForeverText)
                };
                if (UnlockedAchievements > 0)
                    parts.Add(S.Format("Stats_SummaryAchievements", UnlockedAchievements));
                if (Stats.Count > 0)
                    parts.Add(S.Format("Stats_SummaryStats", Stats.Count));
                return string.Join("   •   ", parts);
            }
        }

        public bool HasAchievements => Achievements.Count > 0;
        public bool HasStats => Stats.Count > 0;
        public Visibility AchievementsVisibility => HasAchievements ? Visibility.Visible : Visibility.Collapsed;
        public Visibility StatsVisibility => HasStats ? Visibility.Visible : Visibility.Collapsed;

        public SymbolRegular ChevronSymbol =>
            IsExpanded ? SymbolRegular.ChevronDown24 : SymbolRegular.ChevronRight24;

        public Visibility DetailsVisibility =>
            IsExpanded ? Visibility.Visible : Visibility.Collapsed;

        public event PropertyChangedEventHandler? PropertyChanged;
        private void Notify(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    internal class StatEntry
    {
        public uint Id { get; set; }
        public uint Value { get; set; }
        public string IdText => S.Format("Stats_StatId", Id);
        public string ValueText => Value.ToString(CultureInfo.CurrentCulture);
    }

    internal class AchievementEntry
    {
        public uint StatId { get; set; }
        public int Bit { get; set; }
        public bool Unlocked { get; set; }
        public uint UnlockUnix { get; set; }
        public string Name { get; set; } = "";

        // Prefer the schema display name; fall back to the stat/bit identifier.
        public string Label => !string.IsNullOrEmpty(Name)
            ? Name
            : S.Format("Stats_AchievementBit", StatId, Bit);
        public string UnlockText =>
            Unlocked ? FormatUnixTime(UnlockUnix) : S.Get("Stats_Locked");
        public SymbolRegular StatusSymbol =>
            Unlocked ? SymbolRegular.Trophy24 : SymbolRegular.LockClosed24;
        public System.Windows.Media.Brush StatusBrush =>
            Unlocked
                ? (System.Windows.Media.Brush)Application.Current.Resources["TextFillColorPrimaryBrush"]
                : (System.Windows.Media.Brush)Application.Current.Resources["TextFillColorTertiaryBrush"];
    }
}
