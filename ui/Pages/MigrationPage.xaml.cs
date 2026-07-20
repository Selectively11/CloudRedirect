using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using CloudRedirect.Resources;
using CloudRedirect.Services;

namespace CloudRedirect.Pages;

public partial class MigrationPage : Page
{
    private static readonly (string Key, string Label)[] Providers =
    {
        ("gdrive", "Google Drive"),
        ("onedrive", "OneDrive"),
        ("r2", "Cloudflare R2"),
        ("s3", "S3 Compatible"),
    };

    private readonly SteamStoreClient _storeClient = SteamStoreClient.Shared;
    private CancellationTokenSource? _cts;
    private CancellationTokenSource? _scanCts;
    private Process? _cliProcess;
    private MigrationResult? _lastResult;
    private string? _lastSrc;
    private string? _lastDst;
    private string? _activeProvider; // provider currently written in config.json
    private List<MigrationAppInfo>? _sourceApps;

    public MigrationPage()
    {
        InitializeComponent();
        Loaded += MigrationPage_Loaded;
    }

    // ── Initialization ──────────────────────────────────────────────────

    private void MigrationPage_Loaded(object sender, RoutedEventArgs e)
    {
        SourceCombo.Items.Clear();
        DestCombo.Items.Clear();
        foreach (var (key, label) in Providers)
        {
            SourceCombo.Items.Add(new ComboBoxItem { Content = label, Tag = key });
            DestCombo.Items.Add(new ComboBoxItem { Content = label, Tag = key });
        }

        // Pre-select source to current configured provider.
        var config = SteamDetector.ReadConfig();
        _activeProvider = config?.Provider;
        if (config != null)
        {
            for (int i = 0; i < Providers.Length; i++)
            {
                if (Providers[i].Key == config.Provider)
                {
                    SourceCombo.SelectedIndex = i;
                    break;
                }
            }
        }
        else
        {
            SourceCombo.SelectedIndex = 0;
        }

        int srcIdx = SourceCombo.SelectedIndex;
        DestCombo.SelectedIndex = srcIdx == 0 ? 1 : 0;

        RefreshActiveProviderBanner();
    }

    // Shows which provider the app is currently reading/writing saves through.
    private void RefreshActiveProviderBanner()
    {
        if (ActiveProviderText == null) return;
        if (string.IsNullOrEmpty(_activeProvider))
        {
            ActiveProviderBar.Visibility = Visibility.Collapsed;
            return;
        }
        ActiveProviderBar.Visibility = Visibility.Visible;
        ActiveProviderText.Text = GetProviderLabel(_activeProvider);
    }

    // ── Validation & Source Scanning ────────────────────────────────────

    private void Provider_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ValidateAndScan();
    }

    private void ValidateAndScan()
    {
        if (SourceCombo == null || DestCombo == null || StartButton == null)
            return;

        string? src = (SourceCombo.SelectedItem as ComboBoxItem)?.Tag as string;
        string? dst = (DestCombo.SelectedItem as ComboBoxItem)?.Tag as string;

        if (string.IsNullOrEmpty(src) || string.IsNullOrEmpty(dst))
        {
            StartButton.IsEnabled = false;
            SetValidation("", isError: false);
            HideSourceApps();
            return;
        }

        if (src == dst)
        {
            StartButton.IsEnabled = false;
            SetValidation(S.Get("Migration_SameProvider"), isError: true);
            HideSourceApps();
            return;
        }

        SetValidation("", isError: false);
        StartButton.IsEnabled = false; // re-enabled after scan completes

        // Kick off source scan.
        ScanSourceProvider(src);
    }

    private void SetValidation(string text, bool isError)
    {
        ValidationText.Text = text;
        ValidationText.Foreground = isError
            ? new SolidColorBrush(Color.FromRgb(0xE0, 0x40, 0x40))
            : (Brush)FindResource("TextFillColorSecondaryBrush");
    }

    private void HideSourceApps()
    {
        _scanCts?.Cancel();
        ScanLoadingPanel.Visibility = Visibility.Collapsed;
        SourceAppsHeader.Visibility = Visibility.Collapsed;
        SourceAppList.Visibility = Visibility.Collapsed;
        _sourceApps = null;
    }

    private async void ScanSourceProvider(string provider)
    {
        // Cancel any previous scan.
        _scanCts?.Cancel();
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;

        ScanLoadingPanel.Visibility = Visibility.Visible;
        SourceAppsHeader.Visibility = Visibility.Collapsed;
        SourceAppList.Visibility = Visibility.Collapsed;
        StartButton.IsEnabled = false;

        try
        {
            var apps = await Task.Run(() => FetchSourceApps(provider, token), token);

            if (token.IsCancellationRequested) return;

            _sourceApps = apps;
            ScanLoadingPanel.Visibility = Visibility.Collapsed;

            if (apps.Count == 0)
            {
                SetValidation("No cloud data found on source provider.", isError: true);
                return;
            }

            // Show the app list.
            int accountCount = apps.Select(a => a.AccountId).Distinct().Count();
            string header = accountCount > 1
                ? $"{apps.Count} game(s) across {accountCount} accounts on {GetProviderLabel(provider)}:"
                : $"{apps.Count} game(s) on {GetProviderLabel(provider)}:";
            SourceAppsHeader.Text = header;
            SourceAppsHeader.Visibility = Visibility.Visible;
            SourceAppList.ItemsSource = apps;
            SourceAppList.Visibility = Visibility.Visible;
            StartButton.IsEnabled = true;

            // Resolve game names + images in background.
            _ = ResolveGameNamesAsync(apps, token);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (!token.IsCancellationRequested)
            {
                ScanLoadingPanel.Visibility = Visibility.Collapsed;
                SetValidation($"Scan failed: {ex.Message}", isError: true);
            }
        }
    }

    /// <summary>
    /// Uses `scan-all` CLI command: shallow ListSubfolders per account.
    /// Only returns app IDs — no file counting (that happens during migration).
    /// </summary>
    private List<MigrationAppInfo> FetchSourceApps(string provider, CancellationToken cancel)
    {
        string? cliPath = EmbeddedCli.EnsureExtracted();
        if (string.IsNullOrEmpty(cliPath) || !File.Exists(cliPath))
            throw new InvalidOperationException("CLI not available");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = cliPath,
                Arguments = $"scan-all {provider}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            }
        };

        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        cancel.ThrowIfCancellationRequested();

        if (process.ExitCode != 0)
        {
            try
            {
                using var doc = JsonDocument.Parse(output);
                if (doc.RootElement.TryGetProperty("error", out var ep))
                    throw new InvalidOperationException(ep.GetString() ?? "Unknown error");
            }
            catch (JsonException) { }
            throw new InvalidOperationException($"CLI exited with code {process.ExitCode}");
        }

        var apps = new List<MigrationAppInfo>();
        try
        {
            using var doc = JsonDocument.Parse(output);
            var root = doc.RootElement;
            if (root.TryGetProperty("apps", out var appsArr) && appsArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in appsArr.EnumerateArray())
                {
                    var appId = item.TryGetProperty("app_id", out var aid) ? aid.GetString() ?? "" : "";
                    var accountId = item.TryGetProperty("account_id", out var acId) ? acId.GetString() ?? "" : "";

                    if (!string.IsNullOrEmpty(appId) && appId != "0")
                    {
                        apps.Add(new MigrationAppInfo
                        {
                            AppId = appId,
                            AccountId = accountId,
                        });
                    }
                }
            }
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Invalid CLI response: {ex.Message}");
        }

        return apps;
    }

    private async Task ResolveGameNamesAsync(List<MigrationAppInfo> apps, CancellationToken cancel)
    {
        try
        {
            var appIds = apps
                .Select(a => uint.TryParse(a.AppId, out var id) ? id : 0)
                .Where(id => id != 0)
                .Distinct()
                .ToList();

            if (appIds.Count == 0) return;

            var storeInfo = await _storeClient.GetAppInfoAsync(appIds);
            cancel.ThrowIfCancellationRequested();

            foreach (var app in apps)
            {
                if (uint.TryParse(app.AppId, out var id) && storeInfo.TryGetValue(id, out var info))
                {
                    app.Name = info.Name;
                    app.HeaderUrl = info.HeaderUrl;
                }
            }
        }
        catch { /* Store lookup failure is non-fatal */ }
    }

    // ── Pre-flight auth check ───────────────────────────────────────────

    private static string? ResolveTokenPath(string provider)
    {
        var configDir = SteamDetector.GetConfigDir();
        if (string.IsNullOrEmpty(configDir)) return null;

        var configPath = Path.Combine(configDir, "config.json");
        if (File.Exists(configPath))
        {
            try
            {
                var json = File.ReadAllText(configPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                // 1) Per-provider registry (survives provider switches).
                if (root.TryGetProperty("token_paths", out var tps) &&
                    tps.ValueKind == JsonValueKind.Object &&
                    tps.TryGetProperty(provider, out var perProv))
                {
                    var path = perProv.GetString();
                    if (!string.IsNullOrEmpty(path)) return path;
                }

                // 2) Active provider's token_path.
                if (root.TryGetProperty("provider", out var pp) && pp.GetString() == provider &&
                    root.TryGetProperty("token_path", out var tp))
                {
                    var path = tp.GetString();
                    if (!string.IsNullOrEmpty(path)) return path;
                }
            }
            catch { }
        }

        // 3) Convention-based fallback. Must match the exact default filenames
        //    written by CloudProviderPage (%AppData%\CloudRedirect\...), NOT a
        //    made-up "tokens_{provider}.json" scheme — otherwise migration
        //    can't find credentials until Settings persists an explicit
        //    token_paths entry for the provider.
        var appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "CloudRedirect");
        var fileName = provider switch
        {
            "gdrive"   => "google_tokens.json",
            "onedrive" => "onedrive_tokens.json",
            "r2"       => "r2_credentials.json",
            "s3"       => "s3_credentials.json",
            _          => $"{provider}_tokens.json",
        };
        return Path.Combine(appData, fileName);
    }

    /// <summary>
    /// Light pre-flight: just verify credential file exists and is non-empty.
    /// The CLI does the real authentication test — if it fails, it reports a
    /// clear error in the JSON stream. Avoid DPAPI decryption here since it
    /// can spuriously fail in the UI process.
    /// </summary>
    private static (bool Ok, string Message) CheckProviderAuth(string provider)
    {
        var tokenPath = ResolveTokenPath(provider);
        if (string.IsNullOrEmpty(tokenPath))
            return (false, "Cannot determine credential path");

        if (!File.Exists(tokenPath))
            return (false, $"Credential file not found.\nExpected: {tokenPath}");

        try
        {
            var fi = new FileInfo(tokenPath);
            if (fi.Length == 0)
                return (false, $"Credential file is empty: {Path.GetFileName(tokenPath)}");
        }
        catch (Exception ex)
        {
            return (false, $"Cannot read credential file: {ex.Message}");
        }

        return (true, "Credentials found");
    }

    // ── Start Migration ─────────────────────────────────────────────────

    private async void StartButton_Click(object sender, RoutedEventArgs e)
    {
        string src = (string)((ComboBoxItem)SourceCombo.SelectedItem).Tag;
        string dst = (string)((ComboBoxItem)DestCombo.SelectedItem).Tag;

        // Pre-flight auth check.
        StartButton.IsEnabled = false;
        SetValidation(S.Get("Migration_CheckingCredentials"), isError: false);

        var (srcOk, srcMsg) = await Task.Run(() => CheckProviderAuth(src));
        if (!srcOk)
        {
            SetValidation($"Source ({GetProviderLabel(src)}): {srcMsg}", isError: true);
            StartButton.IsEnabled = true;
            return;
        }

        var (dstOk, dstMsg) = await Task.Run(() => CheckProviderAuth(dst));
        if (!dstOk)
        {
            SetValidation($"Destination ({GetProviderLabel(dst)}): {dstMsg}", isError: true);
            StartButton.IsEnabled = true;
            return;
        }

        // Proceed.
        _lastSrc = src;
        _lastDst = dst;

        ConfigPanel.Visibility = Visibility.Collapsed;
        ProgressPanel.Visibility = Visibility.Visible;
        ResultPanel.Visibility = Visibility.Collapsed;

        ProgressBar.Value = 0;
        ProgressBar.IsIndeterminate = true; // until the CLI reports its file total
        ProgressStatus.Text = S.Get("Migration_Starting");
        ProgressDetail.Text = "";
        ProgressSpeed.Text = "";
        ProgressTitle.Text = $"{GetProviderLabel(src)} → {GetProviderLabel(dst)}";
        CancelButton.IsEnabled = true;

        _cts = new CancellationTokenSource();

        try
        {
            var result = await RunMigrationAsync(src, dst, _cts.Token);
            _lastResult = result;
            ShowResult(result);
        }
        catch (OperationCanceledException)
        {
            _lastResult = new MigrationResult { Cancelled = true };
            ShowResult(_lastResult);
        }
        catch (Exception ex)
        {
            _lastResult = new MigrationResult { Error = ex.Message };
            ShowResult(_lastResult);
        }
    }

    // ── CLI process ─────────────────────────────────────────────────────

    private async Task<MigrationResult> RunMigrationAsync(
        string src, string dst, CancellationToken cancel)
    {
        string? cliPath = EmbeddedCli.EnsureExtracted();
        if (string.IsNullOrEmpty(cliPath) || !File.Exists(cliPath))
            return new MigrationResult { Error = "Embedded CLI executable not available" };

        var result = new MigrationResult();
        var sw = Stopwatch.StartNew();

        var psi = new ProcessStartInfo
        {
            FileName = cliPath,
            Arguments = $"migrate {src} {dst}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = new Process { StartInfo = psi };
        _cliProcess = process;

        try
        {
            process.Start();

            // Drain stderr concurrently so a full pipe buffer can never block
            // the child process (a classic deadlock when only stdout is read).
            // Must be accessed AFTER Start() or the stream isn't redirected yet.
            var stderrTask = process.StandardError.ReadToEndAsync();

            // Parse stdout entirely on this background thread. UI updates are
            // marshalled asynchronously and throttled (see FlushProgress) so a
            // high-frequency progress stream can never flood the dispatcher.
            string? line;
            var reader = process.StandardOutput;
            while ((line = await reader.ReadLineAsync().ConfigureAwait(false)) != null)
            {
                if (cancel.IsCancellationRequested) break;
                if (line.Length == 0) continue;
                ProcessProgressLine(line, result, sw);
            }

            await process.WaitForExitAsync(cancel).ConfigureAwait(false);
            result.ExitCode = process.ExitCode;

            // A nonzero exit with a "complete" line means partial success (some
            // files failed) — that is NOT a hard error; ShowResult renders the
            // "complete with errors / retry" branch from result.Failed. Only
            // treat a nonzero exit as fatal when the run never completed.
            if (result.ExitCode != 0 && !result.Completed && string.IsNullOrEmpty(result.Error))
            {
                var err = await stderrTask.ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(err))
                    result.Error = err.Trim();
            }
        }
        finally
        {
            _cliProcess = null;
        }

        // Push the final state once, synchronously, so the result panel is
        // accurate regardless of how many intermediate frames were dropped.
        await Dispatcher.InvokeAsync(() => FlushProgress(result, sw, force: true));

        result.ElapsedSeconds = sw.Elapsed.TotalSeconds;
        return result;
    }

    // Mutates result state on the background thread and requests a throttled
    // UI refresh. No synchronous Dispatcher.Invoke — the reader thread never
    // blocks on the UI thread.
    private void ProcessProgressLine(string line, MigrationResult result, Stopwatch sw)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            string type = root.TryGetProperty("type", out var typeProp)
                ? typeProp.GetString() ?? "" : "";

            switch (type)
            {
                case "start":
                    result.Total = root.TryGetProperty("total", out var tp) ? tp.GetInt32() : 0;
                    result.Done = 0;
                    RequestProgressRefresh(result, sw, force: true);
                    break;

                case "progress":
                {
                    result.Done = root.TryGetProperty("done", out var dp) ? dp.GetInt32() : result.Done + 1;
                    result.CurrentFile = root.TryGetProperty("file", out var fp) ? fp.GetString() ?? "" : "";
                    result.TotalBytes += root.TryGetProperty("bytes", out var bp) ? bp.GetInt64() : 0;
                    result.Migrated++;
                    RequestProgressRefresh(result, sw);
                    break;
                }

                case "skip":
                {
                    result.Done = root.TryGetProperty("done", out var sdp) ? sdp.GetInt32() : result.Done + 1;
                    result.Skipped++;
                    RequestProgressRefresh(result, sw);
                    break;
                }

                case "error" when root.TryGetProperty("file", out _):
                {
                    result.Done = root.TryGetProperty("done", out var edp) ? edp.GetInt32() : result.Done + 1;
                    result.LastError = root.TryGetProperty("message", out var emp)
                        ? emp.GetString() ?? "Unknown error" : "Unknown error";
                    string errFile = root.TryGetProperty("file", out var efp) ? efp.GetString() ?? "" : "";
                    result.Failed++;
                    result.FailedFiles.Add(errFile);
                    RequestProgressRefresh(result, sw, force: true);
                    break;
                }

                case "error":
                    result.Error = root.TryGetProperty("message", out var fmp)
                        ? fmp.GetString() ?? "Unknown error" : "Unknown error";
                    break;

                case "complete":
                    result.Migrated = root.TryGetProperty("migrated", out var mp) ? mp.GetInt32() : result.Migrated;
                    result.Skipped = root.TryGetProperty("skipped", out var sp) ? sp.GetInt32() : result.Skipped;
                    result.Failed = root.TryGetProperty("failed", out var flp) ? flp.GetInt32() : result.Failed;
                    result.TotalBytes = root.TryGetProperty("total_bytes", out var tbp) ? tbp.GetInt64() : result.TotalBytes;
                    result.Completed = true;
                    break;

                case "status":
                {
                    // Pre-enumeration progress: connecting, discovering accounts,
                    // scanning. Bar stays indeterminate until the "start" total.
                    result.StatusMessage = root.TryGetProperty("message", out var smp)
                        ? smp.GetString() ?? "" : "";
                    int sDone = root.TryGetProperty("done", out var sdop) ? sdop.GetInt32() : -1;
                    int sTotal = root.TryGetProperty("total", out var stop) ? stop.GetInt32() : -1;
                    int sFound = root.TryGetProperty("found", out var sfp) ? sfp.GetInt32() : -1;
                    result.StatusDone = sDone;
                    result.StatusTotal = sTotal;
                    result.StatusFound = sFound;
                    RequestProgressRefresh(result, sw, force: true);
                    break;
                }
            }
        }
        catch (JsonException) { }
    }

    // Coalesces UI refreshes to at most ~15/sec via BeginInvoke. Called from
    // the background reader thread; returns immediately without blocking.
    private long _lastUiTicks;
    private volatile bool _uiRefreshQueued;
    private const long UiRefreshIntervalTicks = TimeSpan.TicksPerSecond / 15;

    private void RequestProgressRefresh(MigrationResult result, Stopwatch sw, bool force = false)
    {
        long now = sw.Elapsed.Ticks;
        if (!force)
        {
            if (_uiRefreshQueued) return;
            if (now - System.Threading.Interlocked.Read(ref _lastUiTicks) < UiRefreshIntervalTicks) return;
        }

        System.Threading.Interlocked.Exchange(ref _lastUiTicks, now);
        _uiRefreshQueued = true;
        Dispatcher.BeginInvoke(() =>
        {
            _uiRefreshQueued = false;
            FlushProgress(result, sw, force: false);
        });
    }

    // Runs on the UI thread. Reads the (racily-updated) result snapshot and
    // paints it; exact values are fine since a final forced flush follows.
    private void FlushProgress(MigrationResult result, Stopwatch sw, bool force)
    {
        // Pre-enumeration phase: no file total yet. Show the CLI's status
        // message (connecting / discovering accounts / scanning) and keep the
        // bar indeterminate so the user knows work is happening.
        if (result.Total <= 0)
        {
            ProgressBar.IsIndeterminate = true;
            if (!string.IsNullOrEmpty(result.StatusMessage))
            {
                ProgressStatus.Text = result.StatusMessage;

                // Detail line: "account X of Y" and running found-file count.
                var parts = new List<string>();
                if (result.StatusTotal > 0)
                    parts.Add($"Account {Math.Max(result.StatusDone, 0)} / {result.StatusTotal}");
                if (result.StatusFound > 0)
                    parts.Add($"{result.StatusFound} file(s) found");
                ProgressDetail.Text = string.Join("  •  ", parts);
            }
            return;
        }

        // Transfer phase: real per-file progress.
        ProgressBar.IsIndeterminate = false;
        ProgressBar.Maximum = result.Total;
        ProgressBar.Value = Math.Min(result.Done, result.Total);

        ProgressStatus.Text = result.Failed > 0
            ? $"{result.Done} / {result.Total} files ({result.Failed} failed)"
            : $"{result.Done} / {result.Total} files";

        if (!string.IsNullOrEmpty(result.CurrentFile))
            ProgressDetail.Text = result.CurrentFile;

        ProgressSpeed.Text = ComputeSpeedEta(result, sw);
    }

    // ── Speed / ETA ─────────────────────────────────────────────────────

    private static string ComputeSpeedEta(MigrationResult result, Stopwatch sw)
    {
        double elapsed = sw.Elapsed.TotalSeconds;
        if (elapsed < 1 || result.Total == 0) return "";

        int processed = result.Migrated + result.Skipped + result.Failed;
        double filesPerSec = processed / elapsed;
        int remaining = result.Total - processed;

        string speed = result.TotalBytes > 0
            ? $"{FormatBytes((long)(result.TotalBytes / elapsed))}/s"
            : $"{filesPerSec:F1} files/s";

        if (remaining <= 0 || filesPerSec < 0.01) return speed;
        double etaSec = remaining / filesPerSec;
        string eta = etaSec switch
        {
            < 60 => $"{(int)etaSec}s",
            < 3600 => $"{(int)(etaSec / 60)}m {(int)(etaSec % 60)}s",
            _ => $"{(int)(etaSec / 3600)}h {(int)((etaSec % 3600) / 60)}m"
        };

        return $"{speed}  •  ~{eta} remaining";
    }

    // ── Result display ──────────────────────────────────────────────────

    private void ShowResult(MigrationResult result)
    {
        Dispatcher.Invoke(() =>
        {
            ProgressPanel.Visibility = Visibility.Collapsed;
            ResultPanel.Visibility = Visibility.Visible;
            RetryButton.Visibility = Visibility.Collapsed;
            SwitchProviderButton.Visibility = Visibility.Collapsed;

            if (result.Cancelled)
            {
                SetResultStyle(ResultKind.Warning);
                ResultTitle.Text = S.Get("Migration_Cancelled");
                ResultSummary.Text = $"Cancelled after migrating {result.Migrated} file(s).";
            }
            else if (!string.IsNullOrEmpty(result.Error))
            {
                SetResultStyle(ResultKind.Error);
                ResultTitle.Text = S.Get("Migration_Failed");
                ResultSummary.Text = result.Error;
            }
            else if (result.Failed > 0)
            {
                SetResultStyle(ResultKind.Warning);
                ResultTitle.Text = S.Get("Migration_CompleteWithErrors");
                ResultSummary.Text = $"Migrated: {result.Migrated}  |  Skipped: {result.Skipped}  |  Failed: {result.Failed}\n" +
                                     $"Total transferred: {FormatBytes(result.TotalBytes)}\n" +
                                     $"Last error: {result.LastError}";
                RetryButton.Visibility = Visibility.Visible;
                // Some data made it across — switch the active provider so the
                // user reads from the destination, then keep Retry for the rest.
                if (result.Migrated > 0 || result.Skipped > 0)
                    AutoSwitchToDestination(result);
            }
            else
            {
                SetResultStyle(ResultKind.Success);
                ResultTitle.Text = S.Get("Migration_Complete");
                ResultSummary.Text = $"Migrated: {result.Migrated}  |  Skipped (already existed): {result.Skipped}\n" +
                                     $"Total transferred: {FormatBytes(result.TotalBytes)}";
                AutoSwitchToDestination(result);
            }
        });
    }

    // On a successful (or partial) migration, make the destination the active
    // provider automatically and reflect it in the UI. Falls back to exposing
    // the manual "switch" button if the automatic config write fails.
    private void AutoSwitchToDestination(MigrationResult result)
    {
        if (_lastDst == null) return;

        // Already active (e.g. re-run) — nothing to change, just confirm.
        if (_activeProvider == _lastDst)
        {
            AppendResultLine(S.Format("Migration_NowUsing", GetProviderLabel(_lastDst)));
            SwitchProviderButton.Visibility = Visibility.Collapsed;
            RefreshActiveProviderBanner();
            return;
        }

        var (ok, _) = TrySwitchActiveProvider(_lastDst);
        if (ok)
        {
            AppendResultLine(S.Format("Migration_SwitchedToActive", GetProviderLabel(_lastDst)));
            SwitchProviderButton.Visibility = Visibility.Collapsed;
            RefreshActiveProviderBanner();
        }
        else
        {
            // Let the user retry the switch manually.
            SwitchProviderButton.Visibility = Visibility.Visible;
        }
    }

    private void AppendResultLine(string line)
    {
        ResultSummary.Text = string.IsNullOrEmpty(ResultSummary.Text)
            ? line
            : ResultSummary.Text + "\n\n" + line;
    }

    private enum ResultKind { Success, Warning, Error }

    // Restrained, app-consistent styling: a soft low-alpha tinted banner with a
    // muted border and a circular status-icon badge — mirrors the Dashboard's
    // update banner rather than a saturated full-colour box. Title text stays
    // the normal primary colour; only the badge carries the accent.
    private void SetResultStyle(ResultKind kind)
    {
        // Base accent per state (matches the Dashboard success green tone).
        (byte r, byte g, byte b, Wpf.Ui.Controls.SymbolRegular icon) = kind switch
        {
            ResultKind.Success => ((byte)0x47, (byte)0x9F, (byte)0x42, Wpf.Ui.Controls.SymbolRegular.CheckmarkCircle24),
            ResultKind.Warning => ((byte)0xC8, (byte)0x8A, (byte)0x2C, Wpf.Ui.Controls.SymbolRegular.Warning24),
            _                  => ((byte)0xC4, (byte)0x3B, (byte)0x3B, Wpf.Ui.Controls.SymbolRegular.ErrorCircle24),
        };

        var accent = Color.FromRgb(r, g, b);

        // Soft tinted background + muted border (low alpha, like #332F7A2F).
        ResultBorder.Background = new SolidColorBrush(Color.FromArgb(0x28, r, g, b));
        ResultBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(0x80, r, g, b));

        // Circular icon badge with a slightly stronger tint.
        ResultIconBadge.Background = new SolidColorBrush(Color.FromArgb(0x40, r, g, b));
        ResultIcon.Symbol = icon;
        ResultIcon.Foreground = new SolidColorBrush(accent);
    }

    // ── Result actions ──────────────────────────────────────────────────

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        SetValidation("", isError: false);
        ConfigPanel.Visibility = Visibility.Visible;
        ProgressPanel.Visibility = Visibility.Collapsed;
        ResultPanel.Visibility = Visibility.Collapsed;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        // Kill the whole tree so in-flight provider API calls die promptly
        // rather than the reader loop waiting on the next line of output.
        try { _cliProcess?.Kill(entireProcessTree: true); } catch { }
        CancelButton.IsEnabled = false;
        ProgressStatus.Text = S.Get("Migration_Cancelling");
    }

    private void RetryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastSrc == null || _lastDst == null) return;

        for (int i = 0; i < Providers.Length; i++)
        {
            if (Providers[i].Key == _lastSrc) SourceCombo.SelectedIndex = i;
            if (Providers[i].Key == _lastDst) DestCombo.SelectedIndex = i;
        }

        ResultPanel.Visibility = Visibility.Collapsed;
        ConfigPanel.Visibility = Visibility.Visible;
        StartButton_Click(this, new RoutedEventArgs());
    }

    private async void SwitchProviderButton_Click(object sender, RoutedEventArgs e)
    {
        if (_lastDst == null) return;
        var (ok, err) = TrySwitchActiveProvider(_lastDst);
        if (ok)
        {
            SwitchProviderButton.IsEnabled = false;
            SwitchProviderButton.Content = S.Format("Migration_SwitchedTo", GetProviderLabel(_lastDst));
        }
        else
        {
            await Dialog.ShowErrorAsync("Error", $"Failed to update config: {err}");
        }
    }

    // Writes the active provider + its token path into config.json so the app
    // now reads/writes cloud saves through <provider>. Returns (success, error).
    private (bool ok, string? error) TrySwitchActiveProvider(string provider)
    {
        var tokenPath = ResolveTokenPath(provider);
        if (string.IsNullOrEmpty(tokenPath))
            return (false, $"Could not resolve token path for {GetProviderLabel(provider)}");

        try
        {
            var configPath = SteamDetector.GetConfigFilePath();
            ConfigHelper.SaveConfig(configPath,
                new[] { "provider", "token_path", "sync_path" },
                writer =>
                {
                    writer.WriteString("provider", provider);
                    writer.WriteString("token_path", tokenPath);
                });
            _activeProvider = provider;
            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static string GetProviderLabel(string key) => key switch
    {
        "gdrive" => "Google Drive",
        "onedrive" => "OneDrive",
        "r2" => "Cloudflare R2",
        "s3" => "S3 Compatible",
        _ => key
    };

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB"
    };

    // ── Models ──────────────────────────────────────────────────────────

    private class MigrationResult
    {
        public int Migrated;
        public int Skipped;
        public int Failed;
        public int Total;
        public int Done;
        public long TotalBytes;
        public int ExitCode;
        public double ElapsedSeconds;
        public string? Error;
        public string? LastError;
        public string? CurrentFile;
        public bool Completed; // CLI emitted a terminal "complete" line
        public bool Cancelled;

        // Pre-enumeration status (before the "start" file total is known).
        public string? StatusMessage;
        public int StatusDone = -1;
        public int StatusTotal = -1;
        public int StatusFound = -1;
        public List<string> FailedFiles = new();
    }
}

/// <summary>Lightweight app info for the source provider scan.</summary>
public class MigrationAppInfo : INotifyPropertyChanged
{
    public string AppId { get; set; } = "";
    public string AccountId { get; set; } = "";

    public string DisplayName => !string.IsNullOrEmpty(Name) ? Name : $"App {AppId}";

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

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify(string n) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
}
