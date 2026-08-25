using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CloudRedirect.Resources;
using CloudRedirect.Services;

namespace CloudRedirect.Pages;

public partial class Cloud760Page : Page
{
    public sealed class FileRow : INotifyPropertyChanged
    {
        public string Name { get; init; } = "";
        public int Size { get; init; }
        public DateTime Timestamp { get; init; }

        private bool _isChecked;
        public bool IsChecked
        {
            get => _isChecked;
            set { if (_isChecked != value) { _isChecked = value; OnPropertyChanged(nameof(IsChecked)); CheckedChanged?.Invoke(); } }
        }

        public string SizeDisplay => FormatSize(Size);
        public string TimestampDisplay => Timestamp.Year > 1971 ? Timestamp.ToString("yyyy-MM-dd HH:mm") : "";

        public Action? CheckedChanged;
        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));

        private static string FormatSize(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB" };
            double v = bytes; int u = 0;
            while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
            return u == 0 ? $"{bytes} B" : $"{v:0.##} {units[u]}";
        }
    }

    private readonly ObservableCollection<FileRow> _files = new();
    private bool _busy;
    private Steam760Cloud? _cloud;       // live connection (kept open like the reference tool)
    private uint _connectedAppId;

    public Cloud760Page()
    {
        InitializeComponent();
        FileList.ItemsSource = _files;
        Unloaded += (_, _) => { _cloud?.Dispose(); _cloud = null; };
        UpdateListVisibility();
    }

    private uint ParseAppId()
    {
        if (uint.TryParse(AppIdBox.Text?.Trim(), out uint id) && id > 0)
            return id;
        return 760;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        BusyRing.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        ConnectButton.IsEnabled = !busy;
        bool connected = _cloud != null && !busy;
        RefreshButton.IsEnabled = connected;
        AppIdBox.IsEnabled = !busy;
        UpdateSelectionUi();
    }

    private void UpdateListVisibility()
    {
        bool hasFiles = _files.Count > 0;
        ListPanel.Visibility = hasFiles ? Visibility.Visible : Visibility.Collapsed;
        EmptyHintCard.Visibility = hasFiles ? Visibility.Collapsed : Visibility.Visible;
    }

    private void UpdateSelectionUi()
    {
        int total = _files.Count;
        int sel = _files.Count(f => f.IsChecked);
        SelectionText.Text = sel > 0
            ? S.Format("Cloud760_FilesSelected", sel, total)
            : S.Format("Cloud760_FilesCount", total);
        bool connected = _cloud != null && !_busy;
        DeleteSelectedButton.IsEnabled = connected && sel > 0;
        DeleteAllButton.IsEnabled = connected && total > 0;
    }

    private void LoadRows(IEnumerable<Steam760Cloud.CloudFile> files)
    {
        _files.Clear();
        foreach (var f in files)
        {
            var row = new FileRow { Name = f.Name, Size = f.Size, Timestamp = f.Timestamp };
            row.CheckedChanged = UpdateSelectionUi;
            _files.Add(row);
        }
        UpdateListVisibility();
        UpdateSelectionUi();
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var f in _files) f.IsChecked = true;
        UpdateSelectionUi();
    }

    private void ClearSelection_Click(object sender, RoutedEventArgs e)
    {
        foreach (var f in _files) f.IsChecked = false;
        UpdateSelectionUi();
    }

    private void OpenConsoleButton_Click(object sender, RoutedEventArgs e)
    {
        SteamConsole.OpenConsole();
        StatusText.Text = S.Format("Cloud760_ConsoleOpened", ParseAppId());
    }

    private void CopyCmdButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText($"cloud_sync_up {ParseAppId()}");
            StatusText.Text = S.Format("Cloud760_CommandCopied", ParseAppId());
        }
        catch { /* clipboard can transiently fail; ignore */ }
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        uint appId = ParseAppId();
        SetBusy(true);
        StatusText.Text = S.Format("Cloud760_Connecting", appId);
        _files.Clear();
        UpdateListVisibility();

        // Tear down any prior connection (only one SteamAPI session at a time).
        _cloud?.Dispose();
        _cloud = null;

        try
        {
            var cloud = new Steam760Cloud();
            var result = await Task.Run(() =>
            {
                cloud.Connect(appId);
                var (total, used) = cloud.GetQuota();
                var files = cloud.ListFiles();
                return (files, total, used);
            });

            _cloud = cloud;
            _connectedAppId = appId;

            LoadRows(result.files);
            QuotaText.Text = S.Format("Cloud760_QuotaUsed", FormatBytes(result.used), FormatBytes(result.total));
            StatusText.Text = _files.Count > 0
                ? S.Format("Cloud760_LoadedFiles", _files.Count, appId)
                : S.Format("Cloud760_ConnectedNoFiles", appId);
        }
        catch (Exception ex)
        {
            _cloud?.Dispose();
            _cloud = null;
            QuotaText.Text = "";
            StatusText.Text = S.Format("Cloud760_Error", ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _cloud == null) return;
        SetBusy(true);
        StatusText.Text = S.Get("Cloud760_Refreshing");
        try
        {
            var cloud = _cloud;
            uint appId = _connectedAppId;
            var result = await Task.Run(() =>
            {
                var (total, used) = cloud.GetQuota();
                var files = cloud.ListFiles();
                return (files, total, used);
            });

            LoadRows(result.files);
            QuotaText.Text = S.Format("Cloud760_QuotaUsed", FormatBytes(result.used), FormatBytes(result.total));
            StatusText.Text = S.Format("Cloud760_LoadedFiles", _files.Count, appId);
        }
        catch (Exception ex)
        {
            StatusText.Text = S.Format("Cloud760_Error", ex.Message);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void DeleteSelectedButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var targets = _files.Where(f => f.IsChecked).Select(f => f.Name).ToList();
        if (targets.Count == 0) return;
        await DeleteFiles(targets, $"Delete {targets.Count} selected cloud file(s) from AppID {_connectedAppId}? This cannot be undone.");
    }

    private async void DeleteAllButton_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var targets = _files.Select(f => f.Name).ToList();
        if (targets.Count == 0) return;
        bool ok = await Dialog.ConfirmDangerCountdownAsync(
            "Delete ALL cloud files",
            $"This will permanently delete ALL {targets.Count} cloud file(s) for AppID {_connectedAppId}. This cannot be undone.",
            3);
        if (!ok) return;
        await DeleteFiles(targets, null);
    }

    private async Task DeleteFiles(List<string> names, string? confirmMessage)
    {
        if (_cloud == null) return;
        if (confirmMessage != null)
        {
            bool ok = await Dialog.ConfirmDangerAsync("Delete cloud files", confirmMessage);
            if (!ok) return;
        }

        SetBusy(true);
        StatusText.Text = S.Format("Cloud760_DeletingFiles", names.Count);

        try
        {
            var cloud = _cloud;
            var (deleted, failed) = await Task.Run(() =>
            {
                int ok = 0, bad = 0;
                foreach (var n in names)
                {
                    if (cloud.DeleteFile(n)) ok++; else bad++;
                }
                return (ok, bad);
            });

            StatusText.Text = failed > 0
                ? S.Format("Cloud760_DeletedFilesFailed", deleted, failed)
                : S.Format("Cloud760_DeletedFiles", deleted);
        }
        catch (Exception ex)
        {
            StatusText.Text = S.Format("Cloud760_Error", ex.Message);
        }
        finally
        {
            SetBusy(false);
        }

        // Refresh the list to reflect deletions.
        if (!_busy && _cloud != null)
            RefreshButton_Click(this, new RoutedEventArgs());
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = bytes; int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return u == 0 ? $"{bytes} B" : $"{v:0.##} {units[u]}";
    }
}
