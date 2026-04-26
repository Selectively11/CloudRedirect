using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CloudRedirect.Resources;

namespace CloudRedirect.Services;

/// <summary>
/// Builds the grouped backup card UI shared by CleanupPage and AppsPage restore sections.
/// </summary>
internal static class BackupListBuilder
{
    /// <summary>
    /// Populates <paramref name="panel"/> with game-grouped backup cards.
    /// </summary>
    /// <param name="panel">The StackPanel to populate (cleared first).</param>
    /// <param name="backups">All backups to display.</param>
    /// <param name="lookupStore">Returns store info for an appId, or null if unknown.</param>
    /// <param name="findResource">Resolves a WPF resource key (e.g. brush names).</param>
    /// <param name="onPreview">Called when the Preview button is clicked.</param>
    /// <param name="onRestore">Called when the Restore button is clicked.</param>
    /// <param name="highlightAfterUtc">
    /// If set, backups with Timestamp >= this value are considered "recent":
    /// sorted to the top, given a blue tint, and labeled with a "recent" badge.
    /// </param>
    internal static void Build(
        Panel panel,
        IReadOnlyList<BackupInfo> backups,
        Func<uint, StoreAppInfo?> lookupStore,
        Func<object, object> findResource,
        Func<BackupInfo, StackPanel, Wpf.Ui.Controls.Button, Task> onPreview,
        Func<BackupInfo, Wpf.Ui.Controls.Button, Task> onRestore,
        DateTime? highlightAfterUtc = null)
    {
        panel.Children.Clear();

        // Group backups by app ID. A backup spanning multiple apps appears under each.
        var byApp = new Dictionary<uint, List<BackupInfo>>();
        foreach (var backup in backups)
        {
            if (backup.AppIds.Count == 0)
            {
                if (!byApp.ContainsKey(0)) byApp[0] = new List<BackupInfo>();
                byApp[0].Add(backup);
            }
            else
            {
                foreach (uint appId in backup.AppIds)
                {
                    if (!byApp.ContainsKey(appId)) byApp[appId] = new List<BackupInfo>();
                    byApp[appId].Add(backup);
                }
            }
        }

        // Sort game groups: groups with recent backups first, then alphabetical by name, then by app ID
        var sortedGroups = byApp.OrderBy(g =>
        {
            bool hasRecent = highlightAfterUtc.HasValue &&
                g.Value.Any(b => b.Timestamp >= highlightAfterUtc.Value);
            int recentOrder = hasRecent ? 0 : 1;

            if (g.Key == 0) return (recentOrder, 1, "", (int)g.Key);
            var si = lookupStore(g.Key);
            if (si != null && !string.IsNullOrEmpty(si.Name))
                return (recentOrder, 0, si.Name, (int)g.Key);
            return (recentOrder, 0, "", (int)g.Key);
        }).ToList();

        foreach (var group in sortedGroups)
        {
            uint appId = group.Key;
            var sorted = group.Value.OrderByDescending(b => b.Timestamp).ToList();

            // Resolve game name + icon URL
            var storeInfo = appId != 0 ? lookupStore(appId) : null;
            string gameName = appId == 0 ? S.Get("Backup_UnknownApp") :
                (storeInfo != null && !string.IsNullOrEmpty(storeInfo.Name)
                    ? storeInfo.Name : S.Format("Apps_AppFallbackName", appId));
            string? headerUrl = storeInfo?.HeaderUrl;

            // Game card
            var card = new Border
            {
                Background = (Brush)findResource("ControlFillColorDefaultBrush"),
                CornerRadius = new CornerRadius(8),
                Margin = new Thickness(0, 0, 0, 8),
                Padding = new Thickness(16)
            };

            var cardContent = new StackPanel();
            card.Child = cardContent;

            // Game header: icon + name + app ID
            var gameHeader = new Grid();
            gameHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            gameHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var iconImage = new Image
            {
                Width = 32,
                Height = 32,
                Stretch = Stretch.UniformToFill,
                Margin = new Thickness(0, 0, 10, 0)
            };
            if (!string.IsNullOrEmpty(headerUrl) && SteamStoreClient.IsValidImageUrl(headerUrl))
            {
                try
                {
                    var uri = new Uri(headerUrl);
                    var bitmap = new BitmapImage();
                    bitmap.BeginInit();
                    if (uri.IsFile)
                    {
                        // OnLoad decodes immediately and releases the backing
                        // file handle; without it a file:// URI keeps the
                        // cached JPEG locked, blocking eviction and the
                        // File.Move(overwrite:true) that installs a refreshed
                        // asset after a Steam CDN hash rotation.
                        bitmap.CacheOption = BitmapCacheOption.OnLoad;
                    }
                    // HTTP URIs: leave CacheOption at Default so the download
                    // streams async rather than blocking the UI thread.
                    bitmap.UriSource = uri;
                    bitmap.DecodePixelWidth = 64;
                    bitmap.EndInit();
                    if (uri.IsFile)
                        bitmap.Freeze();
                    iconImage.Source = bitmap;
                }
                catch { /* icon load failure is fine */ }
            }
            Grid.SetColumn(iconImage, 0);
            gameHeader.Children.Add(iconImage);

            var nameStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            nameStack.Children.Add(new TextBlock
            {
                Text = gameName,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = (Brush)findResource("TextFillColorPrimaryBrush"),
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            if (appId != 0)
            {
                nameStack.Children.Add(new TextBlock
                {
                    Text = S.Format("Backup_AppIdFormat", appId),
                    FontSize = 12,
                    Foreground = (Brush)findResource("TextFillColorTertiaryBrush"),
                    Margin = new Thickness(0, 2, 0, 0)
                });
            }
            Grid.SetColumn(nameStack, 1);
            gameHeader.Children.Add(nameStack);

            cardContent.Children.Add(gameHeader);

            // Backup rows
            foreach (var backup in sorted)
            {
                bool isRecent = highlightAfterUtc.HasValue &&
                    backup.Timestamp >= highlightAfterUtc.Value;

                var rowBorder = new Border
                {
                    Margin = new Thickness(0, 8, 0, 0),
                    Padding = new Thickness(8),
                    CornerRadius = new CornerRadius(4),
                    Background = isRecent
                        ? new SolidColorBrush(Color.FromArgb(35, 60, 140, 230))
                        : (Brush)findResource("ControlFillColorSecondaryBrush")
                };
                if (isRecent)
                {
                    rowBorder.BorderBrush = new SolidColorBrush(Color.FromArgb(80, 60, 140, 230));
                    rowBorder.BorderThickness = new Thickness(1);
                }

                var rowStack = new StackPanel();
                rowBorder.Child = rowStack;

                // Row header: timestamp + stats | buttons
                var rowGrid = new Grid();
                rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var infoStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };

                // Timestamp row with legacy badge
                string timestampText = backup.Timestamp != DateTime.MinValue
                    ? backup.Timestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                    : backup.Id;
                var titleRow = new WrapPanel();
                titleRow.Children.Add(new TextBlock
                {
                    Text = timestampText,
                    FontSize = 13,
                    FontWeight = FontWeights.Medium,
                    Foreground = (Brush)findResource("TextFillColorPrimaryBrush"),
                    Margin = new Thickness(0, 0, 8, 0)
                });
                if (backup.IsLegacy)
                {
                    var legacyBadge = new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(100, 100, 100)),
                        CornerRadius = new CornerRadius(4),
                        Padding = new Thickness(6, 2, 6, 2),
                        VerticalAlignment = VerticalAlignment.Center,
                        Margin = new Thickness(0, 0, 4, 0)
                    };
                    legacyBadge.Child = new TextBlock
                    {
                        Text = S.Get("Backup_Legacy"),
                        FontSize = 11,
                        Foreground = Brushes.White
                    };
                    titleRow.Children.Add(legacyBadge);
                }
                if (isRecent)
                {
                    var recentBadge = new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(50, 120, 210)),
                        CornerRadius = new CornerRadius(4),
                        Padding = new Thickness(6, 2, 6, 2),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    recentBadge.Child = new TextBlock
                    {
                        Text = S.Get("Backup_Recent"),
                        FontSize = 11,
                        Foreground = Brushes.White
                    };
                    titleRow.Children.Add(recentBadge);
                }
                infoStack.Children.Add(titleRow);

                // Stats line
                var tertiaryBrush = (Brush)findResource("TextFillColorTertiaryBrush");
                var statsWrap = new WrapPanel { Margin = new Thickness(0, 2, 0, 0) };
                statsWrap.Children.Add(MakeStatText(S.Format("Backup_FileCountFormat", backup.FileCount), tertiaryBrush));
                statsWrap.Children.Add(MakeStatText(FileUtils.FormatSize(backup.TotalBytes), tertiaryBrush));
                statsWrap.Children.Add(MakeStatText(S.Format("Backup_OperationsFormat", backup.TotalOperations), tertiaryBrush));

                // Multi-app indicator
                int otherApps = backup.AppIds.Count - 1;
                if (otherApps > 0)
                {
                    statsWrap.Children.Add(MakeStatText(
                        S.Format("Backup_OtherAppsFormat", otherApps, otherApps > 1 ? "s" : ""), tertiaryBrush));
                }

                infoStack.Children.Add(statsWrap);

                Grid.SetColumn(infoStack, 0);
                rowGrid.Children.Add(infoStack);

                // Buttons
                var btnPanel = new StackPanel
                {
                    Orientation = Orientation.Horizontal,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(8, 0, 0, 0)
                };

                var previewBtn = new Wpf.Ui.Controls.Button
                {
                    Content = S.Get("Backup_Preview"),
                    Icon = new Wpf.Ui.Controls.SymbolIcon { Symbol = Wpf.Ui.Controls.SymbolRegular.Search24 },
                    Appearance = Wpf.Ui.Controls.ControlAppearance.Secondary,
                    Margin = new Thickness(0, 0, 4, 0)
                };
                var restoreBtn = new Wpf.Ui.Controls.Button
                {
                    Content = S.Get("Apps_Restore"),
                    Icon = new Wpf.Ui.Controls.SymbolIcon { Symbol = Wpf.Ui.Controls.SymbolRegular.ArrowUndo24 },
                    Appearance = Wpf.Ui.Controls.ControlAppearance.Caution
                };

                if (backup.FileCount == 0)
                {
                    previewBtn.IsEnabled = false;
                    restoreBtn.IsEnabled = false;
                    previewBtn.ToolTip = S.Get("Backup_NoFilesOnDisk");
                    restoreBtn.ToolTip = S.Get("Backup_NoFilesOnDisk");
                }

                // Detail panel (hidden until preview clicked)
                var detailPanel = new StackPanel
                {
                    Visibility = Visibility.Collapsed,
                    Margin = new Thickness(0, 8, 0, 0)
                };

                var capturedBackup = backup;
                var capturedDetailPanel = detailPanel;
                var capturedPreviewBtn = previewBtn;
                var capturedRestoreBtn = restoreBtn;

                previewBtn.Click += async (_, _) =>
                {
                    await onPreview(capturedBackup, capturedDetailPanel, capturedPreviewBtn);
                };

                restoreBtn.Click += async (_, _) =>
                {
                    await onRestore(capturedBackup, capturedRestoreBtn);
                };

                btnPanel.Children.Add(previewBtn);
                btnPanel.Children.Add(restoreBtn);
                Grid.SetColumn(btnPanel, 1);
                rowGrid.Children.Add(btnPanel);

                rowStack.Children.Add(rowGrid);
                rowStack.Children.Add(detailPanel);

                cardContent.Children.Add(rowBorder);
            }

            panel.Children.Add(card);
        }
    }

    private static TextBlock MakeStatText(string text, Brush foreground)
    {
        return new TextBlock
        {
            Text = text,
            FontSize = 12,
            Foreground = foreground,
            Margin = new Thickness(0, 0, 12, 0)
        };
    }
}
