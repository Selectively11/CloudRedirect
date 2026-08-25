using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using CloudRedirect.Resources;
using Wpf.Ui.Controls;
using Button = Wpf.Ui.Controls.Button;
using MessageBox = Wpf.Ui.Controls.MessageBox;
using MessageBoxResult = Wpf.Ui.Controls.MessageBoxResult;
using TextBlock = System.Windows.Controls.TextBlock;

namespace CloudRedirect.Services;

/// <summary>
/// Modern dialog helpers using WPF-UI's fluent MessageBox instead of the
/// legacy Win32 MessageBox. All methods are async and theme-aware.
/// </summary>
public static class Dialog
{
    // Collapse empty footer buttons so only the close "OK" button is visible.
    private static Task ShowAcknowledgeAsync(string title, string message, ControlAppearance appearance)
    {
        var box = new MessageBox
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = S.Get("Dialog_OK"),
            CloseButtonAppearance = appearance,
        };

        box.Loaded += (_, _) => CollapseEmptyFooterButtons(box);
        return box.ShowDialogAsync();
    }

    // Scoped to Wpf.Ui.Controls.Button (the footer buttons) so the title-bar
    // close (X) and other chrome are never touched.
    private static void CollapseEmptyFooterButtons(DependencyObject root)
    {
        int count = VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is Button btn)
            {
                var text = (btn.Content as string) ?? (btn.Content as TextBlock)?.Text;
                if (string.IsNullOrWhiteSpace(text) && btn.Icon is null)
                    btn.Visibility = Visibility.Collapsed;
            }
            CollapseEmptyFooterButtons(child);
        }
    }

    public static Task ShowInfoAsync(string title, string message)
        => ShowAcknowledgeAsync(title, message, ControlAppearance.Primary);

    public static Task ShowWarningAsync(string title, string message)
        => ShowAcknowledgeAsync(title, message, ControlAppearance.Caution);

    public static Task ShowErrorAsync(string title, string message)
        => ShowAcknowledgeAsync(title, message, ControlAppearance.Danger);

    public static async Task<bool> ConfirmAsync(string title, string message)
    {
        var box = new MessageBox
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = S.Get("Dialog_Yes"),
            CloseButtonText = S.Get("Dialog_No")
        };
        return await box.ShowDialogAsync() == MessageBoxResult.Primary;
    }

    public static async Task<bool> ConfirmDangerAsync(string title, string message)
    {
        var box = new MessageBox
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = S.Get("Dialog_Yes"),
            PrimaryButtonAppearance = ControlAppearance.Danger,
            CloseButtonText = S.Get("Dialog_No")
        };
        return await box.ShowDialogAsync() == MessageBoxResult.Primary;
    }

    public static async Task<bool> ConfirmDangerAsync(string title, UIElement content)
    {
        var box = new MessageBox
        {
            Title = title,
            Content = content,
            PrimaryButtonText = S.Get("Dialog_Yes"),
            PrimaryButtonAppearance = ControlAppearance.Danger,
            CloseButtonText = S.Get("Dialog_No")
        };
        return await box.ShowDialogAsync() == MessageBoxResult.Primary;
    }

    /// <summary>
    /// Shows a danger confirmation dialog with a countdown timer.
    /// The "Yes" button is disabled and shows a countdown (e.g. "Yes (3)")
    /// until the timer expires, forcing the user to wait before confirming.
    /// </summary>
    public static async Task<bool> ConfirmDangerCountdownAsync(string title, string message, int countdownSeconds = 3)
    {
        var box = new MessageBox
        {
            Title = title,
            Content = new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x66, 0x66))
            },
            PrimaryButtonText = countdownSeconds > 0 ? S.Format("Dialog_YesCountdownFormat", countdownSeconds) : S.Get("Dialog_YesDeleteEverything"),
            PrimaryButtonAppearance = ControlAppearance.Danger,
            IsPrimaryButtonEnabled = countdownSeconds <= 0,
            CloseButtonText = S.Get("Dialog_No")
        };

        DispatcherTimer timer = null;

        if (countdownSeconds > 0)
        {
            int remaining = countdownSeconds;
            timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            timer.Tick += (_, _) =>
            {
                remaining--;
                if (remaining <= 0)
                {
                    timer.Stop();
                    box.IsPrimaryButtonEnabled = true;
                    box.PrimaryButtonText = S.Get("Dialog_YesDeleteEverything");
                }
                else
                {
                    box.PrimaryButtonText = S.Format("Dialog_YesCountdownFormat", remaining);
                }
            };
            timer.Start();
        }

        var result = await box.ShowDialogAsync();

        timer?.Stop();
        return result == MessageBoxResult.Primary;
    }

    /// <summary>
    /// Shows a choice dialog with a primary action and a secondary/close action.
    /// Returns true if the user chose the primary button.
    /// </summary>
    public static async Task<bool> ChoiceAsync(string title, string message,
        string primaryText, string secondaryText)
    {
        var box = new MessageBox
        {
            Title = title,
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap },
            PrimaryButtonText = primaryText,
            CloseButtonText = secondaryText
        };
        return await box.ShowDialogAsync() == MessageBoxResult.Primary;
    }
}
