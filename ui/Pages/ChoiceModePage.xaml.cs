using System;
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

    // M16: Read mode setting off UI thread to avoid slow-disk stall.
    private async Task RefreshStateAsync()
    {
        var mode = await Task.Run(() => SteamDetector.ReadModeSetting());
        ApplyMode(mode);
    }

    private void ApplyMode(string? mode)
    {
        _currentMode = mode;

        if (_currentMode == "cloud_redirect")
        {
            CurrentModeBanner.Visibility = Visibility.Visible;
            CurrentModeText.Text = S.Get("Choice_CurrentMode_CloudRedirect");
            CurrentModeDescription.Text = S.Get("Choice_CurrentMode_CloudRedirect_Desc");
            CloudRedirectCard.Visibility = Visibility.Collapsed;
        }
        else
        {
            CurrentModeBanner.Visibility = Visibility.Collapsed;
            CloudRedirectCard.Visibility = Visibility.Visible;
        }
    }

    private async void CloudRedirectCard_Click(object sender, MouseButtonEventArgs e)
    {
        // One-time consent gate; skipped once accepted.
        if (!ModeService.HasAcceptedDisclaimer())
        {
            var disclaimer = new DisclaimerWindow { Owner = Window.GetWindow(this) };
            if (disclaimer.ShowDialog() != true || !disclaimer.Accepted)
                return;
            ModeService.MarkDisclaimerAccepted();
        }

        if (!await TryPersistModeAsync("cloud_redirect", cloudRedirectEnabled: true))
            return;

        var mw = Window.GetWindow(this) as MainWindow;
        mw?.ApplyMode("cloud_redirect");
        mw?.RootNavigation.Navigate(typeof(SetupPage));
    }

    // Persists both settings.json (mode) and the pin config (cloud_redirect)
    // via ModeService. Surfaces failure so a silent disk/permissions error
    // doesn't leave the UI looking like the choice was saved when it wasn't.
    private static async Task<bool> TryPersistModeAsync(string mode, bool cloudRedirectEnabled)
    {
        try
        {
            ModeService.PersistMode(mode, cloudRedirectEnabled);
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
}
