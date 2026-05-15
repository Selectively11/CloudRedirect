using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using CloudRedirect.Resources;
using Wpf.Ui.Controls;

namespace CloudRedirect.Windows;

public partial class DisclaimerWindow : FluentWindow
{
    private const int CountdownSeconds = 5;
    private int _remaining;
    private DispatcherTimer? _timer;

    /// <summary>
    /// True if the user clicked "I Understand the Risks".
    /// </summary>
    public bool Accepted { get; private set; }

    public DisclaimerWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Fade-in the ASCII art
        var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(800))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
        };
        AsciiArt.BeginAnimation(OpacityProperty, fadeIn);

        // Start countdown
        _remaining = CountdownSeconds;
        UpdateCountdownText();

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += OnTimerTick;
        _timer.Start();
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        _remaining--;

        if (_remaining <= 0)
        {
            _timer?.Stop();
            AcceptButton.IsEnabled = true;
            CountdownText.Text = S.Get("Disclaimer_Warned");
        }
        else
        {
            UpdateCountdownText();
        }
    }

    private void UpdateCountdownText()
    {
        CountdownText.Text = S.Format("Disclaimer_CountdownFormat", _remaining);
    }

    private void Accept_Click(object sender, RoutedEventArgs e)
    {
        Accepted = true;
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Accepted = false;
        DialogResult = false;
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer?.Stop();
        _timer = null;
        base.OnClosed(e);
    }
}
