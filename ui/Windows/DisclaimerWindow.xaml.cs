using System;
using System.Windows;
using Wpf.Ui.Controls;

namespace CloudRedirect.Windows;

public partial class DisclaimerWindow : FluentWindow
{
    /// <summary>True if the user chose to enable Cloud Redirect.</summary>
    public bool Accepted { get; private set; }

    public DisclaimerWindow()
    {
        InitializeComponent();
        // SizeToContent grows the window to fit the text; clamp to the screen so it
        // never overflows on small displays (the ScrollViewer takes over there).
        MaxHeight = SystemParameters.WorkArea.Height - 48;
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
}
