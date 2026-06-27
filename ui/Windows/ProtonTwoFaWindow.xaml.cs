using System.Windows;
using System.Windows.Input;
using Wpf.Ui.Controls;

namespace CloudRedirect.Windows;

public partial class ProtonTwoFaWindow : FluentWindow
{
    public string TotpCode { get; private set; } = "";

    public ProtonTwoFaWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => CodeBox.Focus();
    }

    private void Submit_Click(object sender, RoutedEventArgs e) => TryAccept();

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void Input_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) TryAccept();
        else if (e.Key == Key.Escape) { DialogResult = false; Close(); }
    }

    private void TryAccept()
    {
        var code = CodeBox.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(code))
            return;

        TotpCode = code;
        DialogResult = true;
        Close();
    }
}
