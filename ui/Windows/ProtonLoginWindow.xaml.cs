using System.Windows;
using System.Windows.Input;
using Wpf.Ui.Controls;

namespace CloudRedirect.Windows;

public partial class ProtonLoginWindow : FluentWindow
{
    public string Email { get; private set; } = "";
    public string Password { get; private set; } = "";

    public ProtonLoginWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => EmailBox.Focus();
    }

    private void SignIn_Click(object sender, RoutedEventArgs e) => TryAccept();

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
        var email = EmailBox.Text?.Trim() ?? "";
        var pass  = PasswordBox.Password;

        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(pass))
            return;

        Email    = email;
        Password = pass;
        DialogResult = true;
        Close();
    }
}
