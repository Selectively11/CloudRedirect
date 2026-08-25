using System.Diagnostics;

namespace CloudRedirect.Services;

// Opens Steam's in-client developer console (for the cloud_sync_up command).
public static class SteamConsole
{
    public static void OpenConsole()
    {
        try
        {
            Process.Start(new ProcessStartInfo("steam://open/console") { UseShellExecute = true });
        }
        catch
        {
            // best-effort
        }
    }
}
