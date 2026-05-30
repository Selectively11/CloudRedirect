using System;
using System.IO;
using System.Reflection;
using CloudRedirect.Services;
using CloudRedirect.Services.Patching;

namespace CloudRedirect;

class Program
{
    static int Main(string[] args)
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        var versionStr = version != null ? $"{version.Major}.{version.Minor}.{version.Build}-CLI" : "?";

        if (args.Length == 0)
        {
            PrintHelp(versionStr);
            return 0;
        }

        var command = args[0].ToLowerInvariant().TrimStart('/').TrimStart('-');

        return command switch
        {
            "stfixer" => RunStFixer(),
            "help" or "?" => PrintHelpAndReturn(versionStr),
            _ => UnknownCommand(args[0], versionStr),
        };
    }

    static void PrintHelp(string version)
    {
        Console.WriteLine($"CloudRedirect v{version}");
        Console.WriteLine();
        Console.WriteLine("Usage: CloudRedirect.exe <command>");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  /stfixer    Apply STFixer patches (fixes Capcom saves, manifest downloads)");
        Console.WriteLine("  /help       Show this help message");
    }

    static int PrintHelpAndReturn(string version)
    {
        PrintHelp(version);
        return 0;
    }

    static int UnknownCommand(string cmd, string version)
    {
        Console.Error.WriteLine($"Unknown command: {cmd}");
        Console.Error.WriteLine();
        PrintHelp(version);
        return 1;
    }

    static int RunStFixer()
    {
        Console.WriteLine("=== CloudRedirect STFixer ===");
        Console.WriteLine();

        // Find Steam
        var steamPath = SteamDetector.FindSteamPath();
        if (steamPath == null)
        {
            Console.Error.WriteLine("ERROR: Steam installation not found.");
            Console.Error.WriteLine("Checked registry and common install paths.");
            return 1;
        }
        Console.WriteLine($"Steam: {steamPath}");

        // Check version
        var version = SteamDetector.GetSteamVersion(steamPath);
        if (version == null)
        {
            Console.Error.WriteLine("ERROR: Could not read Steam version.");
            return 1;
        }
        if (!SteamDetector.IsSupportedSteamVersion(version.Value))
        {
            Console.Error.WriteLine($"ERROR: Steam version {version.Value} is not supported.");
            Console.Error.WriteLine($"Supported: {string.Join(", ", SteamDetector.SupportedSteamVersions)}");
            return 1;
        }
        Console.WriteLine($"Steam version: {version.Value} (OK)");

        // Close Steam if running
        if (SteamDetector.IsSteamRunning())
        {
            Console.WriteLine("Steam is running -- shutting it down...");
            var steamExe = Path.Combine(steamPath, "steam.exe");
            if (File.Exists(steamExe))
            {
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = steamExe,
                        Arguments = "-shutdown",
                        UseShellExecute = true
                    })?.Dispose();
                }
                catch { }
            }

            for (int i = 0; i < 30; i++)
            {
                System.Threading.Thread.Sleep(500);
                if (!SteamDetector.IsSteamRunning()) break;
            }

            if (SteamDetector.IsSteamRunning())
            {
                Console.WriteLine("Graceful shutdown timed out, killing Steam...");
                foreach (var p in System.Diagnostics.Process.GetProcessesByName("steam"))
                {
                    try { p.Kill(); } catch { }
                    finally { p.Dispose(); }
                }
                System.Threading.Thread.Sleep(1000);
            }

            Console.WriteLine("Steam closed.");
        }

        var patcher = new Patcher(steamPath, msg => Console.WriteLine(msg));

        // Download core DLLs if missing
        if (!patcher.HasCoreDll())
        {
            Console.WriteLine();
            Console.WriteLine("Downloading SteamTools core DLLs...");
            var repairResult = patcher.RepairCoreDlls();
            if (repairResult?.Succeeded != true)
            {
                Console.Error.WriteLine($"FAILED: {repairResult?.Error ?? "Could not download core DLLs"}");
                return 1;
            }
            Console.WriteLine("OK");
        }

        // Apply STFixer patches
        Console.WriteLine();
        Console.WriteLine("Applying STFixer patches...");
        var result = patcher.ApplyOfflineSetup();
        if (!result.Succeeded)
        {
            Console.Error.WriteLine($"FAILED: {result.Error}");
            return 1;
        }
        Console.WriteLine("OK");

        // Deploy DLL
        Console.WriteLine();
        Console.WriteLine("Deploying cloud_redirect.dll...");
        if (!EmbeddedDll.IsAvailable())
        {
            Console.Error.WriteLine("ERROR: cloud_redirect.dll is not embedded in this build.");
            return 1;
        }

        var dllDest = Path.Combine(steamPath, "cloud_redirect.dll");
        var deployErr = EmbeddedDll.DeployTo(dllDest);
        if (deployErr != null)
        {
            Console.Error.WriteLine($"FAILED: {deployErr}");
            return 1;
        }
        Console.WriteLine($"Deployed to {dllDest}");

        // Enable auto-update in config.json so the DLL stays current
        var configDir = Path.Combine(steamPath, "cloud_redirect");
        var configPath = Path.Combine(configDir, "config.json");
        try
        {
            Directory.CreateDirectory(configDir);
            string json;
            if (File.Exists(configPath))
            {
                json = File.ReadAllText(configPath);
                if (!json.Contains("auto_update_dll"))
                    json = json.TrimEnd().TrimEnd('}') + ",\n  \"auto_update_dll\": true\n}";
            }
            else
            {
                json = "{\n  \"auto_update_dll\": true\n}";
            }
            File.WriteAllText(configPath, json);
            Console.WriteLine("DLL auto-update enabled.");
        }
        catch { }

        Console.WriteLine();
        Console.WriteLine("All patches applied. Start Steam to use STFixer.");
        return 0;
    }
}
