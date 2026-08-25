using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;

namespace CloudRedirect.Services;

// Out-of-process driver for cloud760_tool.exe (32-bit steam_api.dll, can't load in 64-bit UI).
public sealed class Steam760Cloud : IDisposable
{
    public sealed class CloudFile
    {
        public string Name { get; init; } = "";
        public int Size { get; init; }
        public bool Persisted { get; init; }
        public DateTime Timestamp { get; init; }
    }

    private uint _appId;
    private bool _connected;
    private bool _disposed;

    private static string ToolPath()
    {
        string? exe = EmbeddedCloud760.EnsureExtracted();
        if (exe == null || !File.Exists(exe))
            throw new InvalidOperationException(
                "The Steam Cloud manager tool could not be prepared (embedded resource missing).");
        return exe;
    }

    private readonly struct ToolResult
    {
        public ToolResult(int exitCode, List<string> stdout, string stderr)
        {
            ExitCode = exitCode;
            Stdout = stdout;
            Stderr = stderr;
        }
        public int ExitCode { get; }
        public List<string> Stdout { get; }
        public string Stderr { get; }
    }

    // Runs the tool (working dir = tool dir, so steam_api.dll resolves) and
    // captures stdout/stderr.
    private static ToolResult Run(IReadOnlyList<string> args)
    {
        string exe = ToolPath();

        var psi = new ProcessStartInfo
        {
            FileName = exe,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);

        using var proc = new Process { StartInfo = psi };

        var stdout = new List<string>();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.Add(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

        try
        {
            proc.Start();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to launch cloud760_tool.exe: " + ex.Message, ex);
        }

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        if (!proc.WaitForExit(30000))
        {
            try { proc.Kill(true); } catch { }
            throw new InvalidOperationException("cloud760_tool.exe timed out.");
        }
        proc.WaitForExit(); // flush async readers

        return new ToolResult(proc.ExitCode, stdout, stderr.ToString());
    }

    private static InvalidOperationException ToolError(ToolResult r, string fallback)
    {
        string msg = r.Stderr.Trim();
        // Strip Steam's breakpad/minidump stderr chatter (emitted even on success).
        if (!string.IsNullOrEmpty(msg))
        {
            var meaningful = new List<string>();
            foreach (var line in msg.Split('\n'))
            {
                var t = line.Trim();
                if (t.Length == 0) continue;
                if (t.StartsWith("Setting breakpad", StringComparison.OrdinalIgnoreCase)) continue;
                if (t.StartsWith("Steam_SetMinidump", StringComparison.OrdinalIgnoreCase)) continue;
                // The tool prefixes its own messages with "Error:"; strip it so callers
                // that add their own "Error: " prefix don't produce "Error: Error: ...".
                if (t.StartsWith("Error:", StringComparison.OrdinalIgnoreCase))
                    t = t.Substring("Error:".Length).TrimStart();
                if (t.Length == 0) continue;
                meaningful.Add(t);
            }
            if (meaningful.Count > 0)
                return new InvalidOperationException(string.Join(" ", meaningful));
        }
        return new InvalidOperationException(fallback);
    }

    // Validates the tool can reach Steam as appId (via a quota probe). No
    // persistent session; each later call re-inits in a fresh tool process.
    public void Connect(uint appId = 760)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(Steam760Cloud));

        var r = Run(new[] { "quota", appId.ToString(CultureInfo.InvariantCulture), "--porcelain" });
        if (r.ExitCode != 0)
            throw ToolError(r, $"Could not connect to Steam Cloud as AppID {appId}. " +
                               "Make sure Steam is running and you are logged in.");

        _appId = appId;
        _connected = true;
    }

    public (ulong total, ulong used) GetQuota()
    {
        EnsureConnected();
        var r = Run(new[] { "quota", _appId.ToString(CultureInfo.InvariantCulture), "--porcelain" });
        if (r.ExitCode != 0)
            throw ToolError(r, "Failed to read cloud quota.");

        ulong total = 0, used = 0;
        foreach (var line in r.Stdout)
        {
            var f = line.Split('\t');
            if (f.Length >= 3 && f[0] == "QUOTA")
            {
                ulong.TryParse(f[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out total);
                ulong.TryParse(f[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out used);
            }
        }
        return (total, used);
    }

    public List<CloudFile> ListFiles()
    {
        EnsureConnected();
        var r = Run(new[] { "list", _appId.ToString(CultureInfo.InvariantCulture), "--porcelain" });
        if (r.ExitCode != 0)
            throw ToolError(r, "Failed to list cloud files.");

        var files = new List<CloudFile>();
        foreach (var line in r.Stdout)
        {
            var f = line.Split('\t');
            if (f.Length >= 4 && f[0] == "FILE")
            {
                int.TryParse(f[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out int size);
                files.Add(new CloudFile
                {
                    Name = f[1],
                    Size = size,
                    Persisted = f[3] == "1",
                });
            }
        }
        return files;
    }

    /// <summary>Deletes a single cloud file (and forgets it so it won't re-sync).</summary>
    public bool DeleteFile(string name)
    {
        EnsureConnected();
        if (string.IsNullOrEmpty(name)) return false;

        var r = Run(new[] { "delete", _appId.ToString(CultureInfo.InvariantCulture), name, "--porcelain" });
        // The tool returns non-zero only on a delete failure; parse the DEL line.
        foreach (var line in r.Stdout)
        {
            var f = line.Split('\t');
            if (f.Length >= 3 && f[0] == "DEL" && f[1] == name)
                return f[2] == "OK";
        }
        return r.ExitCode == 0;
    }

    private void EnsureConnected()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(Steam760Cloud));
        if (!_connected) throw new InvalidOperationException("Not connected. Call Connect() first.");
    }

    public void Dispose()
    {
        // Nothing to tear down: each operation is a self-contained child process.
        _disposed = true;
        _connected = false;
    }
}
