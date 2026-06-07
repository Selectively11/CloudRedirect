using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace CloudRedirect.Services.Providers;

/// <summary>
/// IUiCloudProvider implementation that delegates to cloud_redirect_cli.exe.
/// This consolidates provider logic in the native DLL rather than reimplementing
/// in C#. Used for gdrive and onedrive providers.
/// </summary>
internal sealed class CliUiCloudProvider : IUiCloudProvider
{
    private readonly string _provider; // "gdrive" or "onedrive"
    private readonly Action<string>? _log;

    public CliUiCloudProvider(string provider, Action<string>? log)
    {
        _provider = provider;
        _log = log;
    }

    public async Task<CloudProviderClient.DeleteResult> DeleteAppDataAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var result = await RunCliAsync($"delete-remote-app {_provider} {accountId} {appId}", cancel);
        
        if (result.ExitCode != 0)
        {
            var error = TryGetError(result.Output) ?? $"CLI exited with code {result.ExitCode}";
            return new CloudProviderClient.DeleteResult(false, 0, error);
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            var root = doc.RootElement;
            
            bool success = root.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            int deleted = root.TryGetProperty("deleted", out var deletedProp) ? deletedProp.GetInt32() : 0;
            string? error = root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : null;
            
            return new CloudProviderClient.DeleteResult(success, deleted, error);
        }
        catch (JsonException ex)
        {
            return new CloudProviderClient.DeleteResult(false, 0, $"Invalid CLI response: {ex.Message}");
        }
    }

    public async Task<CloudProviderClient.ListBlobsResult> ListAppBlobsAsync(
        string accountId, string appId, CancellationToken cancel)
    {
        var result = await RunCliAsync($"list-blobs {_provider} {accountId} {appId}", cancel);
        
        if (result.ExitCode != 0)
        {
            var error = TryGetError(result.Output) ?? $"CLI exited with code {result.ExitCode}";
            return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), false, error);
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            var root = doc.RootElement;
            
            bool complete = root.TryGetProperty("complete", out var completeProp) && completeProp.GetBoolean();
            string? error = root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : null;
            
            var blobs = new List<string>();
            if (root.TryGetProperty("blobs", out var blobsArray) && blobsArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in blobsArray.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        blobs.Add(item.GetString()!);
                    }
                }
            }
            
            return new CloudProviderClient.ListBlobsResult(blobs, complete, error);
        }
        catch (JsonException ex)
        {
            return new CloudProviderClient.ListBlobsResult(Array.Empty<string>(), false, $"Invalid CLI response: {ex.Message}");
        }
    }

    public async Task<CloudProviderClient.DownloadBlobResult> DownloadAppBlobAsync(
        string accountId, string appId, string filename, CancellationToken cancel)
    {
        var arg = filename.Contains(' ') ? $"\"{filename}\"" : filename;
        var result = await RunCliAsync($"download-blob {_provider} {accountId} {appId} {arg}", cancel);

        if (result.ExitCode != 0)
        {
            var error = TryGetError(result.Output) ?? $"CLI exited with code {result.ExitCode}";
            return new CloudProviderClient.DownloadBlobResult(false, null, error);
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            var root = doc.RootElement;

            bool found = root.TryGetProperty("found", out var foundProp) && foundProp.GetBoolean();
            string? error = root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : null;
            string? content = root.TryGetProperty("content", out var contentProp) ? contentProp.GetString() : null;

            return new CloudProviderClient.DownloadBlobResult(found, content, error);
        }
        catch (JsonException ex)
        {
            return new CloudProviderClient.DownloadBlobResult(false, null, $"Invalid CLI response: {ex.Message}");
        }
    }

    public async Task<CloudProviderClient.ListAllStatsResult> ListAllStatsAsync(CancellationToken cancel)
    {
        var result = await RunCliAsync($"list-all-stats {_provider}", cancel);
        if (result.ExitCode != 0)
        {
            var error = TryGetError(result.Output) ?? $"CLI exited with code {result.ExitCode}";
            return new CloudProviderClient.ListAllStatsResult(
                Array.Empty<CloudProviderClient.CloudStatsEntry>(), error);
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            var root = doc.RootElement;
            string? error = root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : null;

            var entries = new List<CloudProviderClient.CloudStatsEntry>();
            if (root.TryGetProperty("apps", out var appsArr) && appsArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in appsArr.EnumerateArray())
                {
                    var acct = item.TryGetProperty("account_id", out var a) ? a.GetString() : null;
                    var app = item.TryGetProperty("app_id", out var p) ? p.GetString() : null;
                    var content = item.TryGetProperty("content", out var c) ? c.GetString() : null;
                    if (!string.IsNullOrEmpty(acct) && !string.IsNullOrEmpty(app) && !string.IsNullOrEmpty(content))
                        entries.Add(new CloudProviderClient.CloudStatsEntry(acct!, app!, content!));
                }
            }
            return new CloudProviderClient.ListAllStatsResult(entries, error);
        }
        catch (JsonException ex)
        {
            return new CloudProviderClient.ListAllStatsResult(
                Array.Empty<CloudProviderClient.CloudStatsEntry>(), $"Invalid CLI response: {ex.Message}");
        }
    }

    public async Task<CloudProviderClient.DeleteBlobsResult> DeleteAppBlobsAsync(
        string accountId, string appId,
        IReadOnlyCollection<string> blobFilenames, CancellationToken cancel)
    {
        if (blobFilenames.Count == 0)
        {
            return new CloudProviderClient.DeleteBlobsResult(0, 0, Array.Empty<string>(), null);
        }
        
        // Build arguments: delete-blobs <provider> <accountId> <appId> <blob1> <blob2> ...
        var args = $"delete-blobs {_provider} {accountId} {appId}";
        foreach (var blob in blobFilenames)
        {
            // Quote blob names that contain spaces
            if (blob.Contains(' '))
                args += $" \"{blob}\"";
            else
                args += $" {blob}";
        }
        
        var result = await RunCliAsync(args, cancel);
        
        if (result.ExitCode != 0)
        {
            var error = TryGetError(result.Output) ?? $"CLI exited with code {result.ExitCode}";
            return new CloudProviderClient.DeleteBlobsResult(0, blobFilenames.Count, blobFilenames.ToList(), error);
        }

        try
        {
            using var doc = JsonDocument.Parse(result.Output);
            var root = doc.RootElement;
            
            int deleted = root.TryGetProperty("deleted", out var deletedProp) ? deletedProp.GetInt32() : 0;
            int failed = root.TryGetProperty("failed", out var failedProp) ? failedProp.GetInt32() : 0;
            string? error = root.TryGetProperty("error", out var errorProp) ? errorProp.GetString() : null;
            
            var failedNames = new List<string>();
            if (root.TryGetProperty("failed_names", out var failedArray) && failedArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in failedArray.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        failedNames.Add(item.GetString()!);
                    }
                }
            }
            
            return new CloudProviderClient.DeleteBlobsResult(deleted, failed, failedNames, error);
        }
        catch (JsonException ex)
        {
            return new CloudProviderClient.DeleteBlobsResult(0, blobFilenames.Count, blobFilenames.ToList(), $"Invalid CLI response: {ex.Message}");
        }
    }

    private async Task<(int ExitCode, string Output)> RunCliAsync(string arguments, CancellationToken cancel)
    {
        string? cliPath = EmbeddedCli.EnsureExtracted();

        if (string.IsNullOrEmpty(cliPath) || !File.Exists(cliPath))
        {
            _log?.Invoke("[CliProvider] Embedded CLI not available");
            return (-1, "{\"error\":\"Embedded CLI executable not available\"}");
        }

        _log?.Invoke($"[CliProvider] Running: {cliPath} {arguments}");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = cliPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            }
        };

        try
        {
            process.Start();
            
            // Read output asynchronously
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            
            // Wait for process with cancellation
            await process.WaitForExitAsync(cancel);
            
            string output = await outputTask;
            string error = await errorTask;
            
            if (!string.IsNullOrEmpty(error))
            {
                _log?.Invoke($"[CliProvider] stderr: {error}");
            }
            
            _log?.Invoke($"[CliProvider] Exit code: {process.ExitCode}, Output: {output.Trim()}");
            
            return (process.ExitCode, output);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(); } catch { }
            throw;
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[CliProvider] Process error: {ex.Message}");
            return (-1, $"{{\"error\":\"{ex.Message}\"}}");
        }
    }

    private static string? TryGetError(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("error", out var errorProp))
            {
                return errorProp.GetString();
            }
        }
        catch { }
        return null;
    }
}
