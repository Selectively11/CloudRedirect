using System.Net.Http;
using CloudRedirect.Services.Providers;

namespace CloudRedirect.Services;

/// <summary>
/// Resolves a <see cref="CloudConfig"/> to the matching
/// <see cref="IUiCloudProvider"/> implementation. Returns <c>null</c> for
/// the local-only / unrecognized cases so the caller can short-circuit to
/// "nothing to do" without a switch of its own.
/// </summary>
internal static class UiCloudProviderFactory
{
    public static IUiCloudProvider? TryResolve(CloudConfig? config, HttpClient http, Action<string>? log)
    {
        if (config == null || config.IsLocal) return null;
        return config.Provider switch
        {
            "gdrive"   => new GoogleDriveUiCloudProvider(http, log, config.TokenPath!),
            "onedrive" => new OneDriveUiCloudProvider(http, log, config.TokenPath!),
            "folder"   => new FolderUiCloudProvider(log, config.SyncPath!),
            _          => null,
        };
    }
}
