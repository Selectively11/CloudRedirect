namespace CloudRedirect.Services;

/// <summary>
/// Per-provider implementation of the UI's cloud operations. Constructed by
/// <see cref="UiCloudProviderFactory"/>; <see cref="CloudProviderClient"/>
/// dispatches here. Result types are nested on the client so existing
/// callers don't need to change references.
/// </summary>
internal interface IUiCloudProvider
{
    /// <summary>
    /// Recursively delete CloudRedirect/{accountId}/{appId}/ on the provider.
    /// </summary>
    Task<CloudProviderClient.DeleteResult> DeleteAppDataAsync(
        string accountId, string appId, CancellationToken cancel);

    /// <summary>
    /// Enumerate file children of CloudRedirect/{accountId}/{appId}/blobs/.
    /// Must set Complete=false on any pagination, auth, or transport failure
    /// (see <see cref="CloudProviderClient.ListBlobsResult"/>).
    /// </summary>
    Task<CloudProviderClient.ListBlobsResult> ListAppBlobsAsync(
        string accountId, string appId, CancellationToken cancel);

    /// <summary>
    /// Delete the named blobs. The facade has already filtered unsafe names
    /// (path separators, traversal, reserved DOS names, trailing dot/space).
    /// </summary>
    Task<CloudProviderClient.DeleteBlobsResult> DeleteAppBlobsAsync(
        string accountId, string appId,
        IReadOnlyCollection<string> blobFilenames, CancellationToken cancel);
}
