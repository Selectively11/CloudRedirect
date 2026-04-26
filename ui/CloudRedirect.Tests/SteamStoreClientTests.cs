using System;
using System.IO;
using CloudRedirect.Services;
using Xunit;

namespace CloudRedirect.Tests;

/// <summary>
/// Tests for SteamStoreClient: URL validation and singleton behavior.
/// Network-dependent API tests are not included (would require mocking HttpClient).
/// </summary>
public class SteamStoreClientTests
{
    // ── IsValidSteamCdnUrl ─────────────────────────────────────────────

    [Fact]
    public void IsValidSteamCdnUrl_NullReturnsFalse()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl(null));
    }

    [Fact]
    public void IsValidSteamCdnUrl_EmptyReturnsFalse()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl(""));
    }

    [Fact]
    public void IsValidSteamCdnUrl_ValidSteamstaticUrl()
    {
        Assert.True(SteamStoreClient.IsValidSteamCdnUrl(
            "https://shared.steamstatic.com/store_item_assets/steam/apps/1221480/header.jpg"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_ValidSteampoweredUrl()
    {
        Assert.True(SteamStoreClient.IsValidSteamCdnUrl(
            "https://cdn.steampowered.com/apps/1221480/header.jpg"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_ValidAkamaiUrl()
    {
        Assert.True(SteamStoreClient.IsValidSteamCdnUrl(
            "https://cdn.steamcdn-a.akamaihd.net/steam/apps/1221480/header.jpg"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_HttpRejected()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl(
            "http://shared.steamstatic.com/store_item_assets/steam/apps/1221480/header.jpg"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_NonSteamDomainRejected()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl(
            "https://evil.example.com/header.jpg"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_MalformedUrlRejected()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl("not-a-url"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_FileSchemeRejected()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl("file:///C:/Windows/System32/calc.exe"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_SpoofedSubdomainRejected()
    {
        // "steamstatic.com.evil.com" should not match ".steamstatic.com"
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl(
            "https://steamstatic.com.evil.com/header.jpg"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_JavascriptSchemeRejected()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl("javascript:alert(1)"));
    }

    [Fact]
    public void IsValidSteamCdnUrl_DataSchemeRejected()
    {
        Assert.False(SteamStoreClient.IsValidSteamCdnUrl("data:text/html,<script>alert(1)</script>"));
    }

    // ── IsValidCachedImagePath ─────────────────────────────────────────
    //
    // The cached-image validator must accept file:// URIs that resolve under
    // %APPDATA%/CloudRedirect/store_images and reject everything else --
    // including path-traversal attempts that would escape the cache dir.

    private static string ImageCacheRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "CloudRedirect", "store_images");

    [Fact]
    public void IsValidCachedImagePath_NullReturnsFalse()
    {
        Assert.False(SteamStoreClient.IsValidCachedImagePath(null));
    }

    [Fact]
    public void IsValidCachedImagePath_EmptyReturnsFalse()
    {
        Assert.False(SteamStoreClient.IsValidCachedImagePath(""));
    }

    [Fact]
    public void IsValidCachedImagePath_ValidFileUnderCacheDir()
    {
        var path = Path.Combine(ImageCacheRoot, "abcdef0123456789.jpg");
        Assert.True(SteamStoreClient.IsValidCachedImagePath(new Uri(path).AbsoluteUri));
    }

    [Fact]
    public void IsValidCachedImagePath_HttpsSchemeRejected()
    {
        Assert.False(SteamStoreClient.IsValidCachedImagePath(
            "https://shared.steamstatic.com/store_item_assets/steam/apps/1/header.jpg"));
    }

    [Fact]
    public void IsValidCachedImagePath_FileOutsideCacheRejected()
    {
        Assert.False(SteamStoreClient.IsValidCachedImagePath(
            new Uri(@"C:\Windows\System32\calc.exe").AbsoluteUri));
    }

    [Fact]
    public void IsValidCachedImagePath_TraversalAttemptRejected()
    {
        // file:///.../store_images/../secret -> normalizes outside the cache root
        var escape = Path.Combine(ImageCacheRoot, "..", "secret.jpg");
        Assert.False(SteamStoreClient.IsValidCachedImagePath(new Uri(escape).AbsoluteUri));
    }

    [Fact]
    public void IsValidCachedImagePath_SiblingPrefixRejected()
    {
        // A directory whose name starts with "store_images" but isn't the cache
        // root itself must not match (guards against the separator check being
        // omitted, e.g. matching "store_images_evil").
        var sibling = Path.GetDirectoryName(ImageCacheRoot)!;
        var spoof = Path.Combine(sibling, "store_images_evil", "x.jpg");
        Assert.False(SteamStoreClient.IsValidCachedImagePath(new Uri(spoof).AbsoluteUri));
    }

    [Fact]
    public void IsValidCachedImagePath_MalformedUriRejected()
    {
        Assert.False(SteamStoreClient.IsValidCachedImagePath("not-a-url"));
    }

    // ── IsValidImageUrl ────────────────────────────────────────────────

    [Fact]
    public void IsValidImageUrl_AcceptsSteamCdn()
    {
        Assert.True(SteamStoreClient.IsValidImageUrl(
            "https://shared.steamstatic.com/store_item_assets/steam/apps/1/header.jpg"));
    }

    [Fact]
    public void IsValidImageUrl_AcceptsCachedFile()
    {
        var path = Path.Combine(ImageCacheRoot, "abcdef0123456789.jpg");
        Assert.True(SteamStoreClient.IsValidImageUrl(new Uri(path).AbsoluteUri));
    }

    [Fact]
    public void IsValidImageUrl_RejectsArbitraryFile()
    {
        Assert.False(SteamStoreClient.IsValidImageUrl(
            new Uri(@"C:\Windows\System32\calc.exe").AbsoluteUri));
    }

    [Fact]
    public void IsValidImageUrl_RejectsArbitraryHttps()
    {
        Assert.False(SteamStoreClient.IsValidImageUrl("https://evil.example.com/x.jpg"));
    }

    // ── Singleton behavior ─────────────────────────────────────────────

    [Fact]
    public void SharedInstance_ReturnsSameInstance()
    {
        var a = SteamStoreClient.Shared;
        var b = SteamStoreClient.Shared;
        Assert.Same(a, b);
    }
}
