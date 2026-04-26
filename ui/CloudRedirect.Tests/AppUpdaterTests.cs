using CloudRedirect.Services;
using Xunit;

namespace CloudRedirect.Tests;

public class AppUpdaterTests
{
    [Theory]
    [InlineData("v1.5.0-test")]
    [InlineData("v1.5.0-pre")]
    [InlineData("v1.5.0-rc")]
    [InlineData("v1.5.0-rc1")]
    [InlineData("v1.5.0-beta")]
    [InlineData("v1.5.0-alpha")]
    [InlineData("v1.5.0-TEST")]
    [InlineData("v1.5.0-Beta")]
    [InlineData("1.0.5-test")]
    public void IsPrereleaseTag_RecognisedSuffixes_True(string tag)
    {
        Assert.True(AppUpdater.IsPrereleaseTag(tag));
    }

    [Theory]
    [InlineData("v1.5.0")]
    [InlineData("v1.0.5")]
    [InlineData("1.5.0")]
    [InlineData("v2.0.0.0")]
    public void IsPrereleaseTag_PlainVersion_False(string tag)
    {
        Assert.False(AppUpdater.IsPrereleaseTag(tag));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void IsPrereleaseTag_NullOrEmpty_False(string? tag)
    {
        Assert.False(AppUpdater.IsPrereleaseTag(tag));
    }

    [Theory]
    [InlineData("v1.5.0-dev")]
    [InlineData("v1.5.0-stable")]
    [InlineData("v1.5.0+build")]
    public void IsPrereleaseTag_UnknownSuffix_False(string tag)
    {
        Assert.False(AppUpdater.IsPrereleaseTag(tag));
    }
}
