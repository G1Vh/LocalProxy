using LocalProxy.Models;
using LocalProxy.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LocalProxy.Tests;

public class DomainMatcherTests
{
    private readonly Mock<ILogger<DomainMatcher>> _loggerMock;

    public DomainMatcherTests()
    {
        _loggerMock = new Mock<ILogger<DomainMatcher>>();
    }

    private DomainMatcher CreateMatcher(List<string> domains)
    {
        var settings = new ProxySettings { Domains = domains };
        var optionsMonitor = Mock.Of<IOptionsMonitor<ProxySettings>>(m => m.CurrentValue == settings);
        return new DomainMatcher(optionsMonitor, _loggerMock.Object);
    }

    [Theory]
    [InlineData("github.com", true)]
    [InlineData("api.github.com", false)]
    [InlineData("github.com:443", true)]
    [InlineData("github.com:80", true)]
    [InlineData("example.com", false)]
    public void Match_ExactDomain_ReturnsExpectedResult(string host, bool expected)
    {
        // Arrange
        var matcher = CreateMatcher(["github.com"]);

        // Act
        var result = matcher.Match(host);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("api.githubcopilot.com", true)]
    [InlineData("dashboard.business.githubcopilot.com", true)]  // matches *.githubcopilot.com (any subdomain)
    [InlineData("githubcopilot.com", false)]  // wildcard doesn't match root
    [InlineData("business.githubcopilot.com", true)]
    [InlineData("individual.githubcopilot.com", true)]
    public void Match_WildcardSubdomain_ReturnsExpectedResult(string host, bool expected)
    {
        // Arrange
        var matcher = CreateMatcher(["*.githubcopilot.com"]);

        // Act
        var result = matcher.Match(host);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData("dashboard.business.githubcopilot.com", true)]
    [InlineData("api.business.githubcopilot.com", true)]
    [InlineData("business.githubcopilot.com", false)]  // wildcard doesn't match the domain itself
    [InlineData("githubcopilot.com", false)]
    [InlineData("api.githubcopilot.com", false)]
    public void Match_NestedWildcard_ReturnsExpectedResult(string host, bool expected)
    {
        // Arrange
        var matcher = CreateMatcher(["*.business.githubcopilot.com"]);

        // Act
        var result = matcher.Match(host);

        // Assert
        Assert.Equal(expected, result);
    }

    [Fact]
    public void Match_WithPort_StripsPortCorrectly()
    {
        // Arrange
        var matcher = CreateMatcher(["github.com"]);

        // Act & Assert
        Assert.True(matcher.Match("github.com:443"));
        Assert.True(matcher.Match("github.com:8080"));
        Assert.False(matcher.Match("api.github.com:443"));
    }

    [Fact]
    public void Match_PatternWithPath_IgnoresPath()
    {
        // Arrange - patterns with paths should have the path stripped
        var matcher = CreateMatcher(["github.com/login/*", "api.github.com/user"]);

        // Act & Assert - only domain is matched, path is ignored
        Assert.True(matcher.Match("github.com"));
        Assert.True(matcher.Match("api.github.com"));
        Assert.False(matcher.Match("example.com"));
    }

    [Fact]
    public void Match_EmptyHost_ReturnsFalse()
    {
        // Arrange
        var matcher = CreateMatcher(["github.com"]);

        // Act & Assert
        Assert.False(matcher.Match(""));
        Assert.False(matcher.Match(null!));
    }

    [Fact]
    public void Match_EmptyDomainsList_ReturnsFalse()
    {
        // Arrange
        var matcher = CreateMatcher([]);

        // Act
        var result = matcher.Match("github.com");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Match_CaseInsensitive_ReturnsTrue()
    {
        // Arrange
        var matcher = CreateMatcher(["GitHub.com"]);

        // Act & Assert
        Assert.True(matcher.Match("github.com"));
        Assert.True(matcher.Match("GITHUB.COM"));
        Assert.True(matcher.Match("GiTHuB.CoM"));
    }

    [Fact]
    public void Match_MultiplePatterns_MatchesAny()
    {
        // Arrange
        var matcher = CreateMatcher([
            "github.com",
            "api.github.com",
            "*.githubcopilot.com"
        ]);

        // Act & Assert
        Assert.True(matcher.Match("github.com"));
        Assert.True(matcher.Match("api.github.com"));
        Assert.True(matcher.Match("api.githubcopilot.com"));
        Assert.False(matcher.Match("example.com"));
    }

    [Fact]
    public void HotReload_UpdatesPatterns()

    {
        // Arrange
        var settings = new ProxySettings { Domains = ["github.com"] };
        var optionsMonitorMock = new Mock<IOptionsMonitor<ProxySettings>>();
        optionsMonitorMock.Setup(m => m.CurrentValue).Returns(settings);

        Action<ProxySettings, string?>? changeCallback = null;
        optionsMonitorMock
            .Setup(m => m.OnChange(It.IsAny<Action<ProxySettings, string?>>()))
            .Callback<Action<ProxySettings, string?>>(callback => changeCallback = callback)
            .Returns(Mock.Of<IDisposable>());

        var matcher = new DomainMatcher(optionsMonitorMock.Object, _loggerMock.Object);

        // Initial state
        Assert.True(matcher.Match("github.com"));
        Assert.False(matcher.Match("api.github.com"));

        // Act - simulate configuration change
        var newSettings = new ProxySettings { Domains = ["api.github.com"] };
        optionsMonitorMock.Setup(m => m.CurrentValue).Returns(newSettings);
        changeCallback?.Invoke(newSettings, null);

        // Assert - patterns should be reloaded
        Assert.False(matcher.Match("github.com"));
        Assert.True(matcher.Match("api.github.com"));
    }

    [Theory]
    [InlineData("*.com")]  // Too broad but valid
    [InlineData("*.")]      // Edge case
    public void Match_EdgeCasePatterns_HandlesGracefully(string pattern)
    {
        // Arrange
        var matcher = CreateMatcher([pattern]);

        // Act & Assert - shouldn't throw
        var result = matcher.Match("github.com");
        Assert.IsType<bool>(result);
    }
}
