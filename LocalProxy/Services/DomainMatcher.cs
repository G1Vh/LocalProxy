using LocalProxy.Models;
using Microsoft.Extensions.Options;

namespace LocalProxy.Services;

/// <summary>
/// Domain pattern matcher with hot-reload support.
/// Supports patterns: exact domain (example.com), wildcard subdomain (*.example.com)
/// </summary>
public class DomainMatcher : IDomainMatcher
{
    private readonly ILogger<DomainMatcher> _logger;
    private List<DomainPattern> _patterns = [];
    private readonly Lock _lock = new();

    public DomainMatcher(IOptionsMonitor<ProxySettings> optionsMonitor, ILogger<DomainMatcher> logger)
    {
        _logger = logger;

        // Initial load
        ReloadPatterns(optionsMonitor.CurrentValue.Domains);

        // Subscribe to configuration changes for hot-reload
        optionsMonitor.OnChange(settings =>
        {
            _logger.LogInformation("Configuration changed, reloading domain patterns...");
            ReloadPatterns(settings.Domains);
        });
    }

    private void ReloadPatterns(List<string> domains)
    {
        var newPatterns = new List<DomainPattern>();

        foreach (var pattern in domains)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                continue;

            var parsed = ParsePattern(pattern.Trim());
            if (parsed != null)
            {
                newPatterns.Add(parsed);
            }
        }

        lock (_lock)
        {
            _patterns = newPatterns;
        }

        _logger.LogInformation("Loaded {Count} domain patterns", newPatterns.Count);
    }

    private static DomainPattern? ParsePattern(string pattern)
    {
        // Strip path if present (paths are not supported, only domains)
        var slashIndex = pattern.IndexOf('/');
        if (slashIndex > 0)
        {
            pattern = pattern[..slashIndex];
        }

        // Check for wildcard subdomain
        bool isWildcardSubdomain = pattern.StartsWith("*.");
        if (isWildcardSubdomain)
        {
            pattern = pattern[1..]; // Remove *, keep the dot: ".example.com"
        }

        return new DomainPattern
        {
            OriginalPattern = pattern,
            Domain = pattern.ToLowerInvariant(),
            IsWildcardSubdomain = isWildcardSubdomain
        };
    }

    /// <inheritdoc />
    public bool Match(string host)
    {
        if (string.IsNullOrEmpty(host))
            return false;

        // Remove port if present (e.g., "github.com:443" -> "github.com")
        var colonIndex = host.LastIndexOf(':');
        if (colonIndex > 0)
        {
            host = host[..colonIndex];
        }

        host = host.ToLowerInvariant();

        List<DomainPattern> patterns;
        lock (_lock)
        {
            patterns = _patterns;
        }

        foreach (var pattern in patterns)
        {
            if (MatchDomain(host, pattern))
            {
                return true;
            }
        }

        return false;
    }

    /// <inheritdoc />
    public bool MatchUrl(string host, string path)
    {
        // Simplified: paths are not supported, just match domain
        return Match(host);
    }

    private static bool MatchDomain(string host, DomainPattern pattern)
    {
        if (pattern.IsWildcardSubdomain)
        {
            // Pattern ".example.com" matches "api.example.com" but not "example.com"
            return host.EndsWith(pattern.Domain, StringComparison.OrdinalIgnoreCase) &&
                   host.Length > pattern.Domain.Length;
        }
        else
        {
            // Exact domain match
            return host.Equals(pattern.Domain, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Parsed domain pattern
    /// </summary>
    private class DomainPattern
    {
        public required string OriginalPattern { get; init; }
        public required string Domain { get; init; }
        public bool IsWildcardSubdomain { get; init; }
    }
}
