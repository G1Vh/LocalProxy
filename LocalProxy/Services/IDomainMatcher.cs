namespace LocalProxy.Services;

/// <summary>
/// Interface for domain pattern matching
/// </summary>
public interface IDomainMatcher
{
    /// <summary>
    /// Check if a host matches any pattern (for HTTPS CONNECT requests)
    /// </summary>
    /// <param name="host">Host to check (e.g., "api.github.com" or "api.github.com:443")</param>
    /// <returns>True if the host matches any pattern</returns>
    bool Match(string host);

    /// <summary>
    /// Check if a host and path match any pattern (for HTTP requests)
    /// </summary>
    /// <param name="host">Host to check</param>
    /// <param name="path">Path to check (e.g., "/copilot_internal/v1/chat")</param>
    /// <returns>True if the host and path match any pattern</returns>
    bool MatchUrl(string host, string path);
}
