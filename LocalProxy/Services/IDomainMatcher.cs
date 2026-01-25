namespace LocalProxy.Services;

/// <summary>
/// Interface for domain pattern matching
/// </summary>
public interface IDomainMatcher
{
    /// <summary>
    /// Check if a host matches any pattern (for HTTPS CONNECT requests and HTTP requests)
    /// </summary>
    /// <param name="host">Host to check (e.g., "api.github.com" or "api.github.com:443")</param>
    /// <returns>True if the host matches any pattern</returns>
    public bool Match(string host);
}
