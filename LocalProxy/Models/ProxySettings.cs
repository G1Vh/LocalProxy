namespace LocalProxy.Models;

/// <summary>
/// Root configuration settings for the proxy server
/// </summary>
public class ProxySettings
{
    /// <summary>
    /// Local proxy port (default: 3128)
    /// </summary>
    public int Port { get; set; } = 3128;

    /// <summary>
    /// Upstream proxy configuration
    /// </summary>
    public UpstreamProxySettings UpstreamProxy { get; set; } = new();

    /// <summary>
    /// Timeout settings
    /// </summary>
    public TimeoutSettings Timeouts { get; set; } = new();

    /// <summary>
    /// List of domain patterns to route through upstream proxy
    /// </summary>
    public List<string> Domains { get; set; } = new();
}

/// <summary>
/// Upstream proxy server settings
/// </summary>
public class UpstreamProxySettings
{
    /// <summary>
    /// Enable routing matched domains through upstream proxy
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Upstream proxy hostname or IP
    /// </summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>
    /// Upstream proxy port
    /// </summary>
    public int Port { get; set; } = 8080;

    /// <summary>
    /// Username for proxy authentication (optional)
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// Password for proxy authentication (optional)
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// Returns the proxy address in host:port format
    /// </summary>
    public string GetProxyAddress() => $"{Host}:{Port}";

    /// <summary>
    /// Returns the full proxy URL with optional authentication
    /// </summary>
    public string GetProxyUrl()
    {
        if (!string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password))
        {
            return $"http://{Uri.EscapeDataString(Username)}:{Uri.EscapeDataString(Password)}@{Host}:{Port}";
        }
        return $"http://{Host}:{Port}";
    }

    /// <summary>
    /// Check if authentication is configured
    /// </summary>
    public bool HasAuthentication => !string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password);
}

/// <summary>
/// Timeout configuration settings
/// </summary>
public class TimeoutSettings
{
    /// <summary>
    /// HTTP request timeout in seconds (default: 30)
    /// </summary>
    public int HttpRequestSeconds { get; set; } = 30;

    /// <summary>
    /// TCP connection timeout in seconds (default: 10)
    /// </summary>
    public int TcpConnectSeconds { get; set; } = 10;

    /// <summary>
    /// Gets HTTP request timeout as TimeSpan
    /// </summary>
    public TimeSpan HttpRequestTimeout => TimeSpan.FromSeconds(HttpRequestSeconds);

    /// <summary>
    /// Gets TCP connect timeout as TimeSpan
    /// </summary>
    public TimeSpan TcpConnectTimeout => TimeSpan.FromSeconds(TcpConnectSeconds);
}
