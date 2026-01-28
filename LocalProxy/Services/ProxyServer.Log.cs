namespace LocalProxy.Services;

/// <summary>
/// Source-generated logging methods for ProxyServer
/// </summary>
public partial class ProxyServer
{
    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Information,
        Message = "Proxy server listening on port {Port}")]
    private partial void LogServerListening(int port);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Information,
        Message = "Upstream proxy: {Status}")]
    private partial void LogUpstreamProxyStatus(string status);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Information,
        Message = "Loaded {Count} domain patterns")]
    private partial void LogDomainPatternsLoaded(int count);

    [LoggerMessage(
        EventId = 1004,
        Level = LogLevel.Information,
        Message = "Proxy server shutting down...")]
    private partial void LogServerShuttingDown();

    [LoggerMessage(
        EventId = 1005,
        Level = LogLevel.Error,
        Message = "Error handling client connection")]
    private partial void LogClientConnectionError(Exception ex);
}
