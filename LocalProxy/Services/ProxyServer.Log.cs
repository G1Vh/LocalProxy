using System.Net;

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

    [LoggerMessage(
        EventId = 1006,
        Level = LogLevel.Information,
        Message = "CONNECT {Target} -> {Destination}")]
    private partial void LogConnectRequest(string target, string destination);

    [LoggerMessage(
        EventId = 1007,
        Level = LogLevel.Warning,
        Message = "Upstream proxy failed for CONNECT {Target}, falling back to direct")]
    private partial void LogConnectUpstreamFailedFallback(string target);

    [LoggerMessage(
        EventId = 1008,
        Level = LogLevel.Information,
        Message = "CONNECT {Target} -> DIRECT (fallback)")]
    private partial void LogConnectDirectFallback(string target);

    [LoggerMessage(
        EventId = 1009,
        Level = LogLevel.Warning,
        Message = "Upstream proxy rejected CONNECT: {Response}")]
    private partial void LogUpstreamProxyRejectedConnect(string response);

    [LoggerMessage(
        EventId = 1010,
        Level = LogLevel.Warning,
        Message = "Failed to connect via upstream proxy: {Error}")]
    private partial void LogUpstreamProxyConnectionFailed(string error);

    [LoggerMessage(
        EventId = 1011,
        Level = LogLevel.Error,
        Message = "Failed to connect directly to {Host}: {Error}")]
    private partial void LogDirectConnectionFailed(string host, string error);

    [LoggerMessage(
        EventId = 1012,
        Level = LogLevel.Information,
        Message = "{Method} {Url} -> {Destination}")]
    private partial void LogHttpRequest(string method, Uri url, string destination);

    [LoggerMessage(
        EventId = 1013,
        Level = LogLevel.Warning,
        Message = "Upstream proxy failed for {Url}, falling back to direct")]
    private partial void LogHttpUpstreamFailedFallback(Uri url);

    [LoggerMessage(
        EventId = 1014,
        Level = LogLevel.Information,
        Message = "{Method} {Url} -> DIRECT (fallback)")]
    private partial void LogHttpDirectFallback(string method, Uri url);

    [LoggerMessage(
        EventId = 1015,
        Level = LogLevel.Error,
        Message = "Error proxying HTTP request to {Url}")]
    private partial void LogHttpProxyError(Exception ex, Uri url);
}
