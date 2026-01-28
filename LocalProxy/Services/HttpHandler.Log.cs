using System.Net;

namespace LocalProxy.Services;

public partial class HttpHandler
{
    [LoggerMessage(
        EventId = 3001,
        Level = LogLevel.Information,
        Message = "CONNECT {Target} -> {Destination}")]
    private partial void LogConnectRequest(string target, string destination);

    [LoggerMessage(
        EventId = 3002,
        Level = LogLevel.Warning,
        Message = "Upstream proxy failed for CONNECT {Target}, falling back to direct")]
    private partial void LogConnectUpstreamFailedFallback(string target);

    [LoggerMessage(
        EventId = 3003,
        Level = LogLevel.Information,
        Message = "CONNECT {Target} -> DIRECT (fallback)")]
    private partial void LogConnectDirectFallback(string target);

    [LoggerMessage(
        EventId = 3004,
        Level = LogLevel.Warning,
        Message = "Upstream proxy rejected CONNECT: {Response}")]
    private partial void LogUpstreamProxyRejectedConnect(string response);

    [LoggerMessage(
        EventId = 3005,
        Level = LogLevel.Warning,
        Message = "Failed to connect via upstream proxy: {Error}")]
    private partial void LogUpstreamProxyConnectionFailed(string error);

    [LoggerMessage(
        EventId = 3006,
        Level = LogLevel.Error,
        Message = "Failed to connect directly to {Host}: {Error}")]
    private partial void LogDirectConnectionFailed(string host, string error);

    [LoggerMessage(
        EventId = 3007,
        Level = LogLevel.Information,
        Message = "{Method} {Url} -> {Destination}")]
    private partial void LogHttpRequest(string method, Uri url, string destination);

    [LoggerMessage(
        EventId = 3008,
        Level = LogLevel.Warning,
        Message = "Upstream proxy failed for {Url}, falling back to direct")]
    private partial void LogHttpUpstreamFailedFallback(Uri url);

    [LoggerMessage(
        EventId = 3009,
        Level = LogLevel.Information,
        Message = "{Method} {Url} -> DIRECT (fallback)")]
    private partial void LogHttpDirectFallback(string method, Uri url);

    [LoggerMessage(
        EventId = 3010,
        Level = LogLevel.Error,
        Message = "Error proxying HTTP request to {Url}")]
    private partial void LogHttpProxyError(Exception ex, Uri url);
}
