namespace LocalProxy.Services;

public partial class Socks5Handler
{
    [LoggerMessage(Level = LogLevel.Information, Message = "SOCKS5 CONNECT {Target} -> {Destination}")]
    private partial void LogSocks5Connect(string target, string destination);

    [LoggerMessage(Level = LogLevel.Warning, Message = "SOCKS5 upstream failed for {Target}, falling back to direct")]
    private partial void LogSocks5UpstreamFailedFallback(string target);

    [LoggerMessage(Level = LogLevel.Information, Message = "SOCKS5 fallback direct for {Target}")]
    private partial void LogSocks5DirectFallback(string target);

    [LoggerMessage(Level = LogLevel.Error, Message = "SOCKS5 protocol error")]
    private partial void LogSocks5Error(Exception ex);

    [LoggerMessage(Level = LogLevel.Warning, Message = "SOCKS5 invalid method count")]
    private partial void LogInvalidMethodCount();

    [LoggerMessage(Level = LogLevel.Warning, Message = "SOCKS5 authentication required but not supported")]
    private partial void LogAuthenticationRequired();

    [LoggerMessage(Level = LogLevel.Warning, Message = "SOCKS5 invalid version: {Version}")]
    private partial void LogInvalidVersion(int version);

    [LoggerMessage(Level = LogLevel.Warning, Message = "SOCKS5 unsupported address type: {AddressType}")]
    private partial void LogUnsupportedAddressType(int addressType);

    [LoggerMessage(Level = LogLevel.Warning, Message = "SOCKS5 unsupported command: {Command}")]
    private partial void LogUnsupportedCommand(int command);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Upstream proxy rejected CONNECT: {Response}")]
    private partial void LogUpstreamProxyRejectedConnect(string response);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Upstream proxy connection failed: {Error}")]
    private partial void LogUpstreamProxyConnectionFailed(string error);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Direct connection to {Target} failed: {Error}")]
    private partial void LogDirectConnectionFailed(string target, string error);
}
