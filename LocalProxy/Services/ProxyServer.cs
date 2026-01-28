using System.Net;
using System.Net.Sockets;
using LocalProxy.Models;
using Microsoft.Extensions.Options;

namespace LocalProxy.Services;

/// <summary>
/// Low-level TCP-based proxy server that detects protocol and delegates to handlers
/// </summary>
public partial class ProxyServer : BackgroundService
{
    private readonly ILogger<ProxyServer> _logger;
    private readonly IOptionsMonitor<ProxySettings> _optionsMonitor;
    private readonly IDomainMatcher _matcher;
    private readonly HttpHandler _httpHandler;
    private readonly Socks5Handler _socks5Handler;
    private TcpListener? _listener;

    public ProxyServer(
        ILogger<ProxyServer> logger,
        IOptionsMonitor<ProxySettings> optionsMonitor,
        IDomainMatcher matcher,
        HttpHandler httpHandler,
        Socks5Handler socks5Handler)
    {
        _logger = logger;
        _optionsMonitor = optionsMonitor;
        _matcher = matcher;
        _httpHandler = httpHandler;
        _socks5Handler = socks5Handler;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = _optionsMonitor.CurrentValue;
        _listener = new TcpListener(IPAddress.Loopback, settings.Port);
        _listener.Start();

        LogServerListening(settings.Port);
        LogUpstreamProxyStatus(
            settings.UpstreamProxy.Enabled
                ? $"{settings.UpstreamProxy.Host}:{settings.UpstreamProxy.Port}"
                : "disabled");
        LogDomainPatternsLoaded(settings.Domains.Count);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(stoppingToken);
                _ = Task.Run(() => HandleClientAsync(client, stoppingToken), stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            LogServerShuttingDown();
        }
        finally
        {
            _listener?.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = client.GetStream();

            // Read first byte to determine protocol
            var firstByte = await ReadByteAsync(stream, cancellationToken);

            var settings = _optionsMonitor.CurrentValue;

            if (firstByte == 0x05) // SOCKS5
            {
                await _socks5Handler.HandleAsync(stream, firstByte, settings, cancellationToken);
            }
            else // HTTP/HTTPS (ASCII text)
            {
                await _httpHandler.HandleAsync(stream, firstByte, settings, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            LogClientConnectionError(ex);
        }
        finally
        {
            client?.Dispose();
        }
    }

    private static async Task<byte> ReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        await stream.ReadExactlyAsync(buffer, cancellationToken);
        return buffer[0];
    }
}
