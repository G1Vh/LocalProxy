using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalProxy.Models;

namespace LocalProxy.Services;

/// <summary>
/// SOCKS5 protocol handler for tunneling TCP connections (e.g., SSH)
/// </summary>
public partial class Socks5Handler : IProtocolHandler
{
    private readonly ILogger<Socks5Handler> _logger;
    private readonly IDomainMatcher _matcher;

    public Socks5Handler(ILogger<Socks5Handler> logger, IDomainMatcher matcher)
    {
        _logger = logger;
        _matcher = matcher;
    }

    public async Task HandleAsync(
        NetworkStream clientStream,
        byte firstByte,
        ProxySettings settings,
        CancellationToken cancellationToken)
    {
        try
        {
            // First byte (0x05) already read, now read auth methods
            var nMethods = await ReadByteAsync(clientStream, cancellationToken);
            if (nMethods == 0)
            {
                LogInvalidMethodCount();
                return;
            }

            var methods = new byte[nMethods];
            await clientStream.ReadExactlyAsync(methods, cancellationToken);

            // We only support NO AUTHENTICATION (0x00)
            if (!methods.Contains((byte)0x00))
            {
                // Reply: no acceptable methods
                await clientStream.WriteAsync(new byte[] { 0x05, 0xFF }, cancellationToken);
                LogAuthenticationRequired();
                return;
            }

            // Reply: use NO AUTH
            await clientStream.WriteAsync(new byte[] { 0x05, 0x00 }, cancellationToken);

            // Read request
            var version = await ReadByteAsync(clientStream, cancellationToken);
            if (version != 0x05)
            {
                LogInvalidVersion(version);
                return;
            }

            var cmd = await ReadByteAsync(clientStream, cancellationToken);
            var reserved = await ReadByteAsync(clientStream, cancellationToken);
            var addressType = await ReadByteAsync(clientStream, cancellationToken);

            string targetHost;
            int targetPort;

            // Parse address
            switch (addressType)
            {
                case 0x01: // IPv4
                    var ipv4 = new byte[4];
                    await clientStream.ReadExactlyAsync(ipv4, cancellationToken);
                    targetHost = new IPAddress(ipv4).ToString();
                    break;

                case 0x03: // Domain name
                    var domainLength = await ReadByteAsync(clientStream, cancellationToken);
                    var domainBytes = new byte[domainLength];
                    await clientStream.ReadExactlyAsync(domainBytes, cancellationToken);
                    targetHost = Encoding.ASCII.GetString(domainBytes);
                    break;

                case 0x04: // IPv6
                    var ipv6 = new byte[16];
                    await clientStream.ReadExactlyAsync(ipv6, cancellationToken);
                    targetHost = new IPAddress(ipv6).ToString();
                    break;

                default:
                    await SendErrorAsync(clientStream, 0x08, cancellationToken); // Address type not supported
                    LogUnsupportedAddressType(addressType);
                    return;
            }

            // Read port (2 bytes, big-endian)
            var portBytes = new byte[2];
            await clientStream.ReadExactlyAsync(portBytes, cancellationToken);
            targetPort = (portBytes[0] << 8) | portBytes[1];

            // Only support CONNECT command
            if (cmd != 0x01)
            {
                await SendErrorAsync(clientStream, 0x07, cancellationToken); // Command not supported
                LogUnsupportedCommand(cmd);
                return;
            }

            var target = $"{targetHost}:{targetPort}";
            var useUpstream = settings.UpstreamProxy.Enabled && _matcher.Match(targetHost);
            var destination = useUpstream ? "PROXY" : "DIRECT";

            LogSocks5Connect(target, destination);

            // Establish connection
            TcpClient? targetClient = null;
            NetworkStream? targetStream = null;

            try
            {
                if (useUpstream)
                {
                    (targetStream, targetClient) = await ConnectViaProxyAsync(target, settings, cancellationToken);
                    if (targetStream == null)
                    {
                        LogSocks5UpstreamFailedFallback(target);
                        (targetStream, targetClient) = await ConnectDirectAsync(targetHost, targetPort, settings, cancellationToken);
                        LogSocks5DirectFallback(target);
                    }
                }
                else
                {
                    (targetStream, targetClient) = await ConnectDirectAsync(targetHost, targetPort, settings, cancellationToken);
                }

                if (targetStream == null)
                {
                    await SendErrorAsync(clientStream, 0x05, cancellationToken); // Connection refused
                    return;
                }

                // Send success response
                await SendSuccessAsync(clientStream, cancellationToken);

                // Start bidirectional tunnel
                await Task.WhenAny(
                    CopyStreamAsync(clientStream, targetStream, "client->target", cancellationToken),
                    CopyStreamAsync(targetStream, clientStream, "target->client", cancellationToken)
                );
            }
            finally
            {
                if (targetStream != null)
                    await targetStream.DisposeAsync();
                targetClient?.Dispose();
            }
        }
        catch (Exception ex)
        {
            LogSocks5Error(ex);
        }
    }

    private async Task<(NetworkStream? stream, TcpClient? client)> ConnectViaProxyAsync(
        string target, ProxySettings settings, CancellationToken cancellationToken)
    {
        var proxySettings = settings.UpstreamProxy;
        TcpClient? tcpClient = null;

        try
        {
            tcpClient = new TcpClient();

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(settings.Timeouts.TcpConnectTimeout);

            await tcpClient.ConnectAsync(proxySettings.Host, proxySettings.Port, connectCts.Token);

            var stream = tcpClient.GetStream();

            // Send CONNECT request
            var connectRequest = new StringBuilder();
            connectRequest.Append($"CONNECT {target} HTTP/1.1\r\n");
            connectRequest.Append($"Host: {target}\r\n");

            if (proxySettings.HasAuthentication)
            {
                var auth = Convert.ToBase64String(
                    Encoding.ASCII.GetBytes($"{proxySettings.Username}:{proxySettings.Password}"));
                connectRequest.Append($"Proxy-Authorization: Basic {auth}\r\n");
            }

            connectRequest.Append("\r\n");

            var requestBytes = Encoding.ASCII.GetBytes(connectRequest.ToString());
            await stream.WriteAsync(requestBytes, cancellationToken);

            // Read response
            var responseLine = await ReadLineAsync(stream, cancellationToken);
            if (string.IsNullOrEmpty(responseLine) ||
                (!responseLine.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase) &&
                 !responseLine.StartsWith("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase)))
            {
                LogUpstreamProxyRejectedConnect(responseLine ?? string.Empty);
                tcpClient.Dispose();
                return (null, null);
            }

            // Read and discard remaining headers
            while (true)
            {
                var line = await ReadLineAsync(stream, cancellationToken);
                if (string.IsNullOrEmpty(line))
                    break;
            }

            return (stream, tcpClient);
        }
        catch (Exception ex)
        {
            LogUpstreamProxyConnectionFailed(ex.Message);
            tcpClient?.Dispose();
            return (null, null);
        }
    }

    private async Task<(NetworkStream? stream, TcpClient? client)> ConnectDirectAsync(
        string host, int port, ProxySettings settings, CancellationToken cancellationToken)
    {
        TcpClient? tcpClient = null;

        try
        {
            tcpClient = new TcpClient();

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(settings.Timeouts.TcpConnectTimeout);

            await tcpClient.ConnectAsync(host, port, connectCts.Token);

            return (tcpClient.GetStream(), tcpClient);
        }
        catch (Exception ex)
        {
            LogDirectConnectionFailed($"{host}:{port}", ex.Message);
            tcpClient?.Dispose();
            return (null, null);
        }
    }

    private static async Task<byte> ReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        await stream.ReadExactlyAsync(buffer, cancellationToken);
        return buffer[0];
    }

    private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>();
        var readBuffer = new byte[1];

        while (true)
        {
            var bytesRead = await stream.ReadAsync(readBuffer, cancellationToken);
            if (bytesRead == 0)
                break;

            var b = readBuffer[0];
            if (b == '\n')
            {
                if (buffer.Count > 0 && buffer[^1] == '\r')
                    buffer.RemoveAt(buffer.Count - 1);
                break;
            }

            buffer.Add(b);
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static async Task SendSuccessAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        // SOCKS5 success response: VER=0x05, REP=0x00 (success), RSV=0x00, ATYP=0x01 (IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
        var response = new byte[] { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        await stream.WriteAsync(response, cancellationToken);
    }

    private static async Task SendErrorAsync(NetworkStream stream, byte errorCode, CancellationToken cancellationToken)
    {
        // SOCKS5 error response
        var response = new byte[] { 0x05, errorCode, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        await stream.WriteAsync(response, cancellationToken);
    }

    private static async Task CopyStreamAsync(Stream source, Stream destination, string direction, CancellationToken cancellationToken)
    {
        try
        {
            await source.CopyToAsync(destination, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Expected
        }
        catch (IOException)
        {
            // Expected when connection closes
        }
    }
}
