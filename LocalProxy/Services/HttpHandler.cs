using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalProxy.Models;

namespace LocalProxy.Services;

/// <summary>
/// HTTP and HTTPS protocol handler
/// </summary>
public partial class HttpHandler : IProtocolHandler
{
    private readonly ILogger<HttpHandler> _logger;
    private readonly IDomainMatcher _matcher;
    private readonly IHttpClientFactory _httpClientFactory;

    public HttpHandler(
        ILogger<HttpHandler> logger,
        IDomainMatcher matcher,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _matcher = matcher;
        _httpClientFactory = httpClientFactory;
    }

    public async Task HandleAsync(
        NetworkStream clientStream,
        byte firstByte,
        ProxySettings settings,
        CancellationToken cancellationToken)
    {
        // Reconstruct the request line with first byte
        var requestLine = await ReadLineWithFirstByteAsync(clientStream, firstByte, cancellationToken);

        if (string.IsNullOrEmpty(requestLine))
            return;

        var parts = requestLine.Split(' ');
        if (parts.Length < 3)
            return;

        var method = parts[0];
        var target = parts[1];

        if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            await HandleConnectAsync(clientStream, target, settings, cancellationToken);
        }
        else
        {
            await HandleHttpAsync(clientStream, method, target, requestLine, settings, cancellationToken);
        }
    }

    private async Task HandleConnectAsync(
        NetworkStream clientStream,
        string target,
        ProxySettings settings,
        CancellationToken cancellationToken)
    {
        // Read and discard headers until blank line
        while (true)
        {
            var line = await ReadLineAsync(clientStream, cancellationToken);
            if (string.IsNullOrEmpty(line))
                break;
        }

        var useUpstream = settings.UpstreamProxy.Enabled && _matcher.Match(target);
        var destination = useUpstream ? "PROXY" : "DIRECT";

        LogConnectRequest(target, destination);

        TcpClient? targetClient = null;
        NetworkStream? targetStream = null;

        try
        {
            if (useUpstream)
            {
                (targetStream, targetClient) = await ConnectViaProxyAsync(target, settings, cancellationToken);
                if (targetStream == null)
                {
                    LogConnectUpstreamFailedFallback(target);
                    (targetStream, targetClient) = await ConnectDirectAsync(target, settings, cancellationToken);
                    LogConnectDirectFallback(target);
                }
            }
            else
            {
                (targetStream, targetClient) = await ConnectDirectAsync(target, settings, cancellationToken);
            }

            if (targetStream == null)
            {
                await SendResponseAsync(clientStream, "HTTP/1.1 502 Bad Gateway\r\n\r\n", cancellationToken);
                return;
            }

            // Send 200 Connection Established
            await SendResponseAsync(clientStream, "HTTP/1.1 200 Connection Established\r\n\r\n", cancellationToken);

            // Start bidirectional tunnel
            await Task.WhenAny(
                CopyStreamAsync(clientStream, targetStream, cancellationToken),
                CopyStreamAsync(targetStream, clientStream, cancellationToken)
            );
        }
        finally
        {
            if (targetStream != null)
                await targetStream.DisposeAsync();
            targetClient?.Dispose();
        }
    }

    private async Task HandleHttpAsync(
        NetworkStream clientStream,
        string method,
        string target,
        string requestLine,
        ProxySettings settings,
        CancellationToken cancellationToken)
    {
        // Parse target URL
        if (!Uri.TryCreate(target, UriKind.Absolute, out var targetUri))
        {
            await SendResponseAsync(clientStream, "HTTP/1.1 400 Bad Request\r\n\r\n", cancellationToken);
            return;
        }

        var host = targetUri.Host;

        // Read headers
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await ReadLineAsync(clientStream, cancellationToken);
            if (string.IsNullOrEmpty(line))
                break;

            var colonIndex = line.IndexOf(':');
            if (colonIndex > 0)
            {
                var name = line[..colonIndex].Trim();
                var value = line[(colonIndex + 1)..].Trim();
                headers[name] = value;
            }
        }

        var useUpstream = settings.UpstreamProxy.Enabled && _matcher.Match(host);
        var destination = useUpstream ? "PROXY" : "DIRECT";

        LogHttpRequest(method, targetUri, destination);

        try
        {
            var request = new HttpRequestMessage(new HttpMethod(method), targetUri);

            // Copy headers
            foreach (var header in headers)
            {
                if (!IsHopByHopHeader(header.Key))
                {
                    request.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            // Handle request body
            if (headers.TryGetValue("Content-Length", out var contentLengthStr) &&
                int.TryParse(contentLengthStr, out var contentLength) &&
                contentLength > 0)
            {
                var bodyBuffer = new byte[contentLength];
                await clientStream.ReadExactlyAsync(bodyBuffer, cancellationToken);
                request.Content = new ByteArrayContent(bodyBuffer);

                if (headers.TryGetValue("Content-Type", out var contentType))
                {
                    request.Content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);
                }
            }

            HttpResponseMessage? response;
            var clientName = useUpstream ? "upstream" : "direct";

            try
            {
                var httpClient = _httpClientFactory.CreateClient(clientName);
                response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            }
            catch when (useUpstream)
            {
                LogHttpUpstreamFailedFallback(targetUri);
                request = new HttpRequestMessage(new HttpMethod(method), targetUri);
                foreach (var header in headers)
                {
                    if (!IsHopByHopHeader(header.Key))
                    {
                        request.Headers.TryAddWithoutValidation(header.Key, header.Value);
                    }
                }
                var httpClient = _httpClientFactory.CreateClient("direct");
                response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                LogHttpDirectFallback(method, targetUri);
            }

            // Send response
            var statusLine = $"HTTP/1.1 {(int)response.StatusCode} {response.ReasonPhrase}\r\n";
            await SendResponseAsync(clientStream, statusLine, cancellationToken);

            foreach (var header in response.Headers)
            {
                if (!IsHopByHopHeader(header.Key))
                {
                    await SendResponseAsync(clientStream, $"{header.Key}: {string.Join(", ", header.Value)}\r\n", cancellationToken);
                }
            }

            foreach (var header in response.Content.Headers)
            {
                if (!IsHopByHopHeader(header.Key))
                {
                    await SendResponseAsync(clientStream, $"{header.Key}: {string.Join(", ", header.Value)}\r\n", cancellationToken);
                }
            }

            await SendResponseAsync(clientStream, "\r\n", cancellationToken);
            await response.Content.CopyToAsync(clientStream, cancellationToken);
        }
        catch (Exception ex)
        {
            LogHttpProxyError(ex, targetUri);
            await SendResponseAsync(clientStream, "HTTP/1.1 502 Bad Gateway\r\n\r\n", cancellationToken);
        }
    }

    private async Task<(NetworkStream? stream, TcpClient? client)> ConnectViaProxyAsync(
        string targetHost, ProxySettings settings, CancellationToken cancellationToken)
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
            connectRequest.Append($"CONNECT {targetHost} HTTP/1.1\r\n");
            connectRequest.Append($"Host: {targetHost}\r\n");

            if (proxySettings.HasAuthentication)
            {
                var auth = Convert.ToBase64String(
                    Encoding.ASCII.GetBytes($"{proxySettings.Username}:{proxySettings.Password}"));
                connectRequest.Append($"Proxy-Authorization: Basic {auth}\r\n");
            }

            connectRequest.Append("\r\n");

            await SendResponseAsync(stream, connectRequest.ToString(), cancellationToken);

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
        string targetHost, ProxySettings settings, CancellationToken cancellationToken)
    {
        TcpClient? tcpClient = null;

        try
        {
            var colonIndex = targetHost.LastIndexOf(':');
            string host;
            int port;

            if (colonIndex > 0)
            {
                host = targetHost[..colonIndex];
                port = int.Parse(targetHost[(colonIndex + 1)..]);
            }
            else
            {
                host = targetHost;
                port = 443;
            }

            tcpClient = new TcpClient();

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(settings.Timeouts.TcpConnectTimeout);

            await tcpClient.ConnectAsync(host, port, connectCts.Token);

            return (tcpClient.GetStream(), tcpClient);
        }
        catch (Exception ex)
        {
            LogDirectConnectionFailed(targetHost, ex.Message);
            tcpClient?.Dispose();
            return (null, null);
        }
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

    private static async Task<string> ReadLineWithFirstByteAsync(Stream stream, byte firstByte, CancellationToken cancellationToken)
    {
        var buffer = new List<byte> { firstByte };
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

    private static async Task SendResponseAsync(Stream stream, string text, CancellationToken cancellationToken)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        await stream.WriteAsync(bytes, cancellationToken);
    }

    private static async Task CopyStreamAsync(Stream source, Stream destination, CancellationToken cancellationToken)
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

    private static bool IsHopByHopHeader(string headerName)
    {
        return headerName.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Proxy-Authenticate", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("TE", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Trailer", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
               headerName.Equals("Upgrade", StringComparison.OrdinalIgnoreCase);
    }
}
