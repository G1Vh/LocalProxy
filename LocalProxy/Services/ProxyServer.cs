using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalProxy.Models;
using Microsoft.Extensions.Options;

namespace LocalProxy.Services;

/// <summary>
/// Low-level TCP-based proxy server that handles both HTTP and HTTPS CONNECT
/// </summary>
public class ProxyServer : BackgroundService
{
    private readonly ILogger<ProxyServer> _logger;
    private readonly IOptionsMonitor<ProxySettings> _optionsMonitor;
    private readonly IDomainMatcher _matcher;
    private readonly IHttpClientFactory _httpClientFactory;
    private TcpListener? _listener;

    public ProxyServer(
        ILogger<ProxyServer> logger,
        IOptionsMonitor<ProxySettings> optionsMonitor,
        IDomainMatcher matcher,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _optionsMonitor = optionsMonitor;
        _matcher = matcher;
        _httpClientFactory = httpClientFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = _optionsMonitor.CurrentValue;
        _listener = new TcpListener(IPAddress.Loopback, settings.Port);
        _listener.Start();

        _logger.LogInformation("Proxy server listening on port {Port}", settings.Port);
        _logger.LogInformation("Upstream proxy: {Status}",
            settings.UpstreamProxy.Enabled
                ? $"{settings.UpstreamProxy.Host}:{settings.UpstreamProxy.Port}"
                : "disabled");
        _logger.LogInformation("Loaded {Count} domain patterns", settings.Domains.Count);

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
            _logger.LogInformation("Proxy server shutting down...");
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
            using var stream = client.GetStream();
            var requestLine = await ReadLineAsync(stream, cancellationToken);

            if (string.IsNullOrEmpty(requestLine))
                return;

            var parts = requestLine.Split(' ');
            if (parts.Length < 3)
                return;

            var method = parts[0];
            var target = parts[1];

            if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                await HandleConnectAsync(stream, target, cancellationToken);
            }
            else
            {
                await HandleHttpAsync(stream, method, target, requestLine, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling client connection");
        }
        finally
        {
            client?.Dispose();
        }
    }

    private async Task HandleConnectAsync(NetworkStream clientStream, string target, CancellationToken cancellationToken)
    {
        var settings = _optionsMonitor.CurrentValue;

        // Read and discard headers until blank line
        while (true)
        {
            var line = await ReadLineAsync(clientStream, cancellationToken);
            if (string.IsNullOrEmpty(line))
                break;
        }

        var useUpstream = settings.UpstreamProxy.Enabled && _matcher.Match(target);
        var destination = useUpstream ? "PROXY" : "DIRECT";

        _logger.LogInformation("CONNECT {Target} -> {Destination}", target, destination);

        TcpClient? targetClient = null;
        NetworkStream? targetStream = null;

        try
        {
            if (useUpstream)
            {
                (targetStream, targetClient) = await ConnectViaProxyAsync(target, settings, cancellationToken);
                if (targetStream == null)
                {
                    _logger.LogWarning("Upstream proxy failed for CONNECT {Target}, falling back to direct", target);
                    (targetStream, targetClient) = await ConnectDirectAsync(target, settings, cancellationToken);
                    _logger.LogInformation("CONNECT {Target} -> DIRECT (fallback)", target);
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
            targetStream?.Dispose();
            targetClient?.Dispose();
        }
    }

    private async Task HandleHttpAsync(NetworkStream clientStream, string method, string target, string requestLine, CancellationToken cancellationToken)
    {
        var settings = _optionsMonitor.CurrentValue;

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

        _logger.LogInformation("{Method} {Url} -> {Destination}", method, targetUri, destination);

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
                _logger.LogWarning("Upstream proxy failed for {Url}, falling back to direct", targetUri);
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
                _logger.LogInformation("{Method} {Url} -> DIRECT (fallback)", method, targetUri);
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
            _logger.LogError(ex, "Error proxying HTTP request to {Url}", targetUri);
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
                _logger.LogWarning("Upstream proxy rejected CONNECT: {Response}", responseLine);
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
            _logger.LogWarning("Failed to connect via upstream proxy: {Error}", ex.Message);
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
            _logger.LogError("Failed to connect directly to {Host}: {Error}", targetHost, ex.Message);
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
