using System.Net;
using System.Net.Sockets;
using System.Text;
using LocalProxy.Models;
using LocalProxy.Services;
using Microsoft.Extensions.Options;

namespace LocalProxy.Middleware;

/// <summary>
/// Proxy middleware that handles both HTTP and HTTPS CONNECT requests.
/// Routes matched domains through upstream proxy, others go direct.
/// </summary>
public class ProxyMiddleware
{
    private readonly ILogger<ProxyMiddleware> _logger;
    private readonly IDomainMatcher _matcher;
    private readonly IOptionsMonitor<ProxySettings> _optionsMonitor;
    private readonly IHttpClientFactory _httpClientFactory;

    // Hop-by-hop headers that should not be forwarded
    private static readonly HashSet<string> HopByHopHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "Proxy-Connection",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade"
    };

    public ProxyMiddleware(
        RequestDelegate next, // Required by convention but not used - we're terminal middleware
        ILogger<ProxyMiddleware> logger,
        IDomainMatcher matcher,
        IOptionsMonitor<ProxySettings> optionsMonitor,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _matcher = matcher;
        _optionsMonitor = optionsMonitor;
        _httpClientFactory = httpClientFactory;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            if (HttpMethods.IsConnect(context.Request.Method))
            {
                await HandleConnectAsync(context);
            }
            else
            {
                await HandleHttpAsync(context);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing request to {Host}", context.Request.Host);
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
        }
    }

    /// <summary>
    /// Handle regular HTTP requests (GET, POST, etc.)
    /// </summary>
    private async Task HandleHttpAsync(HttpContext context)
    {
        var settings = _optionsMonitor.CurrentValue;
        var request = context.Request;

        // Build the target URL
        var targetUri = new Uri($"{request.Scheme}://{request.Host}{request.Path}{request.QueryString}");
        var host = targetUri.Host;
        var path = targetUri.PathAndQuery;

        // Check if this request should go through upstream proxy
        var useUpstream = settings.UpstreamProxy.Enabled && _matcher.MatchUrl(host, path);
        var destination = useUpstream ? "PROXY" : "DIRECT";

        _logger.LogInformation("{Method} {Url} -> {Destination}", request.Method, targetUri, destination);

        // Create the outgoing request
        var requestMessage = CreateProxyRequest(context, targetUri);

        HttpResponseMessage? response = null;

        if (useUpstream)
        {
            try
            {
                var client = _httpClientFactory.CreateClient("upstream");
                response = await client.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Upstream proxy failed for {Url}, falling back to direct: {Error}", targetUri, ex.Message);

                // Fallback to direct
                requestMessage = CreateProxyRequest(context, targetUri);
                var directClient = _httpClientFactory.CreateClient("direct");
                response = await directClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

                _logger.LogInformation("{Method} {Url} -> DIRECT (fallback)", request.Method, targetUri);
            }
        }
        else
        {
            var client = _httpClientFactory.CreateClient("direct");
            response = await client.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
        }

        // Copy response back to client
        await CopyResponseAsync(context, response);
    }

    /// <summary>
    /// Handle HTTPS CONNECT tunneling
    /// </summary>
    private async Task HandleConnectAsync(HttpContext context)
    {
        var settings = _optionsMonitor.CurrentValue;
        var host = context.Request.Host.ToString();

        // Check if this should go through upstream proxy
        var useUpstream = settings.UpstreamProxy.Enabled && _matcher.Match(host);
        var destination = useUpstream ? "PROXY" : "DIRECT";

        _logger.LogInformation("CONNECT {Host} -> {Destination}", host, destination);

        Stream? targetStream = null;
        TcpClient? tcpClient = null;

        try
        {
            if (useUpstream)
            {
                // Connect through upstream proxy
                (targetStream, tcpClient) = await ConnectViaProxyAsync(host, settings, context.RequestAborted);

                if (targetStream == null)
                {
                    // Fallback to direct connection
                    _logger.LogWarning("Upstream proxy failed for CONNECT {Host}, falling back to direct", host);
                    (targetStream, tcpClient) = await ConnectDirectAsync(host, settings, context.RequestAborted);

                    _logger.LogInformation("CONNECT {Host} -> DIRECT (fallback)", host);
                }
            }
            else
            {
                (targetStream, tcpClient) = await ConnectDirectAsync(host, settings, context.RequestAborted);
            }

            if (targetStream == null)
            {
                context.Response.StatusCode = StatusCodes.Status502BadGateway;
                return;
            }

            // Send 200 Connection Established response manually
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentLength = 0;
            await context.Response.StartAsync(context.RequestAborted);

            // Get the underlying connection stream using Body.Stream (DuplexStream)
            var bodyFeature = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpResponseBodyFeature>();
            if (bodyFeature == null)
            {
                _logger.LogError("Unable to access response body feature for CONNECT to {Host}", host);
                return;
            }

            // Disable buffering for raw stream access
            context.Response.Body = bodyFeature.Stream;

            // Get request body stream for reading
            var clientStream = new DuplexStream(context.Request.Body, context.Response.Body);

            // Start bidirectional copy
            await TunnelAsync(clientStream, targetStream, context.RequestAborted);
        }
        finally
        {
            targetStream?.Dispose();
            tcpClient?.Dispose();
        }
    }

    /// <summary>
    /// Connect to target through upstream proxy using CONNECT method
    /// </summary>
    private async Task<(Stream? stream, TcpClient? client)> ConnectViaProxyAsync(
        string targetHost, ProxySettings settings, CancellationToken cancellationToken)
    {
        var proxySettings = settings.UpstreamProxy;
        TcpClient? tcpClient = null;

        try
        {
            tcpClient = new TcpClient();

            // Connect to upstream proxy with timeout
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(settings.Timeouts.TcpConnectTimeout);

            await tcpClient.ConnectAsync(proxySettings.Host, proxySettings.Port, connectCts.Token);

            var stream = tcpClient.GetStream();

            // Send CONNECT request to upstream proxy
            var connectRequest = new StringBuilder();
            connectRequest.Append($"CONNECT {targetHost} HTTP/1.1\r\n");
            connectRequest.Append($"Host: {targetHost}\r\n");

            // Add proxy authentication if configured
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
            var responseBuffer = new byte[1024];
            var bytesRead = await stream.ReadAsync(responseBuffer, cancellationToken);
            var response = Encoding.ASCII.GetString(responseBuffer, 0, bytesRead);

            // Check for 200 Connection established
            if (!response.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase) &&
                !response.StartsWith("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Upstream proxy rejected CONNECT: {Response}", response.Split('\r', '\n')[0]);
                tcpClient.Dispose();
                return (null, null);
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

    /// <summary>
    /// Connect directly to target host
    /// </summary>
    private async Task<(Stream? stream, TcpClient? client)> ConnectDirectAsync(
        string targetHost, ProxySettings settings, CancellationToken cancellationToken)
    {
        TcpClient? tcpClient = null;

        try
        {
            // Parse host:port
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
                port = 443; // Default HTTPS port
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

    /// <summary>
    /// Bidirectional tunnel between client and target
    /// </summary>
    private static async Task TunnelAsync(Stream clientStream, Stream targetStream, CancellationToken cancellationToken)
    {
        var clientToTarget = CopyStreamAsync(clientStream, targetStream, cancellationToken);
        var targetToClient = CopyStreamAsync(targetStream, clientStream, cancellationToken);

        // Wait for either direction to complete (usually when connection closes)
        await Task.WhenAny(clientToTarget, targetToClient);
    }

    private static async Task CopyStreamAsync(Stream source, Stream destination, CancellationToken cancellationToken)
    {
        try
        {
            await source.CopyToAsync(destination, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Expected when connection closes
        }
        catch (IOException)
        {
            // Expected when connection closes
        }
    }

    /// <summary>
    /// Create an HttpRequestMessage from the incoming request
    /// </summary>
    private HttpRequestMessage CreateProxyRequest(HttpContext context, Uri targetUri)
    {
        var request = context.Request;
        var requestMessage = new HttpRequestMessage
        {
            Method = new HttpMethod(request.Method),
            RequestUri = targetUri
        };

        // Copy headers (excluding hop-by-hop headers)
        foreach (var header in request.Headers)
        {
            if (HopByHopHeaders.Contains(header.Key))
                continue;

            // Try to add as request header, if it fails try as content header
            if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
            {
                requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            }
        }

        // Copy body if present
        if (request.ContentLength > 0 || request.Headers.ContainsKey("Transfer-Encoding"))
        {
            requestMessage.Content = new StreamContent(request.Body);

            // Copy content headers
            if (request.ContentType != null)
            {
                requestMessage.Content.Headers.ContentType =
                    System.Net.Http.Headers.MediaTypeHeaderValue.Parse(request.ContentType);
            }

            if (request.ContentLength.HasValue)
            {
                requestMessage.Content.Headers.ContentLength = request.ContentLength;
            }
        }

        return requestMessage;
    }

    /// <summary>
    /// Copy the response from the target back to the client
    /// </summary>
    private static async Task CopyResponseAsync(HttpContext context, HttpResponseMessage response)
    {
        context.Response.StatusCode = (int)response.StatusCode;

        // Copy response headers
        foreach (var header in response.Headers)
        {
            if (!HopByHopHeaders.Contains(header.Key))
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
        }

        foreach (var header in response.Content.Headers)
        {
            if (!HopByHopHeaders.Contains(header.Key))
            {
                context.Response.Headers[header.Key] = header.Value.ToArray();
            }
        }

        // Copy body
        await response.Content.CopyToAsync(context.Response.Body);
    }

    /// <summary>
    /// Duplex stream combining separate read and write streams
    /// </summary>
    private class DuplexStream : Stream
    {
        private readonly Stream _readStream;
        private readonly Stream _writeStream;

        public DuplexStream(Stream readStream, Stream writeStream)
        {
            _readStream = readStream;
            _writeStream = writeStream;
        }

        public override bool CanRead => _readStream.CanRead;
        public override bool CanWrite => _writeStream.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
            => _readStream.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _readStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _readStream.ReadAsync(buffer, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => _writeStream.Write(buffer, offset, count);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _writeStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _writeStream.WriteAsync(buffer, cancellationToken);

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _writeStream.FlushAsync(cancellationToken);

        public override void Flush() => _writeStream.Flush();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _readStream?.Dispose();
                _writeStream?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
