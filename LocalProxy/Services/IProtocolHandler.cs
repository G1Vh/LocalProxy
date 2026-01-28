using System.Net.Sockets;
using LocalProxy.Models;

namespace LocalProxy.Services;

/// <summary>
/// Interface for protocol handlers (HTTP/HTTPS, SOCKS5, etc.)
/// </summary>
public interface IProtocolHandler
{
    /// <summary>
    /// Handles the client connection for a specific protocol
    /// </summary>
    Task HandleAsync(
        NetworkStream clientStream,
        byte firstByte,
        ProxySettings settings,
        CancellationToken cancellationToken);
}
