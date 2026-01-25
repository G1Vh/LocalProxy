using LocalProxy.Models;
using LocalProxy.Services;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

// Configure hot-reload for appsettings.json
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

// Bind configuration with hot-reload support
builder.Services.Configure<ProxySettings>(builder.Configuration);

// Register domain matcher as singleton (it handles hot-reload internally)
builder.Services.AddSingleton<IDomainMatcher, DomainMatcher>();

// Register the TCP-based proxy server as a hosted service
builder.Services.AddHostedService<ProxyServer>();

// Configure HttpClient factory with named clients
var settings = builder.Configuration.Get<ProxySettings>() ?? new ProxySettings();

builder.Services.AddHttpClient("direct", client =>
{
    client.Timeout = settings.Timeouts.HttpRequestTimeout;
})
.ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
{
    AllowAutoRedirect = false,
    UseCookies = false,
    UseProxy = false
});

builder.Services.AddHttpClient("upstream", client =>
{
    client.Timeout = settings.Timeouts.HttpRequestTimeout;
})
.ConfigurePrimaryHttpMessageHandler(sp =>
{
    var options = sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<ProxySettings>>();
    var currentSettings = options.CurrentValue;

    var handler = new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false
    };

    if (currentSettings.UpstreamProxy.Enabled)
    {
        var proxyUrl = currentSettings.UpstreamProxy.GetProxyUrl();
        handler.Proxy = new WebProxy(proxyUrl);
        handler.UseProxy = true;
    }

    return handler;
});

// Add Windows Service support
builder.Host.UseWindowsService();

var app = builder.Build();

// Handle graceful shutdown
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    var logger = app.Services.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Proxy server shutting down...");
});

app.Run();

