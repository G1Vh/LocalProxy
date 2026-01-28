using LocalProxy.Models;
using LocalProxy.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net;

var builder = Host.CreateDefaultBuilder(args)
    .UseWindowsService()
    .ConfigureAppConfiguration((context, config) =>
    {
        config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
    })
    .ConfigureServices((context, services) =>
    {
        // Bind configuration with hot-reload support
        services.Configure<ProxySettings>(context.Configuration);

        // Register domain matcher as singleton (it handles hot-reload internally)
        services.AddSingleton<IDomainMatcher, DomainMatcher>();

        // Register protocol handlers
        services.AddSingleton<HttpHandler>();
        services.AddSingleton<Socks5Handler>();

        // Register the TCP-based proxy server as a hosted service
        services.AddHostedService<ProxyServer>();

        // Configure HttpClient factory with named clients
        var settings = context.Configuration.Get<ProxySettings>() ?? new ProxySettings();

        services.AddHttpClient("direct", client =>
        {
            client.Timeout = settings.Timeouts.HttpRequestTimeout;
        })
        .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false
        });

        services.AddHttpClient("upstream", client =>
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
    });

var host = builder.Build();

await host.RunAsync();