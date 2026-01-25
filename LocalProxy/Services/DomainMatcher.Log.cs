namespace LocalProxy.Services;

/// <summary>
/// Source-generated logging methods for DomainMatcher
/// </summary>
public partial class DomainMatcher
{
    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Information,
        Message = "Configuration changed, reloading domain patterns...")]
    private partial void LogConfigurationChanged();

    [LoggerMessage(
        EventId = 2002,
        Level = LogLevel.Information,
        Message = "Loaded {Count} domain patterns")]
    private partial void LogDomainPatternsLoaded(int count);
}
