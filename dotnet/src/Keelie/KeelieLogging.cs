using Microsoft.Extensions.Logging;

namespace Keelie;

/// <summary>
/// Where the SDK writes its log lines.
/// </summary>
/// <remarks>
/// Each line is one fixed event name and its fields, such as
/// <c>apiable.token_rejected reason=expired</c>. The names are the Python SDK's, so one search
/// finds an event in every language. No line holds a token, a secret or a value taken from the
/// request.
/// <para>
/// By default, warnings go to standard error, and information and debug lines are dropped. Set
/// <see cref="LoggerFactory"/> to send every line to your own logging, such as the
/// <see cref="ILoggerFactory"/> of your ASP.NET Core app. The SDK's categories all start with
/// <c>Keelie</c>.
/// </para>
/// </remarks>
public static class KeelieLogging
{
    private static volatile ILoggerFactory? _factory;

    /// <summary>The factory the SDK makes its loggers with. <see langword="null"/> for the default.</summary>
    public static ILoggerFactory? LoggerFactory
    {
        get => _factory;
        set => _factory = value;
    }

    internal static ILogger For(string category) =>
        _factory?.CreateLogger(category) ?? QuietLogger.Instance;

    /// <summary>The default: warnings and worse to standard error, nothing else.</summary>
    private sealed class QuietLogger : ILogger
    {
        internal static readonly QuietLogger Instance = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning && logLevel != LogLevel.None;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                Console.Error.WriteLine(formatter(state, exception));
            }
        }
    }
}

/// <summary>The SDK's log lines. Each message is a fixed event name and its fields.</summary>
internal static class Log
{
    internal static void Debug(string category, string message, params object?[] args) =>
        Write(category, LogLevel.Debug, message, args);

    internal static void Info(string category, string message, params object?[] args) =>
        Write(category, LogLevel.Information, message, args);

    internal static void Warn(string category, string message, params object?[] args) =>
        Write(category, LogLevel.Warning, message, args);

    private static void Write(string category, LogLevel level, string message, object?[] args)
    {
        var logger = KeelieLogging.For(category);
        if (!logger.IsEnabled(level))
        {
            return;
        }
#pragma warning disable CA2254 // Each caller passes a constant template.
        logger.Log(level, message, args);
#pragma warning restore CA2254
    }

    /// <summary>The name of an error, for a log line. Never its message.</summary>
    internal static string ErrorName(Exception error) => error.GetType().Name;
}
