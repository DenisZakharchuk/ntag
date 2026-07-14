using Microsoft.Extensions.Logging;
using NtagCmacApi.Orchestration;

namespace NtagCmacApi.Notifications;

/// <summary>
/// Placeholder <see cref="IOutcomeNotifier"/> that logs the outcome instead of calling a
/// real master system. Replace with an HTTP/queue-backed implementation registered against
/// the same interface once the real integration is defined.
/// </summary>
public sealed class LoggingOutcomeNotifier : IOutcomeNotifier
{
    private readonly ILogger<LoggingOutcomeNotifier> _logger;

    public LoggingOutcomeNotifier(ILogger<LoggingOutcomeNotifier> logger)
    {
        _logger = logger;
    }

    public Task NotifyAsync(SdmVerificationOutcome outcome, CancellationToken cancellationToken)
    {
        _logger.LogInformation(
            "SDM verification outcome {OutcomeType} for uid={Uid} counter={Counter}",
            outcome.GetType().Name,
            outcome.UidHex ?? "(none)",
            outcome.CounterHex ?? "(none)");

        return Task.CompletedTask;
    }
}
