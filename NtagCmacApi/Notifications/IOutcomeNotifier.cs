using NtagCmacApi.Orchestration;

namespace NtagCmacApi.Notifications;

/// <summary>
/// Reports the outcome of an SDM verification request to an external "master system".
/// Hidden behind this abstraction so the real integration (HTTP call, message queue, etc.)
/// can be added later without touching the orchestrator. Called for every reachable
/// outcome - including every rejection branch - not just successful verifications.
/// </summary>
public interface IOutcomeNotifier
{
    Task NotifyAsync(SdmVerificationOutcome outcome, CancellationToken cancellationToken);
}
