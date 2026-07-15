using Microsoft.Extensions.Logging;
using Ntag424.Cmac;
using NtagCmacApi.KeyProvider;
using NtagCmacApi.Notifications;
using NtagCmacApi.Persistence;

namespace NtagCmacApi.Orchestration;

/// <summary>
/// Orchestrates a full SDM CMAC verification request end to end: replay pre-check (cheap,
/// before any network call - also serves as the idempotency check for safe retries), master
/// key resolution, CMAC verification, replay commit, and outcome notification.
///
/// This is a fixed sequential pipeline, not a family of interchangeable algorithms for a
/// single responsibility, so it is deliberately NOT itself a "Strategy" - each step it
/// composes (<see cref="ISdmVerifyCommandValidationPolicy"/>, <see cref="IReplayGuard"/>,
/// <see cref="ITagKeyProvider"/>, <see cref="INtag424CmacVerifier"/>,
/// <see cref="IOutcomeNotifier"/>) already IS a Strategy, swappable independently via DI.
/// This class's job (Single Responsibility) is purely to sequence those strategies and
/// translate their results into an <see cref="SdmVerificationOutcome"/>.
/// </summary>
public sealed class SdmVerificationOrchestrator : ISdmVerificationOrchestrator
{
    private readonly ISdmVerifyCommandValidationPolicy _validationPolicy;
    private readonly IReplayGuard _replayGuard;
    private readonly ITagKeyProvider _tagKeyProvider;
    private readonly INtag424CmacVerifier _cmacVerifier;
    private readonly IOutcomeNotifier _outcomeNotifier;
    private readonly ILogger<SdmVerificationOrchestrator> _logger;

    public SdmVerificationOrchestrator(
        ISdmVerifyCommandValidationPolicy validationPolicy,
        IReplayGuard replayGuard,
        ITagKeyProvider tagKeyProvider,
        INtag424CmacVerifier cmacVerifier,
        IOutcomeNotifier outcomeNotifier,
        ILogger<SdmVerificationOrchestrator> logger)
    {
        _validationPolicy = validationPolicy;
        _replayGuard = replayGuard;
        _tagKeyProvider = tagKeyProvider;
        _cmacVerifier = cmacVerifier;
        _outcomeNotifier = outcomeNotifier;
        _logger = logger;
    }

    public async Task<SdmVerificationOutcome> VerifyAsync(SdmVerifyCommand command, CancellationToken cancellationToken)
    {
        SdmVerificationOutcome outcome = await DetermineOutcomeAsync(command, cancellationToken);

        // Regardless of the outcome (short of an unhandled CLR-level exception escaping
        // DetermineOutcomeAsync itself), report it to the master system. A broken notifier
        // must never turn an already-decided outcome into an HTTP 500 for the caller.
        try
        {
            await _outcomeNotifier.NotifyAsync(outcome, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Outcome notifier failed for {OutcomeType}", outcome.GetType().Name);
        }

        return outcome;
    }

    private async Task<SdmVerificationOutcome> DetermineOutcomeAsync(SdmVerifyCommand command, CancellationToken cancellationToken)
    {
        if (!_validationPolicy.TryValidate(command, out int counterValue))
        {
            return new SdmVerificationOutcome.MalformedRequest();
        }

        string uid = command.Uid;
        string counterHex = command.Counter;
        string cmacHex = command.Cmac;

        // 1. Cheap pre-check before any network call or crypto: rejects stale replays
        //    outright, and recognizes an exact repeat of the last accepted read as a safe
        //    idempotent retry rather than an attack.
        ReplayPreCheckResult preCheck = await _replayGuard.PreCheckAsync(uid, counterValue, cmacHex, cancellationToken);
        switch (preCheck)
        {
            case ReplayPreCheckResult.Duplicate:
                return new SdmVerificationOutcome.DuplicateOfLastAccepted(uid, counterHex);
            case ReplayPreCheckResult.Rejected:
                return new SdmVerificationOutcome.ReplayRejected(uid, counterHex);
        }

        // 2. Resolve the master key over the network. Never accepted from the caller.
        TagKeyLookupResult keyLookup = await _tagKeyProvider.GetMasterKeyAsync(uid, cancellationToken);
        if (keyLookup.Status != TagKeyLookupStatus.Found || keyLookup.MasterKeyBase64 is null)
        {
            return new SdmVerificationOutcome.TagKeyUnavailable(uid, counterHex, keyLookup.Status);
        }

        // 3. Verify the CMAC (existing zero-alloc, synchronous crypto core - unchanged).
        bool cmacValid = _cmacVerifier.Verify(new Ntag424SdmCmacRequest(
            uid, counterHex, cmacHex, keyLookup.MasterKeyBase64, command.MirroredData ?? string.Empty));
        if (!cmacValid)
        {
            return new SdmVerificationOutcome.CmacInvalid(uid, counterHex);
        }

        // 4. Commit the newly-verified counter as the new accepted state for this UID.
        ReplayCommitResult commit = await _replayGuard.CommitAsync(uid, counterValue, cmacHex, cancellationToken);
        return commit == ReplayCommitResult.Accepted
            ? new SdmVerificationOutcome.Accepted(uid, counterHex)
            : new SdmVerificationOutcome.ReplayLostRace(uid, counterHex);
    }
}
