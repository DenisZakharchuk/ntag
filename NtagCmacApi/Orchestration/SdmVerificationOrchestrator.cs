using Microsoft.Extensions.Logging;
using Ntag424.Cmac;
using NtagCmacApi.KeyProvider;
using NtagCmacApi.Models;
using NtagCmacApi.Notifications;
using NtagCmacApi.Persistence;
using DomainCompany = NtagCmacApi.Models.Company;

namespace NtagCmacApi.Orchestration;

/// <summary>
/// Orchestrates a full SDM CMAC verification request end to end: replay pre-check (cheap,
/// before any network call - also serves as the idempotency check for safe retries),
/// master key resolution, CMAC verification, company resolution, replay commit, and
/// outcome notification.
///
/// This is a fixed sequential pipeline, not a family of interchangeable algorithms for a
/// single responsibility, so it is deliberately NOT itself a "Strategy" - each step it
/// composes (<see cref="ISdmVerifyCommandValidationPolicy"/>, <see cref="ICompanyLookup"/>,
/// <see cref="IReplayGuard"/>, <see cref="ITagKeyProvider"/>,
/// <see cref="INtag424CmacVerifier"/>, <see cref="IOutcomeNotifier"/>) already IS a
/// Strategy, swappable independently via DI. This class's job (Single Responsibility) is
/// purely to sequence those strategies and translate their results into an
/// <see cref="SdmVerificationOutcome"/>.
/// </summary>
public sealed class SdmVerificationOrchestrator : ISdmVerificationOrchestrator
{
    private readonly ISdmVerifyCommandValidationPolicy _validationPolicy;
    private readonly ICompanyLookup _companyLookup;
    private readonly IReplayGuard _replayGuard;
    private readonly ITagKeyProvider _tagKeyProvider;
    private readonly INtag424CmacVerifier _cmacVerifier;
    private readonly IOutcomeNotifier _outcomeNotifier;
    private readonly ILogger<SdmVerificationOrchestrator> _logger;

    public SdmVerificationOrchestrator(
        ISdmVerifyCommandValidationPolicy validationPolicy,
        ICompanyLookup companyLookup,
        IReplayGuard replayGuard,
        ITagKeyProvider tagKeyProvider,
        INtag424CmacVerifier cmacVerifier,
        IOutcomeNotifier outcomeNotifier,
        ILogger<SdmVerificationOrchestrator> logger)
    {
        _validationPolicy = validationPolicy;
        _companyLookup = companyLookup;
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
        if (!_validationPolicy.TryValidate(command, out _))
        {
            _logger.LogDebug("Rejecting SDM verify request: malformed command (uid={Uid})", command.Uid);
            return new SdmVerificationOutcome.MalformedRequest();
        }

        string uid = command.Uid;
        string counterHex = command.Counter;
        string cmacHex = command.Cmac;

        var data = new NtagSDMData(uid, command.Serial, counterHex, cmacHex);
        _logger.LogDebug("Verifying SDM request for uid={Uid}", uid);

        // 1. Cheap pre-check before any network call or crypto: rejects stale replays
        //    outright, and recognizes an exact repeat of the last accepted read as a safe
        //    idempotent retry rather than an attack. Which outcome (if any) a given
        //    pre-check result maps to is SdmVerificationOutcome's own responsibility, not
        //    this class's - see SdmVerificationOutcome.FromReplayPreCheck. Doesn't need a
        //    company - it only compares counter/cmac for the given UID.
        ReplayPreCheckResult preCheck = await _replayGuard.PreCheckAsync(data, cancellationToken);
        if (SdmVerificationOutcome.FromReplayPreCheck(data, preCheck) is { } preCheckOutcome)
        {
            // Rejected is a likely-malicious stale/replayed counter - worth a Warning.
            // Duplicate is a safe idempotent retry - just Debug-level detail.
            if (preCheck == ReplayPreCheckResult.Rejected)
            {
                _logger.LogWarning("Replay pre-check rejected uid={Uid} (stale or invalid counter)", uid);
            }
            else
            {
                _logger.LogDebug("Replay pre-check recognized a duplicate request for uid={Uid}", uid);
            }

            return preCheckOutcome;
        }

        // 2. Resolve the master key over the network. Never accepted from the caller.
        TagKeyLookupResult keyLookup = await _tagKeyProvider.GetMasterKeyAsync(data, cancellationToken);
        if (keyLookup.Status != TagKeyLookupStatus.Found || keyLookup.MasterKeyBase64 is null)
        {
            _logger.LogWarning("Master key unavailable for uid={Uid} (status={Status})", uid, keyLookup.Status);
            return SdmVerificationOutcome.ForTagKeyUnavailable(data, keyLookup.Status);
        }

        // 3. Verify the CMAC (existing zero-alloc, synchronous crypto core - unchanged).
        bool cmacValid = _cmacVerifier.Verify(new Ntag424SdmCmacRequest(
            uid, counterHex, cmacHex, keyLookup.MasterKeyBase64, command.MirroredData ?? string.Empty));
        if (!cmacValid)
        {
            _logger.LogWarning("CMAC verification failed for uid={Uid}", uid);
            return SdmVerificationOutcome.ForCmacInvalid(data);
        }

        // 4. Resolve the company code: only needed now, right before the commit, since it
        //    is solely the commit step (TagReplayState.CompanyId is a mandatory FK) that
        //    requires it - resolving any earlier would spend a lookup on requests that end
        //    up rejected by the pre-check, key lookup, or CMAC verification anyway.
        DomainCompany? company = await _companyLookup.FindByCodeAsync(command.CompanyCode, cancellationToken);
        if (company is null)
        {
            _logger.LogWarning("Unknown company code {CompanyCode} for uid={Uid}", command.CompanyCode, uid);
            return SdmVerificationOutcome.ForCompanyUnknown(data, command.CompanyCode);
        }

        // 5. Commit the newly-verified counter as the new accepted state for this UID.
        ReplayCommitResult commit = await _replayGuard.CommitAsync(data, company, cancellationToken);
        if (commit != ReplayCommitResult.Accepted)
        {
            _logger.LogDebug("Replay commit lost race for uid={Uid}", uid);
        }

        return SdmVerificationOutcome.FromReplayCommit(data, commit);
    }
}
