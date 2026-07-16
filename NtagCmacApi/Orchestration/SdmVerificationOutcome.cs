using System;
using NtagCmacApi.KeyProvider;
using NtagCmacApi.Models;
using NtagCmacApi.Persistence;

namespace NtagCmacApi.Orchestration;

/// <summary>
/// Outcome of a single SDM CMAC verification request. Modeled as a closed set of record
/// types (rather than a single struct with an enum + optional fields) so that each
/// terminal state carries exactly the data relevant to it, and so consumers (the HTTP
/// endpoint, the outcome notifier) can pattern-match exhaustively and get a compiler
/// warning if a new outcome kind is added without being handled.
///
/// <para>
/// Deciding WHICH outcome subtype to build from a given raw result (a
/// <see cref="ReplayPreCheckResult"/>, a <see cref="TagKeyLookupStatus"/>, a CMAC-valid
/// flag, a <see cref="ReplayCommitResult"/>) is this type's own responsibility, via the
/// static factory methods below - deliberately NOT the orchestrator's. Without this, the
/// orchestrator would need to switch on each raw result AND know the full shape/
/// constructor of every outcome subtype just to build the right one - a "feature envy"
/// smell (a class doing work that conceptually belongs to a different class). Keeping that
/// mapping here, next to the outcome definitions it produces, keeps
/// <see cref="SdmVerificationOrchestrator"/> a pure sequencer that never needs to change
/// when a new outcome variant/mapping rule is introduced.
/// </para>
/// </summary>
public abstract record SdmVerificationOutcome(NtagSDMData? Data)
{
    /// <summary>The request was structurally invalid (missing/malformed uid, counter, or cmac).</summary>
    public sealed record MalformedRequest() : SdmVerificationOutcome((NtagSDMData?)null);

    /// <summary>
    /// The supplied company code did not resolve to a registered company via
    /// <see cref="ICompanyLookup"/> - the request cannot proceed since
    /// <c>TagReplayState.CompanyId</c> is a mandatory FK.
    /// </summary>
    public sealed record CompanyUnknown(NtagSDMData? Data, string CompanyCode) : SdmVerificationOutcome(Data);

    /// <summary>The replay guard rejected the counter as not strictly newer than (and not a duplicate of) the last accepted read.</summary>
    public sealed record ReplayRejected(NtagSDMData? Data) : SdmVerificationOutcome(Data);

    /// <summary>The master key could not be resolved (tag unknown, or the key service failed/timed out).</summary>
    public sealed record TagKeyUnavailable(NtagSDMData? Data, TagKeyLookupStatus Reason) : SdmVerificationOutcome(Data);

    /// <summary>The CMAC did not match.</summary>
    public sealed record CmacInvalid(NtagSDMData? Data) : SdmVerificationOutcome(Data);

    /// <summary>
    /// The CMAC was valid but committing it lost a race against another request that
    /// concurrently accepted a newer (or the same) counter for this UID first.
    /// </summary>
    public sealed record ReplayLostRace(NtagSDMData? Data) : SdmVerificationOutcome(Data);

    /// <summary>
    /// The request exactly repeats the last accepted (counter, cmac) pair for this UID:
    /// a safe idempotent retry, not an attack replay. Treated as a successful read by
    /// callers, but reported distinctly to the outcome notifier so it can be deduplicated.
    /// </summary>
    public sealed record DuplicateOfLastAccepted(NtagSDMData? Data) : SdmVerificationOutcome(Data);

    /// <summary>The CMAC was valid and the counter was newly accepted and recorded.</summary>
    public sealed record Accepted(NtagSDMData? Data) : SdmVerificationOutcome(Data);

    /// <summary>True for outcomes that should be reported to the caller as a successful verification.</summary>
    public bool IsSuccess => this is Accepted or DuplicateOfLastAccepted;

    // --- Factory methods: the orchestrator calls these instead of switching on raw
    // dependency results itself. Each maps one step's result to the outcome(s) it can
    // produce at that stage. ---

    /// <summary>Builds the outcome for a company code that didn't resolve to a registered company.</summary>
    public static SdmVerificationOutcome ForCompanyUnknown(NtagSDMData data, string companyCode) =>
        new CompanyUnknown(data, companyCode);

    /// <summary>
    /// Maps a replay pre-check result to a terminal outcome, or <see langword="null"/> if
    /// the pre-check says verification should proceed (i.e. not itself a terminal outcome).
    /// </summary>
    public static SdmVerificationOutcome? FromReplayPreCheck(NtagSDMData data, ReplayPreCheckResult result) => result switch
    {
        ReplayPreCheckResult.Duplicate => new DuplicateOfLastAccepted(data),
        ReplayPreCheckResult.Rejected => new ReplayRejected(data),
        ReplayPreCheckResult.Proceed => null,
        _ => throw new ArgumentOutOfRangeException(nameof(result), result, "Unhandled ReplayPreCheckResult."),
    };

    /// <summary>Builds the outcome for a master-key lookup that didn't resolve to a usable key.</summary>
    public static SdmVerificationOutcome ForTagKeyUnavailable(NtagSDMData data, TagKeyLookupStatus reason) =>
        new TagKeyUnavailable(data, reason);

    /// <summary>Builds the outcome for a CMAC that failed verification.</summary>
    public static SdmVerificationOutcome ForCmacInvalid(NtagSDMData data) => new CmacInvalid(data);

    /// <summary>Maps a replay commit result (after a successful CMAC verification) to its terminal outcome.</summary>
    public static SdmVerificationOutcome FromReplayCommit(NtagSDMData data, ReplayCommitResult result) => result switch
    {
        ReplayCommitResult.Accepted => new Accepted(data),
        ReplayCommitResult.Rejected => new ReplayLostRace(data),
        _ => throw new ArgumentOutOfRangeException(nameof(result), result, "Unhandled ReplayCommitResult."),
    };
}
