using NtagCmacApi.KeyProvider;

namespace NtagCmacApi.Orchestration;

/// <summary>
/// Outcome of a single SDM CMAC verification request. Modeled as a closed set of record
/// types (rather than a single struct with an enum + optional fields) so that each
/// terminal state carries exactly the data relevant to it, and so consumers (the HTTP
/// endpoint, the outcome notifier) can pattern-match exhaustively and get a compiler
/// warning if a new outcome kind is added without being handled.
/// </summary>
public abstract record SdmVerificationOutcome(string? UidHex, string? CounterHex)
{
    /// <summary>The request was structurally invalid (missing/malformed uid, counter, or cmac).</summary>
    public sealed record MalformedRequest() : SdmVerificationOutcome(null, null);

    /// <summary>The replay guard rejected the counter as not strictly newer than (and not a duplicate of) the last accepted read.</summary>
    public sealed record ReplayRejected(string UidHexValue, string CounterHexValue)
        : SdmVerificationOutcome(UidHexValue, CounterHexValue);

    /// <summary>The master key could not be resolved (tag unknown, or the key service failed/timed out).</summary>
    public sealed record TagKeyUnavailable(string UidHexValue, string CounterHexValue, TagKeyLookupStatus Reason)
        : SdmVerificationOutcome(UidHexValue, CounterHexValue);

    /// <summary>The CMAC did not match.</summary>
    public sealed record CmacInvalid(string UidHexValue, string CounterHexValue)
        : SdmVerificationOutcome(UidHexValue, CounterHexValue);

    /// <summary>
    /// The CMAC was valid but committing it lost a race against another request that
    /// concurrently accepted a newer (or the same) counter for this UID first.
    /// </summary>
    public sealed record ReplayLostRace(string UidHexValue, string CounterHexValue)
        : SdmVerificationOutcome(UidHexValue, CounterHexValue);

    /// <summary>
    /// The request exactly repeats the last accepted (counter, cmac) pair for this UID:
    /// a safe idempotent retry, not an attack replay. Treated as a successful read by
    /// callers, but reported distinctly to the outcome notifier so it can be deduplicated.
    /// </summary>
    public sealed record DuplicateOfLastAccepted(string UidHexValue, string CounterHexValue)
        : SdmVerificationOutcome(UidHexValue, CounterHexValue);

    /// <summary>The CMAC was valid and the counter was newly accepted and recorded.</summary>
    public sealed record Accepted(string UidHexValue, string CounterHexValue)
        : SdmVerificationOutcome(UidHexValue, CounterHexValue);

    /// <summary>True for outcomes that should be reported to the caller as a successful verification.</summary>
    public bool IsSuccess => this is Accepted or DuplicateOfLastAccepted;
}
