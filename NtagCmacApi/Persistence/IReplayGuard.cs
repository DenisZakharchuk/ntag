namespace NtagCmacApi.Persistence;

/// <summary>
/// Result of checking an incoming SDM read counter against the persisted state for a UID,
/// before any network key lookup or CMAC verification is attempted.
/// </summary>
public enum ReplayPreCheckResult
{
    /// <summary>No stored state, or the counter is strictly greater than what's stored: continue verification.</summary>
    Proceed,

    /// <summary>
    /// The counter and CMAC exactly match the last accepted read for this UID: this is a
    /// safe, already-verified retry (e.g. a lost HTTP response), not an attack replay.
    /// </summary>
    Duplicate,

    /// <summary>
    /// The counter is not strictly greater than what's stored, and it doesn't match the
    /// last-accepted (counter, cmac) pair either: reject without spending a key lookup or
    /// CMAC computation on it.
    /// </summary>
    Rejected,
}

/// <summary>Result of committing a newly-verified (counter, cmac) pair as the new accepted state for a UID.</summary>
public enum ReplayCommitResult
{
    /// <summary>The new state was persisted successfully.</summary>
    Accepted,

    /// <summary>
    /// Another request committed a newer counter for this UID between this request's
    /// pre-check and commit: this request lost the race and must be treated as rejected.
    /// </summary>
    Rejected,
}

/// <summary>
/// Tracks the last accepted SDM read counter (and CMAC) per UID to reject replayed reads,
/// while allowing an exact-duplicate retry of the last accepted read to be recognized as
/// idempotent rather than an attack. Split into a cheap pre-check (performed before the
/// network key lookup and CMAC verification) and a commit (performed only after CMAC
/// verification succeeds), matching the two-phase SDM verification flow.
/// </summary>
public interface IReplayGuard
{
    Task<ReplayPreCheckResult> PreCheckAsync(string uidHex, long counter, string cmacHex, CancellationToken cancellationToken);

    Task<ReplayCommitResult> CommitAsync(string uidHex, long counter, string cmacHex, CancellationToken cancellationToken);
}
