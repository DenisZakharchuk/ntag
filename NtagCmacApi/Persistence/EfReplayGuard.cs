using Microsoft.EntityFrameworkCore;

namespace NtagCmacApi.Persistence;

/// <summary>
/// EF Core-backed <see cref="IReplayGuard"/>. Registered scoped alongside <see cref="NtagDbContext"/>
/// so that <see cref="PreCheckAsync"/> and <see cref="CommitAsync"/> within the same request
/// operate on the same tracked <see cref="TagReplayState"/> instance, and <see cref="CommitAsync"/>
/// relies on EF Core's optimistic-concurrency check (via <see cref="TagReplayState.LastAcceptedCounter"/>
/// being a concurrency token) to atomically detect a concurrent winner - the persistent,
/// multi-instance-safe equivalent of the previous in-memory CAS loop.
/// </summary>
public sealed class EfReplayGuard : IReplayGuard
{
    private readonly NtagDbContext _dbContext;

    public EfReplayGuard(NtagDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<ReplayPreCheckResult> PreCheckAsync(string uidHex, long counter, string cmacHex, CancellationToken cancellationToken)
    {
        string uid = uidHex.ToUpperInvariant();
        TagReplayState? state = await _dbContext.TagReplayStates.FindAsync([uid], cancellationToken);

        if (state is null)
        {
            return ReplayPreCheckResult.Proceed;
        }

        if (counter > state.LastAcceptedCounter)
        {
            return ReplayPreCheckResult.Proceed;
        }

        if (counter == state.LastAcceptedCounter &&
            string.Equals(cmacHex, state.LastAcceptedCmacHex, StringComparison.OrdinalIgnoreCase))
        {
            return ReplayPreCheckResult.Duplicate;
        }

        return ReplayPreCheckResult.Rejected;
    }

    public async Task<ReplayCommitResult> CommitAsync(string uidHex, long counter, string cmacHex, CancellationToken cancellationToken)
    {
        string uid = uidHex.ToUpperInvariant();

        try
        {
            TagReplayState? state = await _dbContext.TagReplayStates.FindAsync([uid], cancellationToken);

            if (state is null)
            {
                _dbContext.TagReplayStates.Add(new TagReplayState
                {
                    Uid = uid,
                    LastAcceptedCounter = counter,
                    LastAcceptedCmacHex = cmacHex,
                    LastAcceptedAtUtc = DateTimeOffset.UtcNow,
                });
            }
            else
            {
                if (counter <= state.LastAcceptedCounter)
                {
                    // Lost the race between this request's pre-check and commit: another
                    // request already advanced (or matched) the counter first.
                    return ReplayCommitResult.Rejected;
                }

                state.LastAcceptedCounter = counter;
                state.LastAcceptedCmacHex = cmacHex;
                state.LastAcceptedAtUtc = DateTimeOffset.UtcNow;
            }

            await _dbContext.SaveChangesAsync(cancellationToken);
            return ReplayCommitResult.Accepted;
        }
        catch (DbUpdateConcurrencyException)
        {
            // Another request updated this UID's row concurrently between our read and write.
            return ReplayCommitResult.Rejected;
        }
        catch (DbUpdateException)
        {
            // Another request concurrently inserted the first row for this brand-new UID
            // (primary-key violation).
            return ReplayCommitResult.Rejected;
        }
    }
}
