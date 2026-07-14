using Microsoft.EntityFrameworkCore;

namespace NtagCmacApi.Persistence;

/// <summary>
/// EF Core-backed <see cref="IReplayGuard"/>. Depends only on a <see cref="DbSet{TEntity}"/>
/// of <see cref="TagReplayState"/> and an <see cref="IUnitOfWork"/> for committing changes -
/// not on the concrete <see cref="NtagDbContext"/> - so it stays decoupled from EF Core's
/// <c>DbContext</c> type while still relying on EF Core's optimistic-concurrency check (via
/// <see cref="TagReplayState.LastAcceptedCounter"/> being a concurrency token) to atomically
/// detect a concurrent winner - the persistent, multi-instance-safe equivalent of the
/// previous in-memory CAS loop. Registered scoped alongside <see cref="NtagDbContext"/> so
/// that <see cref="PreCheckAsync"/> and <see cref="CommitAsync"/> within the same request
/// operate on the same tracked <see cref="TagReplayState"/> instance.
/// </summary>
public sealed class EfReplayGuard : IReplayGuard
{
    private readonly DbSet<TagReplayState> _tagReplayStates;
    private readonly IUnitOfWork _unitOfWork;

    public EfReplayGuard(DbSet<TagReplayState> tagReplayStates, IUnitOfWork unitOfWork)
    {
        _tagReplayStates = tagReplayStates;
        _unitOfWork = unitOfWork;
    }

    public async Task<ReplayPreCheckResult> PreCheckAsync(string uidHex, long counter, string cmacHex, CancellationToken cancellationToken)
    {
        string uid = uidHex.ToUpperInvariant();
        TagReplayState? state = await _tagReplayStates.FindAsync([uid], cancellationToken);

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
            TagReplayState? state = await _tagReplayStates.FindAsync([uid], cancellationToken);

            if (state is null)
            {
                _tagReplayStates.Add(new TagReplayState
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
                    // request already advanced the counter first.
                    return ReplayCommitResult.Rejected;
                }

                state.LastAcceptedCounter = counter;
                state.LastAcceptedCmacHex = cmacHex;
                state.LastAcceptedAtUtc = DateTimeOffset.UtcNow;
            }

            await _unitOfWork.SaveChangesAsync(cancellationToken);
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
