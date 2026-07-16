using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using NtagCmacApi.Models;
using DomainCompany = NtagCmacApi.Models.Company;

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
    private readonly ILogger<EfReplayGuard> _logger;

    public EfReplayGuard(DbSet<TagReplayState> tagReplayStates, IUnitOfWork unitOfWork, ILogger<EfReplayGuard> logger)
    {
        _tagReplayStates = tagReplayStates;
        _unitOfWork = unitOfWork;
        _logger = logger;
    }

    public async Task<ReplayPreCheckResult> PreCheckAsync(NtagSDMData data, CancellationToken cancellationToken)
    {
        string uid = data.Uid.ToUpperInvariant();
        if (!TryParseCounter(data.Counter, out long counter))
        {
            // Should never happen - ISdmVerifyCommandValidationPolicy already validated
            // the counter is well-formed hex before the orchestrator built this NtagSDMData
            // - but fail closed rather than throw if it somehow does.
            _logger.LogWarning("Failed to parse counter '{Counter}' for uid={Uid} during pre-check - rejecting", data.Counter, uid);
            return ReplayPreCheckResult.Rejected;
        }

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
            string.Equals(data.Cmac, state.LastAcceptedCmacHex, StringComparison.OrdinalIgnoreCase))
        {
            return ReplayPreCheckResult.Duplicate;
        }

        return ReplayPreCheckResult.Rejected;
    }

    public async Task<ReplayCommitResult> CommitAsync(NtagSDMData data, DomainCompany company, CancellationToken cancellationToken)
    {
        string uid = data.Uid.ToUpperInvariant();
        if (!TryParseCounter(data.Counter, out long counter))
        {
            _logger.LogWarning("Failed to parse counter '{Counter}' for uid={Uid} during commit - rejecting", data.Counter, uid);
            return ReplayCommitResult.Rejected;
        }

        try
        {
            TagReplayState? state = await _tagReplayStates.FindAsync([uid], cancellationToken);

            if (state is null)
            {
                _tagReplayStates.Add(new TagReplayState
                {
                    Uid = uid,
                    CompanyId = company.CompanyId,
                    Serial = data.Serial,
                    LastAcceptedCounter = counter,
                    LastAcceptedCmacHex = data.Cmac,
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
                state.LastAcceptedCmacHex = data.Cmac;
                state.LastAcceptedAtUtc = DateTimeOffset.UtcNow;
                state.Serial = data.Serial;
                state.CompanyId = company.CompanyId;
            }

            await _unitOfWork.SaveChangesAsync(cancellationToken);
            return ReplayCommitResult.Accepted;
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // Another request updated this UID's row concurrently between our read and write.
            // Expected under concurrent load, not an operational problem - Debug only.
            _logger.LogDebug(ex, "Lost optimistic-concurrency race committing uid={Uid}", uid);
            return ReplayCommitResult.Rejected;
        }
        catch (DbUpdateException ex)
        {
            // Another request concurrently inserted the first row for this brand-new UID
            // (primary-key violation). Also expected under concurrent load - Debug only.
            _logger.LogDebug(ex, "Lost race inserting first row for uid={Uid}", uid);
            return ReplayCommitResult.Rejected;
        }
    }

    private static bool TryParseCounter(string counterHex, out long counter) =>
        long.TryParse(counterHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out counter);
}
