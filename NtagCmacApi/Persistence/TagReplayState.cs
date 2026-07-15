using System;

namespace NtagCmacApi.Persistence;

/// <summary>
/// Persisted replay-protection state for a single tag (by UID): the last SDM read counter
/// and CMAC accepted for it. <see cref="LastAcceptedCounter"/> doubles as an EF Core
/// optimistic-concurrency token (configured in <see cref="NtagDbContext.OnModelCreating"/>),
/// so a concurrent commit racing against this one is detected as a
/// <see cref="Microsoft.EntityFrameworkCore.DbUpdateConcurrencyException"/> rather than
/// silently overwriting a newer value - the portable (InMemory/SqlServer/Npgsql-agnostic)
/// equivalent of the previous in-memory <c>ConcurrentDictionary.TryUpdate</c> CAS loop.
/// </summary>
public sealed class TagReplayState
{
    /// <summary>Uppercase hex-encoded 7-byte tag UID. Primary key.</summary>
    public required string Uid { get; set; }

    /// <summary>
    /// FK to <see cref="Company.Id"/> - which tenant/organization this tag belongs to.
    /// Nullable: nothing in the verification pipeline currently determines/assigns a
    /// company for a tag yet (scaffolded for future multi-tenant use), so existing and
    /// newly-committed rows are allowed to have no company assigned.
    /// </summary>
    public required int CompanyId { get; set; }

    /// <summary>
    /// The raw "serial" value mirrored in the tag's SDM URL, if present (e.g. an
    /// AN12196 Table 5 deployment's static `serial=` field). Stored for reference/audit
    /// only - it is not itself part of CMAC verification (see
    /// <c>Ntag424.Cmac.MessagePolicies.MirroredDataCmacMessagePolicy</c> for how mirrored
    /// data actually factors into the MAC). Nullable since a Table 4 deployment has none.
    /// </summary>
    public required string Serial { get; set; }

    public long LastAcceptedCounter { get; set; }

    public required string LastAcceptedCmacHex { get; set; }

    public DateTimeOffset LastAcceptedAtUtc { get; set; }
}
