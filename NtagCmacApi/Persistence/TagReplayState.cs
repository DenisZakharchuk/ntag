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

    public long LastAcceptedCounter { get; set; }

    public required string LastAcceptedCmacHex { get; set; }

    public DateTimeOffset LastAcceptedAtUtc { get; set; }
}
