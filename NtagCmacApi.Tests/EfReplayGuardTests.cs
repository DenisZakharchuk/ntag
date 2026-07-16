using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using NtagCmacApi.Models;
using NtagCmacApi.Persistence;
using Xunit;
using DomainCompany = NtagCmacApi.Models.Company;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates <see cref="EfReplayGuard"/>'s pre-check/commit semantics, including the
/// concurrency behavior that replaces the old in-memory CAS loop: a lost race at commit
/// time (another request already advanced the counter) must be reported as
/// <see cref="ReplayCommitResult.Rejected"/>, not silently overwritten or thrown as an
/// unhandled exception.
/// </summary>
public class EfReplayGuardTests
{
    private static NtagDbContext CreateContext(string databaseName)
    {
        var options = new DbContextOptionsBuilder<NtagDbContext>()
            .UseInMemoryDatabase(databaseName)
            .Options;
        return new NtagDbContext(options);
    }

    private static NtagSDMData Data(string uid, long counter, string cmac, string? serial = null) =>
        new(uid, serial, counter.ToString(), cmac);

    private static readonly DomainCompany DefaultCompany = new(1, "ACME");

    private static EfReplayGuard CreateGuard(NtagDbContext db) =>
        new(db.TagReplayStates, db, NullLogger<EfReplayGuard>.Instance);

    [Fact]
    public async Task PreCheck_NoStoredState_ReturnsProceed()
    {
        await using NtagDbContext db = CreateContext(nameof(PreCheck_NoStoredState_ReturnsProceed));
        var guard = CreateGuard(db);

        ReplayPreCheckResult result = await guard.PreCheckAsync(Data("04A1B2C3D4E5F6", 1, "AABBCCDDEEFF0011"), CancellationToken.None);

        Assert.Equal(ReplayPreCheckResult.Proceed, result);
    }

    [Fact]
    public async Task PreCheck_NewerCounter_ReturnsProceed()
    {
        string dbName = nameof(PreCheck_NewerCounter_ReturnsProceed);
        await using (NtagDbContext seed = CreateContext(dbName))
        {
            seed.TagReplayStates.Add(new TagReplayState { Uid = "UID1", CompanyId = 1, LastAcceptedCounter = 5, LastAcceptedCmacHex = "OLDCMAC", LastAcceptedAtUtc = DateTimeOffset.UtcNow });
            await seed.SaveChangesAsync();
        }

        await using NtagDbContext db = CreateContext(dbName);
        var guard = CreateGuard(db);

        ReplayPreCheckResult result = await guard.PreCheckAsync(Data("uid1", 6, "NEWCMAC"), CancellationToken.None);

        Assert.Equal(ReplayPreCheckResult.Proceed, result);
    }

    [Fact]
    public async Task PreCheck_StaleCounter_ReturnsRejected()
    {
        string dbName = nameof(PreCheck_StaleCounter_ReturnsRejected);
        await using (NtagDbContext seed = CreateContext(dbName))
        {
            seed.TagReplayStates.Add(new TagReplayState { Uid = "UID1", CompanyId = 1, LastAcceptedCounter = 5, LastAcceptedCmacHex = "OLDCMAC", LastAcceptedAtUtc = DateTimeOffset.UtcNow });
            await seed.SaveChangesAsync();
        }

        await using NtagDbContext db = CreateContext(dbName);
        var guard = CreateGuard(db);

        ReplayPreCheckResult result = await guard.PreCheckAsync(Data("UID1", 4, "SOMEOTHERCMAC"), CancellationToken.None);

        Assert.Equal(ReplayPreCheckResult.Rejected, result);
    }

    [Fact]
    public async Task PreCheck_ExactRepeatOfLastAccepted_ReturnsDuplicate()
    {
        string dbName = nameof(PreCheck_ExactRepeatOfLastAccepted_ReturnsDuplicate);
        await using (NtagDbContext seed = CreateContext(dbName))
        {
            seed.TagReplayStates.Add(new TagReplayState { Uid = "UID1", CompanyId = 1, LastAcceptedCounter = 5, LastAcceptedCmacHex = "MATCHINGCMAC", LastAcceptedAtUtc = DateTimeOffset.UtcNow });
            await seed.SaveChangesAsync();
        }

        await using NtagDbContext db = CreateContext(dbName);
        var guard = CreateGuard(db);

        ReplayPreCheckResult result = await guard.PreCheckAsync(Data("UID1", 5, "matchingcmac"), CancellationToken.None);

        Assert.Equal(ReplayPreCheckResult.Duplicate, result);
    }

    [Fact]
    public async Task PreCheck_SameCounterDifferentCmac_ReturnsRejected()
    {
        string dbName = nameof(PreCheck_SameCounterDifferentCmac_ReturnsRejected);
        await using (NtagDbContext seed = CreateContext(dbName))
        {
            seed.TagReplayStates.Add(new TagReplayState { Uid = "UID1", CompanyId = 1, LastAcceptedCounter = 5, LastAcceptedCmacHex = "MATCHINGCMAC", LastAcceptedAtUtc = DateTimeOffset.UtcNow });
            await seed.SaveChangesAsync();
        }

        await using NtagDbContext db = CreateContext(dbName);
        var guard = CreateGuard(db);

        ReplayPreCheckResult result = await guard.PreCheckAsync(Data("UID1", 5, "DIFFERENTCMAC"), CancellationToken.None);

        Assert.Equal(ReplayPreCheckResult.Rejected, result);
    }

    [Fact]
    public async Task Commit_NewUid_InsertsRowAndReturnsAccepted()
    {
        await using NtagDbContext db = CreateContext(nameof(Commit_NewUid_InsertsRowAndReturnsAccepted));
        var guard = CreateGuard(db);

        ReplayCommitResult result = await guard.CommitAsync(Data("UID1", 1, "CMAC1"), DefaultCompany, CancellationToken.None);

        Assert.Equal(ReplayCommitResult.Accepted, result);
        TagReplayState? stored = await db.TagReplayStates.FindAsync("UID1");
        Assert.NotNull(stored);
        Assert.Equal(1, stored!.LastAcceptedCounter);
        Assert.Equal("CMAC1", stored.LastAcceptedCmacHex);
    }

    [Fact]
    public async Task Commit_NewUid_WithCompanyAndSerial_PersistsBoth()
    {
        await using NtagDbContext db = CreateContext(nameof(Commit_NewUid_WithCompanyAndSerial_PersistsBoth));
        var guard = CreateGuard(db);

        ReplayCommitResult result = await guard.CommitAsync(
            Data("UID1", 1, "CMAC1", serial: "11111111"), new DomainCompany(1, "ACME"), CancellationToken.None);

        Assert.Equal(ReplayCommitResult.Accepted, result);
        TagReplayState? stored = await db.TagReplayStates.FindAsync("UID1");
        Assert.Equal(1, stored!.CompanyId);
        Assert.Equal("11111111", stored.Serial);
    }

    [Fact]
    public async Task Commit_NewerCounterThanStored_UpdatesAndReturnsAccepted()
    {
        string dbName = nameof(Commit_NewerCounterThanStored_UpdatesAndReturnsAccepted);
        await using (NtagDbContext seed = CreateContext(dbName))
        {
            seed.TagReplayStates.Add(new TagReplayState { Uid = "UID1", CompanyId = 1, LastAcceptedCounter = 5, LastAcceptedCmacHex = "OLDCMAC", LastAcceptedAtUtc = DateTimeOffset.UtcNow });
            await seed.SaveChangesAsync();
        }

        await using NtagDbContext db = CreateContext(dbName);
        var guard = CreateGuard(db);

        ReplayCommitResult result = await guard.CommitAsync(Data("UID1", 6, "NEWCMAC"), DefaultCompany, CancellationToken.None);

        Assert.Equal(ReplayCommitResult.Accepted, result);
        TagReplayState? stored = await db.TagReplayStates.FindAsync("UID1");
        Assert.Equal(6, stored!.LastAcceptedCounter);
    }

    [Fact]
    public async Task Commit_StaleCounter_ReturnsRejected()
    {
        string dbName = nameof(Commit_StaleCounter_ReturnsRejected);
        await using (NtagDbContext seed = CreateContext(dbName))
        {
            seed.TagReplayStates.Add(new TagReplayState { Uid = "UID1", CompanyId = 1, LastAcceptedCounter = 5, LastAcceptedCmacHex = "OLDCMAC", LastAcceptedAtUtc = DateTimeOffset.UtcNow });
            await seed.SaveChangesAsync();
        }

        await using NtagDbContext db = CreateContext(dbName);
        var guard = CreateGuard(db);

        ReplayCommitResult result = await guard.CommitAsync(Data("UID1", 5, "NEWCMAC"), DefaultCompany, CancellationToken.None);

        Assert.Equal(ReplayCommitResult.Rejected, result);
    }

    /// <summary>
    /// Simulates two concurrent requests for the same UID both passing pre-check (reading
    /// the same starting state) and then racing to commit. Each uses its own
    /// <see cref="NtagDbContext"/> instance against the same InMemory database, mirroring
    /// two separate scoped requests in the real app. Exactly one commit must win; the other
    /// must be rejected - the DB-backed equivalent of the old ConcurrentDictionary.TryUpdate
    /// CAS loop, now verified via EF Core's optimistic-concurrency token.
    /// </summary>
    [Fact]
    public async Task Commit_ConcurrentRequestsForSameUid_OnlyOneWins()
    {
        string dbName = nameof(Commit_ConcurrentRequestsForSameUid_OnlyOneWins);
        await using (NtagDbContext seed = CreateContext(dbName))
        {
            seed.TagReplayStates.Add(new TagReplayState { Uid = "UID1", CompanyId = 1, LastAcceptedCounter = 5, LastAcceptedCmacHex = "OLDCMAC", LastAcceptedAtUtc = DateTimeOffset.UtcNow });
            await seed.SaveChangesAsync();
        }

        await using NtagDbContext dbA = CreateContext(dbName);
        await using NtagDbContext dbB = CreateContext(dbName);
        var guardA = CreateGuard(dbA);
        var guardB = CreateGuard(dbB);

        // Both "requests" read the same pre-race state via their own pre-check first.
        await guardA.PreCheckAsync(Data("UID1", 6, "CMAC_A"), CancellationToken.None);
        await guardB.PreCheckAsync(Data("UID1", 6, "CMAC_B"), CancellationToken.None);

        ReplayCommitResult resultA = await guardA.CommitAsync(Data("UID1", 6, "CMAC_A"), DefaultCompany, CancellationToken.None);
        ReplayCommitResult resultB = await guardB.CommitAsync(Data("UID1", 6, "CMAC_B"), DefaultCompany, CancellationToken.None);

        var results = new[] { resultA, resultB };
        Assert.Single(results, r => r == ReplayCommitResult.Accepted);
        Assert.Single(results, r => r == ReplayCommitResult.Rejected);
    }
}
