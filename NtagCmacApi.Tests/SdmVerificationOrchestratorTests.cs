using Microsoft.Extensions.Logging.Abstractions;
using Ntag424.Cmac;
using NtagCmacApi.KeyProvider;
using NtagCmacApi.Notifications;
using NtagCmacApi.Orchestration;
using NtagCmacApi.Persistence;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates <see cref="SdmVerificationOrchestrator"/>'s sequencing (replay pre-check ->
/// key lookup -> CMAC verify -> replay commit -> notify) using hand-written fakes for all
/// four dependencies, consistent with this repo's minimal-dependency style (no mocking
/// library). Confirms each outcome branch short-circuits the remaining steps correctly,
/// and that the outcome notifier is always invoked - even when it throws - without ever
/// changing the returned outcome or propagating an exception.
/// </summary>
public class SdmVerificationOrchestratorTests
{
    private sealed class FakeReplayGuard : IReplayGuard
    {
        public ReplayPreCheckResult PreCheckResult { get; set; } = ReplayPreCheckResult.Proceed;
        public ReplayCommitResult CommitResult { get; set; } = ReplayCommitResult.Accepted;
        public bool PreCheckCalled { get; private set; }
        public bool CommitCalled { get; private set; }

        public Task<ReplayPreCheckResult> PreCheckAsync(string uidHex, long counter, string cmacHex, CancellationToken cancellationToken)
        {
            PreCheckCalled = true;
            return Task.FromResult(PreCheckResult);
        }

        public Task<ReplayCommitResult> CommitAsync(string uidHex, long counter, string cmacHex, CancellationToken cancellationToken)
        {
            CommitCalled = true;
            return Task.FromResult(CommitResult);
        }
    }

    private sealed class FakeTagKeyProvider : ITagKeyProvider
    {
        public TagKeyLookupResult Result { get; set; } = TagKeyLookupResult.Found("AAAAAAAAAAAAAAAAAAAAAA==");
        public bool Called { get; private set; }

        public Task<TagKeyLookupResult> GetMasterKeyAsync(string uidHex, CancellationToken cancellationToken)
        {
            Called = true;
            return Task.FromResult(Result);
        }
    }

    private sealed class FakeCmacVerifier : INtag424CmacVerifier
    {
        public bool ReturnValue { get; set; } = true;
        public bool Called { get; private set; }

        public bool Verify(in Ntag424SdmCmacRequest request)
        {
            Called = true;
            return ReturnValue;
        }
    }

    private sealed class FakeOutcomeNotifier : IOutcomeNotifier
    {
        public List<SdmVerificationOutcome> Notified { get; } = new();
        public Exception? ThrowOnNotify { get; set; }

        public Task NotifyAsync(SdmVerificationOutcome outcome, CancellationToken cancellationToken)
        {
            Notified.Add(outcome);
            if (ThrowOnNotify is not null)
            {
                throw ThrowOnNotify;
            }
            return Task.CompletedTask;
        }
    }

    private const string Uid = "04A1B2C3D4E5F6";
    private const string Counter = "000001";
    private const string Cmac = "0011223344556677";

    private static SdmVerificationOrchestrator CreateOrchestrator(
        FakeReplayGuard replayGuard,
        FakeTagKeyProvider tagKeyProvider,
        FakeCmacVerifier cmacVerifier,
        FakeOutcomeNotifier notifier) =>
        new(new SdmVerifyCommandValidationPolicy(), replayGuard, tagKeyProvider, cmacVerifier, notifier, NullLogger<SdmVerificationOrchestrator>.Instance);

    [Theory]
    [InlineData("", Counter, Cmac)]
    [InlineData(Uid, "", Cmac)]
    [InlineData(Uid, Counter, "")]
    [InlineData(Uid, "ZZZZZZ", Cmac)] // not valid hex
    public async Task MalformedRequest_ShortCircuitsBeforeReplayGuard(string uid, string counter, string cmac)
    {
        var replayGuard = new FakeReplayGuard();
        var tagKeyProvider = new FakeTagKeyProvider();
        var cmacVerifier = new FakeCmacVerifier();
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(uid, counter, cmac), CancellationToken.None);

        Assert.IsType<SdmVerificationOutcome.MalformedRequest>(outcome);
        Assert.False(replayGuard.PreCheckCalled);
        Assert.False(tagKeyProvider.Called);
        Assert.False(cmacVerifier.Called);
        Assert.Single(notifier.Notified);
    }

    [Fact]
    public async Task ReplayPreCheckRejected_ShortCircuitsBeforeKeyLookup()
    {
        var replayGuard = new FakeReplayGuard { PreCheckResult = ReplayPreCheckResult.Rejected };
        var tagKeyProvider = new FakeTagKeyProvider();
        var cmacVerifier = new FakeCmacVerifier();
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        Assert.IsType<SdmVerificationOutcome.ReplayRejected>(outcome);
        Assert.False(tagKeyProvider.Called);
        Assert.False(cmacVerifier.Called);
        Assert.False(replayGuard.CommitCalled);
        Assert.False(outcome.IsSuccess);
    }

    [Fact]
    public async Task ReplayPreCheckDuplicate_ShortCircuitsAsSuccessWithoutKeyLookup()
    {
        var replayGuard = new FakeReplayGuard { PreCheckResult = ReplayPreCheckResult.Duplicate };
        var tagKeyProvider = new FakeTagKeyProvider();
        var cmacVerifier = new FakeCmacVerifier();
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        Assert.IsType<SdmVerificationOutcome.DuplicateOfLastAccepted>(outcome);
        Assert.False(tagKeyProvider.Called);
        Assert.False(cmacVerifier.Called);
        Assert.True(outcome.IsSuccess);
    }

    [Fact]
    public async Task KeyNotFound_ShortCircuitsBeforeCmacVerification()
    {
        var replayGuard = new FakeReplayGuard();
        var tagKeyProvider = new FakeTagKeyProvider { Result = TagKeyLookupResult.NotFound };
        var cmacVerifier = new FakeCmacVerifier();
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        var unavailable = Assert.IsType<SdmVerificationOutcome.TagKeyUnavailable>(outcome);
        Assert.Equal(TagKeyLookupStatus.NotFound, unavailable.Reason);
        Assert.False(cmacVerifier.Called);
        Assert.False(replayGuard.CommitCalled);
    }

    [Fact]
    public async Task KeyServiceError_ShortCircuitsBeforeCmacVerification()
    {
        var replayGuard = new FakeReplayGuard();
        var tagKeyProvider = new FakeTagKeyProvider { Result = TagKeyLookupResult.ServiceError };
        var cmacVerifier = new FakeCmacVerifier();
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        var unavailable = Assert.IsType<SdmVerificationOutcome.TagKeyUnavailable>(outcome);
        Assert.Equal(TagKeyLookupStatus.ServiceError, unavailable.Reason);
        Assert.False(cmacVerifier.Called);
    }

    [Fact]
    public async Task CmacInvalid_ShortCircuitsBeforeCommit()
    {
        var replayGuard = new FakeReplayGuard();
        var tagKeyProvider = new FakeTagKeyProvider();
        var cmacVerifier = new FakeCmacVerifier { ReturnValue = false };
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        Assert.IsType<SdmVerificationOutcome.CmacInvalid>(outcome);
        Assert.False(replayGuard.CommitCalled);
    }

    [Fact]
    public async Task ValidCmac_CommitAccepted_ReturnsAccepted()
    {
        var replayGuard = new FakeReplayGuard { CommitResult = ReplayCommitResult.Accepted };
        var tagKeyProvider = new FakeTagKeyProvider();
        var cmacVerifier = new FakeCmacVerifier { ReturnValue = true };
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        Assert.IsType<SdmVerificationOutcome.Accepted>(outcome);
        Assert.True(outcome.IsSuccess);
    }

    [Fact]
    public async Task ValidCmac_CommitLosesRace_ReturnsReplayLostRace()
    {
        var replayGuard = new FakeReplayGuard { CommitResult = ReplayCommitResult.Rejected };
        var tagKeyProvider = new FakeTagKeyProvider();
        var cmacVerifier = new FakeCmacVerifier { ReturnValue = true };
        var notifier = new FakeOutcomeNotifier();
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        Assert.IsType<SdmVerificationOutcome.ReplayLostRace>(outcome);
        Assert.False(outcome.IsSuccess);
    }

    [Fact]
    public async Task NotifierIsCalledForEveryOutcome()
    {
        var scenarios = new (ReplayPreCheckResult PreCheck, TagKeyLookupResult Key, bool Cmac, ReplayCommitResult Commit)[]
        {
            (ReplayPreCheckResult.Rejected, TagKeyLookupResult.Found("AAAAAAAAAAAAAAAAAAAAAA=="), true, ReplayCommitResult.Accepted),
            (ReplayPreCheckResult.Duplicate, TagKeyLookupResult.Found("AAAAAAAAAAAAAAAAAAAAAA=="), true, ReplayCommitResult.Accepted),
            (ReplayPreCheckResult.Proceed, TagKeyLookupResult.NotFound, true, ReplayCommitResult.Accepted),
            (ReplayPreCheckResult.Proceed, TagKeyLookupResult.Found("AAAAAAAAAAAAAAAAAAAAAA=="), false, ReplayCommitResult.Accepted),
            (ReplayPreCheckResult.Proceed, TagKeyLookupResult.Found("AAAAAAAAAAAAAAAAAAAAAA=="), true, ReplayCommitResult.Accepted),
            (ReplayPreCheckResult.Proceed, TagKeyLookupResult.Found("AAAAAAAAAAAAAAAAAAAAAA=="), true, ReplayCommitResult.Rejected),
        };

        foreach (var scenario in scenarios)
        {
            var replayGuard = new FakeReplayGuard { PreCheckResult = scenario.PreCheck, CommitResult = scenario.Commit };
            var tagKeyProvider = new FakeTagKeyProvider { Result = scenario.Key };
            var cmacVerifier = new FakeCmacVerifier { ReturnValue = scenario.Cmac };
            var notifier = new FakeOutcomeNotifier();
            var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

            await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

            Assert.Single(notifier.Notified);
        }
    }

    [Fact]
    public async Task NotifierThrows_DoesNotAffectReturnedOutcomeOrPropagate()
    {
        var replayGuard = new FakeReplayGuard { CommitResult = ReplayCommitResult.Accepted };
        var tagKeyProvider = new FakeTagKeyProvider();
        var cmacVerifier = new FakeCmacVerifier { ReturnValue = true };
        var notifier = new FakeOutcomeNotifier { ThrowOnNotify = new InvalidOperationException("master system unreachable") };
        var orchestrator = CreateOrchestrator(replayGuard, tagKeyProvider, cmacVerifier, notifier);

        SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(new SdmVerifyCommand(Uid, Counter, Cmac), CancellationToken.None);

        Assert.IsType<SdmVerificationOutcome.Accepted>(outcome);
    }
}
