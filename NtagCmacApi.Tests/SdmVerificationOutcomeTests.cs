using NtagCmacApi.KeyProvider;
using NtagCmacApi.Models;
using NtagCmacApi.Orchestration;
using NtagCmacApi.Persistence;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates <see cref="SdmVerificationOutcome"/>'s static factory methods - the "which
/// outcome subtype for this raw result" mapping that used to live in
/// <see cref="SdmVerificationOrchestrator"/> as inline switches. Testing it here directly
/// (independent of the orchestrator) is exactly the benefit of centralizing it on the
/// outcome type: this mapping is now a pure function, trivially unit-testable on its own.
/// </summary>
public class SdmVerificationOutcomeTests
{
    private static readonly NtagSDMData Data = new("04A1B2C3D4E5F6", null, "000001", "AABBCCDDEEFF0011");

    [Fact]
    public void ForCompanyUnknown_ReturnsCompanyUnknownWithCode()
    {
        SdmVerificationOutcome outcome = SdmVerificationOutcome.ForCompanyUnknown(Data, "ACME");

        var unknown = Assert.IsType<SdmVerificationOutcome.CompanyUnknown>(outcome);
        Assert.Same(Data, unknown.Data);
        Assert.Equal("ACME", unknown.CompanyCode);
        Assert.False(unknown.IsSuccess);
    }

    [Fact]
    public void FromReplayPreCheck_Duplicate_ReturnsDuplicateOfLastAccepted()
    {
        SdmVerificationOutcome? outcome = SdmVerificationOutcome.FromReplayPreCheck(Data, ReplayPreCheckResult.Duplicate);

        var duplicate = Assert.IsType<SdmVerificationOutcome.DuplicateOfLastAccepted>(outcome);
        Assert.Same(Data, duplicate.Data);
        Assert.True(duplicate.IsSuccess);
    }

    [Fact]
    public void FromReplayPreCheck_Rejected_ReturnsReplayRejected()
    {
        SdmVerificationOutcome? outcome = SdmVerificationOutcome.FromReplayPreCheck(Data, ReplayPreCheckResult.Rejected);

        var rejected = Assert.IsType<SdmVerificationOutcome.ReplayRejected>(outcome);
        Assert.Same(Data, rejected.Data);
        Assert.False(rejected.IsSuccess);
    }

    [Fact]
    public void FromReplayPreCheck_Proceed_ReturnsNull()
    {
        SdmVerificationOutcome? outcome = SdmVerificationOutcome.FromReplayPreCheck(Data, ReplayPreCheckResult.Proceed);

        Assert.Null(outcome);
    }

    [Theory]
    [InlineData(TagKeyLookupStatus.NotFound)]
    [InlineData(TagKeyLookupStatus.ServiceError)]
    public void ForTagKeyUnavailable_ReturnsTagKeyUnavailableWithReason(TagKeyLookupStatus reason)
    {
        SdmVerificationOutcome outcome = SdmVerificationOutcome.ForTagKeyUnavailable(Data, reason);

        var unavailable = Assert.IsType<SdmVerificationOutcome.TagKeyUnavailable>(outcome);
        Assert.Same(Data, unavailable.Data);
        Assert.Equal(reason, unavailable.Reason);
        Assert.False(unavailable.IsSuccess);
    }

    [Fact]
    public void ForCmacInvalid_ReturnsCmacInvalid()
    {
        SdmVerificationOutcome outcome = SdmVerificationOutcome.ForCmacInvalid(Data);

        var invalid = Assert.IsType<SdmVerificationOutcome.CmacInvalid>(outcome);
        Assert.Same(Data, invalid.Data);
        Assert.False(invalid.IsSuccess);
    }

    [Fact]
    public void FromReplayCommit_Accepted_ReturnsAccepted()
    {
        SdmVerificationOutcome outcome = SdmVerificationOutcome.FromReplayCommit(Data, ReplayCommitResult.Accepted);

        var accepted = Assert.IsType<SdmVerificationOutcome.Accepted>(outcome);
        Assert.Same(Data, accepted.Data);
        Assert.True(accepted.IsSuccess);
    }

    [Fact]
    public void FromReplayCommit_Rejected_ReturnsReplayLostRace()
    {
        SdmVerificationOutcome outcome = SdmVerificationOutcome.FromReplayCommit(Data, ReplayCommitResult.Rejected);

        var lostRace = Assert.IsType<SdmVerificationOutcome.ReplayLostRace>(outcome);
        Assert.Same(Data, lostRace.Data);
        Assert.False(lostRace.IsSuccess);
    }

    [Fact]
    public void MalformedRequest_HasNullData()
    {
        var outcome = new SdmVerificationOutcome.MalformedRequest();

        Assert.Null(outcome.Data);
        Assert.False(outcome.IsSuccess);
    }
}
