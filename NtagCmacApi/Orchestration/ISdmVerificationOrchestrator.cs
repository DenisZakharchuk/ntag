namespace NtagCmacApi.Orchestration;

public interface ISdmVerificationOrchestrator
{
    Task<SdmVerificationOutcome> VerifyAsync(SdmVerifyCommand command, CancellationToken cancellationToken);
}
