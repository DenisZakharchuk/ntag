namespace NtagCmacApi.Orchestration;

/// <summary>
/// Input to <see cref="ISdmVerificationOrchestrator.VerifyAsync"/>: the raw fields an
/// NTAG 424 DNA tag places in its SDM URL (uid/counter/cmac query parameters). Plain
/// strings (not the zero-alloc <c>Ntag424SdmCmacRequest</c> ref struct) because this
/// command flows through async/await, where ref structs cannot be used.
/// </summary>
public sealed record SdmVerifyCommand(string Uid, string Counter, string Cmac);
