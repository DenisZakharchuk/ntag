namespace NtagCmacApi.Orchestration;

/// <summary>
/// Input to <see cref="ISdmVerificationOrchestrator.VerifyAsync"/>: the raw fields an
/// NTAG 424 DNA tag places in its SDM URL (uid/counter/cmac query parameters). Plain
/// strings (not the zero-alloc <c>Ntag424SdmCmacRequest</c> ref struct) because this
/// command flows through async/await, where ref structs cannot be used.
/// </summary>
/// <param name="MirroredData">
/// The literal ASCII bytes mirrored between <c>SDMMACInputOffset</c> and
/// <c>SDMMACOffset</c> on the tag's NDEF template (AN12196 Table 5 case only) - e.g. a
/// static "serial" value baked into the URL template. Leave <see langword="null"/>/empty
/// for the common Table 4 case; ignored entirely unless the composed
/// <c>ISdmMacMessagePolicy</c> is <c>MirroredDataCmacMessagePolicy</c>.
/// </param>
public sealed record SdmVerifyCommand(string Uid, string Counter, string Cmac, string? MirroredData = null);
