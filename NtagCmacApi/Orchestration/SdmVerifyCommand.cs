namespace NtagCmacApi.Orchestration;

/// <summary>
/// Input to <see cref="ISdmVerificationOrchestrator.VerifyAsync"/>: the raw fields an
/// NTAG 424 DNA tag places in its SDM URL (uid/counter/cmac query parameters), plus the
/// caller-supplied company context. Plain strings (not the zero-alloc
/// <c>Ntag424SdmCmacRequest</c> ref struct) because this command flows through
/// async/await, where ref structs cannot be used.
/// </summary>
/// <param name="CompanyCode">
/// The business code of the company/tenant this verification request is made on behalf
/// of - supplied by the caller of the verification API (not mirrored by the tag itself).
/// Required: resolved to a <c>Models.Company</c> (with its persisted id) early in the
/// orchestration pipeline, since <c>Persistence.TagReplayState.CompanyId</c> is a
/// mandatory FK - an unresolvable code fails the request before any replay/key/CMAC work.
/// </param>
/// <param name="MirroredData">
/// The literal ASCII bytes mirrored between <c>SDMMACInputOffset</c> and
/// <c>SDMMACOffset</c> on the tag's NDEF template (AN12196 Table 5 case only) - e.g. a
/// static "serial" value baked into the URL template. Leave <see langword="null"/>/empty
/// for the common Table 4 case; ignored entirely unless the composed
/// <c>ISdmMacMessagePolicy</c> is <c>MirroredDataCmacMessagePolicy</c>.
/// </param>
/// <param name="Serial">
/// The raw "serial" value itself, if the tag's URL mirrors one (distinct from
/// <paramref name="MirroredData"/>, which is the full literal message bytes used for CMAC
/// verification - this is just the field value, carried through to the
/// <c>NtagSDMData</c> domain model for persistence/business-logic use).
/// </param>
public sealed record SdmVerifyCommand(
    string Uid,
    string Counter,
    string Cmac,
    string CompanyCode,
    string? MirroredData = null,
    string? Serial = null);
