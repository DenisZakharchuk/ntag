namespace NtagCmacApi.Orchestration;

/// <summary>
/// Validates and parses an incoming <see cref="SdmVerifyCommand"/> before any replay-guard
/// lookup, network call, or crypto work is performed. Extracted as its own policy (OCP) -
/// consistent with the crypto core's <c>ISdmMacMessagePolicy</c>/<c>ISdmMacTruncationPolicy</c>
/// pattern - so the well-formedness rules for a request (field presence, counter hex format,
/// etc.) can change independently of <see cref="SdmVerificationOrchestrator"/>.
/// </summary>
public interface ISdmVerifyCommandValidationPolicy
{
    /// <summary>
    /// Attempts to validate <paramref name="command"/> and parse its hex counter.
    /// Returns <see langword="false"/> (with <paramref name="counterValue"/> set to 0) if
    /// the command is malformed in any way.
    /// </summary>
    bool TryValidate(SdmVerifyCommand command, out int counterValue);
}
