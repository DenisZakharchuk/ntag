using System;

namespace Ntag424.Cmac;

/// <summary>
/// Decides what bytes get MACed under the session key to produce the final SDMMAC.
///
/// Per NXP AN12196, this differs by tag configuration:
/// - Table 4 (<c>SDMMACInputOffset == SDMMACOffset</c>, the common case where nothing
///   besides UID/counter/CMAC is mirrored into the URL): the message is empty - UID and
///   counter are already authenticated implicitly because they're baked into the session
///   vector (SV2) that derived the session key.
/// - Table 5 (<c>SDMMACInputOffset != SDMMACOffset</c>): additional mirrored file data
///   (and surrounding literal URL bytes) sits between the two offsets and must be
///   included as the message instead.
///
/// Extracting this as its own policy (Open/Closed Principle) means the Table 5 case can
/// be supported later by adding a new implementation, without modifying
/// <see cref="Ntag424CmacVerifier"/> itself.
/// </summary>
public interface ISdmMacMessagePolicy
{
    /// <summary>
    /// The length in bytes of the message this policy will write for the given UID/counter.
    /// </summary>
    int GetMessageLength(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter);

    /// <summary>
    /// Writes the message to be MACed into <paramref name="message"/>, which must be at
    /// least <see cref="GetMessageLength"/> bytes.
    /// </summary>
    void WriteMessage(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, Span<byte> message);
}
