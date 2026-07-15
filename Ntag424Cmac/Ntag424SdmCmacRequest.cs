using System;

namespace Ntag424.Cmac;

/// <summary>
/// Immutable input payload for <see cref="INtag424CmacVerifier.Verify"/>.
/// Declared as a <c>ref struct</c> so it can carry <see cref="ReadOnlySpan{Char}"/>
/// fields (pointing directly at caller-owned buffers, e.g. an ASP.NET Core request's
/// query string) with zero heap allocation and zero copying of the underlying text.
/// </summary>
public readonly ref struct Ntag424SdmCmacRequest
{
    /// <summary>7-byte tag UID, hex-encoded.</summary>
    public ReadOnlySpan<char> UidHex { get; }

    /// <summary>3-byte SDM read counter, hex-encoded.</summary>
    public ReadOnlySpan<char> CounterHex { get; }

    /// <summary>8-byte truncated CMAC received from the tag/reader, hex-encoded.</summary>
    public ReadOnlySpan<char> ReceivedCmacHex { get; }

    /// <summary>16-byte AES-128 master key for this tag, Base64-encoded.</summary>
    public ReadOnlySpan<char> MasterKeyBase64 { get; }

    /// <summary>
    /// The literal ASCII bytes mirrored between <c>SDMMACInputOffset</c> and
    /// <c>SDMMACOffset</c> on the tag's NDEF template (AN12196 Table 5 case only) -
    /// e.g. static URL text and/or mirrored plaintext file data. Empty for the common
    /// Table 4 case (<c>SDMMACInputOffset == SDMMACOffset</c>), where nothing besides
    /// UID/counter/CMAC is mirrored and the final CMAC message is empty by definition.
    /// Ignored entirely by a Table 4 <see cref="ISdmMacMessagePolicy"/>.
    /// </summary>
    public ReadOnlySpan<char> MirroredDataAscii { get; }

    public Ntag424SdmCmacRequest(
        ReadOnlySpan<char> uidHex,
        ReadOnlySpan<char> counterHex,
        ReadOnlySpan<char> receivedCmacHex,
        ReadOnlySpan<char> masterKeyBase64,
        ReadOnlySpan<char> mirroredDataAscii = default)
    {
        UidHex = uidHex;
        CounterHex = counterHex;
        ReceivedCmacHex = receivedCmacHex;
        MasterKeyBase64 = masterKeyBase64;
        MirroredDataAscii = mirroredDataAscii;
    }
}
