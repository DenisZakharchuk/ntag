using System;

namespace Ntag424.Cmac.MessagePolicies;

/// <summary>
/// <see cref="ISdmMacMessagePolicy"/> for NXP AN12196 Table 5
/// (<c>SDMMACInputOffset != SDMMACOffset</c>): the final SDMMAC is computed over the
/// literal bytes that sit between the two configured offsets on the tag's NDEF template -
/// static URL text and/or additional mirrored (plaintext) file data - instead of an empty
/// message. The caller is responsible for extracting exactly that byte range from the raw
/// tag read (this policy has no awareness of URL structure; it MACs whatever bytes it is
/// given, verbatim).
///
/// <para>
/// <b>Validation status:</b> confirmed correct for at least one real captured tag read
/// (combined with a little-endian/LSB-first counter encoding - see
/// <c>Ntag424.Cmac.Codecs.NumericLittleEndianCounterCodec</c>), cross-validated against an
/// independent BouncyCastle-based implementation. See repo memory notes for the specific
/// vector and investigation.
/// </para>
/// </summary>
public sealed class MirroredDataCmacMessagePolicy : ISdmMacMessagePolicy
{
    public int GetMessageLength(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, ReadOnlySpan<byte> mirroredData)
        => mirroredData.Length;

    public void WriteMessage(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, ReadOnlySpan<byte> mirroredData, Span<byte> message)
        => mirroredData.CopyTo(message);
}
