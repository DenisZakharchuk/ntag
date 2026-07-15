using System;

namespace Ntag424.Cmac;

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
/// <b>Validation status:</b> implemented directly from the documented Table 5 algorithm
/// structure (message = raw bytes of the mirrored region; everything downstream - CMAC
/// derivation, truncation - is the same, already RFC 4493-validated primitive used by
/// <see cref="EmptyCmacMessagePolicy"/>/Table 4). Unlike Table 4 (independently confirmed
/// against NXP's official AN12196 Table 4 worked example), no official NXP Table 5 test
/// vector was available to validate this against. It is currently covered only by
/// self-consistency tests. Treat as unverified against a real tag until confirmed with an
/// official vector or a known-valid captured read.
/// </para>
/// </summary>
public sealed class MirroredDataCmacMessagePolicy : ISdmMacMessagePolicy
{
    public int GetMessageLength(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, ReadOnlySpan<byte> mirroredData)
        => mirroredData.Length;

    public void WriteMessage(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, ReadOnlySpan<byte> mirroredData, Span<byte> message)
        => mirroredData.CopyTo(message);
}
