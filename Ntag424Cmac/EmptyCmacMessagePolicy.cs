using System;

namespace Ntag424.Cmac;

/// <summary>
/// Default <see cref="ISdmMacMessagePolicy"/> matching NXP AN12196 Table 4
/// (<c>SDMMACInputOffset == SDMMACOffset</c>): the final SDMMAC is computed over a
/// zero-length message, since UID and SDMReadCtr are already authenticated implicitly
/// via the session vector -> session key derivation.
/// </summary>
public sealed class EmptyCmacMessagePolicy : ISdmMacMessagePolicy
{
    public int GetMessageLength(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter) => 0;

    public void WriteMessage(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, Span<byte> message)
    {
        // Nothing to write - the message is empty by definition.
    }
}
