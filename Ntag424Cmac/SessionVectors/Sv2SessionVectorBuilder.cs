using System;

namespace Ntag424.Cmac.SessionVectors;

/// <summary>
/// Builds the standard NTAG 424 DNA SDM session vector, SV2, per NXP AN12196:
/// <c>SV2 = 0x3C 0xC3 0x00 0x01 0x00 0x80 || UID(7) || SDMReadCtr(3)</c> - exactly one
/// 16-byte AES block.
/// </summary>
public sealed class Sv2SessionVectorBuilder : ISdmSessionVectorBuilder
{
    public int SessionVectorLength => 16;

    public void Build(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, Span<byte> sessionVector)
    {
        if (uid.Length != 7) throw new ArgumentException("UID must be 7 bytes.", nameof(uid));
        if (counter.Length != 3) throw new ArgumentException("Counter must be 3 bytes.", nameof(counter));
        if (sessionVector.Length < SessionVectorLength) throw new ArgumentException("Buffer too small.", nameof(sessionVector));

        sessionVector[0] = 0x3C;
        sessionVector[1] = 0xC3;
        sessionVector[2] = 0x00;
        sessionVector[3] = 0x01;
        sessionVector[4] = 0x00;
        sessionVector[5] = 0x80;
        uid.CopyTo(sessionVector.Slice(6, 7));
        counter.CopyTo(sessionVector.Slice(13, 3));
    }
}
