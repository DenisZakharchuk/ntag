using System;

namespace Ntag424.Cmac.Truncation;

/// <summary>
/// NTAG 424 DNA SDM truncation scheme: keeps the odd-indexed bytes of the full 16-byte
/// CMAC (indices 1,3,5,7,9,11,13,15), producing an 8-byte result. This is NOT the same as
/// taking the first 8 bytes - that common mistake never matches a real tag.
/// </summary>
public sealed class OddByteOffsetTruncationPolicy : ISdmMacTruncationPolicy
{
    public int TruncatedLength => 8;

    public void Truncate(ReadOnlySpan<byte> fullMac, Span<byte> truncatedMac)
    {
        if (fullMac.Length < 16) throw new ArgumentException("Full MAC must be 16 bytes.", nameof(fullMac));
        if (truncatedMac.Length < TruncatedLength) throw new ArgumentException("Buffer too small.", nameof(truncatedMac));

        for (int i = 0; i < TruncatedLength; i++)
        {
            truncatedMac[i] = fullMac[i * 2 + 1];
        }
    }
}
