using System;
using System.Globalization;

namespace Ntag424.Cmac;

/// <summary>
/// <see cref="ICounterCodec"/> matching the "mishaAlg" reference implementation: the
/// counter hex text is parsed as an unsigned integer (e.g. <c>"000001"</c> -&gt; the
/// value 1) and re-encoded as 3 raw bytes in little-endian/LSB-first order (e.g.
/// <c>[0x01, 0x00, 0x00]</c>) before use in the SV2 session vector - rather than being
/// decoded directly from written hex-byte order like <see cref="LiteralHexCounterCodec"/>.
///
/// Confirmed correct for at least one real captured tag read, cross-validated against an
/// independent BouncyCastle-based implementation (see repo memory notes for the specific
/// vector). Use this when a deployment's <c>ctr</c> values are authored/observed as plain
/// incrementing numbers rather than raw SV2-ready bytes.
/// </summary>
public sealed class NumericLittleEndianCounterCodec : ICounterCodec
{
    private const uint MaxValue = 0xFFFFFF; // 3 bytes

    public bool TryDecode(ReadOnlySpan<char> counterHex, Span<byte> counter)
    {
        if (counter.Length != 3)
            return false;

        if (!uint.TryParse(counterHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint value))
            return false;

        if (value > MaxValue)
            return false;

        counter[0] = (byte)(value & 0xFF);
        counter[1] = (byte)((value >> 8) & 0xFF);
        counter[2] = (byte)((value >> 16) & 0xFF);
        return true;
    }
}
