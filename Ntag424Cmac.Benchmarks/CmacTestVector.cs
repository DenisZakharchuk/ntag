namespace Ntag424Cmac.Benchmarks;

/// <summary>
/// A single confirmed CMAC verification sample, expressed both as a raw scanned URL (for
/// benchmarking the natural end-to-end entry points) and as pre-parsed fields (for
/// benchmarking the "core" CMAC-computation-only entry points, with URL/query parsing
/// excluded). Add more instances to <see cref="CmacTestVectors.All"/> as additional
/// confirmed vectors become available - nothing else needs to change.
/// </summary>
public sealed class CmacTestVector
{
    public required string Name { get; init; }
    public required string Url { get; init; }
    public required string MasterKeyBase64 { get; init; }
    public required string UidHex { get; init; }
    public required string CounterHex { get; init; }
    public required string MacHex { get; init; }
    public required string MirroredData { get; init; }

    /// <summary>Decoded master key bytes, for the mishaAlg entry points which take a raw key.</summary>
    public byte[] MasterKeyBytes => Convert.FromBase64String(MasterKeyBase64);

    /// <summary>Decoded UID bytes, for <see cref="MacCounter.MishaAlg.VerifyCore"/>.</summary>
    public byte[] UidBytes => Convert.FromHexString(UidHex);

    /// <summary>
    /// The 3-byte little-endian/LSB-first counter encoding mishaAlg's <c>BuildSv2</c>
    /// expects (matches this vector's confirmed real-world <c>NumericLittleEndianCounterCodec</c>
    /// wiring on the Ntag424Cmac side).
    /// </summary>
    public byte[] CounterLsbBytes
    {
        get
        {
            uint ctr = Convert.ToUInt32(CounterHex, 16);
            return [(byte)(ctr & 0xFF), (byte)((ctr >> 8) & 0xFF), (byte)((ctr >> 16) & 0xFF)];
        }
    }

    // BenchmarkDotNet uses ToString() to label parameterized benchmark rows.
    public override string ToString() => Name;
}
