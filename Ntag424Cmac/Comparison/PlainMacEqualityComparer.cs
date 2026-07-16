namespace Ntag424.Cmac.Comparison;

/// <summary>
/// A plain, NOT constant-time <see cref="IMacEqualityComparer"/> (<see cref="ReadOnlySpan{T}.SequenceEqual(ReadOnlySpan{T})"/>,
/// which short-circuits on the first mismatching byte).
///
/// <b>Benchmark/test use only.</b> Never register this in production DI - comparing a
/// received CMAC against a locally computed one this way leaks timing information that
/// could help an attacker recover a valid CMAC byte-by-byte. It exists solely so a
/// benchmark can isolate the cost of the CMAC computation itself (byte[] vs. Span/stackalloc)
/// from the incidental, deliberately-constant cost of <see cref="FixedTimeMacEqualityComparer"/>.
/// </summary>
public sealed class PlainMacEqualityComparer : IMacEqualityComparer
{
    public bool AreEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.SequenceEqual(right);
}
