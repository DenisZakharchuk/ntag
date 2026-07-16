namespace Ntag424.Cmac.Comparison;

/// <summary>
/// Compares a computed truncated CMAC against the value received from the tag. Extracted
/// as its own policy (Dependency Inversion Principle) so the actual comparison strategy -
/// constant-time in production, but potentially something else for testing/benchmarking -
/// can be swapped without touching <see cref="Ntag424CmacVerifier"/> itself.
/// </summary>
public interface IMacEqualityComparer
{
    /// <summary>
    /// Returns whether <paramref name="left"/> and <paramref name="right"/> contain the
    /// same bytes. Implementations decide whether this is constant-time or not - see
    /// <see cref="FixedTimeMacEqualityComparer"/> (production default) and
    /// <see cref="PlainMacEqualityComparer"/> (benchmark/test only).
    /// </summary>
    bool AreEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right);
}
