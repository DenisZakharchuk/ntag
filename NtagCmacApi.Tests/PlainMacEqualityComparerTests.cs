using Ntag424.Cmac.Comparison;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates <see cref="PlainMacEqualityComparer"/>'s equal/unequal/length-mismatch
/// contract. This comparer is benchmark/test-only (NOT constant-time) - see its XML docs -
/// so these tests only confirm it behaves like a correct equality check, not that it has
/// any particular timing characteristic.
/// </summary>
public class PlainMacEqualityComparerTests
{
    private static readonly IMacEqualityComparer Comparer = new PlainMacEqualityComparer();

    [Fact]
    public void AreEqual_SameBytes_ReturnsTrue()
    {
        byte[] left = [0x01, 0x02, 0x03, 0x04];
        byte[] right = [0x01, 0x02, 0x03, 0x04];

        Assert.True(Comparer.AreEqual(left, right));
    }

    [Fact]
    public void AreEqual_DifferentBytesSameLength_ReturnsFalse()
    {
        byte[] left = [0x01, 0x02, 0x03, 0x04];
        byte[] right = [0x01, 0x02, 0x03, 0xFF];

        Assert.False(Comparer.AreEqual(left, right));
    }

    [Fact]
    public void AreEqual_DifferentLength_ReturnsFalse()
    {
        byte[] left = [0x01, 0x02, 0x03, 0x04];
        byte[] right = [0x01, 0x02, 0x03];

        Assert.False(Comparer.AreEqual(left, right));
    }

    [Fact]
    public void AreEqual_BothEmpty_ReturnsTrue()
    {
        Assert.True(Comparer.AreEqual([], []));
    }
}
