using Ntag424.Cmac.Comparison;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates <see cref="FixedTimeMacEqualityComparer"/>'s functional behavior (it delegates
/// to <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals"/>,
/// whose actual constant-time guarantee is a BCL implementation detail not re-verified
/// here - only the equal/unequal/length-mismatch contract is).
/// </summary>
public class FixedTimeMacEqualityComparerTests
{
    private static readonly IMacEqualityComparer Comparer = new FixedTimeMacEqualityComparer();

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
