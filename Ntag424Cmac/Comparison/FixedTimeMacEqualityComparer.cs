using System.Security.Cryptography;

namespace Ntag424.Cmac.Comparison;

/// <summary>
/// Production default <see cref="IMacEqualityComparer"/>: delegates to
/// <see cref="CryptographicOperations.FixedTimeEquals"/>, which compares in an amount of
/// time that depends on the sequences' length but not their contents - avoiding a timing
/// side-channel that could otherwise let an attacker recover a valid CMAC byte-by-byte.
/// Always use this (not <see cref="PlainMacEqualityComparer"/>) wherever a received CMAC
/// is compared against a locally computed one.
/// </summary>
public sealed class FixedTimeMacEqualityComparer : IMacEqualityComparer
{
    public bool AreEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        CryptographicOperations.FixedTimeEquals(left, right);
}
