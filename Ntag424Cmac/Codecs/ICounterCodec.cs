using System;

namespace Ntag424.Cmac.Codecs;

/// <summary>
/// Decodes the tag's 3-byte SDM read counter from its wire (hex) representation into raw
/// bytes for use in the SV2 session vector.
///
/// Extracted as its own policy (Single Responsibility/OCP) because different tag
/// deployments have been observed to present <c>ctr</c> hex text under two different
/// conventions:
/// - Literally, as the raw 3 bytes already in the byte order SV2 expects (this is how
///   NXP's own official AN12196 Table 4 worked example presents <c>SDMReadCtr</c> - see
///   <see cref="LiteralHexCounterCodec"/>).
/// - As a human-readable incrementing counter value (e.g. "this is read #1"), which must
///   be parsed as a number and re-encoded little-endian/LSB-first before use in SV2 (see
///   <see cref="NumericLittleEndianCounterCodec"/> - confirmed against a real captured
///   tag read cross-validated with an independent BouncyCastle-based implementation).
///
/// Swappable via DI so the correct convention for a given deployment can be selected
/// without touching <see cref="Ntag424CmacVerifier"/>.
/// </summary>
public interface ICounterCodec
{
    /// <summary>
    /// Attempts to decode <paramref name="counterHex"/> into <paramref name="counter"/>,
    /// which is always exactly 3 bytes. Returns <see langword="false"/> on any malformed,
    /// out-of-range, or wrong-length input - callers must fail closed, never throw.
    /// </summary>
    bool TryDecode(ReadOnlySpan<char> counterHex, Span<byte> counter);
}
