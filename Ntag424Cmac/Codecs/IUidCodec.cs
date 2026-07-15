using System;

namespace Ntag424.Cmac.Codecs;

/// <summary>
/// Decodes the tag's 7-byte UID from its wire (hex) representation into raw bytes.
/// Extracted as its own policy (Single Responsibility/OCP) so the encoding convention can
/// be swapped without touching <see cref="Ntag424CmacVerifier"/>.
/// </summary>
public interface IUidCodec
{
    /// <summary>
    /// Attempts to decode <paramref name="uidHex"/> into <paramref name="uid"/>, which is
    /// always exactly 7 bytes. Returns <see langword="false"/> on any malformed or
    /// wrong-length input - callers must fail closed, never throw.
    /// </summary>
    bool TryDecode(ReadOnlySpan<char> uidHex, Span<byte> uid);
}
