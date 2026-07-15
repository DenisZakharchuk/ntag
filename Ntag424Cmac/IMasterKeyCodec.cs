using System;

namespace Ntag424.Cmac;

/// <summary>
/// Decodes the tag's AES-128 master key from its wire representation into raw bytes.
/// Extracted as its own policy (Single Responsibility/OCP) so the encoding convention can
/// be swapped without touching <see cref="Ntag424CmacVerifier"/>.
/// </summary>
public interface IMasterKeyCodec
{
    /// <summary>
    /// Attempts to decode <paramref name="masterKeyBase64"/> into <paramref name="masterKey"/>,
    /// which is always exactly 16 bytes. Returns <see langword="false"/> on any malformed
    /// or wrong-length input - callers must fail closed, never throw.
    /// </summary>
    bool TryDecode(ReadOnlySpan<char> masterKeyBase64, Span<byte> masterKey);
}
