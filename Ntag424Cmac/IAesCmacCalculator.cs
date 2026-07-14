using System;

namespace Ntag424.Cmac;

/// <summary>
/// Computes an AES-128 CMAC (RFC 4493 / NIST SP 800-38B) over a message with a given key.
/// Isolated behind an interface (Dependency Inversion) so <see cref="Ntag424CmacVerifier"/>
/// depends only on this abstraction, not on a concrete AES/CMAC implementation - e.g. a
/// hardware-security-module-backed calculator could be substituted without touching the
/// verifier.
/// </summary>
public interface IAesCmacCalculator
{
    /// <summary>
    /// Computes the 16-byte AES-CMAC of <paramref name="message"/> under <paramref name="key"/>
    /// and writes it to <paramref name="outputMac"/> (which must be at least 16 bytes).
    /// </summary>
    void ComputeCmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> outputMac);
}
