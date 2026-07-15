using System;
using Ntag424.Cmac;
using Ntag424.Cmac.Cryptography;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates the core AES-CMAC implementation against the well-known RFC 4493 / NIST
/// SP 800-38B AES-128 test vectors. This is the strongest external validation available
/// without a physical NTAG 424 DNA tag, and it exercises every code path used by the
/// verifier: the empty-message case (K2 padding branch), the single-complete-block case
/// (K1 branch, identical shape to the SDM session-key derivation), and a multi-block
/// message (exercises the block-chaining loop, including in-place ECB encryption).
///
/// Exercises <see cref="IAesCmacCalculator"/> directly (via its default
/// <see cref="AesCmacCalculator"/> implementation) rather than the static facade, so this
/// suite validates the same abstraction production code depends on.
/// </summary>
public class AesCmacTests
{
    private static readonly byte[] Key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
    private static readonly IAesCmacCalculator Calculator = new AesCmacCalculator();

    [Fact]
    public void EmptyMessage_MatchesRfc4493Vector()
    {
        Span<byte> mac = stackalloc byte[16];
        Calculator.ComputeCmac(Key, ReadOnlySpan<byte>.Empty, mac);

        Assert.Equal("bb1d6929e95937287fa37d129b756746", Convert.ToHexString(mac).ToLowerInvariant());
    }

    [Fact]
    public void SingleCompleteBlock_MatchesRfc4493Vector()
    {
        byte[] message = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a");
        Span<byte> mac = stackalloc byte[16];
        Calculator.ComputeCmac(Key, message, mac);

        Assert.Equal("070a16b46b4d4144f79bdd9dd04a287c", Convert.ToHexString(mac).ToLowerInvariant());
    }

    [Fact]
    public void MultiBlockPartialMessage_MatchesRfc4493Vector()
    {
        byte[] message = Convert.FromHexString(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411");
        Span<byte> mac = stackalloc byte[16];
        Calculator.ComputeCmac(Key, message, mac);

        Assert.Equal("dfa66747de9ae63030ca32611497c827", Convert.ToHexString(mac).ToLowerInvariant());
    }
}
