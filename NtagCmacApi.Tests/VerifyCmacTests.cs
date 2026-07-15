using System;
using Ntag424.Cmac;
using Ntag424.Cmac.Cryptography;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// End-to-end self-consistency checks for <see cref="Ntag424CmacVerifier"/>.
/// These do not replace validation against a real NTAG 424 DNA tag (no official test
/// vectors were available offline), but they pin down the full pipeline - hex/base64
/// decoding, SV construction, CMAC-based session key derivation, and odd-byte
/// truncation - against regressions, and confirm tampering is correctly rejected.
///
/// Exercises <see cref="INtag424CmacVerifier"/> (via <see cref="Ntag424CmacVerifier.CreateDefault"/>)
/// and the <see cref="Ntag424SdmCmacRequest"/> ref struct directly, rather than the static facade.
/// </summary>
public class VerifyCmacTests
{
    private const string MasterKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAA=="; // 16 zero bytes
    private const string UidHex = "04A1B2C3D4E5F6";
    private const string CounterHex = "000001";

    private static readonly IAesCmacCalculator CmacCalculator = new AesCmacCalculator();
    private static readonly INtag424CmacVerifier Verifier = Ntag424CmacVerifier.CreateDefault();

    private static string ComputeExpectedCmacHex()
    {
        byte[] masterKey = Convert.FromBase64String(MasterKeyBase64);
        byte[] uid = Convert.FromHexString(UidHex);
        byte[] counter = Convert.FromHexString(CounterHex);

        Span<byte> sv = stackalloc byte[16];
        sv[0] = 0x3C;
        sv[1] = 0xC3;
        sv[2] = 0x00;
        sv[3] = 0x01;
        sv[4] = 0x00;
        sv[5] = 0x80;
        uid.CopyTo(sv.Slice(6, 7));
        counter.CopyTo(sv.Slice(13, 3));

        Span<byte> sessionKey = stackalloc byte[16];
        CmacCalculator.ComputeCmac(masterKey, sv, sessionKey);

        // Per AN12196 Table 4 (SDMMACInputOffset == SDMMACOffset), the final CMAC is
        // computed over a zero-length message; UID/counter are already authenticated
        // via SV2 -> SessionKey.
        Span<byte> fullMac = stackalloc byte[16];
        CmacCalculator.ComputeCmac(sessionKey, ReadOnlySpan<byte>.Empty, fullMac);

        Span<byte> truncated = stackalloc byte[8];
        for (int i = 0; i < 8; i++)
        {
            truncated[i] = fullMac[i * 2 + 1];
        }

        return Convert.ToHexString(truncated);
    }

    [Fact]
    public void ValidCmac_IsAccepted()
    {
        string expectedCmacHex = ComputeExpectedCmacHex();

        bool result = Verifier.Verify(new Ntag424SdmCmacRequest(UidHex, CounterHex, expectedCmacHex, MasterKeyBase64));

        Assert.True(result);
    }

    [Fact]
    public void TamperedCmac_IsRejected()
    {
        string expectedCmacHex = ComputeExpectedCmacHex();
        char[] tampered = expectedCmacHex.ToCharArray();
        tampered[0] = tampered[0] == '0' ? '1' : '0';

        bool result = Verifier.Verify(new Ntag424SdmCmacRequest(UidHex, CounterHex, new string(tampered), MasterKeyBase64));

        Assert.False(result);
    }

    [Fact]
    public void TamperedCounter_IsRejected()
    {
        string expectedCmacHex = ComputeExpectedCmacHex();

        bool result = Verifier.Verify(new Ntag424SdmCmacRequest(UidHex, "000002", expectedCmacHex, MasterKeyBase64));

        Assert.False(result);
    }

    [Theory]
    [InlineData("0102", CounterHex, "0000000000000000", MasterKeyBase64)] // UID too short
    [InlineData(UidHex, "01", "0000000000000000", MasterKeyBase64)]      // Counter too short
    [InlineData(UidHex, CounterHex, "00", MasterKeyBase64)]              // CMAC too short
    [InlineData(UidHex, CounterHex, "0000000000000000", "AAAA")]         // Key too short
    public void MalformedInput_IsRejectedWithoutThrowing(string uid, string counter, string cmac, string keyB64)
    {
        bool result = Verifier.Verify(new Ntag424SdmCmacRequest(uid, counter, cmac, keyB64));

        Assert.False(result);
    }
}
