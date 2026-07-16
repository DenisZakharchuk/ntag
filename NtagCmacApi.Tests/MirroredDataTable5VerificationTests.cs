using System;
using Ntag424.Cmac;
using Ntag424.Cmac.Codecs;
using Ntag424.Cmac.Comparison;
using Ntag424.Cmac.Cryptography;
using Ntag424.Cmac.MessagePolicies;
using Ntag424.Cmac.SessionVectors;
using Ntag424.Cmac.Truncation;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// End-to-end self-consistency checks for the AN12196 Table 5 path
/// (<see cref="MirroredDataCmacMessagePolicy"/>): <see cref="Ntag424CmacVerifier"/> wired
/// with the Table 5 message policy instead of the default Table 4
/// <see cref="EmptyCmacMessagePolicy"/>.
///
/// <b>No official NXP Table 5 test vector was available</b> (unlike Table 4, which is
/// independently confirmed against NXP's official AN12196 Table 4 worked example in
/// <see cref="An12196Table4VectorTests"/>). These tests only pin down internal
/// self-consistency - that mirrored data is actually included in, and required by, the
/// final CMAC - not correctness against a real tag. Do not treat this as validated
/// production behavior until confirmed against an official vector or a known-valid
/// captured read.
/// </summary>
public class MirroredDataTable5VerificationTests
{
    private const string MasterKeyBase64 = "AAAAAAAAAAAAAAAAAAAAAA=="; // 16 zero bytes
    private const string UidHex = "04A1B2C3D4E5F6";
    private const string CounterHex = "000001";
    private const string MirroredData = "serial=548721";

    private static readonly IAesCmacCalculator CmacCalculator = new AesCmacCalculator();

    private static INtag424CmacVerifier CreateTable5Verifier() => new Ntag424CmacVerifier(
        new AesCmacCalculator(),
        new Sv2SessionVectorBuilder(),
        new MirroredDataCmacMessagePolicy(),
        new OddByteOffsetTruncationPolicy(),
        new Base64MasterKeyCodec(),
        new HexUidCodec(),
        new LiteralHexCounterCodec(),
        new FixedTimeMacEqualityComparer());

    private static string ComputeExpectedCmacHex(string mirroredData)
    {
        byte[] masterKey = Convert.FromBase64String(MasterKeyBase64);
        byte[] uid = Convert.FromHexString(UidHex);
        byte[] counter = Convert.FromHexString(CounterHex);
        byte[] message = System.Text.Encoding.ASCII.GetBytes(mirroredData);

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

        // Table 5: the final CMAC message is the literal mirrored-data bytes, not empty.
        Span<byte> fullMac = stackalloc byte[16];
        CmacCalculator.ComputeCmac(sessionKey, message, fullMac);

        Span<byte> truncated = stackalloc byte[8];
        for (int i = 0; i < 8; i++)
        {
            truncated[i] = fullMac[i * 2 + 1];
        }

        return Convert.ToHexString(truncated);
    }

    [Fact]
    public void Verify_ValidCmacWithMatchingMirroredData_ReturnsTrue()
    {
        INtag424CmacVerifier verifier = CreateTable5Verifier();
        string expectedCmacHex = ComputeExpectedCmacHex(MirroredData);

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, CounterHex, expectedCmacHex, MasterKeyBase64, MirroredData));

        Assert.True(result);
    }

    [Fact]
    public void Verify_TamperedMirroredData_ReturnsFalse()
    {
        INtag424CmacVerifier verifier = CreateTable5Verifier();
        string expectedCmacHex = ComputeExpectedCmacHex(MirroredData);

        // Same CMAC as computed for "serial=548721", but presented with a different
        // mirrored-data value - proves mirrored data is actually part of the MAC input,
        // not silently ignored.
        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, CounterHex, expectedCmacHex, MasterKeyBase64, "serial=999999"));

        Assert.False(result);
    }

    [Fact]
    public void Verify_MissingMirroredData_ReturnsFalse()
    {
        INtag424CmacVerifier verifier = CreateTable5Verifier();
        string expectedCmacHex = ComputeExpectedCmacHex(MirroredData);

        // A Table 5 verifier fed a CMAC computed over non-empty mirrored data must reject
        // it when mirrored data is missing (empty message instead).
        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, CounterHex, expectedCmacHex, MasterKeyBase64));

        Assert.False(result);
    }

    [Fact]
    public void Verify_EmptyMirroredDataBothSides_MatchesEmptyMessage()
    {
        INtag424CmacVerifier verifier = CreateTable5Verifier();
        string expectedCmacHex = ComputeExpectedCmacHex(string.Empty);

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, CounterHex, expectedCmacHex, MasterKeyBase64, string.Empty));

        Assert.True(result);
    }
}
