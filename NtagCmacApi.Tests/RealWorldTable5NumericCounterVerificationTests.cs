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
/// Regression test for a REAL, confirmed-valid captured tag read (not a self-consistency
/// check or an official NXP-published vector, but cross-validated against an independent
/// BouncyCastle-based implementation - see repo memory notes for the full investigation).
///
/// This deployment's tags use:
/// - AN12196 Table 5 (<see cref="MirroredDataCmacMessagePolicy"/>): the final CMAC message
///   is the literal query text from right after "?" through and including the literal
///   "mac=" text (i.e. <c>SDMMACOffset</c> lands right where the truncated MAC's hex
///   digits begin).
/// - A little-endian/LSB-first counter encoding (<see cref="NumericLittleEndianCounterCodec"/>):
///   "ctr=000001" is parsed as the number 1 and re-encoded as [0x01, 0x00, 0x00] for SV2,
///   rather than being taken literally in written byte order like NXP's own official
///   Table 4 worked example.
///
/// Neither piece alone reproduces the MAC; only the combination does.
/// </summary>
public class RealWorldTable5NumericCounterVerificationTests
{
    private const string UidHex = "04B43132502390";
    private const string CounterHex = "000001";
    private const string MacHex = "E7D76C550FF1755B";
    private const string MasterKeyBase64 = "c55sauQ+2NDG3ZX6P0Yz+Q==";
    private const string MirroredData = "serial=11111111&uid=04B43132502390&ctr=000001&mac=";

    private static INtag424CmacVerifier CreateVerifier() => new Ntag424CmacVerifier(
        new AesCmacCalculator(),
        new Sv2SessionVectorBuilder(),
        new MirroredDataCmacMessagePolicy(),
        new OddByteOffsetTruncationPolicy(),
        new Base64MasterKeyCodec(),
        new HexUidCodec(),
        new NumericLittleEndianCounterCodec(),
        new FixedTimeMacEqualityComparer());

    [Fact]
    public void Verify_RealCapturedTuple_ReturnsTrue()
    {
        INtag424CmacVerifier verifier = CreateVerifier();

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, CounterHex, MacHex, MasterKeyBase64, MirroredData));

        Assert.True(result);
    }

    [Fact]
    public void Verify_WrongCounterCodec_ReturnsFalse()
    {
        // Using the default LiteralHexCounterCodec instead of NumericLittleEndian must NOT
        // verify - proves the counter encoding genuinely matters for this vector, not just
        // the mirrored-data message.
        INtag424CmacVerifier verifier = new Ntag424CmacVerifier(
            new AesCmacCalculator(),
            new Sv2SessionVectorBuilder(),
            new MirroredDataCmacMessagePolicy(),
            new OddByteOffsetTruncationPolicy(),
            new Base64MasterKeyCodec(),
            new HexUidCodec(),
            new LiteralHexCounterCodec(),
            new FixedTimeMacEqualityComparer());

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, CounterHex, MacHex, MasterKeyBase64, MirroredData));

        Assert.False(result);
    }

    [Fact]
    public void Verify_WrongMessagePolicy_ReturnsFalse()
    {
        // Using the default EmptyCmacMessagePolicy (Table 4) instead of MirroredData must
        // NOT verify - proves the mirrored-data message genuinely matters, not just the
        // counter encoding.
        INtag424CmacVerifier verifier = new Ntag424CmacVerifier(
            new AesCmacCalculator(),
            new Sv2SessionVectorBuilder(),
            new EmptyCmacMessagePolicy(),
            new OddByteOffsetTruncationPolicy(),
            new Base64MasterKeyCodec(),
            new HexUidCodec(),
            new NumericLittleEndianCounterCodec(),
            new FixedTimeMacEqualityComparer());

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, CounterHex, MacHex, MasterKeyBase64, MirroredData));

        Assert.False(result);
    }

    [Fact]
    public void Verify_TamperedCounter_ReturnsFalse()
    {
        INtag424CmacVerifier verifier = CreateVerifier();

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            UidHex, "000002", MacHex, MasterKeyBase64, MirroredData));

        Assert.False(result);
    }
}
