using Ntag424.Cmac;
using Ntag424.Cmac.Codecs;
using Ntag424.Cmac.Comparison;
using Ntag424.Cmac.Cryptography;
using Ntag424.Cmac.MessagePolicies;
using Ntag424.Cmac.SessionVectors;
using Ntag424.Cmac.Truncation;
using NtagCmacApi.Orchestration;
using NtagCmacApi.UrlParsing;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// End-to-end proof that the raw-URL input path (<see cref="SdmUrlParser"/>) combined with
/// the confirmed real-world configuration (<see cref="MirroredDataCmacMessagePolicy"/> +
/// <see cref="NumericLittleEndianCounterCodec"/>) reproduces the same result as manually
/// pre-splitting the URL into discrete fields - i.e. a caller can now submit the exact
/// scanned URL text directly, matching the standalone mishaAlg reference implementation.
/// </summary>
public class RealWorldUrlParsingEndToEndTests
{
    private const string Url = "https://example.com/?serial=11111111&uid=04B43132502390&ctr=000001&mac=E7D76C550FF1755B";
    private const string MasterKeyBase64 = "c55sauQ+2NDG3ZX6P0Yz+Q==";

    private static readonly ISdmUrlParser Parser = new SdmUrlParser();

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
    public void ParseRawUrl_ThenVerify_ReturnsTrue()
    {
        SdmVerifyCommand command = Parser.Parse(Url);
        INtag424CmacVerifier verifier = CreateVerifier();

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            command.Uid, command.Counter, command.Cmac, MasterKeyBase64, command.MirroredData));

        Assert.True(result);
    }

    [Fact]
    public void ParseRawUrl_TamperedUrlCounter_ReturnsFalse()
    {
        const string tamperedUrl = "https://example.com/?serial=11111111&uid=04B43132502390&ctr=000002&mac=E7D76C550FF1755B";
        SdmVerifyCommand command = Parser.Parse(tamperedUrl);
        INtag424CmacVerifier verifier = CreateVerifier();

        bool result = verifier.Verify(new Ntag424SdmCmacRequest(
            command.Uid, command.Counter, command.Cmac, MasterKeyBase64, command.MirroredData));

        Assert.False(result);
    }
}
