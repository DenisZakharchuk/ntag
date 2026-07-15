using System;
using Ntag424.Cmac;
using Ntag424.Cmac.Cryptography;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates the full SDM CMAC pipeline against the official worked example published in
/// NXP AN12196 ("NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints"), Table 4:
/// "CMAC calculation when SDMMACInputOffset == SDMMACOffset" - i.e. the common
/// configuration where nothing else is mirrored between the UID/counter and the CMAC
/// (a plain uid+counter+cmac URL, matching this project's default <see cref="Ntag424CmacVerifier"/>
/// configuration).
///
/// This is the strongest available validation of the SDM-specific parts of the
/// algorithm (SV2 construction, CMAC-based session key derivation, and the fact that
/// the final SDMMAC covers a zero-length message rather than UID+Counter) since it
/// comes directly from NXP rather than from self-consistency checks alone.
///
/// Exercises <see cref="IAesCmacCalculator"/> and <see cref="INtag424CmacVerifier"/>
/// directly rather than the static facade.
/// </summary>
public class An12196Table4VectorTests
{
    // AN12196 Table 4, item 1. All-zero 16-byte AES-128 master key.
    // (The document's printed value has 34 hex characters, one byte too many - almost
    // certainly a copy/paste artifact - so this uses the unambiguous 16-zero-byte key.)
    private static readonly byte[] MasterKey = new byte[16];

    // AN12196 Table 4, item 5. 7-byte UID.
    private static readonly byte[] Uid = Convert.FromHexString("04DE5F1EACC040");

    // AN12196 Table 4, item 6. 3-byte SDM read counter.
    private static readonly byte[] SdmReadCtr = Convert.FromHexString("3D0000");

    // AN12196 Table 4, item 12. SV2 = 3CC3 0001 0080 || UID || SDMReadCtr.
    private const string ExpectedSv2Hex = "3CC30001008004DE5F1EACC0403D0000";

    // AN12196 Table 4, item 13. KSesSDMFileReadMAC = MAC(KSDMFileRead; SV2).
    private const string ExpectedSessionKeyHex = "3FB5F6E3A807A03D5E3570ACE393776F";

    // AN12196 Table 4, item 14. SDMMAC = MACt(KSesSDMFileReadMAC; zero length input).
    private const string ExpectedTruncatedCmacHex = "94EED9EE65337086";

    private static readonly IAesCmacCalculator CmacCalculator = new AesCmacCalculator();
    private static readonly INtag424CmacVerifier Verifier = Ntag424CmacVerifier.CreateDefault();

    private static byte[] BuildSv2()
    {
        byte[] sv2 = new byte[16];
        sv2[0] = 0x3C;
        sv2[1] = 0xC3;
        sv2[2] = 0x00;
        sv2[3] = 0x01;
        sv2[4] = 0x00;
        sv2[5] = 0x80;
        Uid.CopyTo(sv2, 6);
        SdmReadCtr.CopyTo(sv2, 13);
        return sv2;
    }

    [Fact]
    public void Sv2Construction_MatchesOfficialVector()
    {
        byte[] sv2 = BuildSv2();

        Assert.Equal(ExpectedSv2Hex, Convert.ToHexString(sv2));
    }

    [Fact]
    public void SessionKeyDerivation_MatchesOfficialVector()
    {
        byte[] sv2 = BuildSv2();
        Span<byte> sessionKey = stackalloc byte[16];

        CmacCalculator.ComputeCmac(MasterKey, sv2, sessionKey);

        Assert.Equal(ExpectedSessionKeyHex, Convert.ToHexString(sessionKey));
    }

    [Fact]
    public void FinalTruncatedCmac_MatchesOfficialVector()
    {
        byte[] sv2 = BuildSv2();
        Span<byte> sessionKey = stackalloc byte[16];
        CmacCalculator.ComputeCmac(MasterKey, sv2, sessionKey);

        Span<byte> fullMac = stackalloc byte[16];
        CmacCalculator.ComputeCmac(sessionKey, ReadOnlySpan<byte>.Empty, fullMac);

        Span<byte> truncated = stackalloc byte[8];
        for (int i = 0; i < 8; i++)
        {
            truncated[i] = fullMac[i * 2 + 1];
        }

        Assert.Equal(ExpectedTruncatedCmacHex, Convert.ToHexString(truncated));
    }

    [Fact]
    public void VerifyCmac_AcceptsOfficialVectorEndToEnd()
    {
        string masterKeyBase64 = Convert.ToBase64String(MasterKey);
        string uidHex = Convert.ToHexString(Uid);
        string counterHex = Convert.ToHexString(SdmReadCtr);

        bool result = Verifier.Verify(new Ntag424SdmCmacRequest(
            uidHex,
            counterHex,
            ExpectedTruncatedCmacHex,
            masterKeyBase64));

        Assert.True(result);
    }
}
