using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Ntag424.Cmac;

/// <summary>
/// Orchestrates SDM CMAC verification by decoding inputs and delegating every
/// cryptographic/format decision to injected policies (Dependency Inversion Principle):
/// this class has a single responsibility - the verification workflow - and knows nothing
/// about how AES-CMAC is computed, how the session vector is laid out, what gets MACed,
/// or how the result is truncated. Each of those is a separately swappable
/// implementation (Open/Closed + Liskov Substitution: any conforming implementation of
/// the policy interfaces can be substituted without changing this class's beh/contract).
/// </summary>
public sealed class Ntag424CmacVerifier : INtag424CmacVerifier
{
    private const int MaxSessionVectorLength = 16;
    private const int MaxTruncatedMacLength = 16;
    private const int MaxMacMessageLength = 64;

    private readonly IAesCmacCalculator _cmacCalculator;
    private readonly ISdmSessionVectorBuilder _sessionVectorBuilder;
    private readonly ISdmMacMessagePolicy _macMessagePolicy;
    private readonly ISdmMacTruncationPolicy _truncationPolicy;
    private readonly IMasterKeyCodec _masterKeyCodec;
    private readonly IUidCodec _uidCodec;
    private readonly ICounterCodec _counterCodec;

    public Ntag424CmacVerifier(
        IAesCmacCalculator cmacCalculator,
        ISdmSessionVectorBuilder sessionVectorBuilder,
        ISdmMacMessagePolicy macMessagePolicy,
        ISdmMacTruncationPolicy truncationPolicy,
        IMasterKeyCodec masterKeyCodec,
        IUidCodec uidCodec,
        ICounterCodec counterCodec)
    {
        _cmacCalculator = cmacCalculator ?? throw new ArgumentNullException(nameof(cmacCalculator));
        _sessionVectorBuilder = sessionVectorBuilder ?? throw new ArgumentNullException(nameof(sessionVectorBuilder));
        _macMessagePolicy = macMessagePolicy ?? throw new ArgumentNullException(nameof(macMessagePolicy));
        _truncationPolicy = truncationPolicy ?? throw new ArgumentNullException(nameof(truncationPolicy));
        _masterKeyCodec = masterKeyCodec ?? throw new ArgumentNullException(nameof(masterKeyCodec));
        _uidCodec = uidCodec ?? throw new ArgumentNullException(nameof(uidCodec));
        _counterCodec = counterCodec ?? throw new ArgumentNullException(nameof(counterCodec));
    }

    /// <summary>
    /// Creates a verifier configured with the standard NTAG 424 DNA SDM policies
    /// (AN12196 Table 4: SV2 session vector, empty MAC message, odd-byte truncation,
    /// literal-hex-byte-order UID/counter decoding, Base64 master key decoding).
    /// </summary>
    public static Ntag424CmacVerifier CreateDefault() => new(
        new AesCmacCalculator(),
        new Sv2SessionVectorBuilder(),
        new EmptyCmacMessagePolicy(),
        new OddByteOffsetTruncationPolicy(),
        new Base64MasterKeyCodec(),
        new HexUidCodec(),
        new LiteralHexCounterCodec());

    public bool Verify(in Ntag424SdmCmacRequest request)
    {
        // 1. Decode inputs strictly on the stack, via the injected codecs
        Span<byte> masterKey = stackalloc byte[16];
        if (!_masterKeyCodec.TryDecode(request.MasterKeyBase64, masterKey))
            return false;

        Span<byte> uid = stackalloc byte[7];
        if (!_uidCodec.TryDecode(request.UidHex, uid))
            return false;

        Span<byte> counter = stackalloc byte[3];
        if (!_counterCodec.TryDecode(request.CounterHex, counter))
            return false;

        int truncatedLength = _truncationPolicy.TruncatedLength;
        if (truncatedLength <= 0 || truncatedLength > MaxTruncatedMacLength)
            return false;

        Span<byte> receivedCmacBuffer = stackalloc byte[MaxTruncatedMacLength];
        Span<byte> receivedCmac = receivedCmacBuffer.Slice(0, truncatedLength);
        if (Convert.FromHexString(request.ReceivedCmacHex, receivedCmac, out _, out int cmacBytesWritten) != OperationStatus.Done || cmacBytesWritten != truncatedLength)
            return false;

        // 2. Build the session vector via the injected policy
        int sessionVectorLength = _sessionVectorBuilder.SessionVectorLength;
        if (sessionVectorLength <= 0 || sessionVectorLength > MaxSessionVectorLength)
            return false;

        Span<byte> sessionVectorBuffer = stackalloc byte[MaxSessionVectorLength];
        Span<byte> sessionVector = sessionVectorBuffer.Slice(0, sessionVectorLength);
        _sessionVectorBuilder.Build(uid, counter, sessionVector);

        // 3. Derive the SDM session key: CMAC(MasterKey, SessionVector)
        Span<byte> sessionKey = stackalloc byte[16];
        _cmacCalculator.ComputeCmac(masterKey, sessionVector, sessionKey);

        // 4. Build the MAC input via the injected policy (empty for the standard Table 4
        // case; the literal mirrored-data bytes for the Table 5 case).
        Span<byte> mirroredDataBuffer = stackalloc byte[MaxMacMessageLength];
        if (request.MirroredDataAscii.Length > MaxMacMessageLength)
            return false;
        Span<byte> mirroredData = mirroredDataBuffer.Slice(0, request.MirroredDataAscii.Length);
        Encoding.ASCII.GetBytes(request.MirroredDataAscii, mirroredData);

        int messageLength = _macMessagePolicy.GetMessageLength(uid, counter, mirroredData);
        if (messageLength < 0 || messageLength > MaxMacMessageLength)
            return false;

        Span<byte> messageBuffer = stackalloc byte[MaxMacMessageLength];
        Span<byte> message = messageBuffer.Slice(0, messageLength);
        _macMessagePolicy.WriteMessage(uid, counter, mirroredData, message);

        // 5. Compute the full CMAC: CMAC(SessionKey, Message)
        Span<byte> fullCmac = stackalloc byte[16];
        _cmacCalculator.ComputeCmac(sessionKey, message, fullCmac);

        // 6. Truncate via the injected policy & compare in constant time
        Span<byte> truncatedCmacBuffer = stackalloc byte[MaxTruncatedMacLength];
        Span<byte> truncatedCmac = truncatedCmacBuffer.Slice(0, truncatedLength);
        _truncationPolicy.Truncate(fullCmac, truncatedCmac);

        return CryptographicOperations.FixedTimeEquals(truncatedCmac, receivedCmac);
    }
}
