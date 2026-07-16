using BenchmarkDotNet.Attributes;
using MacCounter;
using Ntag424.Cmac;
using Ntag424.Cmac.Codecs;
using Ntag424.Cmac.Comparison;
using Ntag424.Cmac.Cryptography;
using Ntag424.Cmac.MessagePolicies;
using Ntag424.Cmac.SessionVectors;
using Ntag424.Cmac.Truncation;

namespace Ntag424Cmac.Benchmarks;

/// <summary>
/// Compares the original byte[]-allocating CMAC verification approach (<see cref="MishaAlg"/>,
/// BouncyCastle-based) against the current Span/stackalloc-based
/// <see cref="Ntag424CmacVerifier"/>, for both processing speed and memory (allocations +
/// GC generation counts, via <see cref="MemoryDiagnoserAttribute"/>).
///
/// Three benchmark methods per vector:
/// - <see cref="MishaAlg_Verify_NaturalUrl"/>: mishaAlg's real entry point, including its
///   own URL/query-string parsing - representative of its actual historical usage.
/// - <see cref="MishaAlg_VerifyCore_Normalized"/>: mishaAlg's CMAC computation only, fed
///   pre-parsed fields - a fair, apples-to-apples pairing with
///   <see cref="Ntag424CmacVerifier_Verify"/> below (neither does URL parsing), isolating
///   the byte[]-vs-Span allocation-style difference from URL-parsing overhead.
/// - <see cref="Ntag424CmacVerifier_Verify"/>: the current implementation, wired with
///   <see cref="PlainMacEqualityComparer"/> (not the constant-time production default) so
///   the deliberately-constant cost of <see cref="FixedTimeMacEqualityComparer"/> doesn't
///   obscure the CMAC-computation comparison itself.
/// </summary>
[MemoryDiagnoser(displayGenColumns: true)]
public class CmacVerificationBenchmarks
{
    public static IEnumerable<CmacTestVector> Vectors => CmacTestVectors.All;

    [ParamsSource(nameof(Vectors))]
    public CmacTestVector Vector { get; set; } = null!;

    private INtag424CmacVerifier _verifier = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        // Matches this vector's confirmed real-world wiring (Table 5 + numeric
        // little-endian counter), but with the plain (non-constant-time) equality
        // comparer - see class remarks for why.
        _verifier = new Ntag424CmacVerifier(
            new AesCmacCalculator(),
            new Sv2SessionVectorBuilder(),
            new MirroredDataCmacMessagePolicy(),
            new OddByteOffsetTruncationPolicy(),
            new Base64MasterKeyCodec(),
            new HexUidCodec(),
            new NumericLittleEndianCounterCodec(),
            new PlainMacEqualityComparer());
    }

    [Benchmark(Baseline = true)]
    public bool MishaAlg_Verify_NaturalUrl() =>
        MishaAlg.Verify(Vector.Url, Vector.MasterKeyBytes);

    [Benchmark]
    public bool MishaAlg_VerifyCore_Normalized() =>
        MishaAlg.VerifyCore(Vector.UidBytes, Vector.CounterLsbBytes, Vector.MirroredData, Vector.MasterKeyBytes, Vector.MacHex);

    [Benchmark]
    public bool Ntag424CmacVerifier_Verify() =>
        _verifier.Verify(new Ntag424SdmCmacRequest(
            Vector.UidHex, Vector.CounterHex, Vector.MacHex, Vector.MasterKeyBase64, Vector.MirroredData));
}
