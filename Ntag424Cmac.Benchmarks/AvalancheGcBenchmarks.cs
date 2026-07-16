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
/// Simulates an "avalanche" of back-to-back verification requests hitting the service
/// (e.g. a burst of tag scans), rather than a single isolated call, to see the CUMULATIVE
/// GC picture (Gen0/Gen1/Gen2 collections, total allocated bytes) for a whole burst - not
/// just a per-call allocation figure. <see cref="CmacVerificationBenchmarks"/> already
/// shows per-call allocation is far lower for the Span-based
/// <see cref="Ntag424CmacVerifier"/>; this class asks the follow-up question: does that
/// difference actually translate into fewer/rarer GC pauses (especially Gen1/Gen2, which a
/// single tiny short-lived allocation would never trigger on its own) once you pile up
/// thousands of requests back-to-back, the way a real burst of traffic would?
///
/// Each <c>[Benchmark]</c> invocation runs <see cref="RequestCount"/> verifications in a
/// tight loop (no <c>OperationsPerInvoke</c> normalization) - so Mean/Allocated/Gen0/Gen1/
/// Gen2 in the results table are reported for the WHOLE BURST, not per single call:
/// - Mean / Allocated: total time / total bytes to process <see cref="RequestCount"/>
///   requests back-to-back.
/// - Gen0 / Gen1 / Gen2: collections per 1000 BURSTS (BenchmarkDotNet's usual unit) - e.g.
///   a value of 500 means roughly 0.5 collections of that generation per single burst of
///   <see cref="RequestCount"/> requests, on average.
///
/// Compares mishaAlg's byte[]-allocating core (`MishaAlg.VerifyCore`, URL-parsing already
/// excluded - see <see cref="CmacVerificationBenchmarks"/>) against the Span/stackalloc-
/// based <see cref="Ntag424CmacVerifier.Verify"/>, wired with <see cref="PlainMacEqualityComparer"/>
/// for the same reason as <see cref="CmacVerificationBenchmarks"/>.
/// </summary>
[MemoryDiagnoser(displayGenColumns: true)]
public class AvalancheGcBenchmarks
{
    [Params(1_000, 10_000, 100_000)]
    public int RequestCount { get; set; }

    private static readonly CmacTestVector Vector = CmacTestVectors.All.First();

    private INtag424CmacVerifier _verifier = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        // Matches this vector's confirmed real-world wiring (Table 5 + numeric
        // little-endian counter), with the plain (non-constant-time) equality comparer -
        // see CmacVerificationBenchmarks remarks for why.
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
    public bool MishaAlg_Avalanche()
    {
        bool result = false;
        for (int i = 0; i < RequestCount; i++)
        {
            result = MishaAlg.VerifyCore(Vector.UidBytes, Vector.CounterLsbBytes, Vector.MirroredData, Vector.MasterKeyBytes, Vector.MacHex);
        }

        return result;
    }

    [Benchmark]
    public bool Ntag424CmacVerifier_Avalanche()
    {
        bool result = false;
        for (int i = 0; i < RequestCount; i++)
        {
            result = _verifier.Verify(new Ntag424SdmCmacRequest(
                Vector.UidHex, Vector.CounterHex, Vector.MacHex, Vector.MasterKeyBase64, Vector.MirroredData));
        }

        return result;
    }
}
