namespace Ntag424Cmac.Benchmarks;

/// <summary>
/// The set of CMAC vectors benchmarked against every implementation. Currently a single
/// confirmed real-world sample (cross-validated in
/// <c>NtagCmacApi.Tests.RealWorldTable5NumericCounterVerificationTests</c> and matching
/// mishaAlg's own default sample) - append more <see cref="CmacTestVector"/> entries here
/// as additional vectors are confirmed; <see cref="CmacVerificationBenchmarks"/> picks up
/// every entry automatically via <c>[ParamsSource]</c>, no other code changes needed.
/// </summary>
public static class CmacTestVectors
{
    public static IEnumerable<CmacTestVector> All =>
    [
        new CmacTestVector
        {
            Name = "RealWorld-Table5-NumericCounter",
            Url = "https://example.com/?serial=11111111&uid=04B43132502390&ctr=000001&mac=E7D76C550FF1755B",
            MasterKeyBase64 = "c55sauQ+2NDG3ZX6P0Yz+Q==",
            UidHex = "04B43132502390",
            CounterHex = "000001",
            MacHex = "E7D76C550FF1755B",
            MirroredData = "serial=11111111&uid=04B43132502390&ctr=000001&mac=",
        },
    ];
}
