using BenchmarkDotNet.Attributes;
using Ntag424.Cmac.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Ntag424Cmac.Benchmarks;

/// <summary>
/// Isolates WHY <see cref="CmacVerificationBenchmarks.Ntag424CmacVerifier_Verify"/> was
/// slower than mishaAlg's BouncyCastle-based CMAC despite allocating far less managed
/// memory.
///
/// Root cause CONFIRMED and FIXED: <see cref="AesCmacCalculator"/> used to call
/// <c>System.Security.Cryptography.Aes.Create()</c> fresh on every <c>ComputeCmac</c> call
/// (and <c>Verify()</c> calls it twice - once for the session key, once for the final MAC).
/// On Windows, <c>Aes.Create()</c> wraps CNG (BCrypt) - opening a new algorithm/key
/// provider handle is a real native/OS-level cost that does NOT show up as managed
/// "Allocated" bytes in <see cref="MemoryDiagnoserAttribute"/>, unlike BouncyCastle's
/// pure-managed, allocation-visible (but interop-free) software AES.
/// <see cref="AesCmacCalculator"/> now caches a single <see cref="System.Security.Cryptography.Aes"/>
/// instance for its own lifetime instead - see its remarks.
///
/// Remaining gap (NOT fixed - inherent to the algorithm, not an inefficiency): RFC 4493
/// CMAC derives its K1/K2 subkeys from an AES-encryption of an all-zero block under
/// whatever KEY was passed in - so <see cref="AesCmacCalculator.ComputeCmac"/> performs
/// TWO <c>EncryptEcb</c> calls per invocation (subkey derivation + the final block), not
/// one. <see cref="Ntag424.Cmac.Ntag424CmacVerifier.Verify"/> calls it twice with two
/// DIFFERENT keys (master key, then the derived session key) - subkeys genuinely differ
/// each time, so this cost can't be cached/amortized across those two calls. That's 4
/// AES-encrypt operations total per <c>Verify()</c>, vs. mishaAlg's simpler 2-operation
/// shape - a real, structural difference in work done, not a bug.
/// </summary>
[MemoryDiagnoser(displayGenColumns: true)]
public class AesPrimitiveBenchmarks
{
    private static readonly byte[] Key = new byte[16];
    private static readonly byte[] Message = new byte[16];

    // A single AesCmacCalculator instance, matching production usage (Transient - one
    // instance per Ntag424CmacVerifier resolution/request, reused sequentially within it -
    // see AesCmacCalculator's remarks for why caching its Aes instance is safe).
    private readonly IAesCmacCalculator _realAesCmacCalculator = new AesCmacCalculator();

    // --- The REAL (now-fixed) AesCmacCalculator.ComputeCmac, called twice per invocation
    // exactly like Ntag424CmacVerifier.Verify does (session key derivation, then final
    // MAC) - includes RFC 4493's inherent 2x-subkey-derivation cost (see class remarks).
    [Benchmark(Baseline = true)]
    public void Bcl_Aes_RealComputeCmac_TwoCallsPerCall()
    {
        Span<byte> output1 = stackalloc byte[16];
        Span<byte> output2 = stackalloc byte[16];
        _realAesCmacCalculator.ComputeCmac(Key, Message, output1);
        _realAesCmacCalculator.ComputeCmac(Key, output1, output2);
    }

    // --- BCL Aes, cached instance, but a SIMPLIFIED single-EncryptEcb-per-call shape (no
    // subkey derivation/padding) - isolates pure Aes.Create()-overhead-removal from the
    // extra work RFC 4493 itself requires (see Bcl_Aes_RealComputeCmac_TwoCallsPerCall).
    [Benchmark]
    public void Bcl_Aes_CachedInstance_TwoComputationsPerCall()
    {
        Span<byte> output1 = stackalloc byte[16];
        Span<byte> output2 = stackalloc byte[16];
        CachedAesCmac(Key, Message, output1);
        CachedAesCmac(Key, output1, output2);
    }

    // --- BouncyCastle CMac(AesEngine), exactly as mishaAlg uses it: a brand-new
    // CMac(new AesEngine()) + Init() per computation (byte[]-allocating, but WITH the same
    // 1-EncryptEcb-per-call shape as Bcl_Aes_CachedInstance_TwoComputationsPerCall since
    // CMac's own subkey derivation is internal/not separately re-triggered here per call
    // the way AesCmacCalculator's is - see class remarks for why that's not an
    // apples-to-apples RFC 4493 comparison either, only a raw-AES-throughput one).
    [Benchmark]
    public void BouncyCastle_Cmac_TwoFreshInstancesPerCall()
    {
        byte[] kSecMac = BouncyCastleCmac(Key, Message);
        byte[] _ = BouncyCastleCmac(kSecMac, Message);
    }

    [GlobalSetup(Target = nameof(Bcl_Aes_CachedInstance_TwoComputationsPerCall))]
    public void SetupCachedAes()
    {
        _cachedAes = System.Security.Cryptography.Aes.Create();
        _cachedAes.Mode = System.Security.Cryptography.CipherMode.ECB;
        _cachedAes.Padding = System.Security.Cryptography.PaddingMode.None;
    }

    private System.Security.Cryptography.Aes? _cachedAes;

    // Minimal single-block-message CMac-shaped encrypt reusing the cached Aes instance -
    // NOT a full RFC 4493 implementation (no subkey derivation/padding), since this
    // benchmark only needs to isolate the "Aes.Create() overhead" question for a
    // single-block message, matching this vector's tiny inputs.
    private void CachedAesCmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> block16, Span<byte> output)
    {
        _cachedAes!.Key = key.ToArray();
        _cachedAes.EncryptEcb(block16, output, System.Security.Cryptography.PaddingMode.None);
    }

    private static byte[] BouncyCastleCmac(byte[] key, byte[] message)
    {
        var cmac = new CMac(new AesEngine());
        cmac.Init(new KeyParameter(key));
        cmac.BlockUpdate(message, 0, message.Length);
        byte[] output = new byte[cmac.GetMacSize()];
        cmac.DoFinal(output, 0);
        return output;
    }
}
