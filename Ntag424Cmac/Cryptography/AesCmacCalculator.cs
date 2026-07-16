using System;
using System.Security.Cryptography;

namespace Ntag424.Cmac.Cryptography;

/// <summary>
/// Standard AES-128 CMAC (RFC 4493 / NIST SP 800-38B) implementation, built directly on
/// top of AES-ECB single-block encryption. Single responsibility: this class knows only
/// how to compute a CMAC - it has no awareness of NTAG 424 DNA, SDM, session vectors, or
/// truncation schemes, all of which live in their own policy types.
///
/// Caches a single <see cref="Aes"/> instance for this object's lifetime rather than
/// calling <see cref="Aes.Create()"/> on every <see cref="ComputeCmac"/> call: on Windows,
/// <c>Aes.Create()</c> wraps CNG (BCrypt), and opening a new algorithm/key provider handle
/// per call is a real native/OS-level cost - measured at roughly 2x the time of reusing one
/// instance (see <c>Ntag424Cmac.Benchmarks/AesPrimitiveBenchmarks.cs</c>), even though the
/// difference doesn't show up as managed heap allocations.
///
/// The <see cref="Aes"/> instance is created LAZILY, on the first <see cref="ComputeCmac"/>
/// call - not in the constructor. This class is DI-resolved as part of the whole CMAC
/// dependency graph every time <see cref="Ntag424CmacVerifier"/> is constructed, which
/// happens on every verification request (it's a constructor dependency of
/// <c>SdmVerificationOrchestrator</c>) - but <see cref="Ntag424CmacVerifier.Verify"/> is
/// only reached after several earlier pipeline steps (validation, company lookup, replay
/// pre-check, key lookup) that each have their own short-circuit/rejection exit points. A
/// request rejected before reaching CMAC verification should not pay for opening a native
/// AES provider handle it will never use. Lazy creation means the constructor - and thus
/// every DI resolution - stays cheap regardless of which branch the request takes; the
/// real cost is only paid the first time this instance is actually asked to compute a CMAC.
///
/// Safe to cache/lazily-init like this because
/// <see cref="Ntag424.Cmac.ServiceCollectionExtensions.AddCmac"/> registers this type
/// Transient (a fresh instance per resolution, used sequentially by a single
/// <see cref="Ntag424CmacVerifier"/> - never shared/concurrent, so there's no race between
/// the lazy-init check and the first real call). Implements <see cref="IDisposable"/> so
/// the cached instance (and its underlying native handle), if ever created, is released;
/// when resolved via DI this happens automatically at the end of the request/scope, since
/// the container disposes every <see cref="IDisposable"/> service it constructs regardless
/// of the interface type it was requested as.
/// </summary>
public sealed class AesCmacCalculator : IAesCmacCalculator, IDisposable
{
    private const byte Rb = 0x87;

    // Null until the first ComputeCmac call - see class remarks for why this is lazy
    // rather than eagerly created in the constructor.
    private Aes? _aes;

    public void ComputeCmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> outputMac)
    {
        Aes aes = _aes ??= CreateAes();
        aes.Key = key.ToArray(); // `Aes.KeySpan` does not exist; byte[] Key is the only setter available

        // Step 1: Derive Subkeys K1 and K2 on stack
        Span<byte> zeroBlock = stackalloc byte[16];
        zeroBlock.Clear();
        Span<byte> l = stackalloc byte[16];
        aes.EncryptEcb(zeroBlock, l, PaddingMode.None);

        Span<byte> k1 = stackalloc byte[16];
        GenerateSubkey(l, k1);

        Span<byte> k2 = stackalloc byte[16];
        GenerateSubkey(k1, k2);

        // Step 2: Block Parameters
        int n = (message.Length + 15) / 16;
        // NOTE: a zero-length message must be treated as an incomplete final block
        // (padded with 0x80 then zeros, XORed with K2), never as a "complete" 16-byte
        // block - there is no data to slice in that case.
        bool isCompleteBlock = message.Length != 0 && (message.Length % 16 == 0);
        if (n == 0) n = 1;

        Span<byte> lastBlock = stackalloc byte[16];
        lastBlock.Clear();

        if (isCompleteBlock)
        {
            message.Slice((n - 1) * 16, 16).CopyTo(lastBlock);
            XorBlocks(lastBlock, k1);
        }
        else
        {
            int lastBlockLen = message.Length % 16;
            message.Slice((n - 1) * 16, lastBlockLen).CopyTo(lastBlock);
            lastBlock[lastBlockLen] = 0x80;
            XorBlocks(lastBlock, k2);
        }

        // Step 3: Mac Chaining
        Span<byte> x = stackalloc byte[16];
        x.Clear();
        Span<byte> y = stackalloc byte[16];

        for (int i = 0; i < n - 1; i++)
        {
            message.Slice(i * 16, 16).CopyTo(y);
            XorBlocks(x, y);
            aes.EncryptEcb(x, x, PaddingMode.None);
        }

        XorBlocks(lastBlock, x);
        aes.EncryptEcb(lastBlock, outputMac, PaddingMode.None);
    }

    private static Aes CreateAes()
    {
        Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        return aes;
    }

    // No-op if ComputeCmac was never called (_aes still null) - correctly avoids creating
    // a native AES handle just to immediately dispose it.
    public void Dispose() => _aes?.Dispose();

    private static void GenerateSubkey(ReadOnlySpan<byte> input, Span<byte> outputSubkey)
    {
        ShiftLeftByOneBit(input, outputSubkey);
        if ((input[0] & 0x80) != 0)
        {
            outputSubkey[15] ^= Rb;
        }
    }

    private static void ShiftLeftByOneBit(ReadOnlySpan<byte> data, Span<byte> result)
    {
        byte overflow = 0;
        for (int i = data.Length - 1; i >= 0; i--)
        {
            result[i] = (byte)((data[i] << 1) | overflow);
            overflow = (byte)(((data[i] & 0x80) != 0) ? 1 : 0);
        }
    }

    private static void XorBlocks(Span<byte> block, ReadOnlySpan<byte> subkey)
    {
        for (int i = 0; i < block.Length; i++)
        {
            block[i] ^= subkey[i];
        }
    }
}
