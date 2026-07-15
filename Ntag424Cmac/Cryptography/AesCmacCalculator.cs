using System;
using System.Security.Cryptography;

namespace Ntag424.Cmac.Cryptography;

/// <summary>
/// Standard AES-128 CMAC (RFC 4493 / NIST SP 800-38B) implementation, built directly on
/// top of AES-ECB single-block encryption. Single responsibility: this class knows only
/// how to compute a CMAC - it has no awareness of NTAG 424 DNA, SDM, session vectors, or
/// truncation schemes, all of which live in their own policy types.
/// </summary>
public sealed class AesCmacCalculator : IAesCmacCalculator
{
    private const byte Rb = 0x87;

    public void ComputeCmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> outputMac)
    {
        using Aes aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
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
