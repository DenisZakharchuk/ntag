using System;
using Ntag424.Cmac;
using Xunit;

namespace NtagCmacApi.Tests;

public class MasterKeyCodecTests
{
    private static readonly IMasterKeyCodec Codec = new Base64MasterKeyCodec();

    [Fact]
    public void TryDecode_ValidBase64_ReturnsTrueAndDecodesBytes()
    {
        Span<byte> key = stackalloc byte[16];
        bool result = Codec.TryDecode("AAAAAAAAAAAAAAAAAAAAAA==", key);

        Assert.True(result);
        Assert.True(key.SequenceEqual(new byte[16]));
    }

    [Fact]
    public void TryDecode_MalformedBase64_ReturnsFalse()
    {
        Span<byte> key = stackalloc byte[16];
        bool result = Codec.TryDecode("not-base64!!!", key);

        Assert.False(result);
    }

    [Fact]
    public void TryDecode_WrongDecodedLength_ReturnsFalse()
    {
        Span<byte> key = stackalloc byte[16];
        // Decodes to 8 bytes, not 16.
        bool result = Codec.TryDecode("AAAAAAAAAAA=", key);

        Assert.False(result);
    }

    [Fact]
    public void TryDecode_WrongBufferLength_ReturnsFalse()
    {
        Span<byte> key = stackalloc byte[8];
        bool result = Codec.TryDecode("AAAAAAAAAAAAAAAAAAAAAA==", key);

        Assert.False(result);
    }
}

public class UidCodecTests
{
    private static readonly IUidCodec Codec = new HexUidCodec();

    [Fact]
    public void TryDecode_ValidHex_ReturnsTrueAndDecodesLiterally()
    {
        Span<byte> uid = stackalloc byte[7];
        bool result = Codec.TryDecode("04A1B2C3D4E5F6", uid);

        Assert.True(result);
        Assert.Equal("04A1B2C3D4E5F6", Convert.ToHexString(uid));
    }

    [Fact]
    public void TryDecode_MalformedHex_ReturnsFalse()
    {
        Span<byte> uid = stackalloc byte[7];
        bool result = Codec.TryDecode("ZZZZZZZZZZZZZZ", uid);

        Assert.False(result);
    }

    [Fact]
    public void TryDecode_WrongLength_ReturnsFalse()
    {
        Span<byte> uid = stackalloc byte[7];
        bool result = Codec.TryDecode("04A1B2", uid);

        Assert.False(result);
    }
}

public class LiteralHexCounterCodecTests
{
    private static readonly ICounterCodec Codec = new LiteralHexCounterCodec();

    [Fact]
    public void TryDecode_DecodesBytesInWrittenOrder_NoReordering()
    {
        Span<byte> counter = stackalloc byte[3];
        bool result = Codec.TryDecode("3D0000", counter);

        Assert.True(result);
        Assert.Equal("3D0000", Convert.ToHexString(counter));
    }

    [Fact]
    public void TryDecode_MalformedHex_ReturnsFalse()
    {
        Span<byte> counter = stackalloc byte[3];
        bool result = Codec.TryDecode("ZZZZZZ", counter);

        Assert.False(result);
    }
}

public class NumericLittleEndianCounterCodecTests
{
    private static readonly ICounterCodec Codec = new NumericLittleEndianCounterCodec();

    [Fact]
    public void TryDecode_ParsesAsNumberAndReencodesLittleEndian()
    {
        Span<byte> counter = stackalloc byte[3];
        bool result = Codec.TryDecode("000001", counter);

        Assert.True(result);
        // Value 1, little-endian/LSB-first: [0x01, 0x00, 0x00].
        Assert.Equal(new byte[] { 0x01, 0x00, 0x00 }, counter.ToArray());
    }

    [Fact]
    public void TryDecode_LargerValue_ReencodesCorrectly()
    {
        Span<byte> counter = stackalloc byte[3];
        bool result = Codec.TryDecode("010203", counter); // 0x010203 = 66051

        Assert.True(result);
        Assert.Equal(new byte[] { 0x03, 0x02, 0x01 }, counter.ToArray());
    }

    [Fact]
    public void TryDecode_MalformedHex_ReturnsFalse()
    {
        Span<byte> counter = stackalloc byte[3];
        bool result = Codec.TryDecode("ZZZZZZ", counter);

        Assert.False(result);
    }

    [Fact]
    public void TryDecode_ValueExceedingThreeBytes_ReturnsFalse()
    {
        Span<byte> counter = stackalloc byte[3];
        bool result = Codec.TryDecode("1000000", counter); // 0x1000000 > 0xFFFFFF

        Assert.False(result);
    }
}
