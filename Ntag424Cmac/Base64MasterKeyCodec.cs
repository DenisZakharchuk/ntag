using System;

namespace Ntag424.Cmac;

/// <summary>
/// Default <see cref="IMasterKeyCodec"/>: standard Base64 decoding to a 16-byte AES-128 key.
/// </summary>
public sealed class Base64MasterKeyCodec : IMasterKeyCodec
{
    public bool TryDecode(ReadOnlySpan<char> masterKeyBase64, Span<byte> masterKey)
    {
        if (masterKey.Length != 16)
            return false;

        return Convert.TryFromBase64Chars(masterKeyBase64, masterKey, out int bytesWritten) && bytesWritten == 16;
    }
}
