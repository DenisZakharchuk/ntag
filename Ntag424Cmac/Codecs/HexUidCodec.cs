using System;
using System.Buffers;

namespace Ntag424.Cmac.Codecs;

/// <summary>
/// Default <see cref="IUidCodec"/>: the UID hex text is decoded directly to bytes in
/// written order (no reordering) - the raw 7-byte UID as printed.
/// </summary>
public sealed class HexUidCodec : IUidCodec
{
    public bool TryDecode(ReadOnlySpan<char> uidHex, Span<byte> uid)
    {
        if (uid.Length != 7)
            return false;

        return Convert.FromHexString(uidHex, uid, out _, out int bytesWritten) == OperationStatus.Done && bytesWritten == 7;
    }
}
