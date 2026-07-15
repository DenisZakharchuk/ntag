using System;
using System.Buffers;

namespace Ntag424.Cmac;

/// <summary>
/// Default <see cref="ICounterCodec"/>, matching NXP's official AN12196 Table 4 worked
/// example: the counter hex text is decoded directly to bytes in written order (no
/// reordering) - the raw 3-byte <c>SDMReadCtr</c> as printed.
/// </summary>
public sealed class LiteralHexCounterCodec : ICounterCodec
{
    public bool TryDecode(ReadOnlySpan<char> counterHex, Span<byte> counter)
    {
        if (counter.Length != 3)
            return false;

        return Convert.FromHexString(counterHex, counter, out _, out int bytesWritten) == OperationStatus.Done && bytesWritten == 3;
    }
}
