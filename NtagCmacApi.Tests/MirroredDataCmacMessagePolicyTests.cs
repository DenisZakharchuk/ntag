using System;
using Ntag424.Cmac;
using Ntag424.Cmac.MessagePolicies;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Unit tests for <see cref="MirroredDataCmacMessagePolicy"/> (AN12196 Table 5): confirms
/// it MACs the given mirrored-data bytes verbatim as the message, ignoring uid/counter
/// (which are already authenticated implicitly via the session vector -> session key,
/// same as Table 4).
/// </summary>
public class MirroredDataCmacMessagePolicyTests
{
    private static readonly ISdmMacMessagePolicy Policy = new MirroredDataCmacMessagePolicy();

    [Fact]
    public void GetMessageLength_ReturnsMirroredDataLength()
    {
        ReadOnlySpan<byte> uid = stackalloc byte[7];
        ReadOnlySpan<byte> counter = stackalloc byte[3];
        ReadOnlySpan<byte> mirroredData = "serial=548721"u8;

        int length = Policy.GetMessageLength(uid, counter, mirroredData);

        Assert.Equal(mirroredData.Length, length);
    }

    [Fact]
    public void GetMessageLength_EmptyMirroredData_ReturnsZero()
    {
        ReadOnlySpan<byte> uid = stackalloc byte[7];
        ReadOnlySpan<byte> counter = stackalloc byte[3];

        int length = Policy.GetMessageLength(uid, counter, ReadOnlySpan<byte>.Empty);

        Assert.Equal(0, length);
    }

    [Fact]
    public void WriteMessage_CopiesMirroredDataVerbatim()
    {
        ReadOnlySpan<byte> uid = stackalloc byte[7];
        ReadOnlySpan<byte> counter = stackalloc byte[3];
        ReadOnlySpan<byte> mirroredData = "serial=548721"u8;
        Span<byte> message = stackalloc byte[mirroredData.Length];

        Policy.WriteMessage(uid, counter, mirroredData, message);

        Assert.True(message.SequenceEqual(mirroredData));
    }
}
