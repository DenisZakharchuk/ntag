using System;

namespace Ntag424.Cmac;

/// <summary>
/// Truncates a full 16-byte AES-CMAC down to the shorter value actually transmitted by
/// the tag. Extracted as its own policy so the truncation scheme can be swapped or unit
/// tested independently of session-key derivation or message construction.
/// </summary>
public interface ISdmMacTruncationPolicy
{
    /// <summary>Length in bytes of the truncated MAC this policy produces.</summary>
    int TruncatedLength { get; }

    /// <summary>
    /// Extracts the truncated MAC from a full 16-byte CMAC into <paramref name="truncatedMac"/>,
    /// which must be at least <see cref="TruncatedLength"/> bytes.
    /// </summary>
    void Truncate(ReadOnlySpan<byte> fullMac, Span<byte> truncatedMac);
}
