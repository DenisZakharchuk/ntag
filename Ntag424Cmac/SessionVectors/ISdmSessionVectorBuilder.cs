using System;

namespace Ntag424.Cmac.SessionVectors;

/// <summary>
/// Builds the 16-byte SDM "Session Vector" (SV2) used to derive the per-read session key
/// via <c>CMAC(MasterKey, SV2)</c>. Extracted as its own policy (Open/Closed Principle) so
/// an alternate session-vector layout (e.g. a different SDM key type, or a future tag
/// generation) can be plugged in without modifying <see cref="Ntag424CmacVerifier"/>.
/// </summary>
public interface ISdmSessionVectorBuilder
{
    /// <summary>Length in bytes of the session vector this builder produces.</summary>
    int SessionVectorLength { get; }

    /// <summary>
    /// Writes the session vector for the given UID/counter into <paramref name="sessionVector"/>,
    /// which must be at least <see cref="SessionVectorLength"/> bytes.
    /// </summary>
    void Build(ReadOnlySpan<byte> uid, ReadOnlySpan<byte> counter, Span<byte> sessionVector);
}
