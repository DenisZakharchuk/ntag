namespace Ntag424.Cmac;

/// <summary>
/// Which <see cref="MessagePolicies.ISdmMacMessagePolicy"/> <see cref="ServiceCollectionExtensions.AddCmac"/>
/// registers.
/// </summary>
public enum MacMessagePolicyKind
{
    /// <summary>
    /// AN12196 Table 4 (<c>SDMMACInputOffset == SDMMACOffset</c>): final CMAC message is
    /// empty. See <see cref="MessagePolicies.EmptyCmacMessagePolicy"/>.
    /// </summary>
    EmptyMessage,

    /// <summary>
    /// AN12196 Table 5 (<c>SDMMACInputOffset != SDMMACOffset</c>): final CMAC message is
    /// the literal bytes mirrored between the two offsets. Confirmed against a real
    /// captured tag read - see <see cref="MessagePolicies.MirroredDataCmacMessagePolicy"/>.
    /// </summary>
    MirroredData,
}

/// <summary>
/// Which <see cref="Codecs.ICounterCodec"/> <see cref="ServiceCollectionExtensions.AddCmac"/>
/// registers.
/// </summary>
public enum CounterCodecKind
{
    /// <summary>
    /// Decodes <c>ctr</c> hex text directly to bytes in written order - matches NXP's
    /// official AN12196 Table 4 vector. See <see cref="Codecs.LiteralHexCounterCodec"/>.
    /// </summary>
    LiteralHex,

    /// <summary>
    /// Parses <c>ctr</c> as a number and re-encodes little-endian/LSB-first before use in
    /// SV2 - confirmed correct for at least one real captured tag read. See
    /// <see cref="Codecs.NumericLittleEndianCounterCodec"/>.
    /// </summary>
    NumericLittleEndian,
}

/// <summary>
/// Options for <see cref="ServiceCollectionExtensions.AddCmac"/>, configured via an options
/// delegate (the same "configure action" pattern used throughout ASP.NET Core's own
/// composition-root APIs, e.g. <c>AddDbContext&lt;TContext&gt;(Action&lt;DbContextOptionsBuilder&gt;)</c>)
/// rather than loose string/positional parameters.
/// </summary>
public sealed class CmacOptions
{
    public MacMessagePolicyKind MacMessagePolicy { get; set; } = MacMessagePolicyKind.EmptyMessage;

    public CounterCodecKind CounterCodec { get; set; } = CounterCodecKind.LiteralHex;
}
