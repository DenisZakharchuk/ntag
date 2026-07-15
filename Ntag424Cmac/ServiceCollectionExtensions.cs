using Microsoft.Extensions.DependencyInjection;

namespace Ntag424.Cmac;

/// <summary>
/// Composition-root helper for the CMAC crypto core: registers each policy independently
/// (Dependency Inversion Principle) so any of them (e.g. <see cref="ISdmMacMessagePolicy"/>
/// for an AN12196 Table 5 implementation) can be swapped by the host application without
/// touching this method or <see cref="Ntag424CmacVerifier"/> itself.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <param name="macMessagePolicy">
    /// Which <see cref="ISdmMacMessagePolicy"/> to register:
    /// <c>"EmptyMessage"</c> (default) for AN12196 Table 4 (<c>SDMMACInputOffset ==
    /// SDMMACOffset</c>), or <c>"MirroredData"</c> for Table 5
    /// (<c>SDMMACInputOffset != SDMMACOffset</c>) - see
    /// <see cref="MirroredDataCmacMessagePolicy"/> for its (currently unverified against an
    /// official NXP vector) implementation notes.
    /// </param>
    /// <param name="counterCodec">
    /// Which <see cref="ICounterCodec"/> to register: <c>"LiteralHex"</c> (default) decodes
    /// <c>ctr</c> hex text directly to bytes in written order (matches NXP's official
    /// AN12196 Table 4 vector), or <c>"NumericLittleEndian"</c> parses it as a number and
    /// re-encodes little-endian/LSB-first first (confirmed correct for at least one real
    /// captured tag read - see <see cref="NumericLittleEndianCounterCodec"/>).
    /// </param>
    public static IServiceCollection AddCmac(
        this IServiceCollection services,
        string macMessagePolicy = "EmptyMessage",
        string counterCodec = "LiteralHex")
    {
        services.AddSingleton<IAesCmacCalculator, AesCmacCalculator>();
        services.AddSingleton<ISdmSessionVectorBuilder, Sv2SessionVectorBuilder>();
        services.AddSingleton<ISdmMacMessagePolicy>(_ => macMessagePolicy switch
        {
            "MirroredData" => new MirroredDataCmacMessagePolicy(),
            _ => new EmptyCmacMessagePolicy(),
        });
        services.AddSingleton<ISdmMacTruncationPolicy, OddByteOffsetTruncationPolicy>();
        services.AddSingleton<IMasterKeyCodec, Base64MasterKeyCodec>();
        services.AddSingleton<IUidCodec, HexUidCodec>();
        services.AddSingleton<ICounterCodec>(_ => counterCodec switch
        {
            "NumericLittleEndian" => new NumericLittleEndianCounterCodec(),
            _ => new LiteralHexCounterCodec(),
        });
        services.AddSingleton<INtag424CmacVerifier, Ntag424CmacVerifier>();

        return services;
    }
}
