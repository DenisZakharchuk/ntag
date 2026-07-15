using System;
using Microsoft.Extensions.DependencyInjection;
using Ntag424.Cmac.Codecs;
using Ntag424.Cmac.Cryptography;
using Ntag424.Cmac.MessagePolicies;
using Ntag424.Cmac.SessionVectors;
using Ntag424.Cmac.Truncation;

namespace Ntag424.Cmac;

/// <summary>
/// Composition-root helper for the CMAC crypto core: registers each policy independently
/// (Dependency Inversion Principle) so any of them (e.g. <see cref="ISdmMacMessagePolicy"/>
/// for an AN12196 Table 5 implementation) can be swapped by the host application without
/// touching this method or <see cref="Ntag424CmacVerifier"/> itself.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <param name="configure">
    /// Configures <see cref="CmacOptions"/> - which <see cref="ISdmMacMessagePolicy"/>
    /// (AN12196 Table 4 vs. Table 5) and which <see cref="ICounterCodec"/> (literal hex
    /// bytes vs. numeric little-endian) to register. Defaults to the settings that match
    /// NXP's official AN12196 Table 4 worked example if left unconfigured.
    /// </param>
    public static IServiceCollection AddCmac(
        this IServiceCollection services,
        Action<CmacOptions>? configure = null)
    {
        var options = new CmacOptions();
        configure?.Invoke(options);

        services.AddSingleton<IAesCmacCalculator, AesCmacCalculator>();
        services.AddSingleton<ISdmSessionVectorBuilder, Sv2SessionVectorBuilder>();
        services.AddSingleton<ISdmMacMessagePolicy>(_ => options.MacMessagePolicy switch
        {
            MacMessagePolicyKind.MirroredData => new MirroredDataCmacMessagePolicy(),
            _ => new EmptyCmacMessagePolicy(),
        });
        services.AddSingleton<ISdmMacTruncationPolicy, OddByteOffsetTruncationPolicy>();
        services.AddSingleton<IMasterKeyCodec, Base64MasterKeyCodec>();
        services.AddSingleton<IUidCodec, HexUidCodec>();
        services.AddSingleton<ICounterCodec>(_ => options.CounterCodec switch
        {
            CounterCodecKind.NumericLittleEndian => new NumericLittleEndianCounterCodec(),
            _ => new LiteralHexCounterCodec(),
        });
        services.AddSingleton<INtag424CmacVerifier, Ntag424CmacVerifier>();

        return services;
    }
}
