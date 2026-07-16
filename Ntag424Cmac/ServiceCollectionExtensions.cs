using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
    /// NXP's official AN12196 Table 4 worked example if left unconfigured. Applied through
    /// the standard <see cref="OptionsBuilder{TOptions}"/> pipeline (not invoked eagerly),
    /// so callers can layer additional <c>IOptionsMonitor</c>-driven configuration on top
    /// via <c>services.AddOptions&lt;CmacOptions&gt;().Configure(...)</c> after calling
    /// this method.
    /// </param>
    public static IServiceCollection AddCmac(
        this IServiceCollection services,
        Action<CmacOptions>? configure = null)
    {
        OptionsBuilder<CmacOptions> optionsBuilder = services.AddOptions<CmacOptions>();
        if (configure is not null)
        {
            optionsBuilder.Configure(configure);
        }

        services.AddTransient<IAesCmacCalculator, AesCmacCalculator>();
        services.AddTransient<ISdmSessionVectorBuilder, Sv2SessionVectorBuilder>();
        services.AddTransient<ISdmMacMessagePolicy>(sp =>
        {
            CmacOptions options = sp.GetRequiredService<IOptionsMonitor<CmacOptions>>().CurrentValue;
            return options.MacMessagePolicy switch
            {
                MacMessagePolicyKind.MirroredData => new MirroredDataCmacMessagePolicy(),
                _ => new EmptyCmacMessagePolicy(),
            };
        });
        services.AddTransient<ISdmMacTruncationPolicy, OddByteOffsetTruncationPolicy>();
        services.AddTransient<IMasterKeyCodec, Base64MasterKeyCodec>();
        services.AddTransient<IUidCodec, HexUidCodec>();
        services.AddTransient<ICounterCodec>(sp =>
        {
            CmacOptions options = sp.GetRequiredService<IOptionsMonitor<CmacOptions>>().CurrentValue;
            return options.CounterCodec switch
            {
                CounterCodecKind.NumericLittleEndian => new NumericLittleEndianCounterCodec(),
                _ => new LiteralHexCounterCodec(),
            };
        });
        services.AddTransient<INtag424CmacVerifier, Ntag424CmacVerifier>();

        return services;
    }
}
