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
    public static IServiceCollection AddCmac(this IServiceCollection services)
    {
        services.AddSingleton<IAesCmacCalculator, AesCmacCalculator>();
        services.AddSingleton<ISdmSessionVectorBuilder, Sv2SessionVectorBuilder>();
        services.AddSingleton<ISdmMacMessagePolicy, EmptyCmacMessagePolicy>();
        services.AddSingleton<ISdmMacTruncationPolicy, OddByteOffsetTruncationPolicy>();
        services.AddSingleton<INtag424CmacVerifier, Ntag424CmacVerifier>();

        return services;
    }
}
