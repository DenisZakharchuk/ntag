namespace NtagCmacApi.KeyProvider;

/// <summary>
/// Configuration for the network-based master-key lookup service. Bound from the
/// "Ntag:KeyService" configuration section.
/// </summary>
public sealed class TagKeyServiceOptions
{
    public const string SectionName = "Ntag:KeyService";

    /// <summary>Base URL of the master-key REST service, e.g. "https://keys.internal.example/".</summary>
    public string BaseUrl { get; set; } = string.Empty;

    public int TimeoutSeconds { get; set; } = 5;
}
