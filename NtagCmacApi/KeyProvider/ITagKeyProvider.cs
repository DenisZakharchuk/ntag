using NtagCmacApi.Models;

namespace NtagCmacApi.KeyProvider;

/// <summary>Outcome of resolving a tag's master key.</summary>
public enum TagKeyLookupStatus
{
    Found,

    /// <summary>The tag is not registered with the key service. Not necessarily an error - could be a probing request.</summary>
    NotFound,

    /// <summary>The key service could not be reached, timed out, or returned an unexpected response. An operational concern.</summary>
    ServiceError,
}

/// <summary>Result of an <see cref="ITagKeyProvider"/> lookup.</summary>
public readonly record struct TagKeyLookupResult(TagKeyLookupStatus Status, string? MasterKeyBase64)
{
    public static TagKeyLookupResult Found(string masterKeyBase64) => new(TagKeyLookupStatus.Found, masterKeyBase64);
    public static readonly TagKeyLookupResult NotFound = new(TagKeyLookupStatus.NotFound, null);
    public static readonly TagKeyLookupResult ServiceError = new(TagKeyLookupStatus.ServiceError, null);
}

/// <summary>
/// Resolves the per-tag AES master key used to derive the SDM session key. Looked up by
/// UID so that a leaked key for one tag cannot be used to forge MACs for another, and so
/// the key is never transmitted by the caller of the verification API.
/// </summary>
public interface ITagKeyProvider
{
    Task<TagKeyLookupResult> GetMasterKeyAsync(NtagSDMData data, CancellationToken cancellationToken);
}
