using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;
using NtagCmacApi.Models;

namespace NtagCmacApi.KeyProvider;

/// <summary>
/// Placeholder response contract for the master-key lookup service:
/// <c>GET {BaseUrl}/tags/{uid}/key</c> -&gt; <c>200 { "masterKeyBase64": "..." }</c>.
/// Adjust this shape once the real service contract is known - it is the only place that
/// needs to change.
/// </summary>
internal sealed record TagKeyLookupResponse(string MasterKeyBase64);

/// <summary>
/// HTTP-backed <see cref="ITagKeyProvider"/>. Registered as a typed client
/// (<c>AddHttpClient&lt;ITagKeyProvider, HttpTagKeyProvider&gt;</c>) so its
/// <see cref="HttpClient.BaseAddress"/> and <see cref="HttpClient.Timeout"/> come from
/// <see cref="TagKeyServiceOptions"/>. Fails closed: any network error, timeout, or
/// unexpected response maps to <see cref="TagKeyLookupStatus.ServiceError"/> rather than
/// throwing out of this method - callers must never let a transport exception here turn
/// into an unhandled 500 that could leak information.
/// </summary>
public sealed class HttpTagKeyProvider : ITagKeyProvider
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<HttpTagKeyProvider> _logger;

    public HttpTagKeyProvider(HttpClient httpClient, ILogger<HttpTagKeyProvider> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    public async Task<TagKeyLookupResult> GetMasterKeyAsync(NtagSDMData data, CancellationToken cancellationToken)
    {
        try
        {
            using HttpResponseMessage response = await _httpClient.GetAsync(
                $"tags/{Uri.EscapeDataString(data.Uid.ToUpperInvariant())}/key",
                cancellationToken);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                _logger.LogDebug("Master key not found for uid={Uid}", data.Uid);
                return TagKeyLookupResult.NotFound;
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Master key service returned {StatusCode} for uid={Uid}", (int)response.StatusCode, data.Uid);
                return TagKeyLookupResult.ServiceError;
            }

            TagKeyLookupResponse? body = await response.Content.ReadFromJsonAsync<TagKeyLookupResponse>(cancellationToken);
            if (body is null || string.IsNullOrEmpty(body.MasterKeyBase64))
            {
                _logger.LogWarning("Master key service returned an empty/malformed response for uid={Uid}", data.Uid);
                return TagKeyLookupResult.ServiceError;
            }

            return TagKeyLookupResult.Found(body.MasterKeyBase64);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or System.Text.Json.JsonException)
        {
            // Network failure, timeout, DNS/TLS error, or an unexpected/malformed response
            // body - fail closed rather than propagate.
            _logger.LogWarning(ex, "Master key lookup failed for uid={Uid}", data.Uid);
            return TagKeyLookupResult.ServiceError;
        }
    }
}
