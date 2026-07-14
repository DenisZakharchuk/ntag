using System.Net;
using NtagCmacApi.KeyProvider;
using Xunit;

namespace NtagCmacApi.Tests;

/// <summary>
/// Validates <see cref="HttpTagKeyProvider"/> against a fake <see cref="HttpMessageHandler"/>,
/// confirming it fails closed (maps to <see cref="TagKeyLookupStatus.ServiceError"/>) for
/// every non-success case rather than throwing out to the caller.
/// </summary>
public class HttpTagKeyProviderTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        {
            _respond = respond;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_respond(request));
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        private readonly Exception _exception;

        public ThrowingHandler(Exception exception)
        {
            _exception = exception;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => throw _exception;
    }

    private static HttpTagKeyProvider CreateProvider(HttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://key-service.test/") };
        return new HttpTagKeyProvider(httpClient);
    }

    [Fact]
    public async Task GetMasterKeyAsync_200WithKey_ReturnsFound()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"masterKeyBase64":"AAAAAAAAAAAAAAAAAAAAAA=="}""", System.Text.Encoding.UTF8, "application/json"),
        });
        HttpTagKeyProvider provider = CreateProvider(handler);

        TagKeyLookupResult result = await provider.GetMasterKeyAsync("04A1B2C3D4E5F6", CancellationToken.None);

        Assert.Equal(TagKeyLookupStatus.Found, result.Status);
        Assert.Equal("AAAAAAAAAAAAAAAAAAAAAA==", result.MasterKeyBase64);
    }

    [Fact]
    public async Task GetMasterKeyAsync_404_ReturnsNotFound()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        HttpTagKeyProvider provider = CreateProvider(handler);

        TagKeyLookupResult result = await provider.GetMasterKeyAsync("04A1B2C3D4E5F6", CancellationToken.None);

        Assert.Equal(TagKeyLookupStatus.NotFound, result.Status);
        Assert.Null(result.MasterKeyBase64);
    }

    [Fact]
    public async Task GetMasterKeyAsync_500_ReturnsServiceError()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        HttpTagKeyProvider provider = CreateProvider(handler);

        TagKeyLookupResult result = await provider.GetMasterKeyAsync("04A1B2C3D4E5F6", CancellationToken.None);

        Assert.Equal(TagKeyLookupStatus.ServiceError, result.Status);
    }

    [Fact]
    public async Task GetMasterKeyAsync_MalformedJsonBody_ReturnsServiceError()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("not json", System.Text.Encoding.UTF8, "application/json"),
        });
        HttpTagKeyProvider provider = CreateProvider(handler);

        TagKeyLookupResult result = await provider.GetMasterKeyAsync("04A1B2C3D4E5F6", CancellationToken.None);

        Assert.Equal(TagKeyLookupStatus.ServiceError, result.Status);
    }

    [Fact]
    public async Task GetMasterKeyAsync_NetworkFailure_ReturnsServiceError()
    {
        var handler = new ThrowingHandler(new HttpRequestException("connection refused"));
        HttpTagKeyProvider provider = CreateProvider(handler);

        TagKeyLookupResult result = await provider.GetMasterKeyAsync("04A1B2C3D4E5F6", CancellationToken.None);

        Assert.Equal(TagKeyLookupStatus.ServiceError, result.Status);
    }

    [Fact]
    public async Task GetMasterKeyAsync_Timeout_ReturnsServiceError()
    {
        var handler = new ThrowingHandler(new TaskCanceledException("timed out"));
        HttpTagKeyProvider provider = CreateProvider(handler);

        TagKeyLookupResult result = await provider.GetMasterKeyAsync("04A1B2C3D4E5F6", CancellationToken.None);

        Assert.Equal(TagKeyLookupStatus.ServiceError, result.Status);
    }
}
