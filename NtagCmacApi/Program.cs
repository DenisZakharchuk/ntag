using System.Collections.Concurrent;
using Ntag424.Cmac;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<ITagKeyProvider, ConfigurationTagKeyProvider>();
builder.Services.AddSingleton<IReplayGuard, InMemoryReplayGuard>();

// SOLID composition root: each policy is registered independently (and can be swapped,
// e.g. an ISdmMacMessagePolicy for AN12196 Table 5) without touching the verifier itself.
builder.Services.AddSingleton<IAesCmacCalculator, AesCmacCalculator>();
builder.Services.AddSingleton<ISdmSessionVectorBuilder, Sv2SessionVectorBuilder>();
builder.Services.AddSingleton<ISdmMacMessagePolicy, EmptyCmacMessagePolicy>();
builder.Services.AddSingleton<ISdmMacTruncationPolicy, OddByteOffsetTruncationPolicy>();
builder.Services.AddSingleton<INtag424CmacVerifier, Ntag424CmacVerifier>();

var app = builder.Build();

app.MapGet("/", () => "NTAG 424 DNA SDM CMAC verifier is running.");

// Mirrors the query parameters an NTAG 424 DNA tag places in its SDM URL
// (e.g. ?uid=...&ctr=...&cmac=...). The master key is NEVER accepted from the
// caller - it is looked up server-side per UID, otherwise anyone could forge a
// valid MAC by simply supplying their own key.
app.MapPost("/api/sdm/verify", (
    SdmVerifyRequest request,
    ITagKeyProvider tagKeyProvider,
    IReplayGuard replayGuard,
    INtag424CmacVerifier cmacVerifier) =>
{
    if (string.IsNullOrEmpty(request.Uid) ||
        string.IsNullOrEmpty(request.Counter) ||
        string.IsNullOrEmpty(request.Cmac))
    {
        return Results.Ok(new SdmVerifyResponse(false));
    }

    if (!tagKeyProvider.TryGetMasterKeyBase64(request.Uid, out string? masterKeyBase64))
    {
        // Unknown tag: still return a generic "false" so callers cannot use this
        // endpoint to enumerate which UIDs are registered.
        return Results.Ok(new SdmVerifyResponse(false));
    }

    bool cmacValid = cmacVerifier.Verify(new Ntag424SdmCmacRequest(
        request.Uid,
        request.Counter,
        request.Cmac,
        masterKeyBase64));

    if (!cmacValid)
    {
        return Results.Ok(new SdmVerifyResponse(false));
    }

    // The SDM read counter must strictly increase between successful reads,
    // otherwise a captured URL could be replayed indefinitely. This check must
    // happen only *after* the MAC is confirmed valid, and the counter must be
    // atomically checked-and-recorded to avoid a race between two concurrent
    // requests for the same tag.
    if (!int.TryParse(request.Counter, System.Globalization.NumberStyles.HexNumber, null, out int counterValue) ||
        !replayGuard.TryAcceptCounter(request.Uid, counterValue))
    {
        return Results.Ok(new SdmVerifyResponse(false));
    }

    return Results.Ok(new SdmVerifyResponse(true));
});

app.Run();

internal record SdmVerifyRequest(string Uid, string Counter, string Cmac);

internal record SdmVerifyResponse(bool Valid);

/// <summary>
/// Resolves the per-tag AES master key used to derive the SDM session key.
/// Looked up by UID so that a leaked key for one tag cannot be used to forge
/// MACs for another, and so the key is never transmitted by the caller.
/// </summary>
internal interface ITagKeyProvider
{
    bool TryGetMasterKeyBase64(string uidHex, out string? masterKeyBase64);
}

/// <summary>
/// Reads per-tag keys from configuration ("Ntag:TagKeys:{UID}").
/// Replace with a database- or HSM-backed provider for production use.
/// </summary>
internal sealed class ConfigurationTagKeyProvider : ITagKeyProvider
{
    private readonly IConfiguration _configuration;

    public ConfigurationTagKeyProvider(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public bool TryGetMasterKeyBase64(string uidHex, out string? masterKeyBase64)
    {
        string? value = _configuration[$"Ntag:TagKeys:{uidHex.ToUpperInvariant()}"];
        masterKeyBase64 = value;
        return !string.IsNullOrEmpty(value);
    }
}

/// <summary>
/// Tracks the last accepted SDM read counter per UID to reject replayed reads.
/// In-memory only; use a shared store (e.g. Redis/SQL) for multi-instance deployments.
/// </summary>
internal interface IReplayGuard
{
    bool TryAcceptCounter(string uidHex, int counter);
}

internal sealed class InMemoryReplayGuard : IReplayGuard
{
    private readonly ConcurrentDictionary<string, int> _lastCounterByUid = new();

    public bool TryAcceptCounter(string uidHex, int counter)
    {
        string key = uidHex.ToUpperInvariant();
        while (true)
        {
            if (_lastCounterByUid.TryGetValue(key, out int lastCounter))
            {
                if (counter <= lastCounter)
                {
                    return false;
                }

                if (_lastCounterByUid.TryUpdate(key, counter, lastCounter))
                {
                    return true;
                }
                // Another request updated it concurrently; retry with fresh value.
            }
            else if (_lastCounterByUid.TryAdd(key, counter))
            {
                return true;
            }
        }
    }
}
