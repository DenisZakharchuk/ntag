using Microsoft.EntityFrameworkCore;
using Ntag424.Cmac;
using NtagCmacApi.KeyProvider;
using NtagCmacApi.Notifications;
using NtagCmacApi.Orchestration;
using NtagCmacApi.Persistence;
using NtagCmacApi.UrlParsing;

var builder = WebApplication.CreateBuilder(args);

// --- Persistence: replay-protection state (per-UID last accepted counter/CMAC) ---
// Provider is switchable via config so the same code path works with InMemory (for local
// dev/tests) and a real DBMS in production - swapping only requires adding the provider
// package, a connection string, and EF Core migrations; no other application code changes.
string persistenceProvider = builder.Configuration["Ntag:Persistence:Provider"] ?? "InMemory";
builder.Services.AddDbContext<NtagDbContext>(options =>
{
    switch (persistenceProvider)
    {
        case "SqlServer":
            options.UseSqlServer(builder.Configuration.GetConnectionString("Ntag"));
            break;
        case "InMemory":
        default:
            options.UseInMemoryDatabase("NtagCmacApi");
            break;
        // case "Npgsql": options.UseNpgsql(builder.Configuration.GetConnectionString("Ntag")); break;
    }
});
// DbSet<T> isn't registered by AddDbContext by default, so EfReplayGuard (and anything
// else that only needs this one entity set) can depend on it - and on IUnitOfWork for
// committing - instead of the concrete NtagDbContext/DbContext.
builder.Services.AddScoped(sp => sp.GetRequiredService<NtagDbContext>().TagReplayStates);
builder.Services.AddScoped<IUnitOfWork>(sp => sp.GetRequiredService<NtagDbContext>());
builder.Services.AddScoped<IReplayGuard, EfReplayGuard>();

// --- Master key resolution: network-based lookup service. Never accepted from the caller. ---
builder.Services.Configure<TagKeyServiceOptions>(builder.Configuration.GetSection(TagKeyServiceOptions.SectionName));
builder.Services.AddHttpClient<ITagKeyProvider, HttpTagKeyProvider>((serviceProvider, httpClient) =>
{
    var options = serviceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<TagKeyServiceOptions>>().Value;
    if (!string.IsNullOrEmpty(options.BaseUrl))
    {
        httpClient.BaseAddress = new Uri(options.BaseUrl);
    }
    httpClient.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
});

// --- Outcome notification: hidden behind an abstraction; logs for now. ---
builder.Services.AddSingleton<IOutcomeNotifier, LoggingOutcomeNotifier>();

// --- SOLID composition root for the CMAC crypto core: registered via AddCmac() so each
// policy (e.g. an ISdmMacMessagePolicy for AN12196 Table 5, or an ICounterCodec for a
// different ctr byte-order convention) can be swapped without touching this file or the
// verifier itself. Configured via an options delegate (CmacOptions), the same pattern
// ASP.NET Core's own composition-root APIs use (e.g. AddDbContext<T>(options => ...)) -
// MacMessagePolicy defaults to EmptyMessage (AN12196 Table 4); CounterCodec defaults to
// LiteralHex (matches NXP's official vector). NumericLittleEndian is confirmed correct
// for at least one real captured tag read - see ICounterCodec remarks.
builder.Services.AddCmac(options =>
{
    if (Enum.TryParse(builder.Configuration["Ntag:MacMessagePolicy:Type"], ignoreCase: true, out MacMessagePolicyKind macMessagePolicy))
    {
        options.MacMessagePolicy = macMessagePolicy;
    }

    if (Enum.TryParse(builder.Configuration["Ntag:CounterCodec:Type"], ignoreCase: true, out CounterCodecKind counterCodec))
    {
        options.CounterCodec = counterCodec;
    }
});

// --- Orchestrator: sequences request validation -> replay pre-check -> key lookup ->
// CMAC verify -> replay commit -> outcome notification. ---
builder.Services.AddSingleton<ISdmVerifyCommandValidationPolicy, SdmVerifyCommandValidationPolicy>();
builder.Services.AddScoped<ISdmVerificationOrchestrator, SdmVerificationOrchestrator>();

// --- Raw-URL parsing: lets callers submit the exact SDM URL text (as scanned from the
// tag) instead of pre-splitting it into uid/counter/cmac/mirrored-data fields themselves. ---
builder.Services.AddSingleton<ISdmUrlParser, SdmUrlParser>();

var app = builder.Build();

app.MapGet("/", () => "NTAG 424 DNA SDM CMAC verifier is running.");

// Mirrors the query parameters an NTAG 424 DNA tag places in its SDM URL
// (e.g. ?uid=...&ctr=...&cmac=...). The master key is NEVER accepted from the
// caller - it is looked up server-side per UID via the network key service.
//
// Accepts EITHER the raw scanned URL (request.Url - parsed via ISdmUrlParser, which also
// derives the AN12196 Table 5 mirrored-data message automatically) OR pre-split
// uid/counter/cmac/mirroredData fields directly. If Url is supplied it takes precedence.
app.MapPost("/api/sdm/verify", async (
    SdmVerifyRequest request,
    ISdmVerificationOrchestrator orchestrator,
    ISdmUrlParser urlParser,
    CancellationToken cancellationToken) =>
{
    SdmVerifyCommand command = !string.IsNullOrWhiteSpace(request.Url)
        ? urlParser.Parse(request.Url)
        : new SdmVerifyCommand(request.Uid, request.Counter, request.Cmac, request.MirroredData);

    SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(command, cancellationToken);

    // Always a generic { valid: bool } response with no distinguishing error reasons, to
    // avoid leaking whether a UID is registered or why verification failed (avoid oracle
    // attacks). A duplicate-of-last-accepted request is reported as valid too, since it is
    // a safe idempotent retry, not an attack replay.
    return Results.Ok(new SdmVerifyResponse(outcome.IsSuccess));
});

app.Run();

internal record SdmVerifyRequest(
    string Uid = "",
    string Counter = "",
    string Cmac = "",
    string? MirroredData = null,
    string? Url = null);

internal record SdmVerifyResponse(bool Valid);

