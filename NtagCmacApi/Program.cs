using Microsoft.EntityFrameworkCore;
using Ntag424.Cmac;
using NtagCmacApi.KeyProvider;
using NtagCmacApi.Notifications;
using NtagCmacApi.Orchestration;
using NtagCmacApi.Persistence;

var builder = WebApplication.CreateBuilder(args);

// --- Persistence: replay-protection state (per-UID last accepted counter/CMAC) ---
// Provider is switchable via config so the same code path works with InMemory (default,
// for local dev/tests) and a real DBMS (SqlServer/Npgsql) in production - swapping only
// requires adding the provider package, a connection string, and (for a real DBMS) EF Core
// migrations; no application code changes.
string persistenceProvider = builder.Configuration["Ntag:Persistence:Provider"] ?? "InMemory";
builder.Services.AddDbContext<NtagDbContext>(options =>
{
    switch (persistenceProvider)
    {
        case "InMemory":
        default:
            options.UseInMemoryDatabase("NtagCmacApi");
            break;
        // case "SqlServer": options.UseSqlServer(builder.Configuration.GetConnectionString("Ntag")); break;
        // case "Npgsql": options.UseNpgsql(builder.Configuration.GetConnectionString("Ntag")); break;
    }
});
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

// --- SOLID composition root for the CMAC crypto core: each policy is registered
// independently (and can be swapped, e.g. an ISdmMacMessagePolicy for AN12196 Table 5)
// without touching the verifier itself. ---
builder.Services.AddSingleton<IAesCmacCalculator, AesCmacCalculator>();
builder.Services.AddSingleton<ISdmSessionVectorBuilder, Sv2SessionVectorBuilder>();
builder.Services.AddSingleton<ISdmMacMessagePolicy, EmptyCmacMessagePolicy>();
builder.Services.AddSingleton<ISdmMacTruncationPolicy, OddByteOffsetTruncationPolicy>();
builder.Services.AddSingleton<INtag424CmacVerifier, Ntag424CmacVerifier>();

// --- Orchestrator: sequences request validation -> replay pre-check -> key lookup ->
// CMAC verify -> replay commit -> outcome notification. ---
builder.Services.AddSingleton<ISdmVerifyCommandValidationPolicy, SdmVerifyCommandValidationPolicy>();
builder.Services.AddScoped<ISdmVerificationOrchestrator, SdmVerificationOrchestrator>();

var app = builder.Build();

app.MapGet("/", () => "NTAG 424 DNA SDM CMAC verifier is running.");

// Mirrors the query parameters an NTAG 424 DNA tag places in its SDM URL
// (e.g. ?uid=...&ctr=...&cmac=...). The master key is NEVER accepted from the
// caller - it is looked up server-side per UID via the network key service.
app.MapPost("/api/sdm/verify", async (
    SdmVerifyRequest request,
    ISdmVerificationOrchestrator orchestrator,
    CancellationToken cancellationToken) =>
{
    SdmVerificationOutcome outcome = await orchestrator.VerifyAsync(
        new SdmVerifyCommand(request.Uid, request.Counter, request.Cmac),
        cancellationToken);

    // Always a generic { valid: bool } response with no distinguishing error reasons, to
    // avoid leaking whether a UID is registered or why verification failed (avoid oracle
    // attacks). A duplicate-of-last-accepted request is reported as valid too, since it is
    // a safe idempotent retry, not an attack replay.
    return Results.Ok(new SdmVerifyResponse(outcome.IsSuccess));
});

app.Run();

internal record SdmVerifyRequest(string Uid, string Counter, string Cmac);

internal record SdmVerifyResponse(bool Valid);

