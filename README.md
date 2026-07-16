# NTAG 424 DNA SDM CMAC Verifier

Verifies the CMAC that an NTAG 424 DNA tag appends to its **SUN (Secure Unique NFC)
message** / **SDM (Secure Dynamic Messaging)** URL when read by a phone, and exposes
that verification as a small ASP.NET Core minimal API.

Reference: NXP application note **AN12196 — "NTAG 424 DNA and NTAG 424 DNA TagTamper
features and hints"** (Rev 2.0). LRP-mode tags use a different derivation (AN12304 /
AN12321) and are **not** covered by this implementation.

## 1. What the tag sends

When configured for SDM, the tag mirrors part of its state into the NDEF URL on every
read, e.g.:

```
https://example.com/tap?uid=04A1B2C3D4E5F6&ctr=000001&cmac=9130AE6B05189C97
```

- `uid` — 7-byte tag UID, hex.
- `ctr` (a.k.a. `SDMReadCtr`) — 3-byte monotonically increasing read counter, hex,
  little-endian on the wire but treated here simply as 3 raw bytes in tag order.
- `cmac` — 8-byte truncated CMAC, hex, proving the `uid`/`ctr` pair genuinely came from
  a tag that holds the AES-128 master key (not just replayed or forged text).

The server's job is to recompute the same 8-byte value from `uid` + `ctr` + the secret
master key for that tag, and compare it to `cmac` in constant time.

## 2. Algorithm, step by step

All of this lives in [`Ntag424CmacVerifier.Verify`](Ntag424Cmac/Ntag424CmacVerifier.cs).

### 2.1 Decode inputs

`uid` (7B), `ctr` (3B), and `cmac` (8B) are decoded from hex; the master key is decoded
from Base64 into 16 bytes. Any length mismatch or malformed hex/Base64 fails closed
(`return false`) before any cryptography runs.

### 2.2 Build the Session Vector (SV2)

A single 16-byte block is assembled:

| Offset | Bytes | Value |
|---|---|---|
| 0–1 | 2 | `0x3C 0xC3` — fixed SDM "SessionVectorMAC" label |
| 2 | 1 | `0x00` |
| 3 | 1 | `0x01` |
| 4 | 1 | `0x00` |
| 5 | 1 | `0x80` |
| 6–12 | 7 | UID |
| 13–15 | 3 | SDMReadCtr |

### 2.3 Derive the SDM session key

```
SessionKey = AES128-CMAC(MasterKey, SV2)
```

This is **not** a plain `AES-ECB(MasterKey, SV2)` encryption. `SV2` is exactly one
16-byte block, so per RFC 4493 CMAC still XORs it with subkey `K1` (derived from
`MasterKey`) before the final AES encryption. Skipping that XOR silently produces a
key that will never match a real tag — this was the first bug found in the original
AI-generated version of this file (see [`AesCmacCalculator.ComputeCmac`](Ntag424Cmac/Cryptography/AesCmacCalculator.cs)).

### 2.4 MAC an empty message

```
FullCmac = AES128-CMAC(SessionKey, "")     // 16 bytes, zero-length input
```

Per **NXP AN12196 Table 4** ("CMAC calculation when `SDMMACInputOffset == SDMMACOffset`"
— the configuration that applies whenever nothing besides UID/counter/CMAC is mirrored
into the URL, i.e. the common case), the final CMAC's message is **empty**, not
`UID || SDMReadCtr`. UID and SDMReadCtr are already authenticated implicitly: they're
baked into `SV2`, which derives `SessionKey` — a wrong UID or counter yields a wrong
`SessionKey` and therefore a wrong `FullCmac`, without needing to MAC them a second
time. Re-MACing `UID || SDMReadCtr` as the message (as earlier versions of this file
did, based on a plausible-looking but incorrect assumption) produces a value that will
never match a real tag.

CMAC still runs its full algorithm on this empty input: it pads it to one block
(`0x80` followed by zeros) and XORs the result with subkey `K2` before the final AES
encryption — the "incomplete block" branch of `ComputeAesCmac`, with `message.Length == 0`.

> **Scope note:** if a tag is configured to mirror additional file data between
> `SDMMACInputOffset` and `SDMMACOffset` (AN12196 Table 5 - e.g. an encrypted file
> payload, plaintext file data, or literal URL text like a static `serial=` value), the
> message becomes the literal bytes of that mirrored region instead of being empty. This
> IS now supported via `MirroredDataCmacMessagePolicy` (select it with
> `Ntag:MacMessagePolicy:Type = "MirroredData"`) - see section 6 below. **It has not been
> validated against an official NXP Table 5 vector**, only against self-consistency tests
> (unlike Table 4, which is confirmed against NXP's official worked example) - confirm
> against your tag's real configuration/a known-valid captured read before relying on it
> in production.

### 2.5 Truncate to 8 bytes

The tag's on-chip firmware does **not** send the first 8 bytes of `FullCmac`. It sends
the **odd-indexed bytes**:

```
TruncatedCmac[i] = FullCmac[2*i + 1]   for i = 0..7
                  = FullCmac[1, 3, 5, 7, 9, 11, 13, 15]
```

Using `FullCmac[0..7]` instead is the second bug found in the original version — it
would compile and run, but never match a real tag.

### 2.6 Constant-time compare

`TruncatedCmac` is compared to the received `cmac` via
`CryptographicOperations.FixedTimeEquals`, avoiding a timing side-channel that could
let an attacker binary-search their way to a valid MAC.

## 3. The AES-CMAC primitive (RFC 4493 / NIST SP 800-38B)

`ComputeAesCmac` implements standard AES-128 CMAC from scratch (no `System.Security.
Cryptography` CMAC type is used, since one wasn't natively available at the time this
was written):

1. **Subkey derivation**: encrypt an all-zero block with AES-ECB to get `L`, then
   derive `K1 = ShiftLeft(L) [^ 0x87 if L's MSB was set]`, and `K2` the same way from
   `K1`. `0x87` is the AES-128 CMAC constant `Rb`.
2. **Last-block handling**: if the message is a non-empty exact multiple of 16 bytes,
   XOR its last block with `K1`. Otherwise, pad the final partial block with `0x80`
   followed by zeros and XOR it with `K2`. **A zero-length message must take the `K2`
   branch** (there's no data to treat as a "complete" block) — this was the third bug
   found: the original length check (`n == 0`) misclassified an empty message as
   complete and crashed with `ArgumentOutOfRangeException` when slicing.
3. **Chaining**: for every full block except the last, XOR it into a running state `X`
   and encrypt in place (`X = AES-ECB(X)`). Finally XOR the prepared last block into `X`
   and do one more AES-ECB encryption to produce the 16-byte MAC.

Validated in [`NtagCmacApi.Tests/AesCmacTests.cs`](NtagCmacApi.Tests/AesCmacTests.cs)
against the official RFC 4493 AES-128 test vectors (empty message, exactly one block,
and a multi-block partial message) — all three pass.

## 4. Known bugs fixed vs. the original AI-generated version

| # | Bug | Symptom | Fix |
|---|---|---|---|
| 1 | `aes.KeySpan = ...` | Does not compile — no such property on `Aes`/`SymmetricAlgorithm` in .NET (verified against the `dotnet/runtime` source). | Use `aes.Key = key.ToArray()`. True zero-heap-allocation AES key assignment is not possible in .NET today; a small 16-byte allocation per CMAC call is unavoidable. |
| 2 | Session key = `AES-ECB(MasterKey, SV2)` | Compiles and runs, but never matches a real tag's CMAC. | Session key = `CMAC(MasterKey, SV2)` (adds the missing `K1` XOR). |
| 3 | Truncation took `FullCmac[0..7]` | Compiles and runs, but never matches a real tag's CMAC. | Truncation takes `FullCmac[1,3,5,...,15]` (odd indices). |
| 4 | Zero-length CMAC input crashed | `ArgumentOutOfRangeException` when `message.Length == 0`. | Treat empty message as an incomplete final block (`K2` branch), not a complete one. |
| 5 | Final CMAC was computed over `Message = UID \|\| SDMReadCtr` | Compiles and runs, but never matches a real tag's CMAC — contradicted by the official AN12196 Table 4 vector, which shows the final CMAC covers a **zero-length** message. | Compute `FullCmac = CMAC(SessionKey, "")`. UID/counter are already authenticated via `SV2 -> SessionKey`. |

None of the above were caught by compiling the code — they either throw at runtime
under specific inputs or silently produce a wrong-but-plausible-looking result. Bug #5
in particular was not something a code review alone would catch, since MACing
`UID || SDMReadCtr` looks entirely reasonable — it took the official NXP worked example
to reveal it. This is why the RFC 4493 test vectors and the official NXP vector matter
more than "it builds and one manual run looked fine."

## 5. Project layout

```
Ntag424Cmac/                      SOLID verifier implementation, its own class library
                                  project (`Ntag424Cmac.csproj`, net10.0) - both projects
                                  below reference it via `<ProjectReference>` rather than
                                  linking its source files in directly. Organized as one
                                  sub-namespace per concern, folder name matching
                                  namespace suffix (e.g. `Codecs/` -> `Ntag424.Cmac.Codecs`).
  Ntag424Cmac.csproj              Class library project file; only external dependency is
                                  `Microsoft.Extensions.DependencyInjection` (for
                                  `ServiceCollectionExtensions.AddCmac`).
  Ntag424SdmCmacRequest.cs        readonly ref struct wrapping VerifyCmac's inputs
                                  (namespace `Ntag424.Cmac` - the library's public surface).
  INtag424CmacVerifier.cs /
  Ntag424CmacVerifier.cs          Orchestrator composed from the policies below via DI
                                  (namespace `Ntag424.Cmac`).
  ServiceCollectionExtensions.cs  `AddCmac(Action<CmacOptions>? configure)` composition-root
                                  helper (options-delegate pattern, matching ASP.NET Core's
                                  own composition-root APIs, e.g. `AddDbContext<T>(options =>
                                  ...)`); selects Table 4 vs Table 5 message policy and
                                  counter byte-order convention via `CmacOptions`. Routes
                                  `CmacOptions` through the standard Options pipeline
                                  (`services.AddOptions<CmacOptions>().Configure(configure)`)
                                  rather than evaluating it eagerly, so
                                  `ISdmMacMessagePolicy`/`ICounterCodec` resolve it via
                                  `IOptionsMonitor<CmacOptions>` at construction time - this
                                  lets a host app layer additional `IOptionsMonitor`-driven
                                  configuration on top after calling `AddCmac()` (see
                                  `NtagCmacApi/Program.cs`). Every service is registered
                                  Transient (not Singleton): `Ntag424CmacVerifier` holds its
                                  policies as constructor fields for its own lifetime, so a
                                  Singleton graph would permanently capture whichever
                                  `CmacOptions` values were current at first resolution -
                                  Transient rebuilds the (cheap, stateless) graph on every
                                  resolution instead, so it always reflects the current
                                  `IOptionsMonitor<CmacOptions>.CurrentValue`.
  CmacOptions.cs                  `MacMessagePolicyKind`/`CounterCodecKind` enums + the
                                  `CmacOptions` POCO configured by the delegate above.
  Cryptography/                   namespace `Ntag424.Cmac.Cryptography`
    IAesCmacCalculator.cs /
    AesCmacCalculator.cs          RFC 4493 AES-CMAC primitive. Caches a single BCL `Aes`
                                  instance for its own lifetime rather than calling
                                  `Aes.Create()` per `ComputeCmac()` call - on Windows,
                                  `Aes.Create()` wraps CNG (BCrypt), and opening a new
                                  algorithm/key handle per call was a measurable native-side
                                  cost invisible to managed-heap allocation metrics (see the
                                  benchmarks project below). The `Aes` instance is created
                                  LAZILY (on first `ComputeCmac()` call, not in the
                                  constructor) since this type is resolved via DI on EVERY
                                  verification request as part of the whole CMAC dependency
                                  graph, but the pipeline has several earlier short-circuit
                                  exit points (validation, company lookup, replay pre-check,
                                  key lookup) before CMAC verification is ever reached - a
                                  rejected request shouldn't pay for opening a native AES
                                  handle it will never use. Implements `IDisposable`
                                  (`Dispose()` is a safe no-op if never actually used).
  SessionVectors/                 namespace `Ntag424.Cmac.SessionVectors`
    ISdmSessionVectorBuilder.cs /
    Sv2SessionVectorBuilder.cs    SV2 construction policy.
  MessagePolicies/                namespace `Ntag424.Cmac.MessagePolicies`
    ISdmMacMessagePolicy.cs /
    EmptyCmacMessagePolicy.cs     Table 4 final-MAC message policy (empty message).
    MirroredDataCmacMessagePolicy.cs Table 5 final-MAC message policy (MACs the literal
                                  bytes mirrored between SDMMACInputOffset/SDMMACOffset,
                                  e.g. a static `serial=` value or a full query string up
                                  to and including `mac=`) - CONFIRMED against a real
                                  captured tag read (see section 6).
  Truncation/                     namespace `Ntag424.Cmac.Truncation`
    ISdmMacTruncationPolicy.cs /
    OddByteOffsetTruncationPolicy.cs Truncation policy.
  Codecs/                         namespace `Ntag424.Cmac.Codecs`
    IMasterKeyCodec.cs / Base64MasterKeyCodec.cs   Master-key wire-decoding policy.
    IUidCodec.cs / HexUidCodec.cs                  UID wire-decoding policy (literal hex
                                                    bytes, written order).
    ICounterCodec.cs / LiteralHexCounterCodec.cs   Default counter-decoding policy (literal
                                                    hex bytes, written order - matches NXP's
                                                    official AN12196 Table 4 vector).
    NumericLittleEndianCounterCodec.cs             Alternate counter-decoding policy: parses
                                                    ctr as a number, re-encodes little-endian/
                                                    LSB-first - confirmed correct for a real
                                                    captured tag read (combined with Table 5).
  Comparison/                      namespace `Ntag424.Cmac.Comparison`
    IMacEqualityComparer.cs /
    FixedTimeMacEqualityComparer.cs Production default - wraps
                                  `CryptographicOperations.FixedTimeEquals` (constant-time,
                                  avoids a timing side-channel when comparing a received
                                  CMAC against the locally computed one).
    PlainMacEqualityComparer.cs   `ReadOnlySpan<byte>.SequenceEqual` - NOT constant-time.
                                  Benchmark/test use only; never registered by `AddCmac`.
NtagCmacApi/                      ASP.NET Core minimal API (.NET 10).
  CmacSettings.cs                 `MacMessagePolicySettings`/`CounterCodecSettings` - thin
                                  app-level POCOs bound from the "Ntag:MacMessagePolicy"/
                                  "Ntag:CounterCodec" config sections (each mirroring that
                                  section's "Type" sub-key) via `services.Configure<T>()`.
                                  Kept separate from Ntag424Cmac's own `CmacOptions` so
                                  config binding stays decoupled from the library's own
                                  composition-root shape; Program.cs maps their resolved
                                  `IOptionsMonitor<T>.CurrentValue.Type` into `CmacOptions`.
  Models/                         Domain models, namespace `NtagCmacApi.Models` - shared
                                  across use cases/business logic/infrastructure, decoupled
                                  from any one transport (HTTP DTOs) or persistence shape.
    NtagSDMData.cs                `record NtagSDMData(Uid, Serial, Counter, Cmac)` - the
                                  raw SDM read fields, serial optional.
    Company.cs                    `record Company(CompanyId, CompanyCode)` - minimal
                                  tenant reference, resolved (via `ICompanyLookup`) from the
                                  `CompanyCode` supplied in the verification request.
                                  Deliberately a DIFFERENT type from
                                  `Persistence.Company` (the EF entity, which also carries
                                  Code/Name/audit fields) - both are named `Company` in
                                  different namespaces; files needing both alias one via
                                  `using DomainCompany = NtagCmacApi.Models.Company;`.
  Persistence/                    EF Core replay-guard state store.
    TagReplayState.cs             Entity: per-UID last-accepted counter/CMAC, plus a
                                  REQUIRED `int CompanyId` FK (every accepted verification
                                  must resolve to a real company) and nullable `Serial`
                                  (plumbed through from `NtagSDMData` on every commit).
    Company.cs                    EF entity (Id, Code, Name, CreatedOn/CreatedBy required +
                                  ModifiedOn/ModifiedBy nullable audit fields); seeded with
                                  a few records, not yet managed via API. `Id` is `int`.
    ICompanyLookup.cs /
    EfCompanyLookup.cs            Resolves a caller-supplied `CompanyCode` to a
                                  `Models.Company` (with its persisted id), by querying the
                                  `Companies` table for a matching `Code`. Required because
                                  `TagReplayState.CompanyId` is mandatory - an unresolvable
                                  code fails the request (`CompanyUnknown` outcome) before
                                  any replay/key/CMAC work. Logs a Debug line on a miss
                                  (not a Warning - the orchestrator already logs that).
    NtagDbContext.cs              DbContext; LastAcceptedCounter is an EF Core
                                  concurrency token (portable across providers, unlike a
                                  SQL-Server-only rowversion column). Configures the
                                  TagReplayState -> Company FK (Restrict on delete) and
                                  seeds Company rows via HasData.
    Migrations/                   EF Core migrations (`dotnet ef migrations add ...`) -
                                  currently EMPTY (deleted pending a model change; not yet
                                  regenerated - run `dotnet ef migrations add InitialCreate`
                                  then `dotnet ef database update` before running against
                                  SqlServer).
    IReplayGuard.cs /
    EfReplayGuard.cs              Async pre-check (cheap, before network/crypto - takes
                                  only a `Models.NtagSDMData`, no company needed) + commit
                                  (conditional update, rejects on lost optimistic-
                                  concurrency race - takes a `Models.NtagSDMData` AND a
                                  REQUIRED `Models.Company`, since persisting always needs
                                  a real CompanyId) split — the DB-backed equivalent of the
                                  old ConcurrentDictionary.TryUpdate CAS loop. A lost
                                  concurrency race is expected under load, so it's only
                                  logged at Debug; an unparseable counter (should never
                                  happen - the validation policy already checked it) is
                                  logged at Warning since it indicates a real bug.
  KeyProvider/                    Master-key resolution over the network.
    ITagKeyProvider.cs            Found / NotFound / ServiceError result contract.
                                  `GetMasterKeyAsync` takes a `Models.NtagSDMData` instance.
    TagKeyServiceOptions.cs       Options bound from "Ntag:KeyService" config.
    HttpTagKeyProvider.cs         Typed HttpClient implementation; fails closed (maps all
                                  network/timeout/malformed-response errors to
                                  ServiceError) rather than throwing. NotFound (a tag simply
                                  isn't registered) is only logged at Debug - it's a normal
                                  outcome, not a failure; actual service/network errors are
                                  logged at Warning.
  Orchestration/                  Composes the pipeline for one verification request.
    SdmVerifyCommand.cs           Plain-string DTO (crosses async boundaries; the crypto
                                  core's ref struct request cannot) - REQUIRED
                                  `CompanyCode` field (like Uid/Counter/Cmac) plus optional
                                  `MirroredData`/`Serial`.
    SdmVerificationOutcome.cs     Closed-set sealed record hierarchy (MalformedRequest,
                                  CompanyUnknown, ReplayRejected, TagKeyUnavailable,
                                  CmacInvalid, ReplayLostRace, DuplicateOfLastAccepted,
                                  Accepted) — enables exhaustive handling of each failure
                                  stage. Carries a `Models.NtagSDMData? Data` (not raw
                                  uid/counter strings). Owns static factory methods
                                  (`ForCompanyUnknown`, `FromReplayPreCheck`,
                                  `ForTagKeyUnavailable`, `ForCmacInvalid`,
                                  `FromReplayCommit`) that map each dependency's raw result
                                  to the right outcome subtype - this mapping logic lives
                                  here, not in the orchestrator, to avoid "feature envy"
                                  (the orchestrator would otherwise need to know every
                                  outcome subtype's shape just to pick one).
    ISdmVerificationOrchestrator.cs /
    SdmVerificationOrchestrator.cs Sequences replay pre-check -> key lookup -> CMAC verify
                                  -> company resolution -> replay commit -> outcome
                                  notification. A fixed pipeline (not itself a Strategy);
                                  each step it composes is independently swappable via DI.
                                  Resolves `command.CompanyCode` via `ICompanyLookup` right
                                  before the commit (the only step that needs one) -
                                  resolving it any earlier would spend a DB lookup on
                                  requests that end up rejected by the pre-check, key
                                  lookup, or CMAC verification anyway. An unresolvable code
                                  short-circuits to `CompanyUnknown` before the commit.
  Notifications/                  Reporting outcomes to an external "master system".
    IOutcomeNotifier.cs           Abstraction; called for every outcome, success or not.
    LoggingOutcomeNotifier.cs     Placeholder implementation — logs instead of calling a
                                  real system. One line per request: Information for a
                                  successful outcome, Warning for anything else. A failing
                                  notifier is swallowed and never changes the HTTP response.
  UrlParsing/                     Optional convenience: accept the raw scanned URL.
    ISdmUrlParser.cs /
    SdmUrlParser.cs               Extracts uid/ctr/mac/serial query params and computes the
                                  AN12196 Table 5 mirrored-data message automatically
                                  (literal query text up to and including "mac=") so
                                  callers can submit the exact tag-scanned URL instead of
                                  pre-splitting it themselves. `CompanyCode` is NOT part of
                                  the tag's URL - the caller always supplies it separately
                                  (Program.cs merges it in via a record `with` expression).
                                  Malformed URLs/missing fields yield an empty command,
                                  letting the existing validation policy classify it as
                                  MalformedRequest.
NtagCmacApi.Tests/                xUnit tests (RFC 4493 + official NXP AN12196 vectors,
                                  end-to-end self-consistency checks, EF Core replay-guard
                                  concurrency tests, HTTP key-provider fake-handler tests,
                                  orchestrator sequencing tests with hand-written fakes,
                                  codec unit tests, a CONFIRMED real-captured-tag-read
                                  regression test, and raw-URL-parsing end-to-end tests) —
                                  all exercise the abstractions above directly.
mishaAlg/                         Standalone historical reference implementation
                                  (BouncyCastle, byte[]-allocating, no policy abstractions) -
                                  the original baseline this project's Span/stackalloc-based
                                  `Ntag424CmacVerifier` was rewritten from. `MishaAlg.Verify(url,
                                  key)` parses a raw scanned URL end-to-end;
                                  `MishaAlg.VerifyCore(uid, counterLsb, macInputAscii, key,
                                  expectedMacHex)` is the same CMAC computation with URL
                                  parsing factored out, so it can be benchmarked against
                                  `Ntag424CmacVerifier.Verify` on equal footing (see below).
Ntag424Cmac.Benchmarks/            BenchmarkDotNet console project comparing mishaAlg
                                  (byte[]-allocating) against `Ntag424CmacVerifier`
                                  (Span/stackalloc-based) for speed, allocations, and GC
                                  generation counts (`[MemoryDiagnoser]`).
  CmacTestVector.cs / CmacTestVectors.cs  A confirmed CMAC sample (currently one - the
                                  real-world Table 5/NumericLittleEndian vector also used in
                                  `RealWorldTable5NumericCounterVerificationTests`), exposed
                                  via `CmacTestVectors.All`. Add more vectors here as they're
                                  confirmed; `[ParamsSource]` picks up every entry
                                  automatically, no other code changes needed.
  CmacVerificationBenchmarks.cs   Three `[Benchmark]` methods per vector:
                                  `MishaAlg_Verify_NaturalUrl` (baseline, includes URL
                                  parsing), `MishaAlg_VerifyCore_Normalized` (URL parsing
                                  excluded - fair pairing with the next one), and
                                  `Ntag424CmacVerifier_Verify` (wired with
                                  `PlainMacEqualityComparer`, not the constant-time
                                  production default, so its deliberately-constant cost
                                  doesn't skew the CMAC-computation comparison). Run via
                                  `dotnet run -c Release` (BenchmarkDotNet requires Release).
  AesPrimitiveBenchmarks.cs       Diagnostic micro-benchmark that isolated WHY
                                  `Ntag424CmacVerifier_Verify` was initially slower than
                                  mishaAlg despite allocating far less: repeated
                                  `Aes.Create()` calls (fixed in `AesCmacCalculator`, see
                                  above), not BouncyCastle's AES being inherently faster.
                                  Also documents the REMAINING gap: RFC 4493's own 2x
                                  subkey-derivation cost across `Verify()`'s two
                                  differently-keyed `ComputeCmac` calls - a genuine
                                  structural difference in work done, not a further bug.
  AvalancheGcBenchmarks.cs        Simulates a burst of back-to-back verification requests
                                  (`[Params(1_000, 10_000, 100_000)]`) instead of a single
                                  isolated call, to see CUMULATIVE GC behavior (total
                                  time/bytes for the whole burst, Gen0/Gen1/Gen2 collections
                                  per burst) - not just a per-call allocation figure. At
                                  100,000 requests: mishaAlg's array-based core allocates
                                  ~318 MB total (~69 Gen0 + ~0.33 Gen1 collections per
                                  burst) vs. `Ntag424CmacVerifier`'s ~82 MB (~17 Gen0, 0 Gen1
                                  observed) - ~4x fewer Gen0 pauses and no Gen1 promotions at
                                  all for the Span-based implementation, at the cost of
                                  being ~2x slower in wall-clock time (consistent with the
                                  structural gap `AesPrimitiveBenchmarks.cs` explains).
```

## 6. The web API

`POST /api/sdm/verify`

Request body — either discrete fields:

```json
{ "uid": "04A1B2C3D4E5F6", "counter": "000001", "cmac": "9130AE6B05189C97", "companyCode": "ACME" }
```

...or the raw scanned URL directly (parsed via `ISdmUrlParser`, which also derives the
AN12196 Table 5 mirrored-data message automatically — see below). `companyCode` is always
supplied separately, since it isn't part of the tag's own URL:

```json
{ "url": "https://example.com/?serial=11111111&uid=04B43132502390&ctr=000001&mac=E7D76C550FF1755B", "companyCode": "ACME" }
```

`companyCode` is **required** - it's resolved via `ICompanyLookup` (querying the
`Companies` table by `Code`), right before the replay commit, since
`TagReplayState.CompanyId` is a mandatory FK and that's the only step that actually needs
one (resolving any earlier would spend a DB lookup on requests already doomed to fail the
pre-check, key lookup, or CMAC verification). An unresolvable code yields a
`CompanyUnknown` outcome (`{ "valid": false }`, no distinguishing detail - same
oracle-attack-prevention rule as every other failure case).


If the tag's SDM configuration is AN12196 Table 5 (`SDMMACInputOffset != SDMMACOffset`,
e.g. a static `serial=` value or other mirrored data sits between the two MAC offsets),
also set `Ntag:MacMessagePolicy:Type` to `"MirroredData"` and include that literal mirrored
text in the request body:

```json
{ "uid": "04A1B2C3D4E5F6", "counter": "000001", "cmac": "...", "mirroredData": "serial=548721" }
```

**This Table 5 support has now been CONFIRMED against a real captured tag read** (not just
self-consistency) - see
[`RealWorldTable5NumericCounterVerificationTests.cs`](NtagCmacApi.Tests/RealWorldTable5NumericCounterVerificationTests.cs),
cross-validated against an independent BouncyCastle-based implementation. That confirmed
vector required combining **two** settings, neither of which alone reproduces the MAC:

- `Ntag:MacMessagePolicy:Type = "MirroredData"` - message = the literal query text from
  right after `?` through and including the literal `mac=` text (i.e. `SDMMACOffset` lands
  exactly where the truncated MAC's hex digits begin).
- `Ntag:CounterCodec:Type = "NumericLittleEndian"` - the `ctr` field is parsed as a plain
  number and re-encoded little-endian/LSB-first for the SV2 session vector, rather than
  decoded literally in written byte order. NXP's own official AN12196 Table 4 vector uses
  the literal-byte-order convention directly (the default, `"LiteralHex"`) - different
  deployments have been observed to use either convention, so confirm which applies to your
  tags (ideally against a real captured read) before choosing.

Response: `{ "valid": true|false }` always — no distinguishing error reasons, so the
endpoint can't be used to enumerate registered UIDs or the reason verification failed.

The request is handled by `ISdmVerificationOrchestrator`
([`SdmVerificationOrchestrator.cs`](NtagCmacApi/Orchestration/SdmVerificationOrchestrator.cs)),
which sequences the following steps and reports the resulting `SdmVerificationOutcome`
to `IOutcomeNotifier` before returning:

1. **Replay pre-check** ([`EfReplayGuard.PreCheckAsync`](NtagCmacApi/Persistence/EfReplayGuard.cs)) —
   cheap, before any network call or crypto. Rejects a stale counter outright, and
   recognizes an exact repeat of the last accepted `(counter, cmac)` pair as a safe
   idempotent retry (`DuplicateOfLastAccepted`) rather than an attack.
2. **Master-key resolution** ([`HttpTagKeyProvider`](NtagCmacApi/KeyProvider/HttpTagKeyProvider.cs)) —
   the master key is **never accepted from the client**. It's resolved server-side per
   UID over HTTP from an external key service (`Ntag:KeyService:BaseUrl` in
   configuration). Any network failure, timeout, or malformed response fails closed to
   `ServiceError` rather than throwing.
3. **CMAC verification** — the existing zero-allocation, synchronous crypto core
   (`INtag424CmacVerifier`, unchanged), invoked with the resolved key.
4. **Replay commit** ([`EfReplayGuard.CommitAsync`](NtagCmacApi/Persistence/EfReplayGuard.cs)) —
   persists the newly-verified counter as the new accepted state for that UID via EF
   Core, using an **optimistic-concurrency token** on `LastAcceptedCounter`
   (`NtagDbContext`) instead of a single in-process `ConcurrentDictionary.TryUpdate`.
   This closes the race window that separating "check" from "record" across a network
   call (step 2) and crypto (step 3) would otherwise reopen: if two concurrent requests
   for the same UID both pass pre-check and reach commit, only one `SaveChangesAsync`
   wins — the other throws `DbUpdateConcurrencyException` (or `DbUpdateException` on a
   racing first insert), which is caught and reported as `ReplayLostRace`, never
   silently overwritten. This design is durable and safe across multiple app instances,
   unlike the previous in-memory dictionary.

Persistence uses **EF Core** (`NtagDbContext`) with the provider selected via
`Ntag:Persistence:Provider` in configuration. Default is `SqlServer`, connecting to a
local SQL Server instance via **Windows Authentication** (`ConnectionStrings:Ntag` -
`Integrated Security=True`); `InMemory` remains available for local dev/tests without a
real DB. Switching to `Npgsql` only requires adding the provider package, a connection
string, and a new EF Core migration; no other application code changes. Schema is managed
via EF Core Migrations (`NtagCmacApi/Migrations/`) — after any model change, run:

```powershell
dotnet tool install --global dotnet-ef   # one-time
cd NtagCmacApi
dotnet ef migrations add <Name>
dotnet ef database update
```

`NtagDbContext` also has a `Company` reference entity (`Id`, `Code`, `Name`), seeded with
a few sample rows via `HasData`. `TagReplayState.CompanyId` is a nullable FK to it,
scaffolded for future multi-tenant use — no current code path assigns a company to a tag
yet.

Regardless of the outcome — success or any failure stage — the orchestrator always
invokes `IOutcomeNotifier` to report it to an external "master system" (currently a
placeholder `LoggingOutcomeNotifier`). A failing notifier is caught and logged but never
changes the returned outcome or the HTTP response.

## 7. Running

```powershell
cd NtagCmacApi
dotnet run

cd ../NtagCmacApi.Tests
dotnet test
```

Speed/memory/GC comparison of the byte[]-allocating vs. Span-based CMAC implementations
(BenchmarkDotNet requires a Release build):

```powershell
cd Ntag424Cmac.Benchmarks
dotnet run -c Release
```

## 8. Validation status

- ✅ Core AES-CMAC primitive validated against official RFC 4493 / NIST SP 800-38B
  AES-128 test vectors ([`AesCmacTests.cs`](NtagCmacApi.Tests/AesCmacTests.cs)).
- ✅ `SV2` construction, CMAC-based session key derivation, and the final truncated
  SDMMAC all validated against the **official NXP AN12196 Table 4 worked example**
  ([`An12196Table4VectorTests.cs`](NtagCmacApi.Tests/An12196Table4VectorTests.cs)) — this
  is what caught bug #5 above.
- ✅ Full `VerifyCmac` pipeline additionally validated by self-consistency tests (valid
  MAC accepted, tampering rejected, malformed input rejected without throwing).
- ⏳ Not yet validated against a real physical tag, nor against AN12196 Table 5 (the
  `SDMMACInputOffset != SDMMACOffset` configuration with additional mirrored file data)
  — that configuration is out of scope for the current `VerifyCmac` implementation.
