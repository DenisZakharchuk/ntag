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
AI-generated version of this file (see [`AesCmacCalculator.ComputeCmac`](Ntag424Cmac/AesCmacCalculator.cs)).

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
> `SDMMACInputOffset` and `SDMMACOffset` (AN12196 Table 5 — e.g. an encrypted file
> payload plus literal URL text like `&cmac=`), the message becomes the literal ASCII
> bytes of that mirrored region instead of being empty. That configuration is **not**
> currently supported by `VerifyCmac`, which assumes the simple Table 4 case.

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
Ntag424Cmac/                      SOLID verifier implementation (single source of truth;
                                  no project duplicates it — both projects below link to
                                  these files via <Compile Include="..\Ntag424Cmac\**\*.cs">).
  Ntag424SdmCmacRequest.cs        readonly ref struct wrapping VerifyCmac's inputs.
  IAesCmacCalculator.cs /
  AesCmacCalculator.cs            RFC 4493 AES-CMAC primitive.
  ISdmSessionVectorBuilder.cs /
  Sv2SessionVectorBuilder.cs      SV2 construction policy.
  ISdmMacMessagePolicy.cs /
  EmptyCmacMessagePolicy.cs       Final-MAC message policy (AN12196 Table 4; Table 5
                                  mirrored-data support can be added as a new policy).
  ISdmMacTruncationPolicy.cs /
  OddByteOffsetTruncationPolicy.cs Truncation policy.
  INtag424CmacVerifier.cs /
  Ntag424CmacVerifier.cs          Orchestrator composed from the policies above via DI.
NtagCmacApi/                      ASP.NET Core minimal API (.NET 10).
NtagCmacApi.Tests/                xUnit tests (RFC 4493 + official NXP AN12196 vectors,
                                  plus end-to-end self-consistency checks) — all exercise
                                  the abstractions above directly.
```

## 6. The web API

`POST /api/sdm/verify`

Request body:

```json
{ "uid": "04A1B2C3D4E5F6", "counter": "000001", "cmac": "9130AE6B05189C97" }
```

Response: `{ "valid": true|false }` always — no distinguishing error reasons, so the
endpoint can't be used to enumerate registered UIDs or the reason verification failed.

Design decisions:

- **The master key is never accepted from the client.** It's resolved server-side per
  UID via `ITagKeyProvider` (demo implementation reads `Ntag:TagKeys:{UID}` from
  configuration — swap in a database/HSM-backed provider for production; do not commit
  real keys to `appsettings.json`).
- **Replay protection.** `IReplayGuard` (in-memory, per-UID) rejects a request whose
  counter is not strictly greater than the last accepted counter for that UID. This is
  checked only *after* the CMAC has been validated, and the check-and-record is atomic
  per UID to avoid a race between two concurrent requests for the same tag. For a
  multi-instance deployment, replace the in-memory dictionary with a shared store
  (Redis/SQL).

## 7. Running

```powershell
cd NtagCmacApi
dotnet run

cd ../NtagCmacApi.Tests
dotnet test
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
