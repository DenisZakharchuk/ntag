namespace NtagCmacApi.Models;

/// <summary>
/// Domain model for the raw fields an NTAG 424 DNA tag places in its SDM URL read
/// (uid/counter/cmac query parameters), plus an optional "serial" value some deployments
/// mirror alongside them (see the AN12196 Table 5 investigation in repo memory notes).
///
/// This is a domain model, not a transport/persistence DTO: it's the shape use cases,
/// business logic, and infrastructure (replay guard, key provider) all share, decoupled
/// from any one transport (HTTP request shape - see <c>Orchestration.SdmVerifyCommand</c>)
/// or persistence shape (see <c>Persistence.TagReplayState</c>).
/// </summary>
public sealed record NtagSDMData(string Uid, string? Serial, string Counter, string Cmac);
