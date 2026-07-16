namespace NtagCmacApi.Models;

/// <summary>
/// Domain-model reference to the tenant/organization that owns a tag, identified only by
/// its id. Deliberately NOT the same type as the EF Core <see cref="Persistence.Company"/>
/// entity (which also carries Code/Name/audit fields) - this is the minimal shape business
/// logic/orchestration needs, decoupled from the persistence schema.
///
/// <b>Naming collision, by design:</b> <c>Persistence.Company</c> is a distinct type in a
/// different namespace. Files that need both (e.g. <c>Persistence.EfReplayGuard</c>) must
/// disambiguate - e.g. via a <c>using DomainCompany = NtagCmacApi.Models.Company;</c> alias
/// - since both are named <c>Company</c>.
/// </summary>
public sealed record Company(int CompanyId, string CompanyCode);
