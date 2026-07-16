using DomainCompany = NtagCmacApi.Models.Company;

namespace NtagCmacApi.Persistence;

/// <summary>
/// Resolves a company by its business code (as supplied in a verification request) to the
/// full domain <see cref="DomainCompany"/>, including its persisted <see cref="Company.Id"/> -
/// required because <see cref="TagReplayState.CompanyId"/> is a mandatory (non-nullable)
/// FK, so every accepted verification must resolve to a real company first.
/// </summary>
public interface ICompanyLookup
{
    /// <summary>
    /// Attempts to resolve <paramref name="companyCode"/> to a company. Returns
    /// <see langword="null"/> if no company with that code is registered - callers must
    /// fail closed (reject the request) rather than proceed with an unresolved company.
    /// </summary>
    Task<DomainCompany?> FindByCodeAsync(string companyCode, CancellationToken cancellationToken);
}
