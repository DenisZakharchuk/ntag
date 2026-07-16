using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using DomainCompany = NtagCmacApi.Models.Company;

namespace NtagCmacApi.Persistence;

/// <summary>
/// EF Core-backed <see cref="ICompanyLookup"/>. Depends only on a <see cref="DbSet{TEntity}"/>
/// of <see cref="Company"/> (the EF entity) - not the concrete <see cref="NtagDbContext"/> -
/// consistent with <see cref="EfReplayGuard"/>.
/// </summary>
public sealed class EfCompanyLookup : ICompanyLookup
{
    private readonly DbSet<Company> _companies;
    private readonly ILogger<EfCompanyLookup> _logger;

    public EfCompanyLookup(DbSet<Company> companies, ILogger<EfCompanyLookup> logger)
    {
        _companies = companies;
        _logger = logger;
    }

    public async Task<DomainCompany?> FindByCodeAsync(string companyCode, CancellationToken cancellationToken)
    {
        Company? entity = await _companies.FirstOrDefaultAsync(c => c.Code == companyCode, cancellationToken);
        if (entity is null)
        {
            _logger.LogDebug("Company code {CompanyCode} not found", companyCode);
            return null;
        }

        return new DomainCompany(entity.Id, entity.Code);
    }
}
