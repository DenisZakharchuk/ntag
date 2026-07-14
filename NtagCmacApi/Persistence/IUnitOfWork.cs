namespace NtagCmacApi.Persistence;

/// <summary>
/// Minimal Unit-of-Work abstraction exposing only the "commit pending changes" operation.
/// Lets consumers (e.g. <see cref="EfReplayGuard"/>) persist changes made through an
/// injected <c>DbSet&lt;T&gt;</c> without depending on the concrete <see cref="NtagDbContext"/>
/// (or EF Core's <c>DbContext</c> base type) directly.
/// </summary>
public interface IUnitOfWork
{
    Task<int> SaveChangesAsync(CancellationToken cancellationToken);
}
