using Microsoft.EntityFrameworkCore;

namespace NtagCmacApi.Persistence;

public sealed class NtagDbContext : DbContext, IUnitOfWork
{
    public NtagDbContext(DbContextOptions<NtagDbContext> options) : base(options)
    {
    }

    public DbSet<TagReplayState> TagReplayStates => Set<TagReplayState>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TagReplayState>(entity =>
        {
            entity.HasKey(e => e.Uid);

            // Portable optimistic-concurrency token (works identically across InMemory,
            // SqlServer, Npgsql) - deliberately NOT a SQL-Server-specific rowversion.
            entity.Property(e => e.LastAcceptedCounter).IsConcurrencyToken();
        });
    }
}
