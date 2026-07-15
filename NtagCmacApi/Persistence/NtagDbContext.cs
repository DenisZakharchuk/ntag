using Microsoft.EntityFrameworkCore;

namespace NtagCmacApi.Persistence;

public sealed class NtagDbContext : DbContext, IUnitOfWork
{
    // Fixed (not DateTimeOffset.UtcNow) so EF Core's HasData seed produces stable migration
    // output - a changing value would make EF think the model changed on every build.
    private static readonly DateTimeOffset SeedCreatedOn = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string SeedCreatedBy = "seed";

    public NtagDbContext(DbContextOptions<NtagDbContext> options) : base(options)
    {
    }

    public DbSet<TagReplayState> TagReplayStates => Set<TagReplayState>();

    public DbSet<Company> Companies => Set<Company>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Company>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Code).IsUnique();

            entity.HasData(
                new Company { Id = 1, Code = "ACME", Name = "Acme Corporation", CreatedOn = SeedCreatedOn, CreatedBy = SeedCreatedBy },
                new Company { Id = 2, Code = "GLOBEX", Name = "Globex Corporation", CreatedOn = SeedCreatedOn, CreatedBy = SeedCreatedBy },
                new Company { Id = 3, Code = "INITECH", Name = "Initech LLC", CreatedOn = SeedCreatedOn, CreatedBy = SeedCreatedBy });
        });

        modelBuilder.Entity<TagReplayState>(entity =>
        {
            entity.HasKey(e => e.Uid);

            // Portable optimistic-concurrency token (works identically across InMemory,
            // SqlServer, Npgsql) - deliberately NOT a SQL-Server-specific rowversion.
            entity.Property(e => e.LastAcceptedCounter).IsConcurrencyToken();

            // Nullable FK: no current code path assigns a company to a tag yet (see
            // TagReplayState.CompanyId remarks) - Restrict keeps a company from being
            // deleted out from under tags that reference it, rather than silently
            // cascading and wiping replay-protection history.
            entity.HasOne<Company>()
                .WithMany()
                .HasForeignKey(e => e.CompanyId)
                .OnDelete(DeleteBehavior.Restrict);
        });
    }
}
