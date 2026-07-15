namespace NtagCmacApi.Persistence;

/// <summary>
/// A tenant/organization that owns one or more tags. Minimal reference entity - seeded
/// with a handful of records (see <see cref="NtagDbContext.OnModelCreating"/>) rather than
/// managed through the API yet.
/// </summary>
public sealed class Company
{
    /// <summary>Primary key.</summary>
    public required int Id { get; set; }

    /// <summary>Short, unique business code (e.g. ticker/slug-style identifier).</summary>
    public required string Code { get; set; }

    public required string Name { get; set; }

    public required DateTimeOffset CreatedOn { get; set; }

    public required string CreatedBy { get; set; }

    public DateTimeOffset? ModifiedOn { get; set; }

    public string? ModifiedBy { get; set; }
}
