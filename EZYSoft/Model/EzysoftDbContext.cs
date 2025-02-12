using EZYSoft.ViewModel;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace EZYSoft.Model
{
	public class EzysoftDbContext : IdentityDbContext<IdentityUser>
	{
        private readonly IConfiguration _configuration;

        // Add DbSet for your custom tables
        public DbSet<UserDetail> UserDetails { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; } 

        public EzysoftDbContext(IConfiguration configuration)
        {
			_configuration= configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("AuthConnectionString"); optionsBuilder.UseSqlServer(connectionString);
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			base.OnModelCreating(modelBuilder);

			// Configure the relationship between UserDetails and AspNetUsers
			modelBuilder.Entity<UserDetail>()
				.HasKey(ud => ud.UserId); // Define UserId as the primary key

			modelBuilder.Entity<UserDetail>()
				.HasOne<IdentityUser>() // One-to-one relationship with IdentityUser
				.WithOne()
				.HasForeignKey<UserDetail>(ud => ud.UserId) // Foreign key
				.OnDelete(DeleteBehavior.Cascade); // Optional: Cascade delete behavior

            // Configure the relationship for PasswordHistory
            modelBuilder.Entity<PasswordHistory>()
                .HasKey(ph => ph.Id); // Define Id as the primary key
            modelBuilder.Entity<PasswordHistory>()
                .HasOne(ph => ph.User) // One-to-many relationship with IdentityUser
                .WithMany()
                .HasForeignKey(ph => ph.UserId) // Foreign key
                .OnDelete(DeleteBehavior.Cascade); // Optional: Cascade delete behavior
        }
	}
}
