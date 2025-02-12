using Microsoft.AspNetCore.Identity;

namespace EZYSoft.Model
{
    public class PasswordHistory
    {
        public int Id { get; set; } // Primary key

        // Foreign key referencing the user
        public string UserId { get; set; }
        public IdentityUser User { get; set; }

        // Hashed password
        public string HashedPassword { get; set; }

        // Timestamp of when the password was set
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
