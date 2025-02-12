using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using EZYSoft.Model;
using Microsoft.AspNetCore.Identity;

namespace EZYSoft.Helpers
{
    public class PasswordService
    {
        private readonly EzysoftDbContext _dbContext;
        private readonly UserManager<IdentityUser> _userManager;

        public PasswordService(EzysoftDbContext dbContext, UserManager<IdentityUser> userManager)
        {
            _dbContext = dbContext;
            _userManager = userManager;
        }

        // Get the timestamp of the most recent password change
        public async Task<DateTime?> GetLastPasswordChangeDateAsync(string userId)
        {
            var latestPasswordHistory = await _dbContext.PasswordHistories
                .Where(ph => ph.UserId == userId)
                .OrderByDescending(ph => ph.CreatedAt)
                .FirstOrDefaultAsync();

            return latestPasswordHistory?.CreatedAt;
        }

        // Check if the minimum password age requirement is met
        public bool IsMinimumPasswordAgeMet(DateTime? lastPasswordChangeDate, int minimumMinutes)
        {
            if (lastPasswordChangeDate == null)
            {
                return true; // No previous password change, so no restriction
            }

            var timeSinceLastChange = DateTime.UtcNow - lastPasswordChangeDate.Value;
            return timeSinceLastChange.TotalMinutes >= minimumMinutes;
        }

        // Check if the maximum password age requirement is exceeded
        public bool IsMaximumPasswordAgeExceeded(DateTime? lastPasswordChangeDate, int maximumMinutes)
        {
            if (lastPasswordChangeDate == null)
            {
                return false; // No previous password change, so no restriction
            }

            var timeSinceLastChange = DateTime.UtcNow - lastPasswordChangeDate.Value;
            return timeSinceLastChange.TotalMinutes > maximumMinutes;
        }

        // Save the new password in the password history
        public async Task SavePasswordHistoryAsync(string userId, string hashedPassword)
        {
            var passwordHistory = new PasswordHistory
            {
                UserId = userId,
                HashedPassword = hashedPassword,
                CreatedAt = DateTime.UtcNow
            };

            _dbContext.PasswordHistories.Add(passwordHistory);

            // Keep only the last 2 passwords
            var oldPasswords = await _dbContext.PasswordHistories
                .Where(ph => ph.UserId == userId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Skip(2)
                .ToListAsync();

            _dbContext.PasswordHistories.RemoveRange(oldPasswords);

            await _dbContext.SaveChangesAsync();
        }

        public async Task<bool> IsPasswordReuseAsync(string userId, string newPassword)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            // Get the last 2 passwords for the user
            var passwordHistories = await _dbContext.PasswordHistories
                .Where(ph => ph.UserId == userId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(2) // Only check the last 2 passwords
                .ToListAsync();

            foreach (var history in passwordHistories)
            {
                // Verify if the new password matches any of the stored hashed passwords
                var isMatch = _userManager.PasswordHasher.VerifyHashedPassword(user, history.HashedPassword, newPassword) == PasswordVerificationResult.Success;
                if (isMatch)
                {
                    return true; // Password reuse detected
                }
            }

            return false; // No password reuse detected
        }
    }
}
