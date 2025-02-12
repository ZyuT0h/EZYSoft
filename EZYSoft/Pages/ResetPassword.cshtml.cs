using EZYSoft.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace EZYSoft.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly EzysoftDbContext _dbContext;

        [BindProperty]
        public ResetPasswordInput Input { get; set; }

        public class ResetPasswordInput
        {
            [Required]
            public string Token { get; set; }

            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string NewPassword { get; set; }

            [Required]
            [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public ResetPasswordModel(UserManager<IdentityUser> userManager, EzysoftDbContext dbContext)
        {
            _userManager = userManager;
            _dbContext = dbContext;
        }

        public IActionResult OnGet(string token, string email)
        {
            Input = new ResetPasswordInput
            {
                Token = token,
                Email = email
            };
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToPage("/ResetPasswordConfirmation");
            }

            // Check for password reuse
            if (await IsPasswordReuseAsync(user.Id, Input.NewPassword, _userManager))
            {
                ModelState.AddModelError("", "You cannot reuse one of your last two passwords.");
                return Page();
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Token, Input.NewPassword);
            if (result.Succeeded)
            {
                // Save the new password hash in the PasswordHistory table
                var hashedPassword = _userManager.PasswordHasher.HashPassword(user, Input.NewPassword);
                await SavePasswordHistoryAsync(user.Id, hashedPassword);

                return RedirectToPage("/ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return Page();
        }

        private async Task<bool> IsPasswordReuseAsync(string userId, string newPassword, UserManager<IdentityUser> userManager)
        {
            var passwordHasher = new PasswordHasher<IdentityUser>();
            var recentPasswords = await _dbContext.PasswordHistories
                .Where(ph => ph.UserId == userId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(2) // Check only the last 2 passwords
                .ToListAsync();

            foreach (var history in recentPasswords)
            {
                if (passwordHasher.VerifyHashedPassword(null, history.HashedPassword, newPassword) != PasswordVerificationResult.Failed)
                {
                    return true; // Password reuse detected
                }
            }

            return false; // No password reuse
        }

        private async Task SavePasswordHistoryAsync(string userId, string hashedPassword)
        {
            var passwordHistory = new PasswordHistory
            {
                UserId = userId,
                HashedPassword = hashedPassword,
                CreatedAt = DateTime.UtcNow
            };

            // Add the new password to the history
            _dbContext.PasswordHistories.Add(passwordHistory);

            // Keep only the last 2 passwords (remove older ones if necessary)
            var oldPasswords = await _dbContext.PasswordHistories
                .Where(ph => ph.UserId == userId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Skip(2) // Keep only the last 2 passwords
                .ToListAsync();

            _dbContext.PasswordHistories.RemoveRange(oldPasswords);

            await _dbContext.SaveChangesAsync();
        }
    }
}
