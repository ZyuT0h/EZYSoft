using EZYSoft.Helpers;
using EZYSoft.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace EZYSoft.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly PasswordService _passwordService;

        [BindProperty]
        public ChangePasswordInput Input { get; set; }

        public class ChangePasswordInput
        {
            [Required]
            [DataType(DataType.Password)]
            public string CurrentPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string NewPassword { get; set; }

            [Required]
            [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public ChangePasswordModel(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, PasswordService passwordService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _passwordService = passwordService;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // Check if the new password is a reused password
            var isPasswordReuse = await _passwordService.IsPasswordReuseAsync(user.Id, Input.NewPassword);
            if (isPasswordReuse)
            {
                ModelState.AddModelError("", "You cannot reuse one of your last two passwords.");
                return Page();
            }

            // Get the last password change date
            var lastPasswordChangeDate = await _passwordService.GetLastPasswordChangeDateAsync(user.Id);

            // Check minimum password age
            if (!_passwordService.IsMinimumPasswordAgeMet(lastPasswordChangeDate, 60)) // Example: 60 minutes
            {
                ModelState.AddModelError("", "You cannot change your password within 60 minutes of the last change.");
                return Page();
            }

            // Check maximum password age
            if (_passwordService.IsMaximumPasswordAgeExceeded(lastPasswordChangeDate, 90 * 24 * 60)) // Example: 90 days
            {
                ModelState.AddModelError("", "Your password has expired. Please change it now.");
                return Page();
            }

            // Verify the current password
            var isCorrectPassword = await _userManager.CheckPasswordAsync(user, Input.CurrentPassword);
            if (!isCorrectPassword)
            {
                ModelState.AddModelError("", "Current password is incorrect.");
                return Page();
            }

            // Update the password
            var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return Page();
            }

            // Save the new password in the password history
            var hashedPassword = _userManager.PasswordHasher.HashPassword(user, Input.NewPassword);
            await _passwordService.SavePasswordHistoryAsync(user.Id, hashedPassword);

            // Re-sign in the user
            await _signInManager.RefreshSignInAsync(user);

            return RedirectToPage("/Index", new { message = "Password changed successfully." });
        }
    }
}
