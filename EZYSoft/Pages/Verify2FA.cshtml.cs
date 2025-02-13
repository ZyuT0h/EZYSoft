using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;
using System.ComponentModel.DataAnnotations;

namespace EZYSoft.Pages
{
    public class Verify2FAModel : PageModel
    {
        private readonly IDistributedCache _cache;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;

        [BindProperty]
        public Verify2FAInput Input { get; set; }

        public class Verify2FAInput
        {
            [Required]
            public string Code { get; set; }
        }

        public Verify2FAModel(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IDistributedCache cache)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _cache = cache;
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var userId = HttpContext.Session.GetString("UserId");

            if (string.IsNullOrEmpty(userId))
            {
                ModelState.AddModelError("", "Session expired. Please log in again.");
                return Page();
            }

            var code = await _cache.GetStringAsync($"2fa-code-{userId}");

            if (code == null)
            {
                ModelState.AddModelError("", "2FA code has expired. Please request a new code.");
                return Page();
            }

            if (Input.Code != code)
            {
                ModelState.AddModelError("", "Invalid 2FA code.");
                return Page();
            }

            // 2FA code is valid, proceed with login
            var user = await _userManager.FindByIdAsync(userId);
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Clear the stored 2FA code after successful verification
            await _cache.RemoveAsync($"2fa-code-{userId}");

            return RedirectToPage("/Index");
        }
    }
}
