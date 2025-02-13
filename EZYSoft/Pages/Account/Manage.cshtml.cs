using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace EZYSoft.Pages.Account
{
    public class ManageModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public ManageModel(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public bool IsTwoFactorEnabled { get; set; }

        public async Task OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                IsTwoFactorEnabled = user.TwoFactorEnabled;
            }
        }

        // Enable 2FA
        public async Task<IActionResult> OnPostEnable2FAAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                user.TwoFactorEnabled = true;
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    return RedirectToPage();
                }
            }

            return Page();
        }

        // Disable 2FA
        public async Task<IActionResult> OnPostDisable2FAAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                user.TwoFactorEnabled = false;
                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    return RedirectToPage();
                }
            }

            return Page();
        }
    }
}
