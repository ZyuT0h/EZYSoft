using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace EZYSoft.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;


        public LogoutModel(SignInManager<IdentityUser> signInManager, IHttpContextAccessor httpContextAccessor)
        {
            this.signInManager = signInManager;
            this._httpContextAccessor = httpContextAccessor;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // Clear session data
            _httpContextAccessor.HttpContext.Session.Clear();

            // Sign out the user
            await signInManager.SignOutAsync();

            return RedirectToPage("/Login");
        }
    }
}