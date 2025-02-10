using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;

namespace EZYSoft.Pages
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IDistributedCache _cache;

        public LogoutModel(SignInManager<IdentityUser> signInManager, IHttpContextAccessor httpContextAccessor, IDistributedCache cache)
        {
            this.signInManager = signInManager;
            this._httpContextAccessor = httpContextAccessor;
            this._cache = cache;

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {
            // Clear session data
            var sessionId = _httpContextAccessor.HttpContext.Session.GetString("SessionId");
            if (sessionId != null)
            {
                await _cache.RemoveAsync($"user-session-{_httpContextAccessor.HttpContext.User.Identity.Name}");
            }

            // Sign out the user
            await signInManager.SignOutAsync();

            // Clear session from cookie
            _httpContextAccessor.HttpContext.Session.Clear();

            return RedirectToPage("/Login");
        }
    }
}