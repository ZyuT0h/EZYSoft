using EZYSoft.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using System.ComponentModel.DataAnnotations;

namespace EZYSoft.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IDistributedCache _cache; // Used for session management
        private readonly IConfiguration _configuration;

        [BindProperty]
        public LoginInput Input { get; set; }

        public string RecaptchaSiteKey => _configuration["Recaptcha:SiteKey"];
        public class LoginInput
        {
            [Required(ErrorMessage = "Email is required.")]
            [EmailAddress(ErrorMessage = "Invalid Email Address.")]
            public string Email { get; set; }

            [Required(ErrorMessage = "Password is required.")]
            [DataType(DataType.Password)]
            public string Password { get; set; }
        }

        public LoginModel(SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager, 
            IHttpContextAccessor httpContextAccessor, 
            IDistributedCache cache,
            IConfiguration configuration)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this._httpContextAccessor = httpContextAccessor;
            this._cache = cache;
            this._configuration = configuration;
        }

        public IActionResult OnGet()
        {
            ViewData["RecaptchaSiteKey"] = _configuration["Recaptcha:SiteKey"];
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Retrieve the reCAPTCHA token from the form
            var recaptchaToken = Request.Form["g-recaptcha-response"];
            var secretKey = _configuration["Recaptcha:SecretKey"];

            // Verify the reCAPTCHA token
            var isValid = await RecaptchaHelper.VerifyRecaptchaAsync(secretKey, recaptchaToken, "login");
            if (!isValid)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
                return Page();
            }

            var user = await userManager.FindByEmailAsync(Input.Email);
            if (user != null && await userManager.CheckPasswordAsync(user, Input.Password))
            {
                // Check if there's already an active session in Redis
                var existingSessionId = await _cache.GetStringAsync($"user-session-{user.Id}");

                if (existingSessionId != null)
                {
                    // Handle multiple logins: Notify user or prevent login
                    ModelState.AddModelError("", "You are already logged in on another device.");
                    return Page();
                }

                // Sign in the user
                await signInManager.SignInAsync(user, isPersistent: false);

                // Generate and save session ID
                var sessionId = Guid.NewGuid().ToString();
                await _cache.SetStringAsync($"user-session-{user.Id}", sessionId, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30)
                });

                // Store session ID in the user's session cookie
                _httpContextAccessor.HttpContext.Session.SetString("SessionId", sessionId);
                // Store UserId in session
                _httpContextAccessor.HttpContext.Session.SetString("UserId", user.Id);

                return RedirectToPage("/Index");
            }

            ModelState.AddModelError("", "Invalid email or password.");
            return Page();
        }
    }

}
