using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using System.ComponentModel.DataAnnotations;

namespace EZYSoft.Pages
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;



        [BindProperty]
        public LoginInput Input { get; set; }

        public class LoginInput
        {
            [Required(ErrorMessage = "Email is required.")]
            [EmailAddress(ErrorMessage = "Invalid Email Address.")]
            public string Email { get; set; }

            [Required(ErrorMessage = "Password is required.")]
            [DataType(DataType.Password)]
            public string Password { get; set; }
        }

        public LoginModel(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, IHttpContextAccessor httpContextAccessor)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this._httpContextAccessor = httpContextAccessor;
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

            var user = await userManager.FindByEmailAsync(Input.Email);
            if (user != null && await userManager.CheckPasswordAsync(user, Input.Password))
            {
                // Sign in the user
                await signInManager.SignInAsync(user, isPersistent: false);

                // Store UserId in session
                _httpContextAccessor.HttpContext.Session.SetString("UserId", user.Id);

                return RedirectToPage("/Index");
            }

            ModelState.AddModelError("", "Invalid email or password.");
            return Page();
        }
    }

}
