using EZYSoft.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Mail;

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

            var recaptchaToken = Request.Form["g-recaptcha-response"];
            var secretKey = _configuration["Recaptcha:SecretKey"];

            var isValid = await RecaptchaHelper.VerifyRecaptchaAsync(secretKey, recaptchaToken, "login");
            if (!isValid)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
                return Page();
            }

            var user = await userManager.FindByEmailAsync(Input.Email);
            if (user != null && await userManager.CheckPasswordAsync(user, Input.Password))
            {
                // Check if TwoFactorEnabled is true
                if (user.TwoFactorEnabled)
                {
                    // Generate a 2FA code
                    var code = new Random().Next(100000, 999999).ToString(); // 6-digit code

                    // Store the 2FA code in a temporary cache for later verification
                    await _cache.SetStringAsync($"2fa-code-{user.Id}", code, new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5) // Valid for 5 minutes
                    });

                    // Store the UserId in session to later use in Verify2FA
                    _httpContextAccessor.HttpContext.Session.SetString("UserId", user.Id);

                    // Send the 2FA code to the user's email
                    var emailSubject = "Your 2FA Code";
                    var emailBody = $"Your 2FA code is {code}. It will expire in 5 minutes.";

                    await SendEmailAsync(user.Email, emailSubject, emailBody);

                    // Redirect to the 2FA verification page
                    return RedirectToPage("/Verify2FA");
                }
                else
                {
                    // No 2FA required, sign the user in directly
                    await signInManager.SignInAsync(user, isPersistent: false);

                    _httpContextAccessor.HttpContext.Session.SetString("UserId", user.Id);

                    // Proceed with the normal login flow
                    return RedirectToPage("/Index");
                }
            }

            ModelState.AddModelError("", "Invalid email or password.");
            return Page();
        }


        private async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            // Get the email configuration from appsettings.json
            var smtpServer = _configuration["EmailSettings:SmtpServer"];
            var smtpPort = int.Parse(_configuration["EmailSettings:Port"]);
            var senderEmail = _configuration["EmailSettings:SenderEmail"];
            var senderName = _configuration["EmailSettings:SenderName"];
            var password = _configuration["EmailSettings:Password"];

            var smtpClient = new SmtpClient(smtpServer, smtpPort)
            {
                Credentials = new NetworkCredential(senderEmail, password),
                EnableSsl = true // Ensure SSL is enabled
            };

            var mailMessage = new MailMessage
            {
                From = new MailAddress(senderEmail, senderName),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };
            mailMessage.To.Add(toEmail);

            try
            {
                await smtpClient.SendMailAsync(mailMessage);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending email: {ex.Message}");
                throw; // Re-throw the exception to propagate it
            }
        }


    }

}
