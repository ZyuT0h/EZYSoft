
using EZYSoft.Helpers;
using EZYSoft.Model;
using EZYSoft.ViewModel.WebApplication1.ViewModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;

namespace EZYSoft.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly EzysoftDbContext dbContext;
        private readonly ILogger<RegisterModel> logger;

        [BindProperty]
        public Register RModel { get; set; }

        public RegisterModel(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            EzysoftDbContext dbContext,
            ILogger<RegisterModel> logger)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dbContext = dbContext;
            this.logger = logger;
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

            // Check for duplicate email
            var existingUser = await userManager.FindByEmailAsync(RModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("RModel.Email", "This email address is already registered.");
                return Page();
            }

            // Create a new user
            var user = new IdentityUser
            {
                UserName = RModel.Email,
                Email = RModel.Email
            };

            var result = await userManager.CreateAsync(user, RModel.Password);
            if (result.Succeeded)
            {
                try
                {
                    //var dataProtectionProvider = DataProtectionProvider.Create("EncryptData");
                    //var protector = dataProtectionProvider.CreateProtector("MySecretKey"); protector.Protect(RModel.NRIC),

                    // Encrypt the NRIC using AES
                    var encryptedNRIC = AesEncryptionHelper.Encrypt(RModel.NRIC);

                    // Save the resume file and get its path
                    var resumePath = await SaveResumeFile(RModel.Resume);

                    // Create a new UserDetail object
                    var userDetails = new UserDetail
                    {
                        UserId = user.Id,
                        FirstName = RModel.FirstName,
                        LastName = RModel.LastName,
                        Gender = RModel.Gender,
                        NRIC = encryptedNRIC,
                        DateOfBirth = RModel.DateOfBirth,
                        ResumePath = resumePath,
                        WhoAmI = RModel.WhoAmI
                    };

                    // Save the UserDetail object to the database
                    dbContext.UserDetails.Add(userDetails);
                    await dbContext.SaveChangesAsync();

                    // Sign in the user
                    await signInManager.SignInAsync(user, isPersistent: false);

                    return RedirectToPage("Index");
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "An error occurred while saving user details.");
                    ModelState.AddModelError("", "An error occurred while saving your details. Please try again.");
                    return Page();
                }
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }

            return Page();
        }

        private async Task<string> SaveResumeFile(IFormFile resume)
        {
            if (resume == null || resume.Length == 0)
            {
                throw new ArgumentException("Resume file is required.");
            }

            // Validate file extension
            var allowedExtensions = new[] { ".docx", ".pdf" };
            var fileExtension = Path.GetExtension(resume.FileName).ToLowerInvariant();
            if (!allowedExtensions.Contains(fileExtension))
            {
                throw new ArgumentException("Only .docx or .pdf files are allowed.");
            }

            // Define the uploads folder path
            var uploadsFolder = Path.Combine("wwwroot", "uploads");

            // Ensure the uploads folder exists
            if (!Directory.Exists(uploadsFolder))
            {
                Directory.CreateDirectory(uploadsFolder);
            }

            // Define the full file path
            var filePath = Path.Combine(uploadsFolder, resume.FileName);

            // Save the file to the specified path
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await resume.CopyToAsync(stream);
            }

            // Return the relative path to store in the database
            return $"/uploads/{resume.FileName}";
        }
    }
}