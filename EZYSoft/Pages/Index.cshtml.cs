using EZYSoft.Helpers;
using EZYSoft.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace EZYSoft.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly EzysoftDbContext dbContext;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public IndexModel(EzysoftDbContext dbContext, IHttpContextAccessor httpContextAccessor)
        {
            this.dbContext = dbContext;
            this._httpContextAccessor = httpContextAccessor;
        }

        public string DecryptedNRIC { get; set; }
        public UserDetail UserDetails { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            // Retrieve UserId from session
            var userId = _httpContextAccessor.HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToPage("/Login"); // Redirect to login if UserId is not found in session
            }

            // Retrieve the user's details from the database
            UserDetails = await dbContext.UserDetails.FirstOrDefaultAsync(u => u.UserId == userId);
            if (UserDetails == null)
            {
                return RedirectToPage("/Error");
            }

            // Decrypt the NRIC using AES
            DecryptedNRIC = AesEncryptionHelper.Decrypt(UserDetails.NRIC);

            return Page();
        }
    }
}