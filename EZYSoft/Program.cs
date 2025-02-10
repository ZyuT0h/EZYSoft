using EZYSoft.Model;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Register DbContext
builder.Services.AddDbContext<EzysoftDbContext>(options =>
	options.UseSqlServer(builder.Configuration.GetConnectionString("AuthConnectionString")));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 12;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);// Locked for 5mins
    options.Lockout.MaxFailedAccessAttempts = 3; // Rate Limitting 
})
.AddEntityFrameworkStores<EzysoftDbContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login"; // Redirect to login page if unauthorized/after seession timeout
    options.AccessDeniedPath = "/AccessDenied"; // Redirect if access is denied

    options.Cookie.HttpOnly = true; // Prevent JavaScript access to cookies
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensure cookies are only sent over HTTPS
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Session timeout
    options.SlidingExpiration = true; // Extend session on activity
    options.Cookie.IsEssential = true; // Mark cookies as essential
});

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache(); // Save session in memory
// Add session services
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Session timeout
    options.Cookie.HttpOnly = true; // Secure cookies
    options.Cookie.IsEssential = true; // Essential cookie
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Error");
	// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
	app.UseHsts();
}

app.UseStatusCodePagesWithRedirects("/error/{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseSession();

app.UseAuthentication();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
