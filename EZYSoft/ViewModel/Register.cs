namespace EZYSoft.ViewModel
{
	using System;
	using System.ComponentModel.DataAnnotations;

	namespace WebApplication1.ViewModels
	{
		public class Register
		{
			[Required(ErrorMessage = "First Name is required.")]
			[Display(Name = "First Name")]
			public string FirstName { get; set; }

			[Required(ErrorMessage = "Last Name is required.")]
			[Display(Name = "Last Name")]
			public string LastName { get; set; }

			[Required(ErrorMessage = "Gender is required.")]
			[Display(Name = "Gender")]
			public string Gender { get; set; }

			[Required(ErrorMessage = "NRIC is required.")]
			[Display(Name = "NRIC")]
			public string NRIC { get; set; }

			[Required(ErrorMessage = "Email is required.")]
			[EmailAddress(ErrorMessage = "Invalid Email Address.")]
			[Display(Name = "Email Address")]
			public string Email { get; set; }

			[Required(ErrorMessage = "Password is required.")]
			[RegularExpression(
				@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{12,}$",
				ErrorMessage = "Password must be at least 12 characters long and include a combination of lowercase, uppercase, numbers, and special characters. Please use a STRONG PASSWORD")]
			[DataType(DataType.Password)]
			[Display(Name = "Password")]
			public string Password { get; set; }

			[Required(ErrorMessage = "Confirm Password is required.")]
			[DataType(DataType.Password)]
			[Compare(nameof(Password), ErrorMessage = "Password and confirmation password do not match.")]
			[Display(Name = "Confirm Password")]
			public string ConfirmPassword { get; set; }

			[Required(ErrorMessage = "Date of Birth is required.")]
			[DataType(DataType.Date)]
			[Display(Name = "Date of Birth")]
			public DateTime DateOfBirth { get; set; }

			[Required(ErrorMessage = "Resume is required.")]
			[Display(Name = "Upload Resume (.docx or .pdf)")]
			[AllowedExtensions(new[] { ".docx", ".pdf" }, ErrorMessage = "Only .docx or .pdf files are allowed.")]
			public IFormFile Resume { get; set; }

			[Required(ErrorMessage = "Who Am I is required.")]
			[Display(Name = "Who Am I")]
			[DataType(DataType.MultilineText)]
			public string WhoAmI { get; set; }
		}

		// Custom Validation Attribute for File Extensions
		public class AllowedExtensionsAttribute : ValidationAttribute
		{
			private readonly string[] _extensions;
			public AllowedExtensionsAttribute(string[] extensions)
			{
				_extensions = extensions;
			}

			protected override ValidationResult IsValid(object value, ValidationContext validationContext)
			{
				if (value is IFormFile file)
				{
					var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
					if (!_extensions.Contains(extension))
					{
						return new ValidationResult(ErrorMessage);
					}
				}
				return ValidationResult.Success;
			}
		}
	}
}
