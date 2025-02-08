using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace EZYSoft.Model
{
    public class UserDetail
    {
        [Key] // Primary key
        public string UserId { get; set; }

        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        public string Gender { get; set; }

        [Required]
        public string NRIC { get; set; } // Encrypted

        [Required]
        public DateTime DateOfBirth { get; set; }

        [Required]
        public string ResumePath { get; set; }

        [Required]
        public string WhoAmI { get; set; }
    }
}