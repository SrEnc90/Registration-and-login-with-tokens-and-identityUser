using System.ComponentModel.DataAnnotations;

namespace Sol_userRegistration.Models.DTOs;

public class UserLoginRequestDTO
{
    [Required] public string Email { get; set; } = string.Empty;

    [Required] public string Password { get; set; } = string.Empty;
}