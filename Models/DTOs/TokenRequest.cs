using System.ComponentModel.DataAnnotations;

namespace Sol_userRegistration.Models.DTOs;

public class TokenRequest
{
    [Required]
    public string Token { get; set; } = string.Empty;
    
    [Required]
    public string RefreshToken { get; set; } = string.Empty;
}