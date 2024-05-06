namespace Sol_userRegistration.Models;

public class AuthResult
{
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public bool Result { get; set; }
    public List<string> Errors { get; set; }
}