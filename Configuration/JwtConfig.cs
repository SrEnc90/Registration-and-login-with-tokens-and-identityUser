namespace Sol_userRegistration.Configuration;

public class JwtConfig : IJwtConfig
{
    public string Secret { get; private set; } = string.Empty;
    public TimeSpan ExpiryTimeFrame { get; set; }

    public JwtConfig(IConfiguration configuration)
    {
        Secret = configuration["JwtConfig:Secret"];
    }
}