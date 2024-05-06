namespace Sol_userRegistration.Configuration;

public interface IJwtConfig
{
    string Secret { get; }
    public TimeSpan ExpiryTimeFrame { get; }
}