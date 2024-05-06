using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using RestSharp.Authenticators;
using Sol_userRegistration.Configuration;
using Sol_userRegistration.Data;
using Sol_userRegistration.Models;
using Sol_userRegistration.Models.DTOs;

namespace Sol_userRegistration.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    // private readonly JwtConfig _jwtConfig; // Revisar el program.cs xq ahí estoy haciendo el setup para que net core haga la inyección de dependencia de JwtConfig
    private readonly IConfiguration _configuration;
    private readonly AppDbContext _context;
    private readonly TokenValidationParameters _tokenValidationParameters; //hemos hecho inyección de dependencia, revisar el program.cs

    public AuthenticationController(
        UserManager<IdentityUser> userManager,
        // JwtConfig jwtConfig
        IConfiguration configuration,
        AppDbContext context,
        TokenValidationParameters tokenValidationParameters
        )
    {
        _userManager = userManager;
        // _jwtConfig = jwtConfig;
        _configuration = configuration;
        _context = context;
        _tokenValidationParameters = tokenValidationParameters;
    }

    [HttpPost]
    [Route("Register")]
    public async Task<ActionResult> Register([FromBody] UserRegistrationRequestDTO userRegistrationDTO)
    {
        // validate the incoming request
        if (ModelState.IsValid)
        {
            // we need to check if the email already exists
            var user_exist = await _userManager.FindByEmailAsync(userRegistrationDTO.Email);

            if (user_exist != null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email already exists"
                    }
                });
            }
            
            // create a user
            var new_user = new IdentityUser()
            {
                Email = userRegistrationDTO.Email,
                UserName = userRegistrationDTO.Email,
                EmailConfirmed = false
            };

            var is_created = await _userManager.CreateAsync(new_user, userRegistrationDTO.Password);

            if (is_created.Succeeded)
            {
                var code = await _userManager
                    .GenerateEmailConfirmationTokenAsync(
                        new_user); //Este método genera un token único asociado a la dirección de correo electrónico del usuario para fines de confirmación.

                var email_body = "Please confirm your email address <a href=\"#URL#\">CLICK HERE</a>";

                // htps://localhost:8080/authentication/verifyemail/userid=carlos&code=fasfsdaf
                var callback_url = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail",
                    "Authentication", new { userid = new_user.Id, code = code });

                // para prevenir posibles vulnerabilidades de seguridad como ataques de scripts entre sitios (XSS). La URL codificada es segura para incluirla en el contenido del correo electrónico.
                // Encoding el callback_url debido a que el code puede ser algo así AFDSDAFSDAFAS/SFSDFASFSD+SFDS*/ y eso puede afectar la navegación(interpretarlo como otro action result)
                var body = email_body.Replace("#URL#", System.Text.Encodings.Web.HtmlEncoder.Default.Encode(callback_url));
                // Codifica la callback_url a su equivalente seguro en HTML, para prevenir vulnerabilidades XSS
                // var body = email_body.Replace("#URL#", System.Web.HttpUtility.HtmlEncode(callback_url));

                // Send Email
                var result = await SendEmail(body, new_user.Email);

                if (result)
                    return Ok("Please verify your email, throught verification email we have just send");

                return BadRequest("Please request an email verification link");
                
                
                // Generate the token
                // var token = GenerateJwtToken(new_user);
                // return Ok(new AuthResult()
                // {
                //     Result = true,
                //     Token = token
                // });
            }
            
            return BadRequest(new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Server Error"
                }
            });
        }

        return BadRequest();
    }

    [Route("ConfirmEmail")]
    [HttpGet]
    public async Task<ActionResult> ConfirmEmail(string userId, string code)
    {
        if (userId == null || code == null)
        {
            return BadRequest(new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Invalid email confirmation URL"
                }
            });
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return NotFound(new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Invalid email parameter"
                }
            });
        }

        // code = Encoding.UTF8.GetString(Convert.FromBase64String(code));
        var result = await _userManager.ConfirmEmailAsync(user, code);
        var status = result.Succeeded
            ? "Thank you for confirming your mail"
            : "Your email is not confirmed, please try again later";
        
        return Ok(status);
    }

    [Route("Login")]
    [HttpPost]
    public async Task<ActionResult> Login([FromBody] UserLoginRequestDTO userLoginDTO)
    {
        if (ModelState.IsValid)
        {
            //check if the user exist
            var existing_user = await _userManager.FindByEmailAsync(userLoginDTO.Email);
            
            if (existing_user == null)
            {
                return NotFound(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid Payload"
                    }
                });
            }

            if (!existing_user.EmailConfirmed)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email needs to be confirm"
                    }
                });
            }

            var isCorrect = await _userManager.CheckPasswordAsync(existing_user, userLoginDTO.Password);

            if (!isCorrect)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid Credentials"
                    }
                });
            }

            var jwtToken = await GenerateJwtToken(existing_user);

            return Ok(jwtToken);
        }

        return BadRequest(new AuthResult()
        {
            Result = false,
            Errors = new List<string>()
            {
                "Invalid Payload"
            }
        });
    }

    private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        // var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
        var key = Encoding.UTF8.GetBytes(_configuration.GetValue<string>("JwtConfig:Secret"));
        
        
        //token descriptor
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("Id", user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, value: user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString("dd/MM/yyyy"))
            }),

            // Expires = DateTime.Now.AddHours(1),
            Expires = DateTime.UtcNow.Add(_configuration.GetValue<TimeSpan>("JwtConfig:ExpiryTimeFrame")),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
            NotBefore = DateTime.Now
            
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);


        var refreshToken = new RefreshToken()
        {
            JwtId = token.Id,
            Token = RandomStringGeneration(23), //Generate a refresh token
            AddedDate = DateTime.UtcNow,
            ExpiryDate = DateTime.UtcNow.AddMonths(6),
            IsRevoked = false,
            IsUsed = false,
            UserId = user.Id
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();
        
        return new AuthResult()
        {
            Result = true,
            RefreshToken = refreshToken.Token,
            Token = jwtToken
        };
    }

    [HttpPost]
    [Route("refreshToken")]
    public async Task<ActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
    {
        if (ModelState.IsValid)
        {
            var result = await VerifyAndGenerateToken(tokenRequest);

            if (result == null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "invalid token"
                    }
                });
            }

            return Ok(result);
        }

        return BadRequest(new AuthResult()
        {
            Result = false,
            Errors = new List<string>()
            {
                "Invalid parameters"
            }
        });
    }

    private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        try
        {
            _tokenValidationParameters.ValidateLifetime = false; // only for testing
            var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters,
                out var validatedToken);

            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                //Primero comprobamos que recibimos el mismo algoritmo de seguridad (HmacSha256) que utilizamos para crear el token
                var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                if (!result)
                    return null;
            }

            //Revisamos la fecha de expiración la cuál se coloca en el claim expiry que creamos cuándo generamos el token
            var utcExpiryDate = long.Parse(tokenInVerification.Claims
                .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

            var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);
            if (expiryDate > DateTime.Now)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Expired token"
                    }
                };
            }

            var storedToken =
                await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

            if (storedToken == null)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid token"
                    }
                };
            }

            if (storedToken.IsUsed)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Used token"
                    }
                };
            }

            if (storedToken.IsRevoked)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Revoked token"
                    }
                };
            }

            var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
            if (storedToken.JwtId != jti)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Invalid token"
                    }
                };
            }

            if (storedToken.ExpiryDate < DateTime.UtcNow)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Expired token"
                    }
                };
            }

            storedToken.IsUsed = true;
            _context.RefreshTokens.Update(storedToken);
            await _context.SaveChangesAsync();

            var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

            return await GenerateJwtToken(dbUser);
        }
        catch (Exception e)
        {
            return new AuthResult()
            {
                Result = false,
                Errors = new List<string>()
                {
                    "Server error"
                }
            };
        }
    }

    private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
    {
        var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();

        return dateTimeVal;
    }
    
    private string RandomStringGeneration(int length)
    {
        var random = new Random();
        var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012346789abcdefghijklmnopqrstuvwxyz_";
        return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
    }
    private async Task<bool> SendEmail(string body, string email)
    {
        //create a client
        var domain = _configuration.GetValue<string>("EmailConfig:Domain");
        //Mi error era que no generé una api key, pensando que con la public key se podía autenticar
        var options = new RestClientOptions($"https://api.mailgun.net/v3")
        {
            Authenticator = new HttpBasicAuthenticator("api", _configuration.GetValue<string>("EmailConfig:API_KEY"))
        };
        var client = new RestClient(options);
        var request = new RestRequest();

        request.AddParameter("domain", domain, ParameterType.UrlSegment);
        request.Resource = "{domain}/messages";
        request.AddParameter("from",
            $"Mailgun Sandbox <postmaster@{domain}>");
        request.AddParameter("to", email);
        request.AddParameter("subject", "Email Verification");
        // request.AddParameter("text", body);
        request.AddParameter("html", body);
        request.Method = Method.Post;

        var response = await client.ExecuteAsync(request);

        return response.IsSuccessful;
    }

}