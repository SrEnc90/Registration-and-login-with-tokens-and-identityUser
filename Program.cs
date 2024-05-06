using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Sol_userRegistration.Configuration;
using Sol_userRegistration.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

//Estamos configurando la clase JwtConfig, cuándo se le necesite net core va a crear e instanciar la clase (Inyección de dependencia)
// builder.Services.Configure<IJwtConfig>(builder.Configuration.GetSection("JwtConfig:Secret"));
// builder.Services.AddSingleton<IJwtConfig, JwtConfig>();

// var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig").Value);
var key = Encoding.UTF8.GetBytes(builder.Configuration.GetSection("JwtConfig:Secret").Value); // UTF8 admite una gama más amplia de caracteres y es menos probable que cause problemas con caracteres no ingleses que puedan estar presentes en su clave secreta.

var tokenValidationParemeter = new TokenValidationParameters()
{
    ValidateIssuerSigningKey = true, // Indica que todas las request que reciba va a verificar siempre la key esté incluida
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false, // solo xq estamos en locahost, sino debe ser true (for dev)
    ValidateAudience = false, // for dev
    RequireExpirationTime = false, // for dev (need to be updated when token is dead, dijo que por defecto un token no vive más de 30 segundos)
    ValidateLifetime = true
};

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(jwt =>
    {
        
        jwt.SaveToken = true; //indica que una vez autenticado, el token se va a almacenar en el header de las requests y las responses
        jwt.TokenValidationParameters = tokenValidationParemeter;
    });

//inyectamos nuestro tokenValidationParameter
builder.Services.AddSingleton(tokenValidationParemeter);

builder.Services.AddDefaultIdentity<IdentityUser>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
    })
    .AddEntityFrameworkStores<AppDbContext>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

//Indicamos a la aplicación que utilice la autenticación
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();