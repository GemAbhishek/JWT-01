namespace JWT_01
{
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.Extensions.Configuration;
    using Microsoft.IdentityModel.Tokens;
    using System.Text;

    public static class TokenValidationHandler
    {
        public static void GetTokenValidationParameters(this JwtBearerOptions options, IConfiguration configuration, string scheme)
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("TokenSecretKey"))),
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidIssuer = configuration.GetSection(scheme)["Issuer"],
                ValidAudience = configuration.GetSection(scheme)["Audience"],
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
            };
        }
    }
}
