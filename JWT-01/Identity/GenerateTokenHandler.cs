namespace JWT_01
{
    using Microsoft.Extensions.Configuration;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Text;

    public class GenerateTokenHandler
    {
        public IConfiguration Configuration { get; }
        public GenerateTokenHandler(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }

        public string GenerateTokenS1(string userId = "scheme1", string name = "scheme1", string Role = "Default")
        {
            //Create a List of Claims, Keep claims name short    
            var tokenClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToLower()),
                new Claim("Role", Role),
                new Claim("userid", userId.ToLower()),
                new Claim("name", name)
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetValue<string>("TokenSecretKey")));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                            issuer: Configuration.GetSection("Scheme1TokenSettings")["Issuer"],
                            audience: Configuration.GetSection("Scheme1TokenSettings")["Audience"],
                            tokenClaims,
                            expires: DateTime.Now.AddDays(1),
                            signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        
        public string GenerateTokenS2(string userId = "scheme2", string name = "scheme2", string Role = "Default")
        {
            //Create a List of Claims, Keep claims name short    
            var tokenClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToLower()),
                new Claim("Role", Role),
                new Claim("userid", userId.ToLower()),
                new Claim("name", name)
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetValue<string>("TokenSecretKey")));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                            issuer: Configuration.GetSection("Scheme2TokenSettings")["Issuer"],
                            audience: Configuration.GetSection("Scheme2TokenSettings")["Audience"],
                            tokenClaims,
                            expires: DateTime.Now.AddDays(1),
                            signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
