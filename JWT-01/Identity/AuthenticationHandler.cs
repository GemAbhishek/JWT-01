namespace JWT_01
{
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Net.Http.Headers;
    using Newtonsoft.Json.Linq;
    using System.IdentityModel.Tokens.Jwt;
    using System.Net;
    using System.Security.Claims;
    using System.Threading.Tasks;

    /// <summary>
    /// AuthenticationHandler static class to implement custom authentication for application - JwtToken.
    /// </summary>
    public static class AuthenticationHandler
    {
        public static void CustomAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication()
            .AddPolicyScheme("scheme1_or_scheme2", "scheme1_or_scheme2", options =>
            {
                options.ForwardDefaultSelector = context =>
                {
                    string token = context.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", string.Empty);

                    if (!string.IsNullOrEmpty(token))
                    {
                        var jwtHandler = new JwtSecurityTokenHandler();
                        if (jwtHandler.CanReadToken(token))
                        {
                            var jwtToken = jwtHandler.ReadJwtToken(token);

                            if (jwtToken.Issuer.Equals(configuration.GetSection("Scheme1TokenSettings")["Issuer"]))
                            {
                                return "scheme1";
                            }
                        }
                    }

                    return "scheme2";
                };
            })
            .AddJwtBearer("scheme1", options =>
            {
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context => OnTokenValidated(context),

                    OnForbidden = context => OnForbidden(context),

                    OnChallenge = context => OnChallenge(context),

                    OnMessageReceived = context => OnMessageReceived(configuration, context, "Scheme1TokenSettings")
                };

                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.IncludeErrorDetails = true;
                options.GetTokenValidationParameters(configuration, "Scheme1TokenSettings");
            })
            .AddJwtBearer("scheme2", options =>
             {
                 options.Events = new JwtBearerEvents
                 {
                     OnTokenValidated = context => OnTokenValidated(context),

                     OnForbidden = context => OnForbidden(context),

                     OnChallenge = context => OnChallenge(context),

                     OnMessageReceived = context => OnMessageReceived(configuration, context, "Scheme2TokenSettings")
                 };

                 options.RequireHttpsMetadata = false;
                 options.SaveToken = true;
                 options.IncludeErrorDetails = true;
                 options.GetTokenValidationParameters(configuration, "Scheme2TokenSettings");
             });

            services.AddAuthorization(options =>
            {
                options.DefaultPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    //.AddAuthenticationSchemes("scheme1")
                    .Build();
            });
        }

        private static Task OnMessageReceived(IConfiguration configuration, MessageReceivedContext context, string scheme)
        {
            if (!string.IsNullOrEmpty(context.Request.Headers[HeaderNames.Authorization].ToString()))
            {
                context.Token = context.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", string.Empty);
            }
            else if (context.Request.Cookies[configuration.GetSection(scheme)["CookieName"]] != null)
            {
                context.Token = context.Request.Cookies[configuration.GetSection(scheme)["CookieName"]];
            }
            return Task.CompletedTask;
        }

        private static Task OnChallenge(JwtBearerChallengeContext context)
        {
            context.HandleResponse();
            var payload = new JObject
            (
                new JProperty("error",
                    new JObject(
                        new JProperty("description", "You are unauthenticated to access"),
                        new JProperty("responseCode", 401),
                        new JProperty("responseName", "Unauthorized")
                        )
                    )
            );
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            context.Response.WriteAsync(payload.ToString());

            return Task.CompletedTask;
        }

        private static Task OnForbidden(ForbiddenContext context)
        {
            var payload = new JObject
                                    (
                                        new JProperty("error",
                                            new JObject(
                                                new JProperty("description", "You are Unauthorized to access the resource."),
                                                new JProperty("responseCode", 403),
                                                new JProperty("responseName", "Forbidden")
                                                )
                                            )
                                    );
            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
            context.Response.WriteAsync(payload.ToString());

            return Task.CompletedTask;
        }

        private static Task OnTokenValidated(TokenValidatedContext context)
        {
            var appIdentity = (ClaimsIdentity)context.Principal.Identity;
            var claimInToken = appIdentity.FindFirst("Role");
            if (claimInToken != null)
            {
                appIdentity.AddClaim(new Claim(ClaimsIdentity.DefaultRoleClaimType, "D:" + claimInToken.Value));
            }
            return Task.CompletedTask;
        }
    }

}
