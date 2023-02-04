using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace JWT_01.Controllers
{
    [ApiController]
    [ApiVersion("1.0")]
    public class GetTokenController : ControllerBase
    {
        private readonly IConfiguration _config;
        public GetTokenController(IConfiguration configuration)
        {
            _config = configuration;
        }

        /// <summary>
        /// login endpoint returns token for valid users
        /// </summary>
        [HttpPost("/api/v{version:apiVersion}/jwt/login/scheme1")]
        [MapToApiVersion("1.0")]
        public IActionResult LoginScheme1()
        {
            GenerateTokenHandler generateTokenHandler = new(_config);
            string response = generateTokenHandler.GenerateTokenS1();
            return Ok(response);
        }

        /// <summary>
        /// login endpoint returns token for valid users
        /// </summary>
        [HttpPost("/api/v{version:apiVersion}/jwt/login/scheme2")]
        [MapToApiVersion("1.0")]
        public IActionResult LoginScheme2()
        {
            GenerateTokenHandler generateTokenHandler = new(_config);
            string response = generateTokenHandler.GenerateTokenS2();
            return Ok(response);
        }

    }
}
