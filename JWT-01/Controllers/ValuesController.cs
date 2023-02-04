using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWT_01.Controllers
{
    [ApiController]
    public class ValuesController : ControllerBase
    {
        [HttpPost("/api/v{version:apiVersion}/jwt/scheme")]
        [MapToApiVersion("1.0")]
        [Authorize]
        public IActionResult Scheme()
        {
            return Ok("Success -- Scheme-default");
        }

        [HttpPost("/api/v{version:apiVersion}/jwt/scheme1")]
        [MapToApiVersion("1.0")]
        [Authorize(AuthenticationSchemes = "scheme1")]
        public IActionResult Scheme1()
        {
            return Ok("Success -- Scheme-1");
        }

        [HttpPost("/api/v{version:apiVersion}/jwt/scheme2")]
        [MapToApiVersion("1.0")]
        [Authorize(AuthenticationSchemes = "scheme2")]
        public IActionResult Scheme2()
        {
            return Ok("Success -- Scheme-2");
        }

        [HttpPost("/api/v{version:apiVersion}/jwt/scheme1-OR-2")]
        [MapToApiVersion("1.0")]
        [Authorize(AuthenticationSchemes = "scheme1, scheme2")]
        public IActionResult Scheme1or2()
        {
            return Ok("Success -- Scheme1or2");
        }

        [HttpPost("/api/v{version:apiVersion}/jwt/scheme1-OR-2-withSchemePolicy")]
        [MapToApiVersion("1.0")]
        [Authorize(AuthenticationSchemes = "scheme1_or_scheme2")]
        public IActionResult Scheme1or2withSchemePolicy()
        {
            return Ok("Success -- Scheme1or2withSchemePolicy");
        }

    }
}
