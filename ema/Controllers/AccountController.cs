using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ema.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace ema.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] Register model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = new IdentityUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        await _userManager.AddToRoleAsync(user, "User");

        return Ok(new { message = "User registered successfully." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] Login model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByEmailAsync(model.Username);
        var email = user?.Email;
        if (user == null || email == null)
        {
            return Unauthorized();
        }

        var result = await _userManager.CheckPasswordAsync(user, model.Password);
        if (!result)
        {
            return Unauthorized();
        }

        var roles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var key = _configuration["Jwt:Key"];
        if (key == null)
        {
            throw new InvalidOperationException("Jwt:Key configuration is missing.");
        }

        var keyBytes = Encoding.UTF8.GetBytes(key);
        var symmetricSecurityKey = new SymmetricSecurityKey(keyBytes);

        var expiryTime = _configuration.GetValue<int>("Jwt:ExpiryMinutes");

        var jwt = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(expiryTime),
            signingCredentials: new SigningCredentials(
                symmetricSecurityKey,
                SecurityAlgorithms.HmacSha256)
        );
        return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(jwt) });
    }

    [HttpPost("add-role")]
    public async Task<IActionResult> AddRole([FromBody] string role)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        if (await _roleManager.RoleExistsAsync(role))
        {
            return BadRequest(new { message = $"Role '{role}' already exists." });
        }

        var result = await _roleManager.CreateAsync(new IdentityRole(role));
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { message = $"Role '{role}' created successfully." });
    }

    [HttpPost("assign-role")]
    public async Task<IActionResult> AssignRole([FromBody] UserRole model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByIdAsync(model.Username);
        if (user == null)
        {
            return NotFound(new { message = $"User with ID '{model.Username}' not found." });
        }

        if (!await _roleManager.RoleExistsAsync(model.Role))
        {
            return BadRequest(new { message = $"Role '{model.Role}' not found." });
        }

        var result = await _userManager.AddToRoleAsync(user, model.Role);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok(new { message = $"User '{model.Username}' assigned role '{model.Role}' successfully." });
    }
}
