using System.ComponentModel.DataAnnotations;

namespace Api.Models.Dtos.Requests;

public record RegisterRequest(
    [Required][EmailAddress] string Email,
    [Required] string UserName,
    [MinLength(6)] string Password,
    [Required] string Name
);

public record LoginRequest([Required][EmailAddress] string Email, [Required] string Password);
