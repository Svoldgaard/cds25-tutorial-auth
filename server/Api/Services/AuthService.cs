using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Api.Etc;
using Api.Mappers;
using Api.Models.Dtos.Requests;
using Api.Models.Dtos.Responses;
using Api.Security;
using DataAccess.Entities;
using DataAccess.Repositories;
using Microsoft.AspNetCore.Identity;

namespace Api.Services;

public interface IAuthService
{
    AuthUserInfo Authenticate(LoginRequest request);
    Task<AuthUserInfo> Register(RegisterRequest request);
    AuthUserInfo? GetUserInfo(ClaimsPrincipal principal);

}

public class AuthService(
    ILogger<AuthService> _logger,
    IPasswordHasher<User> _passwordHasher,
    IRepository<User> _userRepository
        
) : IAuthService
{
    public AuthUserInfo Authenticate(LoginRequest request)
    {
        try
        {
            var user = _userRepository.Query().Single(u => u.Email == request.Email);
            var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (result == PasswordVerificationResult.Success)
            {
                return new AuthUserInfo(user.Id, user.UserName, user.Role);
            }
        }
        catch (Exception e)
        {
            _logger.LogError(e.Message, e);
        }
        throw new AuthenticationError();
    }

    public async Task<AuthUserInfo> Register(RegisterRequest request)
    {
        if (_userRepository.Query().Any(u => u.Email == request.Email))
        {
            throw new ValidationException("Email is taken");
        }

        var user = new User
        {
            Email = request.Email,
            UserName = request.UserName,
        };
        user.PasswordHash = _passwordHasher.HashPassword(user, request.Password);
        await _userRepository.Add(user);
        return new AuthUserInfo(user.Id, user.UserName, user.Role);
    }
    
    public AuthUserInfo? GetUserInfo(ClaimsPrincipal principal)
    {
        var userId = principal.GetUserId();
        return _userRepository
            .Query()
            .Where(user => user.Id == userId)
            .SingleOrDefault()
            ?.ToDto();
    }
}