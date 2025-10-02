using Api;
using DataAccess.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Tests.Security;

public class PasswordHasherTest
{
    IPasswordHasher<User> sut;

    [Before(Test)]
    public void Setup()
    {
        var builder = WebApplication.CreateBuilder();
        Program.ConfigureServices(builder);

        var app = builder.Build();

        sut = app.Services.GetRequiredService<IPasswordHasher<User>>();
        Console.WriteLine($"Using password hasher: {sut.GetType().Name}");
    }

    [Test]
    public async Task HashAnVerifyPassword()
    {
        var password = "S3cret!1";
        var hash = sut.HashPassword(null, password);
        var resulte = sut.VerifyHashedPassword(null, hash, password);
        await Assert.That(resulte).IsEqualTo(PasswordVerificationResult.Success);
    }
}