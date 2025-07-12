// Airline FAPI 2.0 Client Flow in C# (.NET 8+)
// Using IdentityModel and System.IdentityModel.Tokens.Jwt for DPoP and request signing

using IdentityModel.Client;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text.Json;
using System.Net.Http.Headers;

public class Fapi2Client
{
    private readonly string clientId = "travel-agency-app";
    private readonly string redirectUri = "https://app.travelagency.com/callback";
    private readonly string issuer = "https://idp.airline.com";
    private readonly HttpClient client = new HttpClient();

    public async Task StartFlowAsync()
    {
        // Discover metadata
        var disco = await client.GetDiscoveryDocumentAsync(issuer);
        if (disco.IsError) throw new Exception(disco.Error);

        // Generate ephemeral DPoP key
        using var dpopKey = RSA.Create(2048);
        var rsaSecurityKey = new RsaSecurityKey(dpopKey) { KeyId = Guid.NewGuid().ToString() };

        // Build request object (as JWT)
        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", clientId),
                new Claim("aud", disco.AuthorizationEndpoint),
                new Claim("response_type", "code"),
                new Claim("client_id", clientId),
                new Claim("redirect_uri", redirectUri),
                new Claim("scope", "openid profile airline_api"),
                new Claim("state", CryptoRandom.CreateUniqueId()),
                new Claim("nonce", CryptoRandom.CreateUniqueId())
            }),
            SigningCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256),
            Expires = DateTime.UtcNow.AddMinutes(5),
            Issuer = clientId,
            Audience = disco.AuthorizationEndpoint
        };

        var requestJwt = handler.CreateEncodedJwt(tokenDescriptor);

        // Pushed Authorization Request (PAR)
        var parResponse = await client.RequestPushedAuthorizationAsync(new PushedAuthorizationRequest
        {
            Address = disco.PushedAuthorizationRequestEndpoint,
            ClientId = clientId,
            Request = requestJwt
        });

        if (parResponse.IsError) throw new Exception(parResponse.Error);

        var authorizationUrl = disco.AuthorizationEndpoint + "?request_uri=" + parResponse.RequestUri;

        Console.WriteLine("Redirect the travel agent to: " + authorizationUrl);
    }
}

// Usage
// var fapi = new Fapi2Client();
// await fapi.StartFlowAsync();
