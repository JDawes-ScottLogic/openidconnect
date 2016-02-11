using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services.Default;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIDConnect.Core.Dtos;
using OpenIDConnect.Core.Token;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace OpenIDConnect.IdentityServer.Services
{
    public class UsersApiUserService : UserServiceBase
    {
        private readonly string usersApiUri;
        private readonly string identityServerUri;
        private readonly ITokenProvider tokenProvider;

        public UsersApiUserService(ITokenProvider tokenProvider, string usersApiUri, string identityServerUri)
        {
            if (tokenProvider == null)
            {
                throw new ArgumentNullException(nameof(tokenProvider));
            }

            this.tokenProvider = tokenProvider;
            this.usersApiUri = usersApiUri;
            this.identityServerUri = identityServerUri;
        }

        public override async Task AuthenticateExternalAsync(ExternalAuthenticationContext context)
        {
            using (var client = await CreateClientAsync())
            {
                if (!(await ExternalUserExistsAsync(client, context.ExternalIdentity.ProviderId)))
                {
                    context.AuthenticateResult = await AddExternalUserAsync(client, context.ExternalIdentity);
                }
            }

            if (context.AuthenticateResult == null)
            {
                context.AuthenticateResult = new AuthenticateResult(
                    context.ExternalIdentity.ProviderId, 
                    GetDisplayName(context.ExternalIdentity.Claims) ?? context.ExternalIdentity.ProviderId, 
                    context.ExternalIdentity.Claims);
            }
        }

        public override async Task AuthenticateLocalAsync(LocalAuthenticationContext context)
        {
            var userName = context.UserName;
            var password = context.Password;

            using (var client = await CreateClientAsync())
            {
                using (var postResult = await client.PostAsync($"/api/users/{userName}/authenticate", new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("password", password) })))
                {

                    if (postResult.IsSuccessStatusCode)
                    {
                        var claims = await GetClaimsAsync(client, userName, Enumerable.Empty<string>());
                        context.AuthenticateResult = new AuthenticateResult(userName, GetDisplayName(claims) ?? userName, claims);
                    }
                    else
                    {
                        context.AuthenticateResult = new AuthenticateResult($"Could not sign in user {context.UserName}: received status code {postResult.StatusCode}");
                    }
                }
            }
        }

        public override async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var username = GetName(context.Subject);

            using (var client = await CreateClientAsync())
            {
                context.IssuedClaims = await GetClaimsAsync(client, username, context.RequestedClaimTypes ?? Enumerable.Empty<string>());
            }
        }

        public override async Task IsActiveAsync(IsActiveContext context)
        {
            var username = GetName(context.Subject);

            using (var client = await CreateClientAsync())
            {
                context.IsActive = await UserExistsAsync(client, username);
            }
        }

        public override Task SignOutAsync(SignOutContext context)
        {
            return Task.FromResult(0);
        }

        private string GetName(ClaimsPrincipal principal)
        {
            var identity = principal.Identity as ClaimsIdentity;
            return identity.Name ?? identity.Claims.First(c => c.Type == "name").Value;
        }

        private async Task<HttpClient> CreateClientAsync()
        {
            var client = new HttpClient { BaseAddress = new Uri(this.usersApiUri) };
            await SetBearerTokenAsync(client);
            return client;
        }

        private async Task SetBearerTokenAsync(HttpClient client)
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("name", "idServer"),
                    new Claim("role", "IdentityAdminManager"),
                    new Claim("scope", "idserver"),
                    new Claim("scope", "api")
                }),
                TokenIssuerName = this.identityServerUri,
                AppliesToAddress = this.identityServerUri + "/resources",
            };

            var jwtParams = new TokenValidationParameters
            {
                NameClaimType = "name",
                RoleClaimType = "role",
                ValidAudience = this.identityServerUri + "/resources",
                ValidIssuer = this.identityServerUri,
            };

            client.SetBearerToken(await tokenProvider.GenerateAccessToken(tokenDescriptor, jwtParams));
        }

        private async Task<bool> UserExistsAsync(HttpClient client, string userName)
        {
            using (var response = await client.GetAsync($"/api/users/{userName}"))
            {
                return response.IsSuccessStatusCode;
            }
        }

        private Task<bool> ExternalUserExistsAsync(HttpClient client, string userId)
        {
            return Task.FromResult(true);
        }

        private async Task<AuthenticateResult> AddExternalUserAsync(HttpClient client, ExternalIdentity identity)
        {
            using (var response = await client.PostAsync($"/api/users", new StringContent($"{{ id: \"{identity.ProviderId}\", password: \"password\" }}", Encoding.Unicode, "text/json")))
            {
                if (!response.IsSuccessStatusCode)
                {
                    return new AuthenticateResult($"Could not create new external user. Error code: {response.StatusCode}");
                }
            }

            return new AuthenticateResult(identity.ProviderId, GetDisplayName(identity.Claims) ?? identity.ProviderId, identity.Claims);
        }

        private async Task<IEnumerable<Claim>> GetClaimsAsync(HttpClient client, string userName, IEnumerable<string> claimTypes)
        {
            if (claimTypes == null)
            {
                throw new ArgumentNullException(nameof(claimTypes));
            }

            var queryString = claimTypes.Any() ? $"?types={string.Join(",", claimTypes)}" : string.Empty;

            using (var getResult = await client.GetAsync($"/api/users/{userName}/claims{queryString}"))
            {
                var claimsString = await getResult.Content.ReadAsStringAsync();
                var claims = JsonConvert.DeserializeObject<IEnumerable<ClaimDto>>(claimsString);
                return claims?.Select(c => new Claim(c.Type, c.Value)) ?? Enumerable.Empty<Claim>();
            }
        }

        private string GetDisplayName(IEnumerable<Claim> claims)
        {
            return claims.FirstOrDefault(c => c.Type == Core.Constants.ClaimTypes.Name)?.Value;
        }
    }
}
