using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityManager;
using System.Net.Http;
using System.Text;
using OpenIDConnect.Core.Extensions;
using OpenIDConnect.IdentityManager.Dtos;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json;
using OpenIDConnect.Core.Token;
using System.IdentityModel.Tokens;
using OpenIDConnect.Core.Dtos;

namespace OpenIDConnect.IdentityManager.Services
{
    public class UsersApiIdentityManagerService : IIdentityManagerService
    {
        private readonly string usersApiUri;
        private readonly ITokenProvider tokenProvider;
        private readonly string identityServerUri;

        public UsersApiIdentityManagerService(string identityServerUri, string usersApiUri, ITokenProvider tokenProvider)
        {
            if (tokenProvider == null)
            {
                throw new ArgumentNullException(nameof(tokenProvider));
            }

            this.tokenProvider = tokenProvider;
            this.usersApiUri = usersApiUri;
            this.identityServerUri = identityServerUri;
        }

        public Task<IdentityManagerMetadata> GetMetadataAsync()
        {
            var properties = new[] {
                new PropertyMetadata { DataType = PropertyDataType.String, Name = "User Name", Required = true, Type = Core.Constants.ClaimTypes.Name },
                new PropertyMetadata { DataType = PropertyDataType.Password, Name = "Password", Required = true, Type = Core.Constants.ClaimTypes.Password },
                new PropertyMetadata { DataType = PropertyDataType.Email, Name = "Email", Required = false, Type = Core.Constants.ClaimTypes.Email }
            };

            var meta = new IdentityManagerMetadata
            {
                UserMetadata = new UserMetadata
                {
                    SupportsClaims = true,
                    SupportsCreate = true,
                    SupportsDelete = true,
                    CreateProperties = properties,
                    UpdateProperties = properties
                },
                RoleMetadata = new RoleMetadata
                {
                    SupportsCreate = false,
                    SupportsDelete = false,
                    RoleClaimType = "role",
                    CreateProperties = Enumerable.Empty<PropertyMetadata>(),
                    UpdateProperties = Enumerable.Empty<PropertyMetadata>()
                }
            };

            return Task.FromResult(meta);
        }

        public async Task<IdentityManagerResult> AddUserClaimAsync(string subject, string type, string value)
        {
            if (string.IsNullOrEmpty(subject))
            {
                return new IdentityManagerResult("Subject not specified");
            }

            if (string.IsNullOrEmpty(type))
            {
                return new IdentityManagerResult("Claim type not specified");
            }

            if (value == null)
            {
                return new IdentityManagerResult("Claim value cannot be null");
            }

            using (var client = await CreateClientAsync())
            using (var postResponse = await client.PostAsync($"/api/users/{subject}/claims", new StringContent($"[{{ type: \"{type}\", value: \"{value}\" }}]", Encoding.Unicode, "text/json")))
            {
                if (!postResponse.IsSuccessStatusCode)
                {
                    return new IdentityManagerResult($"Unable to add user claim, returned status code {postResponse.StatusCode}");
                }
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> SetUserPropertyAsync(string subject, string type, string value)
        {
            if (string.IsNullOrEmpty(subject))
            {
                return new IdentityManagerResult("Subject not specified");
            }

            if (string.IsNullOrEmpty(type))
            {
                return new IdentityManagerResult("Claim type not specified");
            }

            if (value == null)
            {
                return new IdentityManagerResult("Claim value cannot be null");
            }

            var claimsToUpdate = new[] { new ClaimDto { Type = type, Value = value } };

            using (var client = await CreateClientAsync())
            using (var putResponse = await client.PutAsync($"/api/users/{subject}/claims", new StringContent(JsonConvert.SerializeObject(claimsToUpdate), Encoding.Unicode, "text/json")))
            {
                if (!putResponse.IsSuccessStatusCode)
                {
                    return new IdentityManagerResult($"Could not delete claim {type} with value {value}: return status code {putResponse.StatusCode}");
                }
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult> RemoveUserClaimAsync(string subject, string type, string value)
        {
            if (string.IsNullOrEmpty(subject))
            {
                return new IdentityManagerResult("Subject not specified");
            }

            if (string.IsNullOrEmpty(type))
            {
                return new IdentityManagerResult("Claim type not specified");
            }

            if (value == null)
            {
                return new IdentityManagerResult("Claim value cannot be null");
            }

            using (var client = await CreateClientAsync())
            using (var deleteReponse = await client.DeleteAsync($"/api/users/{subject}/claims?claimType={type}&value={value}"))
            {
                if (!deleteReponse.IsSuccessStatusCode)
                {
                    return new IdentityManagerResult($"Could not delete claim {type} with value {value}: return status code {deleteReponse.StatusCode}");
                }
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult<UserDetail>> GetUserAsync(string subject)
        {
            if (string.IsNullOrEmpty(subject))
            {
                return new IdentityManagerResult<UserDetail>("Subject not specified");
            }

            UserDto userDto;
            IEnumerable<ClaimDto> claimDtos;

            using (var client = await CreateClientAsync())
            {
                using (var getResponse = await client.GetAsync($"/api/users/{subject}"))
                {
                    if (!getResponse.IsSuccessStatusCode)
                    {
                        return new IdentityManagerResult<UserDetail>($"Unable to get user, returned status code {getResponse.StatusCode}");
                    }
                    userDto = await getResponse.DeserializeJsonContentAsync<UserDto>();
                }

                using (var getResponse = await client.GetAsync($"/api/users/{subject}/claims"))
                {
                    if (!getResponse.IsSuccessStatusCode)
                    {
                        return new IdentityManagerResult<UserDetail>($"Unable to get user claims, returned status code {getResponse.StatusCode}");
                    }

                    claimDtos = await getResponse.DeserializeJsonContentAsync<IEnumerable<ClaimDto>>();
                }
            }

            var name = claimDtos.FirstOrDefault(c => c.Type == Core.Constants.ClaimTypes.Name)?.Value ?? userDto.Id;

            return new IdentityManagerResult<UserDetail>(
                new UserDetail
                {
                    Subject = userDto.Id,
                    Name = name,
                    Claims = claimDtos.Select(c => new ClaimValue { Type = c.Type, Value = c.Value })
                } );
        }

        public async Task<IdentityManagerResult<CreateResult>> CreateUserAsync(IEnumerable<PropertyValue> properties)
        {
            var userName = properties.FirstOrDefault(x => (x.Type == Core.Constants.ClaimTypes.Name || x.Type == Core.Constants.ClaimTypes.Username))?.Value ?? string.Empty;
            var password = properties.FirstOrDefault(x => x.Type == Core.Constants.ClaimTypes.Password)?.Value ?? string.Empty;

            var claims = properties.Where(x => x.Type != Core.Constants.ClaimTypes.Password).Select(x => new ClaimDto { Type = x.Type, Value = x.Value });

            var userCreateDto = new UserCreateDto { Username = userName, Password = password, Claims = claims };

            using (var client = await CreateClientAsync())
            {
                using (var postResponse = await client.PostAsync($"/api/users", new StringContent(JsonConvert.SerializeObject(userCreateDto), Encoding.Unicode, "text/json")))
                {
                    if (!postResponse.IsSuccessStatusCode)
                    {
                        return new IdentityManagerResult<CreateResult>($"Error creating user, returned status code {postResponse.StatusCode}");
                    }
                }
            }

            return new IdentityManagerResult<CreateResult>(new CreateResult { Subject = userName });
        }

        public async Task<IdentityManagerResult> DeleteUserAsync(string subject)
        {
            if (string.IsNullOrEmpty(subject))
            {
                return new IdentityManagerResult<UserDetail>("Subject not specified");
            }

            using (var client = await CreateClientAsync())
            using (var deleteResponse = await client.DeleteAsync($"/api/users/{subject}"))
            {
                if (!deleteResponse.IsSuccessStatusCode)
                {
                    return new IdentityManagerResult($"Error deleting user, returned status code {deleteResponse.StatusCode}");
                }
            }

            return IdentityManagerResult.Success;
        }

        public async Task<IdentityManagerResult<QueryResult<UserSummary>>> QueryUsersAsync(string filter, int start, int count)
        {
            var filterParam = !string.IsNullOrEmpty(filter) ? $"username={filter}" : string.Empty;

            if (count < 1)
            {
                count = 1;
            }

            if (start < 1)
            {
                start = 1;
            }

            var page = $"page={start}";
            var pageSize = $"pageSize={count}";

            var queryString = string.Join("&", new[] { filterParam, page, pageSize }.Where(p => !string.IsNullOrEmpty(p)));
            queryString = string.IsNullOrEmpty(queryString) ? queryString : $"?{queryString}";

            using (var client = await CreateClientAsync())
            using (var getResponse = await client.GetAsync($"/api/users{queryString}"))
            {
                if (!getResponse.IsSuccessStatusCode)
                {
                    return new IdentityManagerResult<QueryResult<UserSummary>>($"Error querying users, returned status code {getResponse.StatusCode}");
                }

                var queryResult = await getResponse.DeserializeJsonContentAsync<QueryUsersResultDto>();

                return new IdentityManagerResult<QueryResult<UserSummary>>(
                    new QueryResult<UserSummary>
                    {
                        Count = queryResult.Count,
                        Filter = filter,
                        Start = queryResult.Page * queryResult.PageSize,
                        Items = queryResult.Items.Select(u => new UserSummary { Name = u.Id, Subject = u.Id, Username = u.Id }),
                        Total = queryResult.Total
                    });
            }
        }

        public Task<IdentityManagerResult<CreateResult>> CreateRoleAsync(IEnumerable<PropertyValue> properties)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityManagerResult> DeleteRoleAsync(string subject)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityManagerResult<RoleDetail>> GetRoleAsync(string subject)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityManagerResult<QueryResult<RoleSummary>>> QueryRolesAsync(string filter, int start, int count)
        {
            return Task.FromResult(
                new IdentityManagerResult<QueryResult<RoleSummary>>(
                    new QueryResult<RoleSummary>
                    {
                        Count = count,
                        Filter = filter,
                        Start = start,
                        Items = Enumerable.Empty<RoleSummary>(),
                        Total = 0
                    }));
        }

        public Task<IdentityManagerResult> SetRolePropertyAsync(string subject, string type, string value)
        {
            throw new NotImplementedException();
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
                    new Claim("name", "idManager"),
                    new Claim("role", "IdentityAdminManager"),
                    new Claim("role", "IdentityManagerAdmin"),
                    new Claim("scope", "idadmin"),
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

            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + await tokenProvider.GenerateAccessToken(tokenDescriptor, jwtParams));
        }
    }
}
