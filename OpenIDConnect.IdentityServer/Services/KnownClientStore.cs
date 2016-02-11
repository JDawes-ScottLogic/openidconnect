
using System.Collections.Generic;
using IdentityServer3.Core.Models;
using System;
using IdentityServer3.Core.Services;
using System.Threading.Tasks;
using System.Linq;

namespace OpenIDConnect.IdentityServer.Services
{
    public class KnownClientStore : IClientStore
    {
        private readonly string identityManagerUri;

        private readonly string identityAdminUri;
        private readonly string identityServerUri;

        public KnownClientStore(
            string identityManagerUri,
            string identityAdminUri,
            string identityServerUri)
        {
            if (string.IsNullOrWhiteSpace(identityManagerUri))
            {
                throw new ArgumentNullException("identityManagerUri");
            }

            if (string.IsNullOrWhiteSpace(identityAdminUri))
            {
                throw new ArgumentNullException("identityAdminUri");
            }

            if (string.IsNullOrWhiteSpace(identityServerUri))
            {
                throw new ArgumentNullException(nameof(identityServerUri));
            }

            this.identityManagerUri = identityManagerUri;
            this.identityAdminUri = identityAdminUri;
            this.identityServerUri = identityServerUri;
        }
        
        public Task<Client> FindClientByIdAsync(string clientId)
        {
            var clients = this.GetClients();
            return Task.FromResult(clients.SingleOrDefault(c => c.ClientId == clientId));
        }

        public IEnumerable<Client> GetClients()
        {
            yield return new Client
            {
                Enabled = true,
                ClientName = "IdentityManager",
                ClientId = "idmanager_client",
                Flow = Flows.Implicit,
                RequireConsent = false,
                RedirectUris = new List<string>
                {
                    this.identityManagerUri
                },
                IdentityProviderRestrictions = new List<string>() { IdentityServer3.Core.Constants.PrimaryAuthenticationType },
                AllowedScopes =
                {
                    IdentityServer3.Core.Constants.StandardScopes.OpenId,
                    "idmanager"
                }
            };

            yield return new Client
            {
                Enabled = true,
                ClientName = "IdentityAdmin",
                ClientId = "idadmin_client",
                Flow = Flows.Implicit,
                RequireConsent = false,
                RedirectUris = new List<string>
                    {
                        this.identityAdminUri
                    },
                IdentityProviderRestrictions = new List<string>() { IdentityServer3.Core.Constants.PrimaryAuthenticationType },
                AllowedScopes =
                    {
                        IdentityServer3.Core.Constants.StandardScopes.OpenId,
                        "idadmin"
                    }
            };

            yield return new Client
            {
                Enabled = true,
                ClientName = "IdentityServer",
                ClientId = "idserver_client",
                ClientSecrets = new List<Secret>
                {
                    new Secret("7FFF0184-9A9E-4CD8-86A3-A217567B5584".Sha256())
                },
                RedirectUris = new List<string>
                    {
                        this.identityServerUri
                    },
                Flow = Flows.Implicit,
                AllowedScopes =
                {
                    IdentityServer3.Core.Constants.StandardScopes.OpenId,
                    "idserver"
                }
            };

            //Our hard coded client apps
            yield return new Client
            {
                Enabled = true,
                ClientName = "angular14",
                ClientId = "angular14",
                Flow = Flows.Implicit,
                EnableLocalLogin = true,
                AllowedScopes = new List<string> {
                    IdentityServer3.Core.Constants.StandardScopes.OpenId,
                    IdentityServer3.Core.Constants.StandardScopes.Profile,
                    "api"
                },
                AccessTokenLifetime = 1200,
                IdentityTokenLifetime = 300,
                RedirectUris = new List<string> { "https://localhost:44303/callback" },
                AllowedCorsOrigins = new List<string>
                {
                    "https://localhost:44303"
                },
                PostLogoutRedirectUris = new List<string>
                {
                    "https://localhost:44303"
                },
                RequireConsent = false
            };

            yield return new Client
            {
                Enabled = true,
                ClientName = "angularMaterial",
                ClientId = "angularMaterial",
                Flow = Flows.Implicit,
                EnableLocalLogin = true,
                AllowedScopes = new List<string> {
                    IdentityServer3.Core.Constants.StandardScopes.OpenId,
                    IdentityServer3.Core.Constants.StandardScopes.Profile,
                    "api"
                },
                AccessTokenLifetime = 1200,
                IdentityTokenLifetime = 300,
                RedirectUris = new List<string> { "https://localhost:44300/#/callback/" },
                AllowedCorsOrigins = new List<string>
                {
                    "https://localhost:44300/"
                },
                PostLogoutRedirectUris = new List<string>
                {
                    "https://localhost:44300/"
                },
                RequireConsent = false
            };

            yield return new Client
            {
                Enabled = true,
                ClientName = "usersApi",
                ClientId = "usersApi",
                Flow = Flows.Implicit,
                EnableLocalLogin = true,
                AllowedScopes = new List<string> {
                    IdentityServer3.Core.Constants.StandardScopes.OpenId,
                    IdentityServer3.Core.Constants.StandardScopes.Profile,
                    "api"
                },
                AccessTokenLifetime = 1200,
                IdentityTokenLifetime = 300,
                RedirectUris = new List<string> { "https://localhost:44353/callback" },
                AllowedCorsOrigins = new List<string>
                {
                    "https://localhost:44353"
                },
                PostLogoutRedirectUris = new List<string>
                {
                    "https://localhost:44353"
                },
                RequireConsent = false
            };

        }
    }
}