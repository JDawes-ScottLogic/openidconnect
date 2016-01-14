﻿
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

        public KnownClientStore(
            string identityManagerUri,
            string identityAdminUri)
        {
            if (string.IsNullOrWhiteSpace(identityManagerUri))
            {
                throw new ArgumentNullException("identityManagerUri");
            }

            if (string.IsNullOrWhiteSpace(identityAdminUri))
            {
                throw new ArgumentNullException("identityAdminUri");
            }

            this.identityManagerUri = identityManagerUri;
            this.identityAdminUri = identityAdminUri;
        }
        
        public Task<Client> FindClientByIdAsync(string clientId)
        {
            var clients = this.GetClients();
            return Task.FromResult(clients.SingleOrDefault(c => c.ClientId == clientId));
        }

        private IEnumerable<Client> GetClients()
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
        }
    }
}