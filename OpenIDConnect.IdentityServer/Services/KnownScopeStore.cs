using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using System.Collections.Generic;
using System;
using System.Threading.Tasks;
using System.Linq;

namespace OpenIDConnect.IdentityServer.Services
{
    internal abstract class FixedScopeStore : IScopeStore
    {
        public Task<IEnumerable<Scope>> FindScopesAsync(IEnumerable<string> scopeNames)
        {
            var scopes = this.GetScopes();
            return Task.FromResult(scopes.Where(s => scopeNames.Contains(s.Name)));
        }

        // TODO: review publicOnly param
        public Task<IEnumerable<Scope>> GetScopesAsync(bool publicOnly = true)
        {
            var scopes = this.GetScopes();
            return Task.FromResult(scopes);
        }

        protected abstract IEnumerable<Scope> GetScopes();
    }

    internal class KnownScopeStore : FixedScopeStore
    {
        protected override IEnumerable<Scope> GetScopes()
        {
            yield return StandardScopes.OpenId;

            yield return StandardScopes.Profile;

            yield return new Scope
            {
                Name = "idmanager",
                DisplayName = "IdentityManager",
                Description = "Authorization for IdentityManager",
                Type = ScopeType.Identity,
                Claims = new List<ScopeClaim>
                {
                    new ScopeClaim(IdentityServer3.Core.Constants.ClaimTypes.Name),
                    new ScopeClaim(IdentityServer3.Core.Constants.ClaimTypes.Role)
                }
            };

            yield return new Scope
            {
                Name = "idadmin",
                DisplayName = "IdentityAdmin",
                Description = "Authorization for IdentityAdmin",
                Type = ScopeType.Identity,
                Claims = new List<ScopeClaim>
                {
                    new ScopeClaim(IdentityServer3.Core.Constants.ClaimTypes.Name),
                    new ScopeClaim(IdentityServer3.Core.Constants.ClaimTypes.Role),
                    new ScopeClaim("idadmin-api")
                }
            };

            yield return new Scope
            {
                Name = "idserver",
                DisplayName = "IdentityServer",
                Description = "Authorization for IdentityServer",
                Type = ScopeType.Resource,
                Claims = new List<ScopeClaim>
                {
                    new ScopeClaim(IdentityServer3.Core.Constants.ClaimTypes.Name),
                    new ScopeClaim(IdentityServer3.Core.Constants.ClaimTypes.Role),
                }
            };

            yield return new Scope
            {
                Name = "api",
                DisplayName = "API",
                Description = "Authorization for the API",
                Type = ScopeType.Resource,
                ShowInDiscoveryDocument = true,
                Enabled = true,
                Required = true,
                Claims = new List<ScopeClaim>
                {
                    new ScopeClaim("role")
                }
            };

            yield return new Scope
            {
                Name = "usersApi",
                DisplayName = "Users API",
                Description = "Authorization for the Users API",
                Type = ScopeType.Resource,
                ShowInDiscoveryDocument = true,
                Enabled = true,
                Required = true,
                ScopeSecrets = new List<Secret>
                {
                    new Secret("usersApi".Sha256())
                },
                Claims = new List<ScopeClaim>
                {
                    new ScopeClaim("role")
                }
            };
        }
    }
}