using OpenIDConnect.Core.Constants;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using ClaimTypes = OpenIDConnect.Core.Constants.ClaimTypes;
using AuthenticationTypes = OpenIDConnect.Core.Constants.AuthenticationTypes;

namespace OpenIDConnect.Core.Models
{
    public class AuthenticationResult
    {
        public AuthenticationResult(string errorMessage)
        {
            if (string.IsNullOrWhiteSpace(errorMessage))
            {
                throw new ArgumentNullException(nameof(errorMessage));
            }

            this.ErrorMessage = errorMessage;
        }

        public AuthenticationResult(string redirectPath, ExternalIdentity externalId)
        {
            if (string.IsNullOrWhiteSpace(redirectPath))
            {
                throw new ArgumentNullException(nameof(redirectPath));
            }

            if (!redirectPath.StartsWith("~/") && !redirectPath.StartsWith("/"))
            {
                throw new ArgumentException($"{nameof(redirectPath)} must start with / or ~/");
            }

            if (externalId == null)
            {
                throw new ArgumentNullException(nameof(externalId));
            }

            this.PartialSignInRedirectPath = redirectPath;

            var id = new ClaimsIdentity(externalId.Claims, AuthenticationTypes.PartialSignInAuthenticationType);

            this.User = new ClaimsPrincipal(id);
        }

        public AuthenticationResult(string redirectPath, IEnumerable<Claim> claims)
        {
            if (string.IsNullOrWhiteSpace(redirectPath))
            {
                throw new ArgumentNullException(nameof(redirectPath));
            }

            if (!redirectPath.StartsWith("~/") && !redirectPath.StartsWith("/"))
            {
                throw new ArgumentException($"{nameof(redirectPath)} must start with / or ~/");
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            this.PartialSignInRedirectPath = redirectPath;

            var id = new ClaimsIdentity(claims, AuthenticationTypes.PartialSignInAuthenticationType, ClaimTypes.Name, ClaimTypes.Role);

            this.User = new ClaimsPrincipal(id);
        }

        public AuthenticationResult(
            string subject, 
            string name, 
            IEnumerable<Claim> claims, 
            string identityProvider = IdentityProviders.BuiltInIdentityProvider, 
            string authenticationMethod = null)
        {
            if (string.IsNullOrWhiteSpace(subject))
            {
                throw new ArgumentNullException(nameof(subject));
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            if (string.IsNullOrWhiteSpace(identityProvider))
            {
                throw new ArgumentNullException(nameof(name));
            }

            this.User = CreateUser(subject, name, authenticationMethod, identityProvider, claims);
        }

        public AuthenticationResult(
            string redirectPath, 
            string subject, 
            string name, 
            IEnumerable<Claim> claims = null, 
            string identityProvider = IdentityProviders.BuiltInIdentityProvider,
            string authenticationMethod = null)
            : this(subject, name, claims, identityProvider, authenticationMethod)
        {
            if (string.IsNullOrWhiteSpace(redirectPath))
            {
                throw new ArgumentNullException(nameof(redirectPath));
            }

            if (!redirectPath.StartsWith("~/") && !redirectPath.StartsWith("/"))
            {
                throw new ArgumentException($"{nameof(redirectPath)} must start with / or ~/");
            }

            this.PartialSignInRedirectPath = redirectPath;
        }

        public string ErrorMessage { get; }

        public string PartialSignInRedirectPath { get; }

        public ClaimsPrincipal User { get; }

        public bool IsError
        {
            get
            {
                return !string.IsNullOrEmpty(this.ErrorMessage);
            }
        }

        public bool IsPartialSignIn
        {
            get
            {
                return !string.IsNullOrWhiteSpace(this.PartialSignInRedirectPath);
            }
        }

        public bool HasSubject
        {
            get
            {
                return this.User != null && User.HasClaim(c => c.Type == ClaimTypes.Subject);
            }
        }

        public string Name
        {
            get
            {
                return this.User?.FindFirst(ClaimTypes.Name)?.Value;
            }
        }

        public string Subject
        {
            get
            {
                return this.User?.FindFirst(ClaimTypes.Subject)?.Value;
            }
        }

        public string AuthenticationMethod
        {
            get
            {
                return this.User?.FindFirst(ClaimTypes.AuthenticationMethod)?.Value;
            }
        }

        public string IdentityProvider
        {
            get
            {
                return this.User?.FindFirst(ClaimTypes.IdentityProvider)?.Value;
            }
        }

        private ClaimsPrincipal CreateUser(
            string subject, 
            string name, 
            string authenticationMethod, 
            string identityProvider, 
            IEnumerable<Claim> claims)
        {
            if (string.IsNullOrWhiteSpace(authenticationMethod))
            {
                if (identityProvider == IdentityProviders.BuiltInIdentityProvider)
                {
                    authenticationMethod = AuthenticationMethods.Password;
                }
                else
                {
                    authenticationMethod = AuthenticationMethods.External;
                }
            }

            claims = claims
                .Where(x => !ClaimTypes.OidcProtocolClaimTypes.Contains(x.Type))
                .Where(x => x.Type != ClaimTypes.Name)
                .Union(new[]
            {
                new Claim(ClaimTypes.Subject, subject),
                new Claim(ClaimTypes.Name, name),
                new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod),
                new Claim(ClaimTypes.IdentityProvider, identityProvider),
                new Claim(ClaimTypes.AuthenticationTime, 0.ToString(), ClaimValueTypes.Integer)
            });

            var id = new ClaimsIdentity(claims, AuthenticationTypes.PrimaryAuthenticationType, ClaimTypes.Name, ClaimTypes.Role);

            return new ClaimsPrincipal(id);
        }
    }
}
