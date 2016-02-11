using System;
using System.Collections.Concurrent;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace OpenIDConnect.Core.Token
{
    public class CachingTokenProvider : ITokenProvider
    {
        private readonly ITokenProvider innerTokenProvider;

        private readonly ConcurrentDictionary<SecurityTokenDescriptor, string> tokenCache = new ConcurrentDictionary<SecurityTokenDescriptor, string>();

        public CachingTokenProvider(ITokenProvider innerTokenProvider)
        {
            if (innerTokenProvider == null)
            {
                throw new ArgumentNullException(nameof(innerTokenProvider));
            }

            this.innerTokenProvider = innerTokenProvider;
        }

        public async Task<string> GenerateAccessToken(SecurityTokenDescriptor tokenDescriptor, TokenValidationParameters validationParameters)
        {
            if (tokenCache.ContainsKey(tokenDescriptor) && tokenDescriptor.Lifetime.Expires > DateTime.UtcNow.AddMinutes(-1))
            {
                return tokenCache[tokenDescriptor];
            }
            tokenDescriptor.Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(10));
            var accessToken = await this.innerTokenProvider.GenerateAccessToken(tokenDescriptor, validationParameters);
            return tokenCache.AddOrUpdate(tokenDescriptor, accessToken, (d, t) => accessToken);
        }
    }
}
