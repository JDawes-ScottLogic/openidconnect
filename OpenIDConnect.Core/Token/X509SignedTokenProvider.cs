using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OpenIDConnect.Core.Token
{
    public class X509SignedTokenProvider : ITokenProvider
    {
        private readonly X509Certificate2 cert;

        public X509SignedTokenProvider(X509Certificate2 cert)
        {
            if (cert == null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            this.cert = cert;
        }

        public Task<string> GenerateAccessToken(SecurityTokenDescriptor tokenDescriptor, TokenValidationParameters validationParameters)
        {
            return Task.Run(() =>
            {
                tokenDescriptor.SigningCredentials = new X509SigningCredentials(this.cert);

                var tokenHandler = new JwtSecurityTokenHandler();
                var securityToken = tokenHandler.CreateToken(tokenDescriptor);
                var accessToken = tokenHandler.WriteToken(securityToken);

                validationParameters.IssuerSigningToken = new X509SecurityToken(this.cert);

                SecurityToken validatedToken;
                tokenHandler.ValidateToken(accessToken, validationParameters, out validatedToken);

                return accessToken;
            });
        }
    }
}
