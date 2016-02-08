using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace OpenIDConnect.Core.Token
{
    public interface ITokenProvider
    {
        Task<string> GenerateAccessToken(SecurityTokenDescriptor tokenDescriptor, TokenValidationParameters validationParameters);
    }
}
