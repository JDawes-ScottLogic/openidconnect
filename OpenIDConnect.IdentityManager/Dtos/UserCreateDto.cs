using OpenIDConnect.Core.Dtos;
using System.Collections.Generic;

namespace OpenIDConnect.IdentityManager.Dtos
{
    class UserCreateDto
    {
        public string Username { get; set; }

        public string Password { get; set; }

        public IEnumerable<ClaimDto> Claims { get; set; }
    }
}
