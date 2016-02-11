using System;
using System.Collections.Generic;
using System.Linq;

namespace OpenIDConnect.Users.Domain.Models
{
    public class User
    {        
        private IEnumerable<Claim> claims;

        public User(string id, string username, string password, IEnumerable<Claim> claims)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentNullException(nameof(username));
            }            

            this.Id = id;
            this.Username = username;
            this.Password = password;
            this.claims = claims;
        }

        public string Id
        {
            get;
        }

        public string Username
        {
            get;
        }

        public string Password
        {
            get;
        }

        public IEnumerable<Claim> Claims
        {
            get
            {
                return this.claims ?? (this.claims = Enumerable.Empty<Claim>());
            }

            set
            {
                this.claims = value;
            }
        }
    }
}