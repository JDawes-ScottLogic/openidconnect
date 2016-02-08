
namespace OpenIDConnect.Authorization.Data.EntityFramework.Dtos
{
    using OpenIDConnect.Authorization.Domain.Models;

    public class UserDto
    {
        public string Id { get; set; }

        public string Username { get; set; }

        public User ToDomainModel()
        {
            return new User(this.Id, this.Username);            
        }
    }
}