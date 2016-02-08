
namespace OpenIDConnect.Authorization.Domain.Models
{
    public class User
    {
        public User(string id, string username)
        {
            this.Id = id;
            this.Username = username;
        }

        public string Id { get; }

        public string Username { get; }
    }
}