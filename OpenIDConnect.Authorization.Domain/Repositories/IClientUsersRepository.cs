namespace OpenIDConnect.Authorization.Domain.Repositories
{
    using System.Threading.Tasks;

    using OpenIDConnect.Authorization.Domain.Models;
    using Core.Domain.Models;

    public interface IClientUsersRepository
    {
        Task<PagingResult<User>> GetUsers(string clientId, string groupId, Paging paging);

        Task<User> GetUser(string clientId, string groupId, string userId);

        Task AddUserToGroup(string clientId, string groupId, User user);

        Task RemoveUserFromGroup(string clientId, string groupId, string userId);
    }
}