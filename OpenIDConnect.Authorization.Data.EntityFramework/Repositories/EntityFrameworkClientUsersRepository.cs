namespace OpenIDConnect.Authorization.Data.EntityFramework.Repositories
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    using Microsoft.Data.Entity;

    using OpenIDConnect.Authorization.Data.EntityFramework.Context;
    using OpenIDConnect.Authorization.Domain.Models;
    using OpenIDConnect.Authorization.Domain.Repositories;
    using Core.Domain.Models;
    public class EntityFrameworkClientUsersRepository : IClientUsersRepository
    {
        private readonly AuthorizationDbContext context;

        public EntityFrameworkClientUsersRepository(AuthorizationDbContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            this.context = context;
        }

        public Task AddUserToGroup(string clientId, string groupId, User user)
        {
            throw new NotImplementedException();
        }

        public Task<User> GetUser(string clientId, string groupId, string userId)
        {
            throw new NotImplementedException();
        }

        public Task<PagingResult<User>> GetUsers(string clientId, string groupId, Paging paging)
        {
            throw new NotImplementedException();
        }

        public Task RemoveUserFromGroup(string clientId, string groupId, string userId)
        {
            throw new NotImplementedException();
        }
    }
}