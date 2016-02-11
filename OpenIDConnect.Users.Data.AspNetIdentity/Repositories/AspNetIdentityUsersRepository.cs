using Microsoft.AspNet.Identity;
using OpenIDConnect.Users.Data.AspNetIdentity.Models;
using OpenIDConnect.Users.Domain;
using OpenIDConnect.Users.Domain.Models;
using System;
using System.Threading.Tasks;
using System.Linq;
using OpenIDConnect.Core.Domain.Models;

namespace OpenIDConnect.Users.Data.AspNetIdentity.Repositories
{
    using PagedList;
    using PagedList.EntityFramework;

    public class AspNetIdentityUsersRepository : IUsersRepository
    {
        private readonly UserManager<ApplicationUser> userManager;

        public AspNetIdentityUsersRepository(UserManager<ApplicationUser> userManager)
        {
            if (userManager == null)
            {
                throw new ArgumentNullException(nameof(userManager));
            }

            this.userManager = userManager;
        }

        public async Task<User> GetUserByName(string username)
        {
            var user = await this.userManager.FindByNameAsync(username);
            return user?.ToDomainModel();
        }

        public async Task AddUser(User user)
        {
            var applicationUser = ApplicationUser.FromUser(user);

            var result = await this.userManager.CreateAsync(applicationUser, user.Password);
            var lockedOut = await this.userManager.IsLockedOutAsync(applicationUser);

            if (!result.Succeeded)
            {
                // TODO: change to identity create exception
                throw new Exception("There was an error adding the user");
            }
        }

        public async Task UpdateUser(User user)
        {
            var applicationUser = ApplicationUser.FromUser(user);
            var result = await this.userManager.UpdateAsync(applicationUser);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException("There was an error updating the user");
            }
        }

        public async Task DeleteUser(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentNullException(nameof(username));
            }

            var user = await this.userManager.FindByNameAsync(username);
            if (user == null)
            {
                throw new InvalidOperationException("Invalid username specified");
            }

            var result = await this.userManager.DeleteAsync(user);

            if (!result.Succeeded)
            {
                throw new InvalidOperationException("There was an error deleting the user");
            }
        }

        public async Task<bool> Authenticate(string userId, string password)
        {
            if (string.IsNullOrWhiteSpace(userId))
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            var user = await this.userManager.FindByNameAsync(userId);
            if (user == null)
            {
                throw new InvalidOperationException("Invalid username specified");
            }

            return await this.userManager.CheckPasswordAsync(
                user, 
                password);
        }

        public Task<PagingResult<User>> QueryUsers(string username, string claimType, string claimValue, Paging paging)
        {
            var users =
                this.userManager.Users
                    .WhereIf(() => !string.IsNullOrWhiteSpace(username), u => u.Id.Contains(username))
                    .WhereIf(() => !string.IsNullOrWhiteSpace(claimType) && !string.IsNullOrWhiteSpace(claimValue), 
                                u => u.Claims.Any(c => c.ClaimType == claimType && c.ClaimValue.Contains(claimValue)))
                    .Select(u => u.ToDomainModel());
            
            var pagedUsers = users.ToPagedList(paging.Page, paging.PageSize);
            var pagingResult = new PagingResult<User>(
                new PageDetails(pagedUsers.PageNumber, pagedUsers.PageSize, pagedUsers.Count, pagedUsers.PageCount, pagedUsers.TotalItemCount),
                pagedUsers);

            return Task.FromResult(pagingResult);
        }
    }
}