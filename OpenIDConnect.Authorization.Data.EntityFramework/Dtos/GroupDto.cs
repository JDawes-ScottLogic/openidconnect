namespace OpenIDConnect.Authorization.Data.EntityFramework.Dtos
{
    using System.Collections.Generic;
    using System.Linq;

    using OpenIDConnect.Authorization.Domain.Models;

    public class GroupDto
    {
        private ICollection<GroupClaimDto> groupClaims = null;

        private IEnumerable<UserDto> users;

        public int Id { get; set; }

        public string Name { get; set; }

        public string ClientId { get; set; }

        public ClientDto Client { get; set; }

        public ICollection<GroupClaimDto> GroupClaims
        {
            get
            {
                return this.groupClaims ?? (this.groupClaims = new List<GroupClaimDto>());
            }
            set
            {
                this.groupClaims = value;
            }
        }

        public IEnumerable<UserDto> Users
        {
            get
            {
                return this.users ?? (this.users = Enumerable.Empty<UserDto>());
            }

            set
            {
                this.users = value;
            }
        }

        public Group ToDomainModel()
        {
            return new Group(this.Id.ToString(), this.Name);
        }

        public static GroupDto FromDomain(Group group)
        {
            return new GroupDto
                {
                    Id = string.IsNullOrWhiteSpace(group.Id) ? 0 : int.Parse(group.Id),
                    Name = group.Name
                };
        }
    }
}