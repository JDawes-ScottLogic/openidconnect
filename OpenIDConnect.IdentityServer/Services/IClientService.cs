﻿using IdentityServer3.Core.Models;
using System.Collections.Generic;

namespace OpenIDConnect.IdentityServer.Services
{
    public interface IClientService
    {
        IEnumerable<Client> GetClients();
    }    
}
