﻿using System;
using System.Collections.Generic;
using Zesty.Core.Entities;

namespace Zesty.Core
{
    public interface IStorage
    {
        List<Resource> GetResources(string username, string domainName);
        void SaveToken(Entities.User user, string sessionId, string tokenValue, bool reusable);
        bool CanAccess(string path, Entities.User user);
        bool IsValid(Guid userId, string sessionId, string tokenValue);
        bool RequireToken(string path);
        bool IsPublicResource(string path);
        void Save(Entities.HistoryItem resource);
        string GetType(string resourceName);
        Entities.User Login(string username, string password);
        Dictionary<string, string> LoadProperties(Entities.User user);
        List<Entities.Domain> GetDomains(string username);
        List<string> GetRoles(string username, string domain);
        bool ChangePassword(string username, string currentPassword, string newPassword);
    }
}
