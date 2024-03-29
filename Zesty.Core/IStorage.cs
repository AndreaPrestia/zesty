﻿using System;
using System.Collections.Generic;
using Zesty.Core.Entities;

namespace Zesty.Core
{
    public interface IStorage
    {
        void AddAccessFailure(string ipAddress);
        int CountAccessFailure(string ipAddress, DateTime start);
        void SetDomain(Guid userid, Guid domainid);
        void SaveBearer(Guid userid, string token);
        string GetSecret(string bearer);
        void Remove(User user, Authorization authorization);
        void Add(User user, Authorization authorization);
        void Update(Entities.User user);
        Entities.User GetUser(string user);
        List<Entities.User> Users();
        void HardDeleteUser(Guid userId);
        void DeleteUser(Guid userId);
        Guid Add(Entities.User user);
        void Add(Entities.Domain domain);
        void Add(Entities.Role role);
        void AuthorizeResource(Guid resourceId, Guid roleId);
        void DeauthorizeResource(Guid resourceId, Guid roleId);
        List<Entities.Resource> GetResources();
        List<Entities.Resource> GetAllResources();
        List<Entities.Resource> GetResources(Guid roleId);
        List<Entities.Role> GetRoles();
        void ChangePassword(Guid id, string oldPassword, string password);
        List<SettingValue> GetSettingsValues();
        void SetProperty(string name, string value, Entities.User user);
        Dictionary<string, string> GetClientSettings();
        Guid SetResetToken(string email);
        bool ResetPassword(Guid resetToken, string password);
        User GetUserByResetToken(Guid resetToken);
        List<Translation> GetTranslations(string language);
        List<Language> GetLanguages();
        List<Resource> GetResources(string username, Guid domainId);
        void SaveToken(Entities.User user, string sessionId, string tokenValue, bool reusable);
        bool CanAccess(string path, Entities.User user, string method = null);
        bool IsValid(Guid userId, string sessionId, string tokenValue);
        bool RequireToken(string path, string method = null);
        bool IsPublicResource(string path, string method = null);
        void Save(Entities.HistoryItem resource);
        string GetType(string resourceName);
        Entities.User Login(string username, string password);
        Dictionary<string, string> LoadProperties(Entities.User user);
        List<Entities.Domain> GetDomains(string username);
        List<Entities.Domain> GetDomainsList();
        List<Entities.Role> GetRoles(string username, Guid domainId);
        bool ChangePassword(string username, string currentPassword, string newPassword);
        bool HasTwoFactorAuthentication(Guid domain);
        bool OneTimePasswordExists(string user, Guid domain, string value);
        void OneTimePasswordAdd(Guid user, Guid domain, string value);
        void OneTimePasswordDelete(Guid user, Guid domain);
    }
}
