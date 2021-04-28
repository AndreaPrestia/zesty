using System;
using System.Collections.Generic;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;

namespace Zesty.Core.Business
{
    public static class User
    {
        private static NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        private static IStorage storage = StorageManager.Storage;

        public static void SetDomain(Guid userid, Guid domainid)
        {
            storage.SetDomain(userid, domainid);
        }

        public static void SaveBearer(Guid userid, string token)
        {
            storage.SaveBearer(userid, token);
        }

        public static string GetSecret(string bearer)
        {
            return storage.GetSecret(bearer);
        }

        public static void SetProperty(Entities.User user, string key, string value)
        {
            storage.SetProperty(key, value, user);
        }

        public static void Authorize(Entities.User user, Entities.Authorization authorization)
        {
            storage.Add(user, authorization);
        }

        public static void Deauthorize(Entities.User user, Entities.Authorization authorization)
        {
            storage.Remove(user, authorization);
        }

        public static void Update(Entities.User user)
        {
            storage.Update(user);
        }

        public static Entities.User Get(string user)
        {
            Entities.User u = storage.GetUser(user);

            if (u == null)
            {
                return null;
            }

            u.Properties = storage.LoadProperties(u);

            u.Authorizations = new List<Entities.Authorization>();

            List<Entities.Domain> domains = storage.GetDomains(u.Username);

            foreach (Entities.Domain domain in domains)
            {
                List<Entities.Role> roles = GetRoles(u.Username, domain.Id);

                foreach (Entities.Role role in roles)
                {
                    u.Authorizations.Add(new Entities.Authorization() { Domain = domain, Role = role });
                }
            }

            return u;
        }

        public static List<Entities.User> List()
        {
            List<Entities.User> users = storage.Users();

            foreach (Entities.User user in users)
            {
                user.Authorizations = new List<Entities.Authorization>();

                List<Entities.Domain> domains = storage.GetDomains(user.Username);

                foreach (Entities.Domain domain in domains)
                {
                    List<Entities.Role> roles = GetRoles(user.Username, domain.Id);

                    foreach (Entities.Role role in roles)
                    {
                        user.Authorizations.Add(new Entities.Authorization() { Domain = domain, Role = role });
                    }
                }
            }

            return users;
        }

        public static void HardDelete(Guid id)
        {
            storage.HardDeleteUser(id);
        }

        public static void Delete(Guid id)
        {
            storage.DeleteUser(id);
        }

        public static Guid Add(Entities.User user)
        {
            return storage.Add(user);
        }

        public static void ChangePassword(Guid id, string oldPassword, string password)
        {
            storage.ChangePassword(id, oldPassword, password);
        }

        public static Guid SetResetToken(string email)
        {
            return storage.SetResetToken(email);
        }

        public static bool ResetPassword(Guid token, string password)
        {
            return storage.ResetPassword(token, password);
        }

        public static Entities.User Get(Guid resetToken)
        {
            return storage.GetUserByResetToken(resetToken);
        }

        public static bool ChangePassword(string username, string currentPassword, string newPassword)
        {
            return storage.ChangePassword(username, currentPassword, newPassword);
        }

        public static List<Entities.Domain> GetDomains(string username)
        {
            return storage.GetDomains(username);
        }

        public static List<Entities.Role> GetRoles(string username, Guid domain)
        {
            return storage.GetRoles(username, domain);
        }

        public static int InvalidAccesses(string username, DateTime start)
        {
            return storage.CountAccessFailure(username, start);
        }

        public static LoginOutput Login(string username, string password)
        {
            logger.Info($"Login request for user {username}");

            LoginOutput output = new LoginOutput()
            {
                Result = LoginResult.Success,
                User = storage.Login(username, password)
            };

            if (output.User == null)
            {
                output.Result = LoginResult.Failed;
                storage.AddAccessFailure(username);
            }
            else
            {
                int passwordDays = (int)DateTime.Now.Subtract(DateTimeHelper.GetFromUnixTimestamp(output.User.PasswordChanged)).TotalDays;

                if (passwordDays >= Settings.GetInt("PasswordLifetimeInDays"))
                {
                    output.Result = LoginResult.PasswordExpired;
                }
                else
                {
                    output.User.Properties = storage.LoadProperties(output.User);
                }
            }

            string json = JsonHelper.Serialize(output);

            logger.Info(json);

            return output;
        }
    }
}
