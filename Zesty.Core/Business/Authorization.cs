﻿using System;
using System.Security;
using Microsoft.AspNetCore.Http;
using Zesty.Core.Entities.Settings;

namespace Zesty.Core.Business
{
    public static class Authorization
    {
        private static NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        private static IStorage storage = StorageManager.Storage;

        private static string setDomainResource = Settings.Get("SetDomainResourceName", "/system.domain.api");

        private static string setDomainResourceController = Settings.Get("SetDomainResourceController", "/api/System/Domain");
        private static string setDomainListResourceController = Settings.Get("SetDomainListResourceController", "/api/System/Domains");

        public static void Logout(HttpContext context)
        {
            Context.Current.Reset();

            context.Session.Clear();
            context.Response.Headers.Clear();
            context.Request.Headers.Clear();
        }

        internal static bool CanAccess(string path, Entities.User user, string method = null)
        {
            //TODO add cache

            bool isPublic = StorageManager.Storage.IsPublicResource(path, method);

            if (isPublic)
            {
                logger.Info($"The resource {path} is public");

                return true;
            }

            if (user == null)
            {
                logger.Warn($"Access denied for resource {path} for null user");

                throw new SecurityException(Messages.AccessDenied);
            }

            if (user.Domain == null && path != setDomainResource && path != setDomainResourceController && path != setDomainListResourceController)
            {
                logger.Warn($"Access denied for resource {path} for null user.Domain");

                throw new SecurityException(Messages.AccessDenied);
            }

            //TODO add cache

            return storage.CanAccess(path, user, method);
        }

        internal static string GetToken(string sessionId, bool reusable)
        {
            string tokenValue = (Guid.NewGuid().ToString() + Guid.NewGuid().ToString()).Replace("-", "");

            storage.SaveToken(Context.Current.User, sessionId, tokenValue, reusable);

            return tokenValue;
        }

        internal static bool RequireToken(string path, string method = null)
        {
            //TODO add cache

            return storage.RequireToken(path, method);
        }

        internal static bool IsValid(Guid userId, string sessionId, string tokenValue)
        {
            return storage.IsValid(userId, sessionId, tokenValue);
        }
    }
}
