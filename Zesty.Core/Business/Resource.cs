﻿using System;
using System.Collections.Generic;

namespace Zesty.Core.Business
{
    static class Resource
    {
        private static IStorage storage = StorageManager.Instance;

        internal static string GetType(string resourceName)
        {
            //TODO add cache support

            return storage.GetType(resourceName);
        }

        internal static List<Entities.Resource> GetResources(string username, Guid domainId)
        {
            //TODO add cache support

            return storage.GetResources(username, domainId);
        }

        internal static List<Entities.Resource> ResourceList()
        {
            //TODO add cache support

            return storage.GetResources();
        }

        internal static List<Entities.Resource> ResourceList(Guid roleId)
        {
            //TODO add cache support

            return storage.GetResources(roleId);
        }

        internal static void Authorize(Guid resourceId, Guid roleId)
        {
            storage.AuthorizeResource(resourceId, roleId);
        }

        internal static void Deauthorize(Guid resourceId, Guid roleId)
        {
            storage.DeauthorizeResource(resourceId, roleId);
        }
    }
}
