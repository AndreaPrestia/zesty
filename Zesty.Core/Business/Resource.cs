﻿using System.Collections.Generic;

namespace Zesty.Core.Business
{
    static class Resource
    {
        internal static string GetType(string resourceName)
        {
            //TODO add cache support

            return StorageManager.Instance.GetType(resourceName);
        }

        internal static List<Entities.Resource> GetResources(string username, string domainName)
        {
            //TODO add cache support

            return StorageManager.Instance.GetResources(username, domainName);
        }
    }
}
