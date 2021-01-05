﻿using System.Collections.Generic;

namespace Zesty.Core.Business
{
    class Domain
    {
        private static IStorage storage = StorageManager.Instance;

        internal static List<Entities.Domain> List()
        {
            return storage.GetDomainsList();
        }

        internal static void Add(Entities.Domain domain)
        {
            storage.Add(domain);
        }
    }
}
