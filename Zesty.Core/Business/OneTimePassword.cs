using System;

namespace Zesty.Core.Business
{
    class OneTimePassword
    {
        private static IStorage storage = StorageManager.Storage;

        internal static bool Exists(string user, Guid domain, string value)
        {
            return storage.OneTimePasswordExists(user, domain, value);
        }

        internal static void Add(Guid user, Guid domain, string value)
        {
            storage.OneTimePasswordAdd(user, domain, value);
        }

        internal static void Delete(Guid user, Guid domain)
        {
            storage.OneTimePasswordDelete(user, domain);
        }
    }
}
