using System;

namespace Zesty.Core.Common
{
    static class RandomHelper
    {
        internal static string GenerateSecureRandom()
        {
            Random generator = new Random();

            string r = generator.Next(0, 999999).ToString("D6");

            return r.Trim();
        }
    }
}
