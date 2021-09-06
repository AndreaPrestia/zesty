using System.Security.Cryptography;
using System.Text;

namespace Zesty.Core.Common
{
    public static class HashHelper
    {
        public static string GetSha256(string text)
        {
            byte[] b = Encoding.Default.GetBytes(text);

            using (SHA256 calculator = SHA256.Create())
            {
                byte[] c = calculator.ComputeHash(b);

                StringBuilder stringBuilder = new StringBuilder();

                for (int i = 0; i < c.Length; i++)
                {
                    stringBuilder.Append($"{c[i]:X2}");
                }

                return stringBuilder.ToString();
            }
        }
    }
}
