using System;

namespace Zesty.Core
{
    public interface IAuthProcessor
    {
        void GenerateAuth(string username);

        void GenerateOtp(Guid user, Guid domain);
    }
}
