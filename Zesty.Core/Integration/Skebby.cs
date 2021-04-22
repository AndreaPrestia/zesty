using System;
using Zesty.Core.Common;

namespace Zesty.Core.Integration
{
    public class Skebby : IAuthProcessor
    {
        public void GenerateAuth(string username)
        {
            Entities.User user = Business.User.Get(username);

            if (user != null)
            {
                string random = RandomHelper.GenerateSecureRandom();

                long.TryParse(user.Properties["Mobile"].Substring(1), out long mobile);

                Guid resetToken = Business.User.SetResetToken(user.Email);

                SmsHelper.SendSms($"Your resetToken: {resetToken}", mobile);
            }
        }
    }
}
