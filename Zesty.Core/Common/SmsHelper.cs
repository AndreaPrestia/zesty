using System.Net;
using Zesty.Core.Entities.Integration.Skebby;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Common
{
    static class SmsHelper
    {
        static string BASEURL = Settings.Get("Skebby.Host");
        static string MESSAGE_HIGH_QUALITY = "GP";

        internal static void SendSms(string message, long number)
        {
            string skebbyUsername = Settings.Get("Skebby.Username");

            string skebbyPassword = Settings.Get("Skebby.Password");

            string[] auth = Authenticate(skebbyUsername, skebbyPassword);

            SmsRequest smsRequest = new SmsRequest();

            smsRequest.Message = message;
            smsRequest.MessageType = MESSAGE_HIGH_QUALITY;
            smsRequest.Recipient = new string[] { $"+{number}" };

            SmsResponse smsResponse = SendSMS(auth, smsRequest);

            if (!"OK".Equals(smsResponse.Result))
            {
                throw new SmsSendException($"Error sending sms for user {number} \n\r {smsResponse.Result}");
            }
        }

        private static string[] Authenticate(string username, string password)
        {
            string[] auth = null;

            using (WebClient wb = new WebClient())
            {
                var response = wb.DownloadString(BASEURL + "login?username=" + username + "&password=" + password);
                auth = response.Split(';');
            }

            return auth;
        }

        private static SmsResponse SendSMS(string[] auth, SmsRequest smsRequest)
        {
            using (WebClient wb = new WebClient())
            {
                // Setting the encoding is required when sending UTF8 characters!
                wb.Encoding = System.Text.Encoding.UTF8;

                wb.Headers.Set(HttpRequestHeader.ContentType, "application/json");
                wb.Headers.Add("user_key", auth[0]);
                wb.Headers.Add("session_key", auth[1]);

                string json = JsonHelper.Serialize(smsRequest);

                string responseBody = wb.UploadString(BASEURL + "sms", "POST", json);

                SmsResponse smsResponse = JsonHelper.Deserialize<SmsResponse>(responseBody);

                return smsResponse;
            }
        }
    }
}
