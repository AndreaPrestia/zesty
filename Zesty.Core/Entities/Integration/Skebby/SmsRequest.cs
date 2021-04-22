using System;
using System.Text.Json.Serialization;

namespace Zesty.Core.Entities.Integration.Skebby
{
    internal class SmsRequest
    {
        /** The message body */
        [JsonPropertyName("message")]
        public string Message { get; set; }

        /** The message type */
        [JsonPropertyName("message_type")]
        public string MessageType { get; set; }

        /** The sender Alias (TPOA) */
        [JsonPropertyName("sender")]
        public string Sender { get; set; }

        /** Postpone the SMS message sending to the specified date */
        [JsonPropertyName("scheduled_delivery_time")]
        public DateTime? ScheduledDeliveryTime { get; set; }

        /** The list of recipients */
        [JsonPropertyName("recipient")]
        public string[] Recipient { get; set; }

        /** Should the API return the remaining credits? */
        [JsonPropertyName("ReturnCredits")]
        public bool returnCredits { get; set; } = false;
    }
}
