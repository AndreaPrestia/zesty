using System.Text.Json.Serialization;

namespace Zesty.Core.Entities.Integration.Skebby
{
    internal class SmsResponse
    {
        /** The result of the SMS message sending */
        [JsonPropertyName("result")]
        public string Result { get; set; }

        /** The order ID of the SMS message sending */
        [JsonPropertyName("order_id")]
        public string OrderId { get; set; }

        /** The actual number of sent SMS messages */
        [JsonPropertyName("total_sent")]
        public int TotalSent { get; set; }

        /** The remaining credits */
        [JsonPropertyName("remaining_credits")]
        public int RemainingCredits { get; set; }
    }
}
