using System;
using System.Runtime.Serialization;

namespace Zesty.Core.Exceptions
{
    public class SmsSendException : Exception
    {
        public SmsSendException()
        {
        }

        public SmsSendException(string message) : base(message)
        {
        }

        public SmsSendException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected SmsSendException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
