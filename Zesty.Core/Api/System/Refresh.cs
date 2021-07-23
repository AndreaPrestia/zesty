using System;
using JWT.Algorithms;
using JWT.Builder;
using Zesty.Core.Entities;

namespace Zesty.Core.Api.System
{
    public class Refresh : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            string bearer = input.Context.Request.Headers["ZestyApiBearer"];

            if (String.IsNullOrWhiteSpace(bearer))
            {
                ThrowApplicationError("Bearer non found");
            }

            string secret = Business.User.GetSecret(bearer);

            string token = JwtBuilder.Create()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret(secret)
                .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(12).ToUnixTimeSeconds())
                .AddClaim("user", Context.Current.User)
                .Encode();

            logger.Debug($"token generated: {token}");

            Business.User.SaveBearer(Context.Current.User.Id, token);

            RefreshResponse response = new RefreshResponse() { Bearer = token };

            return GetOutput(response);
        }
    }

    public class RefreshRequest
    {

    }

    public class RefreshResponse
    {
        public string Bearer { get; set; }
    }
}
