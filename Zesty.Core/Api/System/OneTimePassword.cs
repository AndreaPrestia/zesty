using JWT.Algorithms;
using JWT.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Api.System
{
    public class OneTimePassword : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            OneTimePasswordRequest request = GetEntity<OneTimePasswordRequest>(input);

            if (!Business.OneTimePassword.Exists(request.Username, Guid.Parse(request.Domain), request.Otp))
            {
                throw new ApiAccessDeniedException(Messages.LoginFailed);
            }


            LoginOutput loginOutput = new LoginOutput();

            loginOutput.User = Business.User.Get(request.Username);

            if (loginOutput.User == null)
            {
                ThrowInvalidArgument();
            }

            List<Entities.Domain> domains = Business.User.GetDomains(loginOutput.User.Username);

            Entities.Domain domain = domains.Where(x => x.Id.ToString().ToLower() == request.Domain.ToLower() || x.Name.ToLower() == request.Domain.ToLower()).FirstOrDefault();

            if (domain == null)
            {
                domain = NestSearch(domains, request.Domain);

                if (domain == null)
                {
                    throw new ApiNotFoundException(request.Domain);
                }
            }

            Business.User.SetDomain(loginOutput.User.Id, domain.Id);

            loginOutput.User.DomainId = domain.Id;
            loginOutput.User.Domain = domain;

            LoginResponse response = new LoginResponse()
            {
                Output = loginOutput
            };

            if (request.Bearer == "true" && loginOutput.User != null)
            {
                string secret = HashHelper.GetSha256(request.Password);

                var p = loginOutput.User.Properties;

                loginOutput.User.Properties.Clear();

                string token = JwtBuilder.Create()
                      .WithAlgorithm(new HMACSHA256Algorithm())
                      .WithSecret(secret)
                      .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(12).ToUnixTimeSeconds())
                      .AddClaim("user", response.Output.User)
                      .Encode();

                logger.Debug($"token generated: {token}");

                Business.User.SaveBearer(loginOutput.User.Id, token);

                response.Bearer = token;

                loginOutput.User.Properties = p;
            }

            input.Context.Session.Set(response.Output.User);

            return GetOutput(response);
        }

        private Entities.Domain NestSearch(List<Entities.Domain> domains, string domain)
        {
            foreach (Entities.Domain d in domains)
            {
                if (d.Id.ToString() == domain || d.Name == domain)
                {
                    return d;
                }

                Entities.Domain inner = NestSearch(d.Childs, domain);

                if (inner != null)
                {
                    return inner;
                }
            }

            return null;
        }
    }

    public class OneTimePasswordRequest
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Domain { get; set; }
        [Required]
        public string Otp { get; set; }
        [Required]
        public string Password { get; set; }
        public string Bearer { get; set; }
    }
}
