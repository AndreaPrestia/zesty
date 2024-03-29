﻿using JWT.Algorithms;
using JWT.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Exceptions;
using Zesty.Core.Integration;

namespace Zesty.Core.Api.System
{
    public class Login : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            LoginRequest request = GetEntity<LoginRequest>(input);

            LoginOutput loginOutput = Business.User.Login(request.Username, request.Password);

            if (loginOutput.Result == LoginResult.Failed)
            {
                throw new ApiAccessDeniedException(Messages.LoginFailed);
            }
            else if (loginOutput.Result == LoginResult.PasswordExpired)
            {
                throw new ApiAccessDeniedException(Messages.PasswordExpired);
            }

            if (!string.IsNullOrEmpty(request.Domain))
            {
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
            }

            if(loginOutput.User.DomainId != Guid.Empty && Business.Domain.HasTwoFactorAuthentication(loginOutput.User.DomainId))
            {
                IAuthProcessor processor = new Skebby();

                processor.GenerateOtp(loginOutput.User.Id, loginOutput.User.DomainId);

                LoginTwoFactorResponse twoFactorResponse = new LoginTwoFactorResponse() { Domain = loginOutput.User.DomainId };

                return GetOutput(twoFactorResponse);
            }

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

    public class LoginRequest
    {
        [Required]
        public string Username { get; set; }
        public string Domain { get; set; }
        [Required]
        public string Password { get; set; }
        public string Bearer { get; set; }
    }

    public class LoginResponse
    {
        public LoginOutput Output { get; set; }
        public string Bearer { get; set; }
    }

    public class LoginTwoFactorResponse
    {
        public Guid Domain { get; set; }
    }
}
