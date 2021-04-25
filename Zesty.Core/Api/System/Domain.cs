using System;
using System.Collections.Generic;
using System.Linq;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Api.System
{
    public class Domain : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            DomainRequest request = GetEntity<DomainRequest>(input);

            List<Entities.Domain> domains = Business.User.GetDomains(Context.Current.User.Username);

            Entities.Domain domain = domains.Where(x => x.Id.ToString().ToLower() == request.Domain.ToLower() || x.Name.ToLower() == request.Domain.ToLower()).FirstOrDefault();

            if (domain == null)
            {
                domain = NestSearch(domains, request.Domain);

                if (domain == null)
                {
                    throw new ApiNotFoundException(request.Domain);
                }
            }

            Business.User.SetDomain(Context.Current.User.Id, domain.Id);

            Context.Current.User.DomainId = domain.Id;
            Context.Current.User.Domain = domain;

            DomainResponse response = new DomainResponse()
            {
                User = Context.Current.User
            };

            input.Context.Session.Set(Context.Current.User);

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

    public class DomainRequest
    {
        [Required]
        public string Domain { get; set; }
    }

    public class DomainResponse
    {
        public User User { get; set; }
    }
}
