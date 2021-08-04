using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using Zesty.Core;
using Zesty.Core.Api.System;
using Zesty.Core.Common;
using Zesty.Core.Controllers;
using Zesty.Core.Entities;

namespace Zesty.Web.Controllers
{
    [Produces("application/json")]
    [ApiController]
    [Route("api/[controller]")]
    public class SecuredController : SecureController
    {
        //public ActionResult Hello()
        //{
        //    return Content($"Hi {Context.Current.User.Username}", "text/html");
        //}

        /// <summary>
        /// Login Api
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [HttpGet]
        [Route("Login")]
        public ActionResult Login()
        {
            LoginOutput output = Core.Business.User.Login("aprestia", "Password.1");

            if (output != null && output.Result == LoginResult.Success && output.User != null)
            {
                Context.Current.User = output.User;
                Session.Set(Context.Current.User);

                return Content(JsonHelper.Serialize(output));
            }
            else if (output.Result == LoginResult.Failed)
            {
                throw new SecurityException("Login failed");
            }
            else if (output.Result == LoginResult.PasswordExpired)
            {
                throw new SecurityException("Password expired");
            }
            else
            {
                throw new Exception("Login error");
            }
        }

        /// <summary>
        /// Set domain
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [HttpGet]
        [Route("Domain")]
        public ActionResult DomainSet()
        {
            List<Core.Entities.Domain> domains = Core.Business.User.GetDomains(Context.Current.User.Username);

            Core.Entities.Domain domain = domains.Where(x => x.Id.ToString().ToLower() == "BC89E749-784B-479F-91E6-85708326558E".ToLower() || x.Name.ToLower() == "BC89E749-784B-479F-91E6-85708326558E".ToLower()).FirstOrDefault();

            if (domain == null)
            {
                domain = NestSearch(domains, domain.Id.ToString());

                if (domain == null)
                {
                    throw new ApiNotFoundException("BC89E749-784B-479F-91E6-85708326558E");
                }
            }

            Core.Business.User.SetDomain(Context.Current.User.Id, domain.Id);

            Context.Current.User.DomainId = domain.Id;
            Context.Current.User.Domain = domain;

            DomainResponse response = new DomainResponse()
            {
                User = Context.Current.User
            };

            this.HttpContext.Session.Set(Context.Current.User);

            return Content(JsonHelper.Serialize(response));
        }

        /// <summary>
        /// Logout API
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [HttpGet]
        [Route("Logout")]
        public ActionResult Logout()
        {
            Zesty.Core.Business.Authorization.Logout(base.CurrentHttpContext);

            return Content($"Logged out :)", "text/html");
        }

        /// <summary>
        /// Test api
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [HttpGet]
        [Route("TestApi")]
        public ActionResult TestApi(int id)
        {
            return Content($"Id: {id}");
        }

        private Core.Entities.Domain NestSearch(List<Core.Entities.Domain> domains, string domain)
        {
            foreach (Core.Entities.Domain d in domains)
            {
                if (d.Id.ToString() == domain || d.Name == domain)
                {
                    return d;
                }

                Core.Entities.Domain inner = NestSearch(d.Childs, domain);

                if (inner != null)
                {
                    return inner;
                }
            }

            return null;
        }
    }
}