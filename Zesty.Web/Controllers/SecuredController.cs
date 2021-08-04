using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security;
using Zesty.Core;
using Zesty.Core.Common;
using Zesty.Core.Controllers;
using Zesty.Core.Entities;

namespace Zesty.Web.Controllers
{
    [Produces("application/json")]
    [ApiController]
    [Route("[controller]")]
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
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [HttpGet]
        [Route("Login")]
        public ActionResult Login()
        {
            LoginOutput output = Core.Business.User.Login("aprestia", "password");

            if (output != null && output.Result == LoginResult.Success && output.User != null)
            {
                Context.Current.User = output.User;
                Session.Set(Context.Current.User);

                return Redirect("Hello");
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
        /// Logout API
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status201Created)]
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
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [HttpGet]
        [Route("TestApi")]
        public ActionResult TestApi(int id)
        {
            return Content($"Id: {id}");
        }
    }
}