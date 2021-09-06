using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Controllers
{
    [ApiController]
    [ApiExplorerSettings(IgnoreApi = true)]
    public class ErrorController : ControllerBase
    {
        private static readonly NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();
        readonly bool propagateApplicationErrorInFault = Settings.GetBool("PropagateApplicationErrorInFault", false);

        [Route("/error")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult Error()
        {
            var context = HttpContext.Features.Get<IExceptionHandlerFeature>();

            var e = context?.Error;

            string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;

            logger.Error(e);

            int statusCode = 500;

            if (e is ApiInvalidArgumentException)
            {
                statusCode = 501;
            }
            else if (e is ApiNotFoundException)
            {
                statusCode = 404;
            }
            else if (e is ApiTokenExpiredException || e is ApiAccessDeniedException)
            {
                statusCode = 401;

                Business.User.AddAccessFailure(HttpContext.Request.HttpContext.Connection.RemoteIpAddress.ToString());
            }
            else if (e is MissingRequiredProperty)
            {
                statusCode = 400;
            }
            else if (e is CustomJsonException)
            {
                statusCode = 502;
            }
            else if (e is SecurityException)
            {
                statusCode = 403;

                Business.User.AddAccessFailure(HttpContext.Request.HttpContext.Connection.RemoteIpAddress.ToString());
            }

            Trace.Write(new TraceItem() { Error = e.Message }, HttpContext);

            return GetOutput(new ErrorResponse { Message = message }, statusCode);
        }

        protected IActionResult GetOutput(object response = null, int statusCode = 200, string contentType = null)
        {
            return new ContentResult() { Content = response != null ? JsonHelper.Serialize(response) : string.Empty, ContentType = string.IsNullOrEmpty(contentType) ? ContentType.ApplicationJson : contentType, StatusCode = response == null ? StatusCodes.Status204NoContent : statusCode };
        }
    }
}
