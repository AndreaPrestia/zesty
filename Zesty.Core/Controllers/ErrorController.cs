using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using System.Security;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Controllers
{
    [ApiController]
    public class ErrorController : AnonymousController
    {
        private static readonly NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();
        readonly bool propagateApplicationErrorInFault = Settings.GetBool("PropagateApplicationErrorInFault", false);

        [Route("/error")]
        public IActionResult Error()
        {
            var context = HttpContext.Features.Get<IExceptionHandlerFeature>();

            var e = context?.Error;

            string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;

            logger.Error(e);

            if (e is ApiInvalidArgumentException)
            {
                Trace.Write(new TraceItem() { Error = e.Message, Millis = TimeKeeperDuration }, HttpContext);

                return GetOutput(new ErrorResponse { Message = message }, 501);
            }
            else if (e is ApiNotFoundException)
            {
                Trace.Write(new TraceItem() { Error = e.Message, Millis = TimeKeeperDuration }, HttpContext);

                return GetOutput(new ErrorResponse { Message = message }, 404);
            }
            else if (e is ApiTokenExpiredException || e is ApiAccessDeniedException)
            {
                Trace.Write(new TraceItem() { Error = e.Message, Millis = TimeKeeperDuration }, HttpContext);

                return GetOutput(new ErrorResponse { Message = message }, 401);
            }
            else if (e is MissingRequiredProperty)
            {
                Trace.Write(new TraceItem() { Error = e.Message, Millis = TimeKeeperDuration }, HttpContext);

                return GetOutput(new ErrorResponse { Message = message }, 400);
            }
            else if (e is CustomJsonException)
            {
                Trace.Write(new TraceItem() { Error = e.Message, Millis = TimeKeeperDuration }, HttpContext);

                return GetOutput(new ErrorResponse { Message = message }, 502);
            }
            else if (e is SecurityException)
            {
                Trace.Write(new TraceItem() { Error = e.Message, Millis = TimeKeeperDuration }, HttpContext);

                return GetOutput(new ErrorResponse { Message = message }, 403);
            }

            Trace.Write(new TraceItem() { Error = e.Message, Millis = TimeKeeperDuration }, HttpContext);

            return GetOutput(new ErrorResponse { Message = message }, 500);
        }
    }
}
