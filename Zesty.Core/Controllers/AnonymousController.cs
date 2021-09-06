using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Reflection;
using System.Security;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Controllers
{
    [ResponseCache(Duration = -1, Location = ResponseCacheLocation.None, NoStore = true)]
    public class AnonymousController : Controller
    {
        private static readonly NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        private TimeKeeper timeKeeper = new TimeKeeper();

        protected double TimeKeeperDuration
        {
            get
            {
                return timeKeeper.Stop().TotalMilliseconds;
            }
        }

        protected ISession Session
        {
            get
            {
                return HttpContext.Session;
            }
        }

        protected HttpContext CurrentHttpContext
        {
            get
            {
                return HttpContext;
            }
        }

        protected string ErrorMessage
        {
            get
            {
                if (Session == null)
                {
                    return null;
                }

                if (Session.GetString(Keys.SessionLastError) == null)
                {
                    return null;
                }

                string errorMessage = Session.GetString(Keys.SessionLastError);

                Session.Remove(Keys.SessionLastError);

                return errorMessage;
            }
            set
            {
                Session.SetString(Keys.SessionLastError, value);
            }
        }

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            base.OnActionExecuting(context);

            Context.Current.Reset();

            string remoteIp = HttpContext.Connection.RemoteIpAddress.ToString();

            if (!CanAccess(remoteIp))
            {
                logger.Warn("Forbidden Request from Remote IP address: {RemoteIp}", remoteIp);

                HttpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                return;
            }

            string scheme = HttpContext.Request.Scheme;
            string host = HttpContext.Request.Host.Value;
            string path = HttpContext.Request.Path;
            string queryString = HttpContext.Request.QueryString.HasValue ? HttpContext.Request.QueryString.Value : "";

            string url = $"{scheme}://{host}{path}{queryString}";

            logger.Info($"Request {url} with session id {Session.Id}");

            HandlerProcessor.Process(Settings.List("PreExecutionHandler"), context.HttpContext);
        }

        public override void OnActionExecuted(ActionExecutedContext context)
        {
            base.OnActionExecuted(context);

            double executionMS = timeKeeper.Stop().TotalMilliseconds;

            logger.Info($"Execution require {executionMS} ms");

            Trace.Write(new TraceItem()
            {
                Millis = executionMS
            },
            context.HttpContext);

            HandlerProcessor.Process(Settings.List("PostExecutionHandler"), context.HttpContext);
        }

        protected void ValidateEntity<T>(T entity)
        {
            if (entity == null)
            {
                throw new ApplicationException(Messages.RequestIsNull);
            }

            PropertyInfo[] props = entity.GetType().GetProperties();

            foreach (PropertyInfo prop in props)
            {
                IEnumerable<Attribute> attributes = prop.GetCustomAttributes();

                foreach (Attribute attribute in attributes)
                {
                    if (attribute is RequiredAttribute)
                    {
                        if (prop.PropertyType == typeof(string))
                        {
                            string s = prop.GetValue(entity) as string;

                            if (string.IsNullOrWhiteSpace(s))
                            {
                                throw new MissingRequiredProperty(prop.Name);
                            }
                        }
                        else if (prop.PropertyType == typeof(IList) || prop.PropertyType == typeof(Array))
                        {
                            if (prop.GetValue(entity) == null)
                            {
                                throw new MissingRequiredProperty(prop.Name);
                            }
                        }
                        else if (prop.PropertyType == typeof(IList) || prop.PropertyType == typeof(Array))
                        {
                            if (prop.GetValue(entity) == null)
                            {
                                throw new MissingRequiredProperty(prop.Name);
                            }
                        }
                        else if (prop.PropertyType == typeof(object))
                        {
                            if (prop.GetValue(entity) == null)
                            {
                                throw new MissingRequiredProperty(prop.Name);
                            }
                        }
                        else if (prop.PropertyType == typeof(Guid))
                        {
                            //TODO fix
                            //string s = prop.GetValue(t) as string;

                            //if (string.IsNullOrWhiteSpace(s))
                            //{
                            //    throw new MissingRequiredProperty(prop.Name);
                            //}

                            //Guid g = Guid.Parse(s);

                            //if (g == Guid.Empty)
                            //{
                            //    throw new MissingRequiredProperty(prop.Name);
                            //}
                        }
                    }
                }
            }
        }

        protected IActionResult GetOutput(object response = null, int statusCode = 200, string contentType = null)
        {
            return new ContentResult() { Content = response != null ? JsonHelper.Serialize(response) : string.Empty, ContentType = string.IsNullOrEmpty(contentType) ? ContentType.ApplicationJson : contentType, StatusCode = response == null ? StatusCodes.Status204NoContent : statusCode };
        }

        protected void RequireContext()
        {
            if (Context.Current == null)
            {
                throw new ApiApplicationErrorException("Context is null");
            }
        }

        protected void RequireDomain()
        {
            RequireUser();

            if (Context.Current.User.Domain == null)
            {
                throw new ApiApplicationErrorException("Domain is null");
            }
        }

        protected void RequireUser()
        {
            RequireContext();

            if (Context.Current.User == null)
            {
                throw new ApiApplicationErrorException("User is null");
            }

            if (String.IsNullOrWhiteSpace(Context.Current.User.Username))
            {
                throw new ApiApplicationErrorException("Username is empty");
            }
        }

        protected void ThrowCustomJson(string json)
        {
            throw new CustomJsonException(json);
        }

        protected void ThrowInvalidArgument()
        {
            throw new ApiInvalidArgumentException(Messages.ArgumentNotFound);
        }

        protected void ThrowInvalidArgument(string message)
        {
            throw new ApiInvalidArgumentException(message);
        }

        protected void ThrowAccessDenied(string message)
        {
            throw new ApiAccessDeniedException(message);
        }

        protected void ThrowAccessDenied()
        {
            throw new ApiAccessDeniedException(Messages.AccessDenied);
        }

        protected void ThrowNotFound()
        {
            throw new ApiNotFoundException(Messages.ObjectNotFound);
        }

        protected void ThrowNotFound(string message)
        {
            throw new ApiNotFoundException(message);
        }

        protected void ThrowApplicationError(string message)
        {
            throw new ApiApplicationErrorException(message);
        }

        private bool CanAccess(string ipAddress)
        {
            int accessFailureLimit = Settings.GetInt("AccessFailureLimit", 3);

            int accessLimitMinutes = Settings.GetInt("AccessLimitMinutes", 5);

            DateTime start = DateTime.Now.AddMinutes(-accessLimitMinutes);

            return Business.User.InvalidAccesses(ipAddress, start) >= accessFailureLimit;
        }
    }
}
