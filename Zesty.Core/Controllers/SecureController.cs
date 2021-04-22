using System.Linq;
using System.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;

namespace Zesty.Core.Controllers
{
    [ResponseCache(Duration = -1, Location = ResponseCacheLocation.None, NoStore = true)]
    public class SecureController : AnonymousController
    {
        private static readonly NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            base.OnActionExecuting(context);

            string scheme = HttpContext.Request.Scheme;
            string host = HttpContext.Request.Host.Value;
            string path = HttpContext.Request.Path;
            string queryString = HttpContext.Request.QueryString.HasValue ? HttpContext.Request.QueryString.Value : "";

            string url = $"{scheme}://{host}{path}{queryString}";

            logger.Info($"Request: {url}");

            string item = Settings.List("UrlWhitelist").Where(x => x == path).FirstOrDefault();

            if (item != null)
            {
                return;
            }

            Entities.User user = Session.Get<Entities.User>(Keys.SessionUser);

            if (user == null)
            {
                logger.Info($"User is null with session id {Session.Id}");

                Session.Clear();

                if (Settings.GetBool("ThrowsOnAccessDenied"))
                {
                    logger.Warn($"Access denied for resource {path}");

                    Trace.Write(new TraceItem()
                    {
                        Error = Messages.AccessDenied
                    },
                    context.HttpContext);

                    throw new SecurityException(Messages.AccessDenied);
                }
                else
                {
                    logger.Warn($"Access denied for resource {path}");

                    Trace.Write(new TraceItem()
                    {
                        Error = Messages.AccessDenied
                    },
                    context.HttpContext);

                    ErrorMessage = Messages.AccessDenied;

                    Redirect(Settings.Get("RedirectPathOnAccessDenied"));
                }
            }
            else
            {
                bool canAccess = Business.Authorization.CanAccess(path, user);

                logger.Info($"User {user.Username} can access path {path}: {canAccess}");

                if (!canAccess)
                {
                    Session.Clear();

                    if (Settings.GetBool("ThrowsOnAuthorizationFailed"))
                    {
                        logger.Warn($"Access denied for resource {path}");

                        Trace.Write(new TraceItem()
                        {
                            Error = Messages.AuthorizationFailed
                        },
                        context.HttpContext);

                        throw new SecurityException(Messages.AuthorizationFailed);
                    }
                    else
                    {
                        ErrorMessage = Messages.AuthorizationFailed;

                        logger.Warn($"Access denied for resource {path}");

                        Trace.Write(new TraceItem()
                        {
                            Error = Messages.AuthorizationFailed
                        },
                        context.HttpContext);

                        Redirect(Settings.Get("RedirectPathOnAccessDenied"));
                    }
                }
                else
                {
                    Context.Current.User = user;

                    if (Business.Authorization.RequireToken(path))
                    {
                        string tokenValue = CurrentHttpContext.Request.Query["t"];

                        logger.Info($"Token: {tokenValue}");

                        if (!Business.Authorization.IsValid(user.Id, CurrentHttpContext.Session.Id, tokenValue))
                        {
                            if (Settings.GetBool("ThrowsOnAuthorizationFailed"))
                            {
                                logger.Warn($"Access denied for resource {path}");

                                Trace.Write(new TraceItem()
                                {
                                    Error = Messages.AuthorizationFailed
                                },
                                context.HttpContext);

                                throw new SecurityException(Messages.TokenMissing);
                            }
                            else
                            {
                                logger.Warn($"Access denied for resource {path}");

                                Trace.Write(new TraceItem()
                                {
                                    Error = Messages.AuthorizationFailed
                                },
                                context.HttpContext);

                                ErrorMessage = Messages.AuthorizationFailed;

                                Redirect(Settings.Get("RedirectPathOnAccessDenied"));
                            }
                        }
                    }
                }
            }
        }
    }
}
