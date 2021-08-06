using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Controllers
{
    [ResponseCache(Duration = -1, Location = ResponseCacheLocation.None, NoStore = true)]
    public class SecureController : AnonymousController
    {
        private static readonly NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();
        readonly string refreshResource = Settings.Get("RefreshResourceName", "/system.refresh.api");

        public override void OnActionExecuting(ActionExecutingContext context)
        {
            base.OnActionExecuting(context);

            CanAccess(HttpContext.Connection.RemoteIpAddress.ToString());

            string scheme = HttpContext.Request.Scheme;
            string host = HttpContext.Request.Host.Value;
            string path = HttpContext.Request.Path;
            string queryString = HttpContext.Request.QueryString.HasValue ? HttpContext.Request.QueryString.Value : "";
            string method = HttpContext.Request.Method;
            string bearer = HttpContext.Request.Headers["ZestyApiBearer"];

            string url = $"{scheme}://{host}{path}{queryString}";

            logger.Info($"Request: {url}");

            string item = Settings.List("UrlWhitelist").Where(x => x == $"{path};{method}").FirstOrDefault();

            if (item != null)
            {
                if(path.StartsWith("/api"))
                {
                    if (!item.Contains(';'))
                    {
                        throw new SecurityException(Messages.AccessDenied);
                    }

                    if (!method.Equals(item.Split(';')[1]))
                    {
                        throw new SecurityException(Messages.AccessDenied);
                    }
                }

                return;
            }

            Entities.User user = Session.Get<Entities.User>(Keys.SessionUser);

            if (user == null && String.IsNullOrWhiteSpace(bearer))
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
                if(user == null)
                {
                    LoadUser(bearer);

                    user = Context.Current.User;
                }

                bool canAccess = Business.Authorization.CanAccess(path, user, method);

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

                    if (Business.Authorization.RequireToken(path, method))
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

        private void LoadUser(string bearer)
        {
            logger.Info($"Bearer received: {bearer}");

            string secret = Business.User.GetSecret(bearer);

            if (String.IsNullOrWhiteSpace(secret))
            {
                throw new SecurityException("Invalid token");
            }

            var json = JwtBuilder.Create()
       .WithAlgorithm(new HMACSHA256Algorithm())
       .WithSecret(secret)
       .MustVerifySignature()
       .Decode(bearer);

            logger.Debug($"Json from bearer: {json}");

            Bearer b = JsonHelper.Deserialize<Bearer>(json);

            if (b == null || b.User == null)
            {
                return;
            }

            DateTime expiration = DateTimeHelper.GetFromUnixTimestamp(b.Exp);

            if (expiration < DateTime.Now && HttpContext.Request.Path != refreshResource)
            {
                throw new ApiTokenExpiredException("Token expired");
            }

            if (b.User.DomainId != Guid.Empty)
            {
                List<Domain> domains = Business.User.GetDomains(b.User.Username);

                b.User.Domain = domains.Where(x => x.Id == b.User.DomainId).FirstOrDefault();
            }

            Context.Current.User = b.User;
        }

        private void CanAccess(string ipAddress)
        {
            int accessFailureLimit = Settings.GetInt("AccessFailureLimit", 3);

            int accessLimitMinutes = Settings.GetInt("AccessLimitMinutes", 5);

            DateTime start = DateTime.Now.AddMinutes(-accessLimitMinutes);

            if (Business.User.InvalidAccesses(ipAddress, start) >= accessFailureLimit)
            {
                throw new SecurityException(string.Format(Messages.LoginBanned, accessLimitMinutes));
            }
        }
    }
}
