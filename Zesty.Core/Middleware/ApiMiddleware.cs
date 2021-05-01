using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Threading.Tasks;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.AspNetCore.Http;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Middleware
{
    public class ApiMiddleware
    {
        private static readonly NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();
        readonly bool propagateApplicationErrorInFault = Settings.GetBool("PropagateApplicationErrorInFault", false);
        readonly string refreshResource = Settings.Get("RefreshResourceName", "/system.refresh.api");

        public ApiMiddleware(RequestDelegate next)
        {
        }

        public async Task Invoke(HttpContext context)
        {
            TimeKeeper timeKeeper = new TimeKeeper();

            string contentType = null;
            string content = null;
            int statusCode = 200;

            try
            {
                CanAccess(context.Request.HttpContext.Connection.RemoteIpAddress.ToString());

                LoadUser(context);

                string resourceName = context.Request.Path.Value;
                string body = new StreamReader(context.Request.Body).ReadToEndAsync().Result;

                logger.Info($"User: {Context.Current.User?.Username}");
                logger.Info($"Resource: {resourceName}");
                logger.Debug($"Body: {body}");
                logger.Info($"Session ID: {context.Session.Id}");
                logger.Info($"HTTP method: {context.Request.Method}");

                ApiInputHandler input = new ApiInputHandler()
                {
                    Body = body,
                    Context = context,
                    Resource = resourceName
                };

                if (context.Request.Method == "OPTIONS")
                {
                    //TODO improve this poor code :D
                    contentType = ContentType.TextPlain;
                    content = ":)";
                }
                else
                {
                    HandlerProcessor.Process(Settings.List("PreExecutionHandler"), context);

                    ApiHandlerOutput output = Process(input);

                    HandlerProcessor.Process(Settings.List("PostExecutionHandler"), context);

                    if (output.Type == ApiHandlerOutputType.JSon)
                    {
                        contentType = ContentType.ApplicationJson;
                        content = JsonHelper.Serialize(output.Output);
                    }
                    else if (output.Type == ApiHandlerOutputType.TextAsJson)
                    {
                        contentType = ContentType.ApplicationJson;
                        content = output.Output as string;
                    }
                    else if (output.Type == ApiHandlerOutputType.Text)
                    {
                        contentType = ContentType.TextPlain;
                        content = output.Output as string;
                    }
                    else
                    {
                        throw new Exception(Messages.WrongApiOutput);
                    }
                }
            }

            #region catches

            catch (ApiInvalidArgumentException e)
            {
                logger.Error(e);

                statusCode = 501;
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);
            }
            catch (ApiNotFoundException e)
            {
                logger.Error(e);

                statusCode = 404;
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);
            }
            catch (ApiTokenExpiredException e)
            {
                logger.Error(e);

                statusCode = 401;
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);

                if (context != null)
                {
                    Business.User.AddAccessFailure(context.Request.HttpContext.Connection.RemoteIpAddress.ToString());
                }
            }
            catch (ApiAccessDeniedException e)
            {
                logger.Error(e);

                statusCode = 401;
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);

                if (context != null)
                {
                    Business.User.AddAccessFailure(context.Request.HttpContext.Connection.RemoteIpAddress.ToString());
                }
            }
            catch (MissingRequiredProperty e)
            {
                logger.Error(e);

                statusCode = 400;
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);
            }
            catch (CustomJsonException e)
            {
                logger.Error(e);

                statusCode = 502; // TODO check this code
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);
            }
            catch (SecurityException e)
            {
                logger.Error(e);

                statusCode = 403; // TODO check this code
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);

                if(context != null)
                {
                    Business.User.AddAccessFailure(context.Request.HttpContext.Connection.RemoteIpAddress.ToString());
                }
            }
            catch (Exception e)
            {
                logger.Error(e);

                statusCode = 500;
                contentType = ContentType.ApplicationJson;
                string message = propagateApplicationErrorInFault ? e.Message : Messages.GenericFailure;
                content = JsonHelper.Serialize(new { Message = message });

                Trace.Write(new TraceItem() { Error = e.Message, Millis = timeKeeper.Stop().TotalMilliseconds }, context);
            }

            #endregion

            finally
            {
                logger.Debug($"ContentType: {contentType}");
                logger.Debug($"Content: {content}");
                logger.Info($"statusCode: {statusCode}");

                context.Response.ContentType = contentType;
                context.Response.StatusCode = statusCode;

                await context.Response.WriteAsync(content);

                double ms = timeKeeper.Stop().TotalMilliseconds;

                Trace.Write(new TraceItem() { Millis = ms }, context);

                logger.Info($"Request completed in {ms} ms");
            }
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

        private void LoadUser(HttpContext context)
        {
            Context.Current.Reset();

            Context.Current.User = context.Session.Get<Entities.User>(Keys.SessionUser);

            if (Context.Current.User != null)
            {
                return;
            }

            string bearer = context.Request.Headers["ZestyApiBearer"];

            if (String.IsNullOrWhiteSpace(bearer))
            {
                return;
            }

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

            if (expiration < DateTime.Now && context.Request.Path != refreshResource)
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

        private ApiHandlerOutput Process(ApiInputHandler input)
        {
            string typeName = Business.Resource.GetType(input.Resource);

            if (string.IsNullOrWhiteSpace(typeName))
            {
                throw new ApiNotFoundException(input.Resource);
            }

            bool canAccess = Business.Authorization.CanAccess(input.Resource, Context.Current.User);

            if (!canAccess)
            {
                logger.Warn($"Access denied for resource {input.Resource}");

                throw new SecurityException(Messages.AccessDenied);
            }

            if (Business.Authorization.RequireToken(input.Resource))
            {
                string token = input.Context.Request.Headers["ZestyApiToken"];

                if (string.IsNullOrWhiteSpace(token))
                {
                    token = input.Context.Request.Query["t"];
                }

                if (!Business.Authorization.IsValid(Context.Current.User.Id, input.Context.Session.Id, token))
                {
                    logger.Warn($"Invalid token for resource {input.Resource}");

                    throw new SecurityException(Messages.TokenMissing);
                }
            }

            ApiCacheItem cacheItem = ApiCache.Get(input);

            if (cacheItem != null)
            {
                logger.Info($"Output found in cache for request {input.Resource}");

                return cacheItem.Output;
            }
            else
            {
                ApiHandlerBase handler = InstanceHelper.Create<ApiHandlerBase>(typeName);

                ApiHandlerOutput output = handler.Process(input);

                if (output.CachePolicy == ApiCachePolicy.Enable)
                {
                    cacheItem = new ApiCacheItem
                    {
                        Created = DateTime.Now,
                        Output = output,
                        Payload = input.Body,
                        Resource = input.Resource
                    };

                    ApiCache.Store(cacheItem);

                    logger.Info($"Output stored in cache for request {input.Resource}");
                }


                if (output.ResourceHistoryOutput != null && output.ResourceHistoryOutput.ResourceHistoryPolicy == ApiResourceHistoryPolicy.Save)
                {
                    Business.History.Save(output.ResourceHistoryOutput.Item);
                }

                return output;
            }
        }
    }
}