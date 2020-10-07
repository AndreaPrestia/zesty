﻿using System;
using System.IO;
using System.Security;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Exceptions;

namespace Zesty.Core.Middleware
{
    public class ApiMiddleware
    {
        private static NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        public ApiMiddleware(RequestDelegate next)
        {
        }

        public async Task Invoke(HttpContext context)
        {
            TimeKeeper timeKeeper = new TimeKeeper();

            Context.Current.Reset();

            ISession session = context.Session;

            Context.Current.User = session.Get<Entities.User>(Keys.SessionUser);

            string resourceName = context.Request.Path.Value;
            string body = new StreamReader(context.Request.Body).ReadToEndAsync().Result;

            logger.Info($"Resource: {resourceName}");
            logger.Info($"Body: {body}");
            logger.Info($"Session ID: {session.Id}");
            logger.Info($"HTTP method: {context.Request.Method}");

            ApiInputHandler input = new ApiInputHandler()
            {
                Body = body,
                Context = context,
                Resource = resourceName
            };

            string contentType = null;
            string content = null;
            int statusCode = 200;

            try
            {
                if (context.Request.Method == "OPTIONS")
                {
                    //TODO improve this poor code :D
                    context.Response.Headers.Add("Access-Control-Allow-Credentials", "true");
                    context.Response.Headers.Add("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST,PUT");
                    context.Response.Headers.Add("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers");

                    contentType = "text/plain";
                    content = ":)";
                }
                else
                {
                    HandlerProcessor.Process(Settings.Current.PreExecutionHandler, context);

                    ApiHandlerOutput output = Process(input);

                    HandlerProcessor.Process(Settings.Current.PostExecutionHandler, context);

                    if (output.Type == ApiHandlerOutputType.JSon)
                    {
                        contentType = "application/json";
                        content = JsonHelper.Serialize(output.Output);
                    }
                    else if (output.Type == ApiHandlerOutputType.TextAsJson)
                    {
                        contentType = "application/json";
                        content = output.Output as string;
                    }
                    else if (output.Type == ApiHandlerOutputType.Text)
                    {
                        contentType = "plain/text";
                        content = output.Output as string;
                    }
                    else
                    {
                        throw new Exception(Messages.WrongApiOutput);
                    }
                }
            }
            catch (ApiInvalidArgumentException e)
            {
                logger.Error(e.Message);

                statusCode = 501;
                contentType = "application/json";
                content = JsonHelper.Serialize(new { e.Message });
            }
            catch (ApiNotFoundException e)
            {
                logger.Error(e.Message);

                statusCode = 404;
                contentType = "application/json";
                content = JsonHelper.Serialize(new { e.Message });
            }
            catch (ApiAccessDeniedException e)
            {
                logger.Error(e.Message);

                statusCode = 403;
                contentType = "application/json";
                content = JsonHelper.Serialize(new { e.Message });
            }
            catch (CustomJsonException e)
            {
                logger.Error(e.Message);

                statusCode = 502; // TODO check this code
                contentType = "application/json";
                content = JsonHelper.Serialize(new { e.Message });
            }
            catch (SecurityException e)
            {
                logger.Error(e.Message);

                statusCode = 403; // TODO check this code
                contentType = "application/json";
                content = JsonHelper.Serialize(new { e.Message });
            }
            catch (Exception e)
            {
                logger.Error(e.Message);

                statusCode = 500;
                contentType = "application/json";
                content = JsonHelper.Serialize(new { e.Message });
            }
            finally
            {
                logger.Info($"ContentType: {contentType}");
                logger.Info($"Content: {content}");

                context.Response.Headers.Add("Access-Control-Allow-Origin", "*");

                context.Response.ContentType = contentType;
                context.Response.StatusCode = statusCode;
                context.Session = session;
                await context.Response.WriteAsync(content);

                logger.Info($"Request completed");
            }
        }

        private ApiHandlerOutput Process(ApiInputHandler input)
        {
            bool canAccess = Business.Authorization.CanAccess(input.Resource, Context.Current.User);

            if (!canAccess)
            {
                logger.Warn($"Access denied for resource {input.Resource}");

                throw new SecurityException(Messages.AccessDenied);
            }

            if (Business.Authorization.RequireToken(input.Resource))
            {
                if (!Business.Authorization.IsValid(Context.Current.User.Id, input.Context.Session.Id, input.Context.Request.Query["t"]))
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
                string typeName = Business.Resource.GetType(input.Resource);

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