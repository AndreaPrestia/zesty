﻿using System;
using System.Collections.Generic;
using System.Data.Common;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Zesty.Core.Entities.Settings;
using Zesty.Core.Middleware;

namespace Zesty.Core.Common
{
    public static class Extensions
    {
        public static T Get<T>(this DbDataReader reader, string name)
        {
            object o = reader[name];

            if (o == null || o == DBNull.Value)
            {
                return default(T);
            }

            return (T)o;
        }

        public static void Set(this ISession session, Entities.User user)
        {
            session.Set(Keys.SessionUser, user);
        }

        public static void Set<T>(this ISession session, string key, T value)
        {
            session.SetString(key, JsonHelper.Serialize(value));
        }

        public static T Get<T>(this ISession session, string key)
        {
            var value = session.GetString(key);
            return value == null ? default : JsonHelper.Deserialize<T>(value);
        }

        public static void ConfigureZesty(this IApplicationBuilder builder)
        {
            List<string> origins = Settings.List("CorsOrigins");

            builder.UseCors(builder => builder
                .WithOrigins(origins.ToArray())
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials());

            builder.UseSession(new SessionOptions() { Cookie = new CookieBuilder() { Name = ".AspNetCore.Session.MyApp1" } });


            builder.UseCookiePolicy();

            builder.MapWhen(context => context.Request.Path.ToString().EndsWith(".api"), appBranch => {
                appBranch.UseMiddleware<ApiMiddleware>();
            });
        }

        public static void ConfigureZesty(this IServiceCollection services)
        {
            services.AddCors();

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => false;
                options.MinimumSameSitePolicy = SameSiteMode.None;
                options.Secure = CookieSecurePolicy.None;
                options.HttpOnly = HttpOnlyPolicy.None;
            });

            services.AddDistributedMemoryCache();

            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(Settings.GetInt("SessionLifetimeInMinutes"));
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });
        }

        public static string SafeSubstring(this string s, int length)
        {
            return SafeSubstring(s, 0, length);
        }

        public static string SafeSubstring(this string s, int start, int length)
        {
            if (String.IsNullOrWhiteSpace(s))
            {
                return String.Empty;
            }

            if (start > s.Length)
            {
                return String.Empty;
            }

            if (start + length > s.Length)
            {
                length = s.Length - start;
            }

            return s.Substring(start, length);
        }
    }
}
