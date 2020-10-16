﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Configuration;

namespace Zesty.Core.Entities.Settings
{
    public class Settings
    {
        private static NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        private static object Lock = new object();
        private static List<SettingValue> values = null;

        static Settings()
        {
            IConfigurationBuilder builder = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json");
            IConfigurationRoot config = builder.Build();

            Current = config.GetSection("Zesty").Get<Settings>();

            logger.Info(Messages.SettingsLoaded);
        }

        public static Settings Current { get; set; }

        public string StorageImplementationType { get; set; }
        public string StorageSource { get; set; }

        private static void Load()
        {
            //TODO add cache

            if (values == null)
            {
                lock (Lock)
                {
                    if (values == null)
                    {
                        values = StorageManager.Instance.GetSettingsValues();
                    }
                }
            }
        }

        private static string PrivateGet(string key, bool required = true)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ApplicationException(Messages.KeyNotFound);
            }

            Load();

            SettingValue settingValue = values.Where(x => x.Key == key).FirstOrDefault();

            if (settingValue == null)
            {
                if (required)
                {
                    throw new ApplicationException(String.Format(Messages.SettingNotFound, key));
                }

                return null;
            }

            return settingValue.Value;
        }

        private static List<string> PrivateGetList(string key, bool required = true)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ApplicationException(Messages.KeyNotFound);
            }

            Load();

            List<SettingValue> settingValues = values.Where(x => x.Key == key).ToList();

            if (settingValues == null || settingValues.Count == 0)
            {
                if (required)
                {
                    throw new ApplicationException(String.Format(Messages.SettingNotFound, key));
                }

                return null;
            }

            return (from c in settingValues
                    orderby c.Order
                    select c.Value).Distinct().ToList();
        }

        public static string Get(string key, bool required = true)
        {
            return PrivateGet(key, required);
        }

        public static List<string> List(string key, bool required = true)
        {
            return PrivateGetList(key, required);
        }

        public static bool GetBool(string key)
        {
            return bool.Parse(PrivateGet(key, true));
        }

        public static int GetInt(string key)
        {
            return int.Parse(PrivateGet(key, true));
        }

        public static int GetInt(string key, int defaultValue)
        {
            string s = Get(key, false);

            if (string.IsNullOrWhiteSpace(s))
            {
                return defaultValue;
            }

            return int.Parse(s);
        }

        public static string Get(string key, string defaultValue)
        {
            string s = Get(key, false);

            if (string.IsNullOrWhiteSpace(s))
            {
                return defaultValue;
            }

            return s;
        }
    }
}
