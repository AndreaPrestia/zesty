using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;

namespace Zesty.Core.Storage
{
    public class SqlServer : IStorage
    {
        private static NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        public void AuthorizeResource(Guid resourceId, Guid roleId)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ResourceAuthorize", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@resource", Value = resourceId });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@role", Value = roleId });

                    command.ExecuteNonQuery();
                }
            }
        }

        public void DeauthorizeResource(Guid resourceId, Guid roleId)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ResourceDeauthorize", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@resource", Value = resourceId });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@role", Value = roleId });

                    command.ExecuteNonQuery();
                }
            }
        }

        public List<Entities.Resource> GetResources(Guid roleId)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ResourceListGrant", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@role", Value = roleId });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        List<Entities.Resource> list = new List<Resource>();

                        while (reader.Read())
                        {
                            Entities.Resource resource = new Resource();

                            resource.Id = reader.Get<Guid>("Id");

                            list.Add(resource);
                        }

                        return list;
                    }
                }
            }
        }

        public List<Entities.Resource> GetResources()
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ResourceList", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        List<Entities.Resource> list = new List<Resource>();

                        while (reader.Read())
                        {
                            Entities.Resource resource = new Resource();

                            resource.Id = reader.Get<Guid>("Id");
                            resource.ParentId = reader.Get<Guid>("ParentId");
                            resource.IsPublic = reader.Get<bool>("IsPublic");
                            resource.RequireToken = reader.Get<bool>("RequireToken");
                            resource.Order = reader.Get<int>("Order");
                            resource.Url = reader.Get<string>("Url");
                            resource.Label = reader.Get<string>("Label");
                            resource.Image = reader.Get<string>("Image");
                            resource.Title = reader.Get<string>("Title");

                            list.Add(resource);
                        }

                        return list;
                    }
                }
            }
        }

        public List<Entities.Resource> GetAllResources()
        {
            List<Entities.Resource> list = new List<Resource>();

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Resource_List", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Entities.Resource resource = new Entities.Resource();

                            resource.Id = reader.Get<Guid>("Id");
                            resource.ParentId = reader.Get<Guid>("ParentId");
                            resource.Image = reader.Get<string>("Image");
                            resource.Label = reader.Get<string>("Label");
                            resource.Title = reader.Get<string>("Title");
                            resource.Url = reader.Get<string>("Url");
                            resource.IsPublic = reader.Get<bool>("IsPublic");
                            resource.RequireToken = reader.Get<bool>("RequireToken");
                            resource.Type = reader.Get<string>("Type");

                            resource.Domain = new Entities.Domain();

                            resource.Domain.Id = reader.Get<Guid>("DomainId");
                            resource.Domain.Name = reader.Get<string>("Domain");

                            list.Add(resource);
                        }

                        return list;
                    }
                }
            }
        }

        public void Add(Entities.Role role)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Role_Add", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@id", Value = role.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@name", Value = role.Name });

                    command.ExecuteNonQuery();
                }
            }
        }

        public void Add(Entities.Domain domain)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Domain_Add", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@id", Value = domain.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@name", Value = domain.Name });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@parent", Value = domain.ParentDomainId == Guid.Empty ? DBNull.Value : (Object)domain.ParentDomainId});

                    command.ExecuteNonQuery();
                }
            }
        }

        public List<Entities.Role> GetRoles()
        {
            List<Entities.Role> list = new List<Entities.Role>();

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Role_List", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Entities.Role role = new Entities.Role();

                            role.Id = reader.Get<Guid>("Id");
                            role.Name = reader.Get<string>("Name");

                            list.Add(role);
                        }

                        return list;
                    }
                }
            }
        }

        public void Remove(User user, Authorization authorization)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand(@"Zesty_User_Deauthorize", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@user", Value = user.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domain", Value = authorization.Domain.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@role", Value = authorization.Role.Id });

                    command.ExecuteNonQuery();
                }
            }
        }

        public void Add(User user, Authorization authorization)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand(@"Zesty_User_Authorize", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@user", Value = user.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domain", Value = authorization.Domain.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@role", Value = authorization.Role.Id });

                    command.ExecuteNonQuery();
                }
            }
        }

        public void Update(Entities.User user)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand(@"Zesty_User_Update", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = user.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = user.Username });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@email", Value = user.Email });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@firstname", Value = user.Firstname });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@lastname", Value = user.Lastname });

                    command.ExecuteNonQuery();
                }
            }
        }

        public Entities.User GetUser(string user)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_Get", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@user", Value = user });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        Entities.User u = null;

                        if (reader.Read())
                        {
                            u = new User();

                            u.Id = reader.Get<Guid>("Id");
                            u.Username = reader.Get<string>("Username");
                            u.Email = reader.Get<string>("Email");
                            u.Firstname = reader.Get<string>("Firstname");
                            u.Lastname = reader.Get<string>("Lastname");
                            u.Deleted = DateTimeHelper.GetUnixTimestamp(reader.Get<DateTime>("Deleted"));
                            u.Created = DateTimeHelper.GetUnixTimestamp(reader.Get<DateTime>("Created"));
                        }

                        return u;
                    }
                }
            }

        }

        public List<Entities.User> Users()
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_List", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        List<Entities.User> users = new List<User>();

                        while (reader.Read())
                        {
                            Entities.User user = new User();

                            user.Id = reader.Get<Guid>("Id");
                            user.Username = reader.Get<string>("Username");
                            user.Email = reader.Get<string>("Email");
                            user.Firstname = reader.Get<string>("Firstname");
                            user.Lastname = reader.Get<string>("Lastname");
                            user.Deleted = DateTimeHelper.GetUnixTimestamp(reader.Get<DateTime>("Deleted"));
                            user.Created = DateTimeHelper.GetUnixTimestamp(reader.Get<DateTime>("Created"));

                            users.Add(user);
                        }

                        return users;
                    }
                }
            }
        }

        public void HardDeleteUser(Guid userId)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_HardDelete", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = userId });

                    command.ExecuteNonQuery();
                }
            }
        }

        public void DeleteUser(Guid userId)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_Delete", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = userId });

                    command.ExecuteNonQuery();
                }
            }
        }

        public Guid Add(Entities.User user)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_AlreadyExists", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = user.Username });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@email", Value = user.Email });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            throw new ApplicationException(Messages.UserCannotCreateBecauseAlreadyExists);
                        }
                    }
                }

                Guid id = Guid.NewGuid();

                using (SqlCommand command = new SqlCommand(@"Zesty_User_Add", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@id", Value = id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = user.Username });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@email", Value = user.Email });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@firstname", Value = user.Firstname });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@lastname", Value = user.Lastname });

                    command.ExecuteNonQuery();
                }

                return id;
            }
        }

        public void ChangePassword(Guid id, string oldPassword, string password)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ChangePassword", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@previousPassword", Value = HashHelper.GetSha256(oldPassword) });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@newPassword", Value = HashHelper.GetSha256(password) });

                    command.ExecuteNonQuery();
                }
            }
        }

        public List<SettingValue> GetSettingsValues()
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ServerSetting_List", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        List<SettingValue> values = new List<SettingValue>();

                        while (reader.Read())
                        {
                            SettingValue settingValue = new SettingValue();

                            settingValue.Key = reader.Get<string>("Key");
                            settingValue.Value = reader.Get<string>("Value");
                            settingValue.Order = reader.Get<int>("Order");

                            values.Add(settingValue);
                        }

                        return values;
                    }
                }
            }

        }

        public void SetProperty(string name, string value, Entities.User user)
        {
            string statement = "Zesty_UserProperty_Set";

            if (String.IsNullOrWhiteSpace(value))
            {
                statement = "Zesty_UserProperty_Delete";
            }

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand(statement, connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = user.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@propertyName", Value = name });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@propertyValue", Value = value });

                    command.ExecuteNonQuery();
                }
            }
        }

        public Dictionary<string, string> GetClientSettings()
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ClientSetting_List", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        Dictionary<string, string> pairs = new Dictionary<string, string>();

                        while (reader.Read())
                        {
                            string k = reader.Get<string>("Key");
                            string v = reader.Get<string>("Value");

                            pairs.Add(k, v);
                        }

                        return pairs;
                    }
                }
            }
        }

        public Guid SetResetToken(string email)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_Update_ResetToken", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@email", Value = email });

                    return (Guid)command.ExecuteScalar();
                }
            }
        }

        public bool ResetPassword(Guid resetToken, string password)
        {
            string hash = HashHelper.GetSha256(password);

#if DEBUG
            logger.Info($"Password \"{password}\" become \"{hash}\"");
#endif

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ResetPassword", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@token", Value = resetToken.ToString() });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@password", Value = hash });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string status = reader.Get<string>("Status");

                            return status == "OK" ? true : false;
                        }

                        return false;
                    }
                }
            }
        }

        public User GetUserByResetToken(Guid resetToken)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_Get_ByResetToken", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@token", Value = resetToken.ToString() });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        User user = null;

                        if (reader.Read())
                        {
                            user = new User();

                            user.Id = reader.Get<Guid>("Id");
                            user.Username = reader.Get<string>("Username");
                            user.Email = reader.Get<string>("Email");
                            user.Firstname = reader.Get<string>("Firstname");
                            user.Lastname = reader.Get<string>("Lastname");
                        }

                        return user;
                    }
                }
            }
        }

        public List<Translation> GetTranslations(string language)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Translation_List_ByLanguage", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@language", Value = language });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        List<Translation> list = new List<Translation>();

                        while (reader.Read())
                        {
                            Translation translation = new Translation();

                            translation.Original = reader.Get<string>("Original");
                            translation.Translated = reader.Get<string>("Translated");

                            list.Add(translation);
                        }

                        return list;
                    }
                }
            }

        }

        public List<Language> GetLanguages()
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Language_List", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        List<Language> list = new List<Language>();

                        while (reader.Read())
                        {
                            Language language = new Language();

                            language.Id = reader.Get<int>("Id");
                            language.Name = reader.Get<string>("Name");
                            language.Description = reader.Get<string>("Description");
                            language.LeftToRight = reader.Get<string>("Direction") == "R" ? true : false;

                            list.Add(language);
                        }

                        return list;
                    }
                }
            }
        }

        public List<Resource> GetResources(string username, Guid domainId)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Resource_List_ByUsernameDomain", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = username });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domainId", Value = domainId });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        List<Resource> list = new List<Resource>();

                        while (reader.Read())
                        {
                            Resource resource = new Resource();

                            resource.Id = reader.Get<Guid>("Id");
                            resource.ParentId = reader.Get<Guid>("ParentId");
                            resource.Image = reader.Get<string>("Image");
                            resource.Label = reader.Get<string>("Label");
                            resource.Title = reader.Get<string>("Title");
                            resource.Url = reader.Get<string>("Url");
                            resource.IsPublic = reader.Get<bool>("IsPublic");
                            resource.RequireToken = reader.Get<bool>("RequireToken");

                            list.Add(resource);
                        }

                        return list;
                    }
                }
            }
        }

        public bool ChangePassword(string username, string currentPassword, string newPassword)
        {
            Guid userid = Guid.Empty;

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_Get_ByUsername", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = username });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            userid = reader.Get<Guid>("Id");
                        }
                        else
                        {
                            throw new ApplicationException(Messages.UserNotFound);
                        }
                    }
                }
            }

            ChangePassword(userid, currentPassword, newPassword);

            return true;
        }

        public List<Domain> GetDomainsList()
        {
            List<Domain> all = new List<Domain>();

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Domain_List", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Domain domain = new Domain();

                            domain.Name = reader.Get<string>("Name");
                            domain.Id = reader.Get<Guid>("Id");
                            domain.ParentDomainId = reader.Get<Guid>("ParentDomainId");

                            all.Add(domain);
                        }
                    }
                }
            }

            return all;
        }

        public List<Domain> GetDomains(string username)
        {
            List<Domain> all = new List<Domain>();
            List<Domain> list = new List<Domain>();

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Domain_List_ByUsername", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = username });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Domain domain = new Domain();

                            domain.Name = reader.Get<string>("Name");
                            domain.Id = reader.Get<Guid>("Id");
                            domain.ParentDomainId = reader.Get<Guid>("ParentDomainId");

                            list.Add(domain);
                        }
                    }
                }

                using (SqlCommand command = new SqlCommand("Zesty_Domain_List", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Domain domain = new Domain();

                            domain.Name = reader.Get<string>("Name");
                            domain.Id = reader.Get<Guid>("Id");
                            domain.ParentDomainId = reader.Get<Guid>("ParentDomainId");

                            all.Add(domain);
                        }
                    }
                }

                foreach (Domain domain in list)
                {
                    Populate(domain, all);
                }
            }

            return list;
        }

        private static void Populate(Domain domain, List<Domain> domains)
        {
            if (domain == null)
            {
                return;
            }

            domain.Childs = domains.Where(x => x.ParentDomainId == domain.Id).ToList();

            foreach (Domain child in domain.Childs)
            {
                Populate(child, domains);
            }
        }

        public List<Entities.Role> GetRoles(string username, Guid domainId)
        {
            List<Entities.Role> list = new List<Entities.Role>();

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Role_List_ByUsernameDomain", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = username });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domain", Value = domainId });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            Entities.Role role = new Entities.Role();

                            role.Id = reader.Get<Guid>("Id");
                            role.Name = reader.Get<string>("Name");

                            list.Add(role);
                        }

                        return list;
                    }
                }
            }
        }

        public bool CanAccess(string path, User user)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_CanAccess", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@path", Value = path });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = user.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domainid", Value = user.Domain != null ? user.Domain.Id : (object)DBNull.Value  });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        return reader.HasRows;
                    }
                }
            }
        }

        public string GetType(string resourceName)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_ResourceType_List_ByResourceName", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@resourceName", Value = resourceName });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return reader.Get<string>("Type");
                        }

                        return null;
                    }
                }
            }
        }

        public bool IsPublicResource(string path)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Resource_IsPublic", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@path", Value = path });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string s = reader.Get<string>("IsPublic");

                            return s == "Y" ? true : false;
                        }

                        return false;
                    }
                }
            }
        }

        public bool IsValid(Guid userId, string sessionId, string tokenValue)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_IsValid", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = userId });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@sessionid", Value = sessionId });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@token", Value = tokenValue });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string s = reader.Get<string>("IsValid");

                            return s == "Y" ? true : false;
                        }

                        return false;
                    }
                }
            }
        }

        public Dictionary<string, string> LoadProperties(User user)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_UserProperty_List_ByUserid", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = user.Id });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        Dictionary<string, string> props = new Dictionary<string, string>();

                        while (reader.Read())
                        {
                            string k = reader.Get<string>("Key");
                            string v = reader.Get<string>("Value");

                            props.Add(k, v);
                        }

                        return props;
                    }
                }
            }
        }

        public User Login(string username, string password)
        {
            string hash = HashHelper.GetSha256(password);

#if DEBUG
            logger.Info($"Password \"{password}\" become \"{hash}\"");
#endif

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Login", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@username", Value = username });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@password", Value = hash });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        User user = null;

                        if (reader.Read())
                        {
                            user = new User();

                            user.Id = reader.Get<Guid>("Id");
                            user.Username = reader.Get<string>("Username");
                            user.Email = reader.Get<string>("Email");
                            user.Firstname = reader.Get<string>("Firstname");
                            user.Lastname = reader.Get<string>("Lastname");
                            user.PasswordChanged = DateTimeHelper.GetUnixTimestamp(reader.Get<DateTime>("Created"));
                        }

                        return user;
                    }
                }
            }
        }

        public bool RequireToken(string path)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_RequireToken", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@path", Value = path });

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string s = reader.Get<string>("IsRequired");

                            return s == "Y" ? true : false;
                        }

                        return false;
                    }
                }
            }
        }

        public void Save(HistoryItem resource)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_History_Add", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = resource.User == null ? Guid.Empty : resource.User.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@resource", Value = resource.Resource });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@actor", Value = resource.Actor });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@text", Value = resource.Text });

                    command.ExecuteNonQuery();
                }
            }
        }

        public void SaveToken(User user, string sessionId, string tokenValue, bool reusable)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Token_Add", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = user.Id });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@sessionid", Value = sessionId });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@value", Value = tokenValue });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@reusable", Value = reusable });

                    command.ExecuteNonQuery();
                }
            }
        }

        public string GetSecret(string bearer)
        {
            string b = HashHelper.GetSha256(bearer);

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Bearer_GetSecret", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@bearer", Value = b });

                    return command.ExecuteScalar() as string;
                }
            }
        }

        public void SaveBearer(Guid userid, string bearer)
        {
            string b = HashHelper.GetSha256(bearer);

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Bearer_Add", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = userid });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@bearer", Value = b });

                    command.ExecuteNonQuery();
                }
            }
        }

        public void SetDomain(Guid userid, Guid domainid)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_User_Domain", connection))
                {
                    command.CommandType = System.Data.CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@userid", Value = userid });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domainid", Value = domainid });

                    command.ExecuteNonQuery();
                }
            }
        }
    }
}
