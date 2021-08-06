using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;

namespace Zesty.Core.Controllers
{
    [Produces("application/json")]
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : SecureController
    {
        #region Domain
        /// <summary>
        /// Create a domain on the system
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(typeof(AddDomainResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("Domain")]
        public IActionResult Domain(AddDomainRequest request)
        {
            ValidateEntity<AddDomainRequest>(request);

            Entities.Domain domain = new Entities.Domain()
            {
                Id = Guid.NewGuid(),
                Name = request.Name,
                ParentDomainId = String.IsNullOrWhiteSpace(request.Parent) ? Guid.Empty : Guid.Parse(request.Parent)
            };

            Business.Domain.Add(domain);

            return GetOutput(new AddDomainResponse()
            {
                Domain = domain
            }, 201);
        }

        /// <summary>
        /// List of all domains on the system 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(DomainsResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet("Domains")]
        public IActionResult Domains()
        {
            return GetOutput(new DomainsResponse()
            {
                Domains = Business.Domain.List()
            });
        }
        #endregion

        #region Role
        /// <summary>
        /// Add a role on the system
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(typeof(AddRoleResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("Role")]
        public IActionResult Role(AddRoleRequest request)
        {
            ValidateEntity<AddRoleRequest>(request);

            Entities.Role role = new Entities.Role()
            {
                Id = Guid.NewGuid(),
                Name = request.Name
            };

            Business.Role.Add(role);

            return GetOutput(new AddRoleResponse()
            {
                Role = role
            });
        }

        /// <summary>
        /// Role list on the system
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(RolesResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet("Roles")]
        public IActionResult Roles()
        {
            return GetOutput(new RolesResponse()
            {
                Roles = Business.Role.List()
            });
        }
        #endregion

        #region Resource
        /// <summary>
        /// Add a resource (ZestyAPI, .NET Core API/Action, everything that can be an url :) ) on the system
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("Resource")]
        public IActionResult Resource(ResourceAddRequest request)
        {
            ValidateEntity<ResourceAddRequest>(request);

            Guid domainId = Guid.Parse(request.Domain);

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Resource_Add", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@url", Value = request.Url.Trim() });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@ParentId", Value = !string.IsNullOrEmpty(request.ParentId) ? Guid.Parse(request.ParentId) : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@isPublic", Value = request.IsPublic ? 1 : 0 });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@requireToken", Value = request.RequireToken ? 1 : 0 });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@order", Value = request.Order });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@label", Value = !string.IsNullOrEmpty(request.Label) ? request.Label.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@title", Value = !string.IsNullOrEmpty(request.Title) ? request.Title.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@image", Value = !string.IsNullOrEmpty(request.Image) ? request.Image.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@type", Value = !string.IsNullOrEmpty(request.Type) ? request.Type.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domain", Value = domainId });

                    command.ExecuteNonQuery();
                }
            }

            return GetOutput();
        }

        /// <summary>
        /// Returns all resources on the system 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(ResourcesAllResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet("Resource/All")]
        public IActionResult ResourceAll()
        {
            return GetOutput(new ResourcesAllResponse() { Resources = Business.Resource.ResourceAll() });
        }

        /// <summary>
        /// Authorize a resource on a role
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("Resource/Authorize")]
        public IActionResult ResourceAuthorize(ResourceAuthorizeRequest request)
        {
            ValidateEntity(request);

            Business.Resource.Authorize(Guid.Parse(request.Resource), Guid.Parse(request.Role));

            return GetOutput(204);
        }

        /// <summary>
        /// Deauthorize a resource on a role
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("Resource/Deauthorize")]
        public IActionResult ResourceDeauthorize(ResourceAuthorizeRequest request)
        {
            ValidateEntity(request);

            Business.Resource.Deauthorize(Guid.Parse(request.Resource), Guid.Parse(request.Role));

            return GetOutput(204);
        }

        /// <summary>
        /// Deletes a resource. It can be dangerous, use it with safe :) 
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpDelete("Resource")]
        public IActionResult ResourceDelete(Guid id)
        {
            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Resource_Delete", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@resourceId", Value = id });

                    command.ExecuteNonQuery();
                }
            }

            return GetOutput(204);
        }

        /// <summary>
        /// List of resources for a role 
        /// </summary>
        /// <returns></returns>
        ///<param name="roleId"></param>
        [ProducesResponseType(typeof(ResourcesGrantsResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet("Resource/Grants")]
        public IActionResult ResourceGrants(Guid roleId)
        {
            return GetOutput(new ResourcesGrantsResponse()
            {
                Resources = Business.Resource.ResourceList(roleId)
            });
        }

        /// <summary>
        /// Resource list 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(ResourceListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet("Resources")]
        public IActionResult ResourceList()
        {
            return GetOutput(new ResourceListResponse() { Resources = Business.Resource.ResourceList() });
        }

        /// <summary>
        /// Update the resources
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPatch("Resource")]
        public IActionResult ResourceUpdate(ResourceUpdateRequest request)
        {
            ValidateEntity(request);

            Guid resourceId = Guid.Parse(request.Id);

            Guid domainId = Guid.Parse(request.Domain);

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Resource_Update", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@resourceId", Value = resourceId });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@url", Value = request.Url.Trim() });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@ParentId", Value = !string.IsNullOrEmpty(request.ParentId) ? Guid.Parse(request.ParentId) : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@isPublic", Value = request.IsPublic ? 1 : 0 });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@requireToken", Value = request.RequireToken ? 1 : 0 });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@order", Value = request.Order });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@label", Value = !string.IsNullOrEmpty(request.Label) ? request.Label.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@title", Value = !string.IsNullOrEmpty(request.Title) ? request.Title.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@image", Value = !string.IsNullOrEmpty(request.Image) ? request.Image.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@type", Value = !string.IsNullOrEmpty(request.Type) ? request.Type.Trim() : (Object)DBNull.Value });
                    command.Parameters.Add(new SqlParameter() { ParameterName = "@domain", Value = domainId });

                    command.ExecuteNonQuery();
                }
            }

            return GetOutput(204);
        }
        #endregion

        #region User
        /// <summary>
        /// Add a user to the system
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("User")]
        public IActionResult UserAdd(AddUserRequest request)
        {
            ValidateEntity<AddUserRequest>(request);

            Entities.User user = new Entities.User()
            {
                Username = request.Username,
                Email = request.Email,
                Firstname = request.Firstname,
                Lastname = request.Lastname
            };

            Guid id = Business.User.Add(user);

            List<Translation> translations = Business.Languages.GetTranslations("en");

            string subject = translations.Where(x => x.Original == "User created").FirstOrDefault().Translated;
            string body = translations.Where(x => x.Original == "Go to the portal and reset your password to grant access").FirstOrDefault().Translated;

            Common.SmtpClient.Send(request.Email, subject, body);

            return GetOutput();
        }

        /// <summary>
        /// Add an authorization for a User on a Domain for a Role
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("User/Authorize")]
        public IActionResult UserAuthorize(UserAuthorizeRequest request)
        {
            ValidateEntity<UserAuthorizeRequest>(request);

            Business.User.Authorize(
                 new Entities.User()
                 {
                     Id = Guid.Parse(request.User)
                 },
                 new Entities.Authorization()
                 {
                     Domain = new Entities.Domain()
                     {
                         Id = Guid.Parse(request.Domain)
                     },
                     Role = new Entities.Role()
                     {
                         Id = Guid.Parse(request.Role)
                     }
                 });

            return GetOutput();
        }

        /// <summary>
        /// Remove an authorization for a User on a Domain for a Role
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost("User/Deauthorize")]
        public IActionResult UserDeauthorize(UserAuthorizeRequest request)
        {
            ValidateEntity<UserAuthorizeRequest>(request);

            Business.User.Deauthorize(
                new Entities.User()
                {
                    Id = Guid.Parse(request.User)
                },
                new Entities.Authorization()
                {
                    Domain = new Entities.Domain()
                    {
                        Id = Guid.Parse(request.Domain)
                    },
                    Role = new Entities.Role()
                    {
                        Id = Guid.Parse(request.Role)
                    }
                });

            return GetOutput();
        }

        /// <summary>
        /// Logical delete of a user from the system
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpDelete("User")]
        public IActionResult UserDelete(Guid id)
        {
            RequireUser();

            if (Context.Current.User.Id == id)
            {
                ThrowApplicationError("Cannot delete current user");
            }

            Business.User.Delete(id);

            return GetOutput(204);
        }

        /// <summary>
        /// Get a user by id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [ProducesResponseType(typeof(UserGetResponse), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet("User")]
        public IActionResult UserGet(Guid id)
        {
            Entities.User user = Business.User.Get(id);

            if (user == null)
            {
                ThrowNotFound(id.ToString());
            }

            return GetOutput(new UserGetResponse()
            {
                User = user
            });
        }

        /// <summary>
        /// Physical delete a user from the system
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpDelete("User/HardDelete")]
        public IActionResult UserHardDelete(Guid id)
        {
            RequireUser();

            if (Context.Current.User.Id == id)
            {
                ThrowApplicationError("Cannot delete current user");
            }

            Business.User.HardDelete(id);

            return GetOutput(204);
        }

        /// <summary>
        /// User list from the system. Can be time consuming, we should paginate it :)
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [ProducesResponseType(typeof(UserListResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet("Users")]
        public IActionResult UserList()
        {
            return GetOutput(new UserListResponse()
            {
                Users = Business.User.List()
            });
        }

        /// <summary>
        /// Updates specific user
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPatch("User")]
        public IActionResult UserUpdate(UserUpdateRequest request)
        {
            ValidateEntity(request);

            Entities.User user = new Entities.User()
            {
                Id = Guid.Parse(request.Id),
                Username = request.Username,
                Email = request.Email,
                Firstname = request.Firstname,
                Lastname = request.Lastname
            };

            Business.User.Update(user);

            return GetOutput(204);
        }
        #endregion
    }
}
