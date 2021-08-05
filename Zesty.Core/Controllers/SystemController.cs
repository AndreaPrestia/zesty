using JWT.Algorithms;
using JWT.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Security;
using System.Text;
using Zesty.Core.Api.System;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Exceptions;
using Zesty.Core.Integration;

namespace Zesty.Core.Controllers
{
    [Produces("application/json")]
    [ApiController]
    [Route("api/[controller]")]
    public class SystemController : SecureController
    {
        private static readonly NLog.Logger logger = NLog.Web.NLogBuilder.ConfigureNLog("nlog.config").GetCurrentClassLogger();

        #region Access
        /// <summary>
        /// Login 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost]
        [Route("Login")]
        public IActionResult Login(LoginRequest request)
        {
            ValidateEntity<LoginRequest>(request);

            LoginOutput loginOutput = Business.User.Login(request.Username, request.Password);

            if (loginOutput.Result == LoginResult.Failed)
            {
                throw new ApiAccessDeniedException(Messages.LoginFailed);
            }
            else if (loginOutput.Result == LoginResult.PasswordExpired)
            {
                throw new ApiAccessDeniedException(Messages.PasswordExpired);
            }

            if (!string.IsNullOrEmpty(request.Domain))
            {
                List<Entities.Domain> domains = Business.User.GetDomains(loginOutput.User.Username);

                Entities.Domain domain = domains.Where(x => x.Id.ToString().ToLower() == request.Domain.ToLower() || x.Name.ToLower() == request.Domain.ToLower()).FirstOrDefault();

                if (domain == null)
                {
                    domain = NestSearch(domains, request.Domain);

                    if (domain == null)
                    {
                        throw new ApiNotFoundException(request.Domain);
                    }
                }

                Business.User.SetDomain(loginOutput.User.Id, domain.Id);

                loginOutput.User.DomainId = domain.Id;
                loginOutput.User.Domain = domain;
            }

            if (loginOutput.User.DomainId != Guid.Empty && Business.Domain.HasTwoFactorAuthentication(loginOutput.User.DomainId))
            {
                IAuthProcessor processor = new Skebby();

                processor.GenerateOtp(loginOutput.User.Id, loginOutput.User.DomainId);

                LoginTwoFactorResponse twoFactorResponse = new LoginTwoFactorResponse() { Domain = loginOutput.User.DomainId };

                return GetOutput(twoFactorResponse);
            }

            LoginResponse response = new LoginResponse()
            {
                Output = loginOutput
            };

            if (request.Bearer == "true" && loginOutput.User != null)
            {
                string secret = HashHelper.GetSha256(request.Password);

                var p = loginOutput.User.Properties;

                loginOutput.User.Properties.Clear();

                string token = JwtBuilder.Create()
                      .WithAlgorithm(new HMACSHA256Algorithm())
                      .WithSecret(secret)
                      .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(12).ToUnixTimeSeconds())
                      .AddClaim("user", response.Output.User)
                      .Encode();

                logger.Debug($"token generated: {token}");

                Business.User.SaveBearer(loginOutput.User.Id, token);

                response.Bearer = token;

                loginOutput.User.Properties = p;
            }

            HttpContext.Session.Set(response.Output.User);

            return GetOutput(loginOutput);
        }

        /// <summary>
        /// Logout API
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(LogoutResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("Logout")]
        public IActionResult Logout()
        {
            Business.Authorization.Logout(base.CurrentHttpContext);

            return GetOutput(new LogoutResponse()
            {
                Message = Messages.Success
            });
        }

        /// <summary>
        /// One time password 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost]
        [Route("OneTimePassword")]
        public IActionResult OneTimePassword(OneTimePasswordRequest request)
        {
            ValidateEntity<OneTimePasswordRequest>(request);

            if (!Business.OneTimePassword.Exists(request.Username, Guid.Parse(request.Domain), request.Otp))
            {
                throw new ApiAccessDeniedException(Messages.LoginFailed);
            }

            LoginOutput loginOutput = new LoginOutput();

            loginOutput.User = Business.User.Get(request.Username);

            if (loginOutput.User == null)
            {
                ThrowInvalidArgument();
            }

            List<Entities.Domain> domains = Business.User.GetDomains(loginOutput.User.Username);

            Entities.Domain domain = domains.Where(x => x.Id.ToString().ToLower() == request.Domain.ToLower() || x.Name.ToLower() == request.Domain.ToLower()).FirstOrDefault();

            if (domain == null)
            {
                domain = NestSearch(domains, request.Domain);

                if (domain == null)
                {
                    throw new ApiNotFoundException(request.Domain);
                }
            }

            Business.User.SetDomain(loginOutput.User.Id, domain.Id);

            loginOutput.User.DomainId = domain.Id;
            loginOutput.User.Domain = domain;

            LoginResponse response = new LoginResponse()
            {
                Output = loginOutput
            };

            if (request.Bearer == "true" && loginOutput.User != null)
            {
                string secret = HashHelper.GetSha256(request.Password);

                var p = loginOutput.User.Properties;

                loginOutput.User.Properties.Clear();

                string token = JwtBuilder.Create()
                      .WithAlgorithm(new HMACSHA256Algorithm())
                      .WithSecret(secret)
                      .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(12).ToUnixTimeSeconds())
                      .AddClaim("user", response.Output.User)
                      .Encode();

                logger.Debug($"token generated: {token}");

                Business.User.SaveBearer(loginOutput.User.Id, token);

                response.Bearer = token;

                loginOutput.User.Properties = p;
            }

            HttpContext.Session.Set(response.Output.User);

            return GetOutput(response);
        }

        /// <summary>
        /// Set reset token 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("SetResetToken")]
        public IActionResult SetResetToken(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                throw new ApiInvalidArgumentException("email");
            }

            Guid token = Business.User.SetResetToken(email);

            if (token != Guid.Empty)
            {
                List<Translation> translations = Business.Languages.GetTranslations("en");

                string subject = translations.Where(x => x.Original == "Reset password").FirstOrDefault().Translated;
                string body = translations.Where(x => x.Original == "Password reset token: {0}").FirstOrDefault().Translated;

                body = String.Format(body, token.ToString());

                Common.SmtpClient.Send(email, subject, body);

                logger.Info($"Password reset email set to email address {email}");
            }

            return GetOutput();
        }

        /// <summary>
        /// Reset password 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost]
        [Route("ResetPassword")]
        public IActionResult ResetPassword(ResetPasswordRequest request)
        {
            ValidateEntity<ResetPasswordRequest>(request);

            if (!Business.User.ResetPassword(Guid.Parse(request.Token), request.Password))
            {
                throw new ApiInvalidArgumentException(Messages.TokenMissing);
            }

            return GetOutput();
        }

        /// <summary>
        /// Password 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost]
        [Route("Password")]
        public IActionResult Password(PasswordRequest request)
        {
            ValidateEntity<PasswordRequest>(request);

            string username = request.Username;

            if (String.IsNullOrWhiteSpace(username))
            {
                username = Context.Current.User.Username;
            }

            LoginOutput loginOutput = Business.User.Login(username, request.Old);

            if (loginOutput.Result == LoginResult.Failed)
            {
                throw new ApiAccessDeniedException(Messages.WrongPassword);
            }

            if (request.Old == request.New)
            {
                throw new ApplicationException(Messages.PasswordChangeSame);
            }

            if (request.New != request.Confirm)
            {
                throw new ApplicationException(Messages.PasswordDontMatch);
            }

            Business.User.ChangePassword(username, request.Old, request.New);

            return GetOutput();
        }

        /// <summary>
        /// Refresh bearer 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(RefreshResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("Refresh")]
        public IActionResult Refresh()
        {
            string bearer = HttpContext.Request.Headers["ZestyApiBearer"];

            if (String.IsNullOrWhiteSpace(bearer))
            {
                ThrowApplicationError("Bearer non found");
            }

            string secret = Business.User.GetSecret(bearer);

            string token = JwtBuilder.Create()
                .WithAlgorithm(new HMACSHA256Algorithm())
                .WithSecret(secret)
                .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(12).ToUnixTimeSeconds())
                .AddClaim("user", Context.Current.User)
                .Encode();

            logger.Debug($"token generated: {token}");

            Business.User.SaveBearer(Context.Current.User.Id, token);

            RefreshResponse response = new RefreshResponse() { Bearer = token };

            return GetOutput(response);
        }


        /// <summary>
        /// Antiforgery token 
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("Token")]
        public IActionResult Token(bool isReusable)
        {
            return GetOutput(new TokenResponse()
            {
                Text = Business.Authorization.GetToken(HttpContext.Session.Id, isReusable)
            });
        }
        #endregion

        #region Roles
        /// <summary>
        /// Available roles by domain
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
        [HttpGet]
        [Route("Roles")]
        public IActionResult Roles(Guid domain)
        {
            if (domain == Guid.Empty)
            {
                throw new ApiInvalidArgumentException(nameof(domain));
            }

            return GetOutput(new RolesResponse()
            {
                Roles = Business.User.GetRoles(Context.Current.User.Username, domain)
            });
        }
        #endregion

        #region Resources
        /// <summary>
        /// Available resources by domain
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(ResourcesResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("Resources")]
        public IActionResult Resources()
        {
            RequireDomain();

            return GetOutput(new ResourcesResponse()
            {
                Resources = Business.Resource.GetResources(Context.Current.User.Username, Context.Current.User.Domain.Id)
            });
        }
        #endregion

        #region Domain
        /// <summary>
        /// Available domains
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
        [HttpGet]
        [Route("Domains")]
        public IActionResult Domains()
        {
            RequireUser();

            return GetOutput(new DomainsResponse()
            {
                Domains = Business.User.GetDomains(Context.Current.User.Username)
            });
        }

        /// <summary>
        /// Login Api
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(LoginOutput), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost]
        [Route("Domain")]
        public IActionResult Domain(DomainRequest request)
        {
            ValidateEntity<DomainRequest>(request);

            List<Entities.Domain> domains = Business.User.GetDomains(Context.Current.User.Username);

            Entities.Domain domain = domains.Where(x => x.Id.ToString().ToLower() == request.Domain.ToLower() || x.Name.ToLower() == request.Domain.ToLower()).FirstOrDefault();

            if (domain == null)
            {
                domain = NestSearch(domains, request.Domain);

                if (domain == null)
                {
                    throw new ApiNotFoundException(request.Domain);
                }
            }

            Business.User.SetDomain(Context.Current.User.Id, domain.Id);

            Context.Current.User.DomainId = domain.Id;
            Context.Current.User.Domain = domain;

            DomainResponse response = new DomainResponse()
            {
                User = Context.Current.User
            };

            HttpContext.Session.Set(Context.Current.User);

            return GetOutput(response);
        }
        #endregion

        #region Languages
        /// <summary>
        /// Available languages
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(LanguagesResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("Languages")]
        public IActionResult Languages()
        {
            return GetOutput(new LanguagesResponse()
            {
                List = Business.Languages.List()
            });
        }

        /// <summary>
        /// Available translations
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(LanguagesResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("Translations")]
        public IActionResult Translations(string language)
        {
            if (string.IsNullOrWhiteSpace(language))
            {
                throw new ApiInvalidArgumentException(nameof(language));
            }

            return GetOutput(new TranslationResponse()
            {
                List = Business.Languages.GetTranslations(language)
            });
        }
        #endregion

        #region User
        /// <summary>
        /// User info
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(InfoResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("Info")]
        public IActionResult Info()
        {
            return GetOutput(new InfoResponse()
            {
                User = Context.Current.User
            });
        }

        /// <summary>
        /// User by reset token
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(UserByResetTokenResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("UserByResetToken")]
        public IActionResult UserByResetToken(Guid token)
        {
            UserByResetTokenResponse response = new UserByResetTokenResponse()
            {
                User = Business.User.Get(token)
            };

            if (response.User == null)
            {
                throw new ApiNotFoundException(token.ToString());
            }

            return GetOutput(response);
        }

        /// <summary>
        /// User property set
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpPost]
        [Route("Property")]
        public IActionResult Property(PropertyRequest request)
        {
            ValidateEntity<PropertyRequest>(request);

            Business.User.SetProperty(Context.Current.User, request.Name, request.Value);

            if (string.IsNullOrWhiteSpace(request.Value))
            {
                if (Context.Current.User.Properties.ContainsKey(request.Name))
                {
                    Context.Current.User.Properties.Remove(request.Name);
                }
            }
            else
            {
                if (Context.Current.User.Properties.ContainsKey(request.Name))
                {
                    Context.Current.User.Properties[request.Name] = request.Value;
                }
                else
                {
                    Context.Current.User.Properties.Add(request.Name, request.Value);
                }
            }

            HttpContext.Session.Set(Context.Current.User);

            return GetOutput();
        }

        #endregion

        #region Utility
        /// <summary>
        /// Client settings
        /// </summary>
        /// <returns></returns>
        [ProducesResponseType(typeof(ClientSettingsResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status501NotImplemented)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status502BadGateway)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        [HttpGet]
        [Route("ClientSettings")]
        public IActionResult ClientSettings(Guid token)
        {
            return GetOutput(new ClientSettingsResponse()
            {
                Settings = Business.ClientSettings.All()
            });
        }
        #endregion

        #region Private methods
        private Core.Entities.Domain NestSearch(List<Core.Entities.Domain> domains, string domain)
        {
            foreach (Core.Entities.Domain d in domains)
            {
                if (d.Id.ToString() == domain || d.Name == domain)
                {
                    return d;
                }

                Core.Entities.Domain inner = NestSearch(d.Childs, domain);

                if (inner != null)
                {
                    return inner;
                }
            }

            return null;
        }
        #endregion
    }
}
