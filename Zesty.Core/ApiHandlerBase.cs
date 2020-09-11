﻿using System;
using Zesty.Core.Common;
using Zesty.Core.Entities;
using Zesty.Core.Exceptions;

namespace Zesty.Core
{
    public abstract class ApiHandlerBase
    {
        public abstract ApiHandlerOutput Process(ApiInputHandler input);

        protected T GetEntity<T>(ApiInputHandler input, bool mandatory)
        {
            if (String.IsNullOrWhiteSpace(input.Body))
            {
                if (mandatory)
                {
                    ThrowInvalidArgument();
                }
                else
                {
                    return default;
                }
            }

            T r = JsonHelper.Deserialize<T>(input.Body);

            if (r == null && mandatory)
            {
                ThrowInvalidArgument();
            }

            return r;
        }

        protected T GetEntity<T>(ApiInputHandler input)
        {
            if (String.IsNullOrWhiteSpace(input.Body))
            {
                return default;
            }

            return JsonHelper.Deserialize<T>(input.Body);
        }

        protected string Serialize(Object obj)
        {
            return JsonHelper.Serialize(obj);
        }

        public void IsNotNull<T>(T parameter, string name)
        {
            IsNotEmptyString(name, "name");

            if (parameter == null)
            {
                throw new ApiInvalidArgumentException(name);
            }
        }

        public void IsNotEmptyString(string parameter, string name)
        {
            if (String.IsNullOrWhiteSpace(parameter))
            {
                throw new ApiInvalidArgumentException(name);
            }
        }

        public void IsNotDefault<T>(T paramenter, string name) where T : class
        {
            T a = default(T);

            if (paramenter == a)
            {
                throw new ApiInvalidArgumentException(name);
            }
        }

        public void IsNotEmpty(Guid parameter, string name)
        {
            if (parameter == Guid.Empty)
            {
                throw new ApiInvalidArgumentException(name);
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
    }
}
