﻿using Zesty.Core.Common;
using Zesty.Core.Entities;

namespace Zesty.Core.Api.System
{
    public class Property : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            PropertyRequest request = base.GetEntity<PropertyRequest>(input);

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

            input.Context.Session.Set(Context.Current.User);

            return GetOutput();
        }
    }

    public class PropertyRequest
    {
        public string Name { get; set; }
        public string Value { get; set; }
    }
}
