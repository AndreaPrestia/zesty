using System.Collections.Generic;
using Zesty.Core.Entities;

namespace Zesty.Core.Api.System.Admin.Resource
{
    public class All : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            return GetOutput(new AllResponse() { Resources = Business.Resource.ResourceAll() });
        }

        public class AllResponse
        {
            public List<Entities.Resource> Resources { get; set; }
        }
    }


}
}
