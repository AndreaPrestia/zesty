using System;
using System.Data;
using System.Data.SqlClient;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;

namespace Zesty.Core.Api.System.Admin.Resource
{
    public class Delete : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            Guid resourceId = Guid.Parse(input.Get("id"));

            using (SqlConnection connection = new SqlConnection(Settings.Current.StorageSource))
            {
                connection.Open();

                using (SqlCommand command = new SqlCommand("Zesty_Resource_Delete", connection))
                {
                    command.CommandType = CommandType.StoredProcedure;

                    command.Parameters.Add(new SqlParameter() { ParameterName = "@resourceId", Value = resourceId });

                    command.ExecuteNonQuery();
                }
            }

            return GetOutput();
        }
    }
}
