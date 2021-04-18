using System;
using System.Data;
using System.Data.SqlClient;
using Zesty.Core.Entities;
using Zesty.Core.Entities.Settings;

namespace Zesty.Core.Api.System.Admin.Resource
{
    public class Add : ApiHandlerBase
    {
        public override ApiHandlerOutput Process(ApiInputHandler input)
        {
            AddResourceRequest request = GetEntity<AddResourceRequest>(input);

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

        public class AddResourceRequest
        {
            [Required]
            public string Url { get; set; }
            public string ParentId { get; set; }
            public bool IsPublic { get; set; }
            public bool RequireToken { get; set; }
            public int Order { get; set; }
            public string Label { get; set; }
            public string Title { get; set; }
            public string Image { get; set; }
            public string Type { get; set; }
            [Required]
            public string Domain { get; set; }
        }
    }
}
