namespace Zesty.Core.Entities
{
    public class AddRoleRequest
    {
        [Required]
        public string Name { get; set; }
    }

    public class AddRoleResponse
    {
        public Entities.Role Role { get; set; }
    }
}
