namespace Zesty.Core.Entities
{
    public class ResourceAuthorizeRequest
    {
        [Required]
        public string Resource { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
