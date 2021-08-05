namespace Zesty.Core.Entities
{
    public class AddDomainRequest
    {
        [Required]
        public string Name { get; set; }
        public string Parent { get; set; }
    }

    public class AddDomainResponse
    {
        public Domain Domain { get; set; }
    }
}
