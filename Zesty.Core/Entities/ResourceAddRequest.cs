namespace Zesty.Core.Entities
{
    public class ResourceAddRequest
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
