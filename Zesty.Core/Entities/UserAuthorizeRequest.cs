using System;
using System.Collections.Generic;
using System.Text;

namespace Zesty.Core.Entities
{
    public class UserAuthorizeRequest
    {
        [Required]
        public string User { get; set; }
        [Required]
        public string Domain { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
