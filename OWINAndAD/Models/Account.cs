using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

namespace OWINAndAD.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Username is empty!")]
        [AllowHtml]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is empty!")]
        [AllowHtml]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}