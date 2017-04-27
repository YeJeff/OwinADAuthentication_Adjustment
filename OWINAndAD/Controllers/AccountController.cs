using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OWINAndAD.Models;
using Microsoft.Owin.Security;
using System.Threading.Tasks;

namespace OWINAndAD.Controllers
{
    public class AccountController : Controller
    {
        // GET: Account
        [AllowAnonymous]
        public virtual ActionResult Index(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async virtual Task<ActionResult> Index(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;

                // 将OWIN系统的Authentication注入自定义的认证类，此处是Windows窗体认证
                var authService = new AuthenticationService(authenticationManager); 

                var authenticationResult = await authService.SignIn(model.Username, model.Password);

                if (authenticationResult.IsSuccess)
                {
                    return RedirectToLocal(returnUrl);
                }

                ModelState.AddModelError("", authenticationResult.ErrorMessage);
            }
            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home",
                new { ReturnUrl = "/Account/Index", Hash = DateTime.Now.Millisecond });
        }

        [ValidateAntiForgeryToken]
        public virtual ActionResult Logoff()
        {
            IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;
            authenticationManager.SignOut(OWINAndADAuthentication.ApplicationCookie);

            return RedirectToAction("Index");
        }
    }
}