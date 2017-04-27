using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;

namespace OWINAndAD
{
    public static class OWINAndADAuthentication
    {
        public const string ApplicationCookie = "OWINAndADAuthenticationType";
    }
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = OWINAndADAuthentication.ApplicationCookie,
                LoginPath = new PathString("/Account"),
                Provider = new CookieAuthenticationProvider(),
                CookieName = "OWINAndADCookieName",
                CookieHttpOnly = true,
                ExpireTimeSpan = TimeSpan.FromHours(12.0)
            });
            
        }
    }
}