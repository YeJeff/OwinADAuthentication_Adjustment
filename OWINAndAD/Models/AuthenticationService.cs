using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.DirectoryServices.AccountManagement;
using Microsoft.Owin.Security;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OWINAndAD.Models
{
    public class AuthenticationService
    {
        public class AuthenticationResult
        {
            public string ErrorMessage { get; private set; }
            public bool IsSuccess => String.IsNullOrEmpty(ErrorMessage);
            public AuthenticationResult(string errorMessage = null)
            {
                ErrorMessage = errorMessage;
            }
        }

        private readonly IAuthenticationManager authenticationManager;

        public AuthenticationService(IAuthenticationManager manager)
        {
            authenticationManager = manager;
        }

        public async Task<AuthenticationResult> SignIn(string username, string password)
        {
#if DEBUG
            ContextType authenticationType = ContextType.Machine;
#else
            ContextType authenticationType = ContextType.Domain;
#endif
            PrincipalContext principalContext = new PrincipalContext(authenticationType);
            bool isAuthenticated = false;
            UserPrincipal userPrincipal = null;
            try
            {
                userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
                

                if (userPrincipal != null)
                {
                    isAuthenticated = principalContext.ValidateCredentials(username, password, ContextOptions.Negotiate);
                }
            }
            catch (Exception)
            {
                isAuthenticated = false;
                userPrincipal = null;
                return new AuthenticationResult("Username or password is not correct.");
            }

            if(!isAuthenticated || userPrincipal == null)
            {
                return new AuthenticationResult("Username or password is not correct.");
            }

            if (userPrincipal.IsAccountLockedOut())
            {
                return new AuthenticationResult("Your account is locked.");
            }

            var identity = CreateIdentity(userPrincipal);

            authenticationManager.SignOut(OWINAndADAuthentication.ApplicationCookie);
            authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, identity);

            return new AuthenticationResult();
        }

        private ClaimsIdentity CreateIdentity(UserPrincipal userPrincipal)
        {
            ClaimsIdentity identity = new ClaimsIdentity(OWINAndADAuthentication.ApplicationCookie, 
                ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "Active Directory"));
            identity.AddClaim(new Claim(ClaimTypes.Name,userPrincipal.SamAccountName));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userPrincipal.SamAccountName));

            //以下三行为当前声明三个自定义的角色
            identity.AddClaim(new Claim(ClaimTypes.Role,"Admins"));
            identity.AddClaim(new Claim(ClaimTypes.Role, "Users"));
            identity.AddClaim(new Claim(ClaimTypes.Role, "Managers"));

            //获取当前系统用户所属的组
            var groups = userPrincipal.GetAuthorizationGroups();
            foreach(var @group in groups)
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, @group.Name));
            }

            if (!string.IsNullOrEmpty(userPrincipal.EmailAddress))
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, userPrincipal.EmailAddress));
            }

            // we can add more claims for needs.

            return identity;
        }
    }
}