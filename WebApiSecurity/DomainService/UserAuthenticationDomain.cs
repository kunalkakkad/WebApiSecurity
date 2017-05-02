using Rx.Security.JsonWebToken;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Helpers;
using WebApiSecurity.Constants;
using WebApiSecurity.Security;

namespace WebApiSecurity.DomainService
{
    public class UserAuthenticationDomain
    {
        public ApplicationSecurity ApplicationSecurity { get; set; }
        public UserAuthenticationDomain()
        {
            ApplicationSecurity = new ApplicationSecurity(new TokenIssuer());
        }
        public string ApplicationToken()
        {
            string antiToken = string.Empty;
            string cookieToken = string.Empty;
            TokenOptions tokenOptions = new TokenOptions
            {
                Issuer = ApplicationConstants.TokenIssuer,
                KeyIssuer = ApplicationConstants.TokenKeyIssuer,
                UserId = 1,
                UserType = ApplicationConstants.UserType,
                UserRoles = new string[] { },
                UserName = "emailId"
            };
            var tokenClaims = new Dictionary<string, string>();
            
            // Add any tokenClaim details in Dict

            var jwt = ApplicationSecurity.Authenticate(tokenOptions, tokenClaims);
            AntiForgery.GetTokens(null, out cookieToken, out antiToken);
            string jwtToken = jwt.ToString();


            /*Insert generated token into table Here */

            //var applicationUserToken = new ApplicationUsersToken
            //{
            //    CookieToken = cookieToken,
            //    AntiForgeryToken = antiToken,
            //    AuthToken = jwtToken,
            //    ClientSecret = jwt.AsymmetricKey,
            //    TokenType = ApplicationConstants.TokenType,
            //    UserId = 1, //userId 
            //    CreatedDateTime = DateTime.Now,
            //    IsActive = true
            //};

            //DbContext.Add(applicationUserToken);
            //DbContext.SaveChange();

            HttpContext.Current.Response.AddHeader("Authorization", jwtToken);

            HttpContext.Current.Response.Cookies.Add(new HttpCookie(ApplicationConstants.RequestVerificationCookie, Convert.ToString(cookieToken)));

            return jwtToken;
        }
    }
}