using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Helpers;
using WebApiSecurity.Constants;
using WebApiSecurity.Security;

namespace WebApiSecurity.Statics
{
    public static class ApiPrincipal
    {
        public static bool SessionCheck(HttpRequestMessage request)
        {
            try
            {
                var value = request.Headers.GetValues(ApplicationConstants.SessionHeader);
                var sessionTime = Convert.ToDateTime(value.First());
                return (DateTime.UtcNow > sessionTime);
            }
            catch (Exception)
            {
                return false;
            }
        }
        public static HttpResponseMessage SetSession(HttpResponseMessage response)
        {

            DateTime epochStart = new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, DateTime.UtcNow.Day, DateTime.UtcNow.Hour, DateTime.UtcNow.Minute, DateTime.UtcNow.Second, DateTime.UtcNow.Millisecond, DateTimeKind.Utc).AddMinutes(Convert.ToDouble(System.Configuration.ConfigurationManager.AppSettings["sessionTimeOut"]));
            response.Headers.Add(ApplicationConstants.SessionHeader, epochStart.ToString());
            return response;
        }
        public static bool RequestValidation(HttpRequestMessage request)
        {
            try
            {
                var applicationSecurity = request.GetDependencyScope().GetService(typeof(IApplicationSecurity)) as IApplicationSecurity;


                //get record from Database for validation here
                ApplicationTokenContext context = new ApplicationTokenContext();
                var userToken = context.ApplicationUsersTokens.SingleOrDefault(t => t.AuthToken == request.Headers.Authorization.ToString());

                applicationSecurity.AuthenticateToken(request.Headers.Authorization.ToString(), userToken.ClientSecret);
                var cookie = request.Headers.GetCookies(ApplicationConstants.RequestVerificationCookie).FirstOrDefault();
                if (cookie != null)
                {
                    AntiForgery.Validate(cookie[ApplicationConstants.RequestVerificationCookie].Value, userToken.AntiForgeryToken);
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}