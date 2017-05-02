using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApiSecurity.Constants
{
    public class ApplicationConstants
    {
        public const string SessionHeader = "x-session";
        public const string Key = "ApplicationKey";
        public const string TokenType = "JWT";
        public const string TokenIssuer = "CMS";
        public const string TokenKeyIssuer = "CMSKentiko";
        public const string RequestVerificationCookie = "__RequestVerificationToken";
        public const string UserType = "Admin";
    }
}