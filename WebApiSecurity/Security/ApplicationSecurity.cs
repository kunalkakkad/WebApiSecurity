using Rx.Security.JsonWebToken;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace WebApiSecurity.Security
{
    public class ApplicationSecurity : IApplicationSecurity
    {
        ITokenIssuer tokenIssuer { get; set; }
        public ApplicationSecurity(ITokenIssuer _tokenIssuer)
        {
            tokenIssuer = _tokenIssuer;
        }

        public JsonWebEncryptedToken Authenticate(TokenOptions tokenOptions)
        {
            Tuple<string, string> key = KeyIssuer.GenerateAsymmetricKey();
            tokenOptions.KeyIssuer = key.Item2;
            this.token = tokenIssuer.EncryptedToken(tokenOptions);
            return this.Authenticate(key.Item2);
        }

        public JsonWebEncryptedToken Authenticate(TokenOptions tokenOptions,Dictionary<string, string> tokenClaims)
        {
            Tuple<string, string> key = KeyIssuer.GenerateAsymmetricKey();
            tokenOptions.KeyIssuer = key.Item2;
            this.token = tokenIssuer.EncryptedToken(tokenOptions, tokenClaims);
            return this.Authenticate(key.Item2);
        }

        private JsonWebEncryptedToken Authenticate(string _secretKey)
        {
            JsonWebEncryptedToken jwt = null;
            jwt = JsonWebEncryptedToken.Parse(this.token, _secretKey);
            Thread.CurrentPrincipal = new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims, "JWT"));
            HttpContext.Current.User = Thread.CurrentPrincipal;
            return jwt;
        }

        public JsonWebEncryptedToken AuthenticateToken(string _token, string _secretKey)
        {
            JsonWebEncryptedToken jwt = null;
            jwt = JsonWebEncryptedToken.Parse(_token, _secretKey);
            Thread.CurrentPrincipal = new ClaimsPrincipal(new ClaimsIdentity(jwt.Claims, "JWT"));
            HttpContext.Current.User = Thread.CurrentPrincipal;
            return jwt;
        }

        private string token = string.Empty;
    }
}
