using Rx.Security.JsonWebToken;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WebApiSecurity.Security
{
    public interface IApplicationSecurity
    {
        JsonWebEncryptedToken Authenticate(TokenOptions tokenOptions);
        JsonWebEncryptedToken Authenticate(TokenOptions tokenOptions, Dictionary<string, string> tokenClaims);
        JsonWebEncryptedToken AuthenticateToken(string Token, string SecretKey);
    }
}
