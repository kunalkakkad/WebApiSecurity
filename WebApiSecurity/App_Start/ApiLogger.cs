using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using WebApiSecurity.Statics;

namespace WebApiSecurity.App_Start
{
    public class ApplicationAuthenticationHandler : DelegatingHandler
    {
        protected async override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Stopwatch stopwatch = new Stopwatch();
            var userString = new Regex("userAuthentication");
            var userStringMatch = userString.Match(request.RequestUri.AbsolutePath);
            if (!userStringMatch.Success)
            {
                if (request.Headers.Authorization != null)
                {
                    if (!ApiPrincipal.RequestValidation(request) || ApiPrincipal.SessionCheck(request))
                    {
                        return new HttpResponseMessage(HttpStatusCode.NotAcceptable);
                    }
                }
                else
                {
                    return new HttpResponseMessage(HttpStatusCode.NotAcceptable);
                }
            }    
            stopwatch.Start();
            var response = await base.SendAsync(request, cancellationToken);
            stopwatch.Stop();
            //return response;

            return ApiPrincipal.SetSession(response);
        }
    }
}