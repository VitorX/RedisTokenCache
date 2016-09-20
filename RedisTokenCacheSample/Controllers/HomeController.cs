using Cache;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace RedisTokenCacheSample.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public async Task<ActionResult> Contact()
        {
            ViewBag.Message = "Your contact page.";

            var userId = ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier).Value;
            var tenantId = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
            var userObjectID = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;

            var ctx = new AuthenticationContext(
                Startup.aadInstance + tenantId, 
                new RedisTokenCache(userId));
            var authn = await ctx.AcquireTokenSilentAsync(
                Startup.GraphResourceId, 
                Startup.Credential, 
                new UserIdentifier(userObjectID, UserIdentifierType.UniqueId));
            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authn.AccessToken);
            var req = Startup.GraphResourceId + "/me?api-version=1.6";
            var meJson = await client.GetStringAsync(req);
            var me = new { mobile = "" };
            me = JsonConvert.DeserializeAnonymousType(meJson, me);
            ViewBag.Mobile = me.mobile;

            return View();
        }
    }
}