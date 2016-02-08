using OpenIDConnect.Clients.Angular14.Models;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;
using System;

namespace OpenIDConnect.Clients.Angular14.Controllers
{
    public class NewsController : ApiController
    {
        [HttpGet]
        [Route("api/news")]
        public IHttpActionResult GetNews()
        {
            var newsArticles = GetArticles(this.User.IsInRole("Premium"));
            return this.Ok(newsArticles.ToList());
        }

        private IEnumerable<NewsArticleApiModel> GetArticles(bool includePremium)
        {
            yield return new NewsArticleApiModel { Id = 1, Type = NewsArticleType.Free, Title = "Free news", Body = "This is some sample news" };

            if (includePremium)
            {
                yield return new NewsArticleApiModel { Id = 2, Type = NewsArticleType.Premium, Title = "Premium news!", Body = "This is some more sample news" };
            }
        }
    }
}