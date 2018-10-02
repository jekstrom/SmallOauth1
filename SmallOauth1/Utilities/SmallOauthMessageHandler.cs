using System.Net.Http;
using System.Threading.Tasks;

namespace SmallOauth1.Utilities
{
    class SmallOauthMessageHandler : DelegatingHandler
	{
		private string _accessToken;
		private string _accessTokenSecret;
		private SmallOauth _smallOauth;

		public SmallOauthMessageHandler(SmallOauthConfig config, string accessToken, string accessTokenSecret) : base(new HttpClientHandler())
		{
			_smallOauth = new SmallOauth(config);
			_accessTokenSecret = accessTokenSecret;
			_accessToken = accessToken;
		}

		protected override Task<HttpResponseMessage> SendAsync(
			HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
		{
			request.Headers.Authorization = _smallOauth.GetAuthorizationHeader(_accessToken, _accessTokenSecret,
				request.RequestUri.AbsoluteUri, request.Method);

			return base.SendAsync(request, cancellationToken);
		}
	}
}
