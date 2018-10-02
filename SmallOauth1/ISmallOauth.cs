﻿using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace SmallOauth1
{
    public interface ISmallOauth
    {
		Task<AccessTokenInfo> GetAccessTokenAsync(string requestToken, string requestTokenSecret, string verifier);
		AuthenticationHeaderValue GetAuthorizationHeader(string accessToken, string accessTokenSecret, string url, HttpMethod httpMethod);
		string GetAuthorizationHeaderValue(string accessToken, string accessTokenSecret, string url, HttpMethod httpMethod);
		string GetAuthorizationUrl(string requestToken);
		Task<RequestTokenInfo> GetRequestTokenAsync();
	}
}
