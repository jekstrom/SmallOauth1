using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SmallOauth1
{
	public class SmallOauth : ISmallOauth
	{
		private readonly SmallOauthConfig _config;

		public SmallOauth(SmallOauthConfig config)
		{
			_config = config ?? throw new ArgumentNullException(nameof(config));
		}

		public Task<AccessTokenInfo> GetAccessTokenAsync(string requestToken, string requestTokenSecret, string verifier)
		{
			throw new NotImplementedException();
		}

		public AuthenticationHeaderValue GetAuthorizationHeader(string accessToken, string accessTokenSecret, string url, HttpMethod httpMethod)
		{
			return new AuthenticationHeaderValue("OAuth", GetAuthorizationHeaderValue(accessToken, accessTokenSecret, url, httpMethod));
		}

		public string GetAuthorizationHeaderValue(string accessToken, string accessTokenSecret, string url, HttpMethod httpMethod)
		{
			/*5.2.  Consumer Request Parameters

			OAuth Protocol Parameters are sent from the Consumer to the Service Provider in one of three methods, in order of decreasing preference:

			In the HTTP Authorization header as defined in OAuth HTTP Authorization Scheme.
			As the HTTP POST request body with a content-type of application/x-www-form-urlencoded.
			Added to the URLs in the query part (as defined by [RFC3986] section 3).
			In addition to these defined methods, future extensions may describe alternate methods for sending the OAuth Protocol Parameters. The methods for sending other request parameters are left undefined, but SHOULD NOT use the OAuth HTTP Authorization Scheme header.

      		*/

			/* 5.4.1.  Authorization Header

			The OAuth Protocol Parameters are sent in the Authorization header the following way:

			Parameter names and values are encoded per Parameter Encoding.
			For each parameter, the name is immediately followed by an ‘=’ character (ASCII code 61), a ‘”’ character (ASCII code 34), the parameter value (MAY be empty), and another ‘”’ character (ASCII code 34).
			Parameters are separated by a comma character (ASCII code 44) and OPTIONAL linear whitespace per [RFC2617].
			The OPTIONAL realm parameter is added and interpreted per [RFC2617], section 1.2.
			For example:

			Authorization: OAuth realm="http://sp.example.com/",
			oauth_consumer_key="0685bd9184jfhq22",
			oauth_token="ad180jjd733klru7",
			oauth_signature_method="HMAC-SHA1",
			oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
			oauth_timestamp="137131200",
			oauth_nonce="4572616e48616d6d65724c61686176",
			oauth_version="1.0"
			
			*/

			var nonce = GetNonce();
			var timeStamp = GetTimeStamp();

			var requestParameters = new List<string>
			{
				"oauth_consumer_key=" + _config.ConsumerKey,
				"oauth_token=" + accessToken,
				"oauth_signature_method=" + _config.SignatureMethod,
				"oauth_timestamp=" + timeStamp,
				"oauth_nonce=" + nonce,
				"oauth_version=1.0"
			};

			var requestUri = new Uri(url, UriKind.Absolute);

			if (!string.IsNullOrWhiteSpace(requestUri.Query))
			{
				var parameters = ExtractQueryParameters(requestUri.Query);

				foreach (var kvp in parameters)
					requestParameters.Add(kvp.Key + "=" + kvp.Value);

				// TODO: url = GetNormalizedUrl(requestUri);
			}

			// Appendix A.5.1. Generating Signature Base String
			var signatureBaseString = GetSignatureBaseString(httpMethod.ToString().ToUpper(), url, requestParameters);

			// Appendix A.5.2. Calculating Signature Value
			string signature = String.Empty;
			if (_config.SignatureMethod.ToLower().Contains("rsa"))
			{
				signature = GetRSASignature(signatureBaseString, _config.SigningKey);
			}
			else
			{
				signature = GetSignature(signatureBaseString, _config.ConsumerSecret, accessTokenSecret);
			}

			// Same as request parameters but uses a quote (") character around its values and is comma separated
			var requestParametersForHeader = new List<string>
			{
				"oauth_consumer_key=\"" + _config.ConsumerKey + "\"",
				"oauth_token=\"" + accessToken + "\"",
				"oauth_signature_method=\"" + _config.SignatureMethod + "\"",
				"oauth_timestamp=\"" + timeStamp + "\"",
				"oauth_nonce=\"" + nonce + "\"",
				"oauth_version=\"1.0\"",
				"oauth_signature=\"" + Uri.EscapeDataString(signature) + "\""
			};

			return ConcatList(requestParametersForHeader, ",");
		}

		public string GetAuthorizationUrl(string requestToken)
		{
			string url = $"{_config.AuthorizeTokenUrl}?{Uri.UnescapeDataString($"oauth_token={requestToken}")}";

			if (!String.IsNullOrWhiteSpace(_config.OauthCallback))
			{
				url += $"&{Uri.UnescapeDataString($"oauth_callback={_config.OauthCallback}")}";
			}

			return url;
		}

		public Task<RequestTokenInfo> GetRequestTokenAsync()
		{
			throw new NotImplementedException();
		}

		private string GetNonce()
		{
			var rand = new Random();
			var nonce = rand.Next(1000000000);
			return nonce.ToString();
		}

		private string GetTimeStamp()
		{
			var ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
			return Convert.ToInt64(ts.TotalSeconds).ToString();
		}

		private Dictionary<string, string> ExtractQueryParameters(string queryString)
		{
			if (queryString.StartsWith("?"))
				queryString = queryString.Remove(0, 1);

			var result = new Dictionary<string, string>();

			if (string.IsNullOrEmpty(queryString))
				return result;

			foreach (var s in queryString.Split('&'))
				if (!string.IsNullOrEmpty(s) && !s.StartsWith("oauth_"))
					if (s.IndexOf('=') > -1)
					{
						var temp = s.Split('=');
						result.Add(temp[0], temp[1]);
					}
					else
					{
						result.Add(s, string.Empty);
					}

			return result;
		}

		private string GetSignatureBaseString(string method, string url, List<string> requestParameters)
		{
			// It's very important that we "normalize" the parameters, that is sort them:
			//9.1.1.Normalize Request Parameters

			//The request parameters are collected, sorted and concatenated into a normalized string:

			// * Parameters in the OAuth HTTP Authorization header excluding the realm parameter.
			// * Parameters in the HTTP POST request body(with a content - type of application / x - www - form - urlencoded).
			// * HTTP GET parameters added to the URLs in the query part(as defined by[RFC3986] section 3).
			var sortedList = new List<string>(requestParameters);
			sortedList.Sort();

			var requestParametersSortedString = ConcatList(sortedList, "&");

			// Url must be slightly reformatted because of:

			/*9.1.2. Construct Request URL

			The Signature Base String includes the request absolute URL, tying the signature to a specific endpoint. The URL used in the Signature Base String MUST include the scheme, authority, and path, and MUST exclude the query and fragment as defined by [RFC3986] section 3.

			If the absolute request URL is not available to the Service Provider (it is always available to the Consumer), it can be constructed by combining the scheme being used, the HTTP Host header, and the relative HTTP request URL. If the Host header is not available, the Service Provider SHOULD use the host name communicated to the Consumer in the documentation or other means.

			The Service Provider SHOULD document the form of URL used in the Signature Base String to avoid ambiguity due to URL normalization. Unless specified, URL scheme and authority MUST be lowercase and include the port number; http default port 80 and https default port 443 MUST be excluded.

			For example, the request:

							HTTP://Example.com:80/resource?id=123
			Is included in the Signature Base String as:

							http://example.com/resource
 */


			url = ConstructRequestUrl(url);

			return method.ToUpper() + "&" + Uri.EscapeDataString(url) + "&" +
				   Uri.EscapeDataString(requestParametersSortedString);
		}

		private string GetRSASignature(string stringToSign, string privateKey)
		{
			using (var reader = new StringReader(privateKey))
			{
				AsymmetricCipherKeyPair kp = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

				ISigner signer = SignerUtilities.GetSigner("SHA1withRSA");

				signer.Init(true, kp.Private);

				var bytes = Encoding.UTF8.GetBytes(stringToSign);

				signer.BlockUpdate(bytes, 0, bytes.Length);
				byte[] signature = signer.GenerateSignature();

				return Convert.ToBase64String(signature);
			}
		}

		private string GetSignature(string signatureBaseString, string consumerSecret, string tokenSecret = null)
		{
			/*9.2.  HMAC-SHA1

			The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104] where the Signature Base String is the text and the key is the concatenated values (each first encoded per Parameter Encoding) of the Consumer Secret and Token Secret, separated by an '&' character (ASCII code 38) even if empty.
			*/

			var hmacsha1 = new HMACSHA1();

			var key = Uri.EscapeDataString(consumerSecret) + "&" + (string.IsNullOrEmpty(tokenSecret)
						  ? ""
						  : Uri.EscapeDataString(tokenSecret));
			hmacsha1.Key = Encoding.ASCII.GetBytes(key);

			var dataBuffer = Encoding.ASCII.GetBytes(signatureBaseString);
			var hashBytes = hmacsha1.ComputeHash(dataBuffer);

			return Convert.ToBase64String(hashBytes);

			// .NET Core implementation
			// var signingKey = string.Format("{0}&{1}", consumerSecret, !string.IsNullOrEmpty(requestTokenSecret) ? requestTokenSecret : "");
			// IBuffer keyMaterial = CryptographicBuffer.ConvertStringToBinary(signingKey, BinaryStringEncoding.Utf8);
			// MacAlgorithmProvider hmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
			// CryptographicKey macKey = hmacSha1Provider.CreateKey(keyMaterial);
			// IBuffer dataToBeSigned = CryptographicBuffer.ConvertStringToBinary(signatureBaseString, BinaryStringEncoding.Utf8);
			// IBuffer signatureBuffer = CryptographicEngine.Sign(macKey, dataToBeSigned);
			// String signature = CryptographicBuffer.EncodeToBase64String(signatureBuffer);
			// return signature;
		}

		private static string ConcatList(IEnumerable<string> source, string separator)
		{
			var sb = new StringBuilder();
			foreach (var s in source)
				if (sb.Length == 0)
				{
					sb.Append(s);
				}
				else
				{
					sb.Append(separator);
					sb.Append(s);
				}
			return sb.ToString();
		}

		private string ConstructRequestUrl(string url)
		{
			var uri = new Uri(url, UriKind.Absolute);
			var normUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);
			if (!(uri.Scheme == "http" && uri.Port == 80 ||
				  uri.Scheme == "https" && uri.Port == 443))
				normUrl += ":" + uri.Port;

			normUrl += uri.AbsolutePath;

			return normUrl;
		}
	}
}
