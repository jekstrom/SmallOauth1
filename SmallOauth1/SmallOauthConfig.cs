namespace SmallOauth1
{
    public class SmallOauthConfig
    {
		public string ConsumerKey { get; set; }
		public string ConsumerSecret { get; set; }
		public string AccessTokenUrl { get; set; }
		public string AuthorizeTokenUrl { get; set; }
		public string RequestTokenUrl { get; set; }
		public string SignatureMethod { get; set; } = "HMAC-SHA1";
		public string SigningKey { get; set; }
		public string OauthCallback { get; set; } = "oob";
	}
}
