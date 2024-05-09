using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http;
using System.IO;
using System.Threading.Tasks;

public class Program
{
    // The service account key as a string. Ideally this is pulled from a secrets manager.
    static string credentials = "SERVICE ACCOUNT KEY VALUES HERE";

    public static void Main(string[] args)
    {
      // Convert service account key JSON into a dictionary.
      Dictionary<string, string> routesList = JsonConvert.DeserializeObject<Dictionary<string, string>>(credentials);

      // Sign the JWT token.
      var token = CreateToken(routesList, routesList["privateKey"]);

      // Exchange the JWT token for an auth bearer token.
      var response = GetAuthToken(token, routesList["tokenURI"]);

      Console.WriteLine(response.Result);
    }

  public static string CreateToken(Dictionary<string, string> payload, string privateRsaKey)
  {
    var claims = new Dictionary<string, object>
    {
        { "exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds() },
        { "iss", payload["clientID"] },
        { "key", payload["keyID"] },
        { "aud", payload["tokenURI"] },
        { "sub", payload["clientID"] }
    };

    // Convert PEM formatted private key into just a Base64 string for the private key.
    privateRsaKey = privateRsaKey.Replace("-----BEGIN PRIVATE KEY-----", "");
    privateRsaKey = privateRsaKey.Replace("-----END PRIVATE KEY-----", "");
    privateRsaKey = privateRsaKey.Replace("\n", "");
    privateRsaKey = privateRsaKey.Replace("\r\n", "");

    // Convert the private key into an RSA Parameter.
    var keyInfoByte = System.Convert.FromBase64String(privateRsaKey);
    AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(keyInfoByte);
    var privateRsaParams = privateKey as RsaPrivateCrtKeyParameters;
    RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);

    // Sign the JWT token.
    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
    {
      rsa.ImportParameters(rsaParams);
      return Jose.JWT.Encode(claims, rsa, Jose.JwsAlgorithm.RS256);
    }
  }

  public static async Task<String> GetAuthToken(string token, string uri)
  {
    // JSON string for the body of the POST call.
    string json = Newtonsoft.Json.JsonConvert.SerializeObject(new {grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion = token});

    // Post the JWT token to the server to get an auth bearer token.
    using (var client = new HttpClient())
    {
        var response = await client.PostAsync(uri,
          new StringContent(json, Encoding.UTF8, "application/json"));

      return await response.Content.ReadAsStringAsync();
    }
  }
}