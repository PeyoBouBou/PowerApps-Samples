using Microsoft.Extensions.Configuration;
using Microsoft.Identity.Client;
using System.Net;
using System.Security;

namespace PowerApps.Samples
{
    public class App
    {
        private static readonly IConfiguration appSettings = new ConfigurationBuilder()
       //appsettings.json file 'Copy To Output Directory' property must be 'Copy if Newer'
       .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
       .Build();

        //Establishes the MSAL app to manage caching access tokens
        private static IPublicClientApplication app = PublicClientApplicationBuilder.Create(appSettings["ClientId"])
            .WithRedirectUri(appSettings["RedirectUri"])
            .WithAuthority(appSettings["Authority"])
            .Build();

        public static Config InitializeApp()
        {
            //Used to configure the service
            Config config = new()
            {
                Url = appSettings["Url"],
                GetAccessToken = GetToken, //Function defined below to manage getting OAuth token

                //Optional settings that have defaults if not specified:
                MaxRetries = byte.Parse(appSettings["MaxRetries"]), //Default: 2
                TimeoutInSeconds = ushort.Parse(appSettings["TimeoutInSeconds"]), //Default: 120
                Version = appSettings["Version"], //Default 9.2
                CallerObjectId = new Guid(appSettings["CallerObjectId"]), //Default empty Guid
                DisableCookies = false
            };
            return config;



        }

        internal static async Task<string> GetToken()
        {
            List<string> scopes = new() { $"{appSettings["Url"]}/user_impersonation" };

            var accounts = await app.GetAccountsAsync();

            AuthenticationResult? result;
            if (accounts.Any())
            {
                result = await app.AcquireTokenSilent(scopes, accounts.FirstOrDefault())
                                  .ExecuteAsync();
            }
            else
            {
                //https://docs.microsoft.com/azure/active-directory/develop/scenario-desktop-acquire-token?tabs=dotnet#username-and-password

                if (!string.IsNullOrEmpty(appSettings["Password"]) && !string.IsNullOrEmpty(appSettings["UserPrincipalName"]))
                {
                    try
                    {
                        SecureString password = new NetworkCredential("", appSettings["Password"]).SecurePassword;

                        result = await app.AcquireTokenByUsernamePassword(scopes.ToArray(), appSettings["UserPrincipalName"], password)
                            .ExecuteAsync();
                    }
                    catch (MsalUiRequiredException)
                    {

                        //Open browser to enter credentials when MFA required
                        result = await app.AcquireTokenInteractive(scopes).ExecuteAsync();

                    }
                    catch (Exception)
                    {
                        throw;
                    }
                }
                else
                {
                    throw new Exception("Need password in appsettings.json.");
                }
            }

            if (result != null && !string.IsNullOrEmpty(result.AccessToken))
            {

                return result.AccessToken;
            }
            else
            {
                throw new Exception("Failed to get access token.");
            }
        }

    }
}

