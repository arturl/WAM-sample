using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Microsoft.Azure.Devices;
using Windows.Devices.Geolocation;
using Windows.UI.Xaml.Controls.Maps;
using System.Threading.Tasks;
using System.Text;
using System.Diagnostics;
using Windows.Security.Authentication.Web.Core;
using Windows.System;
using Windows.UI.ApplicationSettings;
using Windows.Data.Json;
using Windows.Web.Http;
using Windows.Security.Credentials;
using Windows.Storage;
using Windows.Security.Authentication.Web;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Windows.UI.Popups;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=
//NOTE: Authentication doesn't really work right now, so if you don't have a corporate/organization azure account
//please fill in the necessary strings and uncomment NavigateToMap() in On_Loaded()

namespace WAMUWP
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        const string MicrosoftProviderId = "https://login.microsoft.com";
        const string MicrosoftAccountAuthority = "consumers";
        const string AzureActiveDirectoryAuthority = "organizations";

        const string MicrosoftAccountClientId = "none";
        const string MicrosoftAccountScopeRequested = "wl.basic";

        // To obtain azureAD tokens, you must register this app on the AzureAD portal, and obtain the client ID
        const string AzureActiveDirectoryClientId = "5cec90d8-14eb-41ac-9b2c-b3e8a7d95da5";
        const string AzureActiveDirectoryScopeRequested = "wl.basic";

        private const string AzureResourceApi = "2015-01-01";
        public MainPage()
        {
            this.InitializeComponent();
        }
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            AccountsSettingsPane.GetForCurrentView().AccountCommandsRequested += BuildPaneAsync;
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            AccountsSettingsPane.GetForCurrentView().AccountCommandsRequested -= BuildPaneAsync;
        }
        private async void BuildPaneAsync(AccountsSettingsPane sender, AccountsSettingsPaneCommandsRequestedEventArgs e)
        {
            var deferral = e.GetDeferral();

            var msaProvider = await WebAuthenticationCoreManager.FindAccountProviderAsync(MicrosoftProviderId, MicrosoftAccountAuthority);
            e.WebAccountProviderCommands.Add(new WebAccountProviderCommand(msaProvider, WebAccountProviderCommandInvoked_MSA));

            var aadProvider = await WebAuthenticationCoreManager.FindAccountProviderAsync(MicrosoftProviderId, AzureActiveDirectoryAuthority);
            e.WebAccountProviderCommands.Add(new WebAccountProviderCommand(aadProvider, WebAccountProviderCommandInvoked_AAD));

            deferral.Complete();
        }

        private async void WebAccountProviderCommandInvoked_MSA(WebAccountProviderCommand command)
        {
            var scope = MicrosoftAccountScopeRequested;

            //scope = "service::insiderservice.microsoft.com::MBI_SSL";
            //scope = "service::wl.basic::DELEGATION";
            scope = "wl.basic";

            // ClientID is ignored by MSA
            WebTokenRequest request = new WebTokenRequest(command.WebAccountProvider, scope, "none");

            //var account = await WebAuthenticationCoreManager.FindAccountAsync(command.WebAccountProvider, "77ab17918e49b08f23b5b5c4f5bb01a3");
            WebAccount account = null;

            await AuthenticateWithRequestToken(request, account);
        }

        private async void WebAccountProviderCommandInvoked_AAD(WebAccountProviderCommand command)
        {
            WebTokenRequest request = new WebTokenRequest(command.WebAccountProvider, AzureActiveDirectoryScopeRequested, AzureActiveDirectoryClientId, WebTokenRequestPromptType.Default);
            request.Properties.Add("resource", "https://management.azure.com/");
            await AuthenticateWithRequestToken(request, null);
        }

        int depth = 0;

        private async Task AuthenticateWithRequestToken(WebTokenRequest request, WebAccount account)
        {
            WebTokenRequestResult result;
            if (account == null)
            {
                result = await WebAuthenticationCoreManager.RequestTokenAsync(request);
            }
            else
            {
                result = await WebAuthenticationCoreManager.GetTokenSilentlyAsync(request, account);
            }

            if (result.ResponseStatus == WebTokenRequestStatus.Success)
            {
                string userName = result.ResponseData[0].WebAccount.UserName;

                string token = result.ResponseData[0].Token;
                List<string> subscriptionIds = new List<string>();
                string relative = "subscriptions?api-version=" + AzureResourceApi;

                var client = new System.Net.Http.HttpClient();
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                var restApi = new Uri("https://management.azure.com/" + relative);
                var infoResult = await client.GetAsync(restApi);
                string content = await infoResult.Content.ReadAsStringAsync();
                var jsonObject = JsonObject.Parse(content);
                if (jsonObject.ContainsKey("value"))
                {
                    var subscriptions = jsonObject["value"].GetArray();
                    subscriptionIds.AddRange(subscriptions.Select(_ => _.GetObject().GetNamedValue("subscriptionId").GetString()));
                    AzureSubscription.Items.Clear();
                    if (subscriptionIds.Count == 0)
                    {
                        AzureSubscription.Items.Add("no subscriptions listed");
                    }
                    foreach (var id in subscriptionIds)
                    {
                        AzureSubscription.Items.Add(id);
                    }

                }
                else
                {
                    string error = jsonObject.GetObject().GetNamedValue("error").GetObject().GetNamedValue("message").ToString();
                    AzureSubscription.Items.Clear();
                    AzureSubscription.Items.Add(error);
                }
            }
            else
            {
                AzureSubscription.Items.Clear();
                AzureSubscription.Items.Add(result.ResponseStatus.ToString());
            }
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            AccountsSettingsPane.Show();
        }
    }
}


