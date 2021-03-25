using System;
using System.Collections.Generic;
using System.ServiceModel.Security;
using System.Web;
using System.Xml;
using Telligent.DynamicConfiguration.Components;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Evolution.Extensibility.Authentication.Version1;
using Telligent.Evolution.Extensibility.UI.Version1;
using Telligent.Evolution.Extensibility.Urls.Version1;
using Telligent.Evolution.Extensibility.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;
using Telligent.Services.SamlAuthenticationPlugin.Extensibility.Events;

namespace Telligent.Services.SamlAuthenticationPlugin  
{

    public class SamlOAuthClient : IScriptedContentFragmentFactoryDefaultProvider, IRequiredConfigurationPlugin, INavigable, ITokenProcessorConfiguration, IOAuthClient, IInstallablePlugin, ICategorizedPlugin, ISingletonPlugin
    {

        public static string PluginName = "SAML Authentication OAuth Client";  //allows for build automation
        //public string clientType = "saml";  //oauth client type

        #region Defaults

        public static List<string> PluginCategories = new List<string> { "SAML", "OAuth" }; //leverage this for extensions to make them easier to find

        private const string _idpUrlDefault = "";
        private const SamlBinding _idpBindingTypeDefault = SamlBinding.SAML20_POST;
        private const string _issuerUrlDefault = "";
        private const string _issuerThumbprintDefault = "";
        private const X509CertificateValidationMode _issuerCertificateValidationModeDefault = X509CertificateValidationMode.None;
        private const AuthnBinding _idpAuthRequestTypeDefault = AuthnBinding.IDP_Initiated;
        private const string _authThumbprintDefault = "";
        private const string _usernameClaimDefault = "name";
        private const string _emailClaimDefault = "email";
        private const string _logoutUrlDefault = "";
        private const string _iconUrlDefault = "";
        private const LogoutUrlBehavior _logoutUrlBehaviorDefault = LogoutUrlBehavior.INTERNAL;
        private const SubjectRecipientValidationMode _subjectRecipientValidationModeDefault = SubjectRecipientValidationMode.ExactMatch;
        private const bool _allowTokenMatchingByEmailAddressDefault = true;
        private const bool _allowAutoUserRegistrationDefault = true;
        internal const string oauthTokeyQuerystringKey = "saml_data_token_key";
        private IEventLog _eventLogApi;
        private IUsers _usersApi;
        private IUrl _urlApi;
        private ICoreUrls _coreUrlsApi;

        #endregion

        #region IPlugin

        public string Name
        {
            get { return PluginName; }
        }

        public string Description

        {
            get { return "Allows single-sign-on by converting SAML Tokens into OAuth tokens."; }
        }
        
        public void Initialize()
        {
            _eventLogApi = Apis.Get<IEventLog>();
            _usersApi = Apis.Get<IUsers>();
            _urlApi = Apis.Get<IUrl>();
            _coreUrlsApi = Apis.Get<ICoreUrls>();

            //hook the user created event to save SAML token data (from secure cookie if persist flag is set) for new users
            _usersApi.Events.AfterCreate += new UserAfterCreateEventHandler(Events_AfterUserCreate);

            //hook to create custom user authenticated event
            _usersApi.Events.AfterIdentify += new UserAfterIdentifyEventHandler(Events_AfterIdentify);

            //cleanup persistant storage when a user is deleted
            _usersApi.Events.AfterDelete += new UserAfterDeleteEventHandler(Events_AfterUserDelete);

        }

        #endregion

        #region Configuration

        public bool IsConfigured
        {
            get
            {
                if (string.IsNullOrEmpty(UserNameAttributeName))
                    return false;

                if (string.IsNullOrEmpty(this.IdpUrl))
                    return false;

                if (string.IsNullOrEmpty(this.TrustedIssuerThumbprint))
                    return false;

                return true;
            }
        }

        protected IPluginConfiguration Configuration
        {
            get;
            private set;
        }


        public void Update(IPluginConfiguration configuration)
        {
            Configuration = configuration;
            //clientType = SamlCookieName;
            tokenProcessor = null; //reset the security token handler so we can regen it
        }

        public PropertyGroup[] ConfigurationOptions
        {
            get
            {
                var groups = new[] { new PropertyGroup("issuer", "Issuer", 0), new PropertyGroup("auth", "AuthN", 1), new PropertyGroup("logout", "Logout", 2), new PropertyGroup("options", "Options", 3) };

                #region Issuer

                var idpUrl = new Property("idpUrl", "The SAML Identity Provider URL", PropertyType.String, 10, _idpUrlDefault);
                idpUrl.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(idpUrl);

                var IdpBindingType = new Property("idpBindingType", "The SAML Binding Type Used by the Identity Provider", PropertyType.String, 20, _idpBindingTypeDefault.ToString());
                IdpBindingType.SelectableValues.Add(new PropertyValue(SamlBinding.SAML11_POST.ToString(), SamlBinding.SAML11_POST.ToString(), 1));
                IdpBindingType.SelectableValues.Add(new PropertyValue(SamlBinding.SAML20_POST.ToString(), SamlBinding.SAML20_POST.ToString(), 2));
                groups[0].Properties.Add(IdpBindingType);

                var issuerThumbprint = new Property("issuerThumbprint", "Issuer Certificate Thumbprints", PropertyType.String, 30, _issuerThumbprintDefault) { DescriptionText = "A comma seperated list of thumbprints used by the trusted issuer(s) (used to validate the SAML token)" };
                issuerThumbprint.Rules.Add(new PropertyRule(typeof(Telligent.Services.SamlAuthenticationPlugin.Components.CleanThumbprintRule), false));
                groups[0].Properties.Add(issuerThumbprint);

                var issuerCertificateValidationMode = new Property("issuerCertificateValidationMode", "Issuer Certificate Validation Mode", PropertyType.String, 40, _issuerCertificateValidationModeDefault.ToString()) { DescriptionText = "Validation of the SAML signing certificate issuer" };
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue(X509CertificateValidationMode.ChainTrust.ToString(), X509CertificateValidationMode.ChainTrust.ToString(), 1));
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue(X509CertificateValidationMode.PeerOrChainTrust.ToString(), X509CertificateValidationMode.PeerOrChainTrust.ToString(), 2));
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue(X509CertificateValidationMode.PeerTrust.ToString(), X509CertificateValidationMode.PeerTrust.ToString(), 3));
                issuerCertificateValidationMode.SelectableValues.Add(new PropertyValue(X509CertificateValidationMode.None.ToString(), X509CertificateValidationMode.None.ToString(), 4));
                groups[0].Properties.Add(issuerCertificateValidationMode);

                var subjectRecipientValidationMode = new Property("subjectRecipientValidationMode", "Token Subject Recipient Validation Mode", PropertyType.String, 50, _subjectRecipientValidationModeDefault.ToString()) { DescriptionText = "Rules to use for validation of SAML Token Subject Recipient clause" };
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue(SubjectRecipientValidationMode.ExactMatch.ToString(), SubjectRecipientValidationMode.ExactMatch.ToString(), 1));
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue(SubjectRecipientValidationMode.HostOnly.ToString(), SubjectRecipientValidationMode.HostOnly.ToString(), 2));
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue(SubjectRecipientValidationMode.HostAndScheme.ToString(), SubjectRecipientValidationMode.HostAndScheme.ToString(), 3));
                subjectRecipientValidationMode.SelectableValues.Add(new PropertyValue(SubjectRecipientValidationMode.None.ToString(), SubjectRecipientValidationMode.None.ToString(), 4));
                groups[0].Properties.Add(subjectRecipientValidationMode);

                var usernameClaim = new Property("usernameClaim", "User Name Attribute Name", PropertyType.String, 60, _usernameClaimDefault) { DescriptionText = "The name saml attribute containing the users name. (Must be present, must be unique, must be valid based on community settings.)" }; ;
                usernameClaim.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(usernameClaim);

                var emailClaim = new Property("emailClaim", "Email Address Attribute name", PropertyType.String, 70, _emailClaimDefault) { DescriptionText = "The name saml attribute containing the users email address. (Must be present, must be unique.)" };
                emailClaim.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[0].Properties.Add(emailClaim);

                #endregion

                #region AuthN

                var idpAuthRequestType = new Property("idpAuthRequestType", "AuthN Binding Type", PropertyType.String, 100, _idpAuthRequestTypeDefault.ToString()) { DescriptionText = "The AuthN request type to intiate the saml login (IDP_Initiated is a simple redirect without AuthN payload)" };
                idpAuthRequestType.SelectableValues.Add(new PropertyValue(AuthnBinding.IDP_Initiated.ToString(), AuthnBinding.IDP_Initiated.ToString(), 1));
                idpAuthRequestType.SelectableValues.Add(new PropertyValue(AuthnBinding.Redirect.ToString(), AuthnBinding.Redirect.ToString(), 2));
                //idpAuthRequestType.SelectableValues.Add(new PropertyValue(AuthnBinding.SignedRedirect.ToString(), AuthnBinding.SignedRedirect.ToString(), 3));  //not yet supported
                idpAuthRequestType.SelectableValues.Add(new PropertyValue(AuthnBinding.POST.ToString(), AuthnBinding.POST.ToString(), 4));
                idpAuthRequestType.SelectableValues.Add(new PropertyValue(AuthnBinding.SignedPOST.ToString(), AuthnBinding.SignedPOST.ToString(), 5));
                idpAuthRequestType.SelectableValues.Add(new PropertyValue(AuthnBinding.WSFededation.ToString(), AuthnBinding.WSFededation.ToString(), 6));
                groups[1].Properties.Add(idpAuthRequestType);

                var authThumbprint = new Property("authThumbprint", "AuthN Certificate Thumbprint", PropertyType.String, 110, _authThumbprintDefault) { DescriptionText = "The Thumbprint of a private key located in the localmachine/personal store, for which the applicaiton pool user has been given permissions; required for signed AuthN request types" };
                authThumbprint.Rules.Add(new PropertyRule(typeof(Telligent.Services.SamlAuthenticationPlugin.Components.CleanThumbprintRule), false));
                groups[1].Properties.Add(authThumbprint);


                #endregion

                #region Logout

                var logoutUrlBehavior = new Property("logoutUrlBehavior", "Logout Behavior", PropertyType.String, 200, _logoutUrlBehaviorDefault.ToString()) { DescriptionText = "Controls how the site uses the logout Url (Internal the URL is not used or requred; the default platform logout is used)" };
                logoutUrlBehavior.SelectableValues.Add(new PropertyValue(LogoutUrlBehavior.INTERNAL.ToString(), LogoutUrlBehavior.INTERNAL.ToString(), 1));
                logoutUrlBehavior.SelectableValues.Add(new PropertyValue(LogoutUrlBehavior.EXTERNAL.ToString(), LogoutUrlBehavior.EXTERNAL.ToString(), 2));
                logoutUrlBehavior.SelectableValues.Add(new PropertyValue(LogoutUrlBehavior.IFRAME.ToString(), LogoutUrlBehavior.IFRAME.ToString(), 3));
                groups[2].Properties.Add(logoutUrlBehavior);


                var logoutUrl = new Property("logoutUrl", "Identity Provider Logout Url", PropertyType.String, 210, _logoutUrlDefault) { DescriptionText = "Identity Provider Logout Url (used by Iframe or external options)" };
                logoutUrl.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[2].Properties.Add(logoutUrl);

                #endregion

                #region Options
                var allowTokenMatchingByEmailAddress = new Property("allowTokenMatchingByEmailAddress", "Lookup Users By Email", PropertyType.Bool, 50, _allowTokenMatchingByEmailAddressDefault.ToString()) { DescriptionText = "Allow the email address to be used to locate an existing user account if the username doesnt match." };
                groups[3].Properties.Add(allowTokenMatchingByEmailAddress);

                var persistClaims = new Property("persistClaims", "Persist Claims", PropertyType.Bool, 70, "false") { DescriptionText = "If checked, the claim collection will be stored in the database and be avaiable durning non login events." };
                groups[3].Properties.Add(persistClaims);

                var secureCookie = new Property("secureCookie", "Force HTTPS", PropertyType.Bool, 80, "true") { DescriptionText = "If checked, saml token data will be passed using a secure only (https cookie) uncheck only if your site doesnt support HTTPS (less secure)." };
                groups[3].Properties.Add(secureCookie);

                var iconUrl = new Property("iconUrl", "The URL for the OAuth image", PropertyType.String, 120, _iconUrlDefault) { DescriptionText = "overrides the built in SAML oauth image" };
                iconUrl.Rules.Add(new PropertyRule(typeof(Telligent.Evolution.Controls.PropertyRules.TrimStringRule), false));
                groups[3].Properties.Add(iconUrl);

                groups[3].Properties.Add(new Property("samlCookieName", "SAML Cookie Name", PropertyType.String, 3, "saml"));


                #endregion

                return groups;
            }
        }

        #endregion

        #region Lifecycle Events
        private void Events_AfterUserCreate(UserAfterCreateEventArgs e)
        {

            var afterCreatedCookie = CookieHelper.GetCookie(SamlCookieName);
            if (afterCreatedCookie == null) return;
            
            var samlTokenData = SamlTokenData.GetTokenDataFromDatabase(afterCreatedCookie.Value);
            if (samlTokenData == null) return; 

            //destroy secure cookie for new user if cookie is still present
            CookieHelper.DeleteCookie(afterCreatedCookie.Value);
            //also cleanup our afterCreatedCookie
            CookieHelper.DeleteCookie(afterCreatedCookie.Name);

            //update the samlTokenData now that we know the user ID and cleanup the cookie used by the login
            samlTokenData.UserId = e.Id.Value;

            //Update the cookie SAMLToken Data to have the UserId now that its an existing user to fire the after authenticated events (which also removes the cookie)
            var tokenKey = samlTokenData.SaveTokenDataToDatabase();
            var afterAuthenticatedCookie = new HttpCookie(clientType, tokenKey)
            {
                Expires = DateTime.Now.AddHours(8), 
                HttpOnly = true
            };
            CookieHelper.AddCookie(afterAuthenticatedCookie);

            if (PersistClaims)
            {
                SqlData.SaveSamlToken(samlTokenData);
            }

            var apiUser = _usersApi.Get(new UsersGetOptions() { Id = e.Id.Value });

            //raise new SamlUserCreated Event
            try
            {
                SamlEvents.Instance.OnAfterUserCreate(apiUser, samlTokenData);
            }
            catch (Exception ex)
            {
                _eventLogApi.Write("SamlOAuthClient Error OnAfterUserCreate: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error"  });
            }

        }

        void Events_AfterIdentify(UserAfterIdentifyEventArgs e)
        {

            var context = HttpContext.Current;
            if (context == null) return;
            if (context.Request == null) return;
            if (!context.Request.IsAuthenticated) return;

            //filter some requests basic non UI requests
            if (context.Request.RawUrl.ToLower().StartsWith("/socket.ashx")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/webresource.axd")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/api.ashx")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/utility/")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/cfs-filesystemfile/")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/dynamic-style")) return;
            if (context.Request.RawUrl.ToLower().StartsWith("/favicon.ico")) return;
            if (context.Request.RawUrl.ToLower().EndsWith(".css")) return;

            //check to see if our Oauth ProcessLogin() cookie exists
            try
            {
                var afterAuthenticatedCookie = CookieHelper.GetCookie(clientType);
                if (afterAuthenticatedCookie == null) return;

                var samlTokenData = SamlTokenData.GetTokenDataFromDatabase(afterAuthenticatedCookie.Value);
                if (samlTokenData == null) return;

                if (!samlTokenData.IsExistingUser()) return;

                if (samlTokenData.UserId != e.Id.Value) return;  //check to see that the logged in user and ProcessLogin() user have the same ID;

                if (Guid.TryParse(afterAuthenticatedCookie.Value, out var tokenKey))
                    SamlTokenData.DeleteTokenDataFromDatabase(afterAuthenticatedCookie.Value);

                CookieHelper.DeleteCookie(afterAuthenticatedCookie.Value);
                CookieHelper.DeleteCookie(afterAuthenticatedCookie.Name);

                //Get the API user and the last SAML token to keep things API friendly
                var apiUser = _usersApi.Get(new UsersGetOptions() { Id = e.Id.Value });

                SamlEvents.Instance.OnAfterAuthenticate(apiUser, samlTokenData);
            }
            catch (Exception ex)
            {
                _eventLogApi.Write("SamlOAuthClient Error OnAfterAuthenticate: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
            }

        }

        private void Events_AfterUserDelete(UserAfterDeleteEventArgs e)
        {
            try
            {
                SqlData.DeleteSamlTokenData(e.Id.Value);
            }
            catch (Exception ex)
            {
                _eventLogApi.Write("SamlOAuthClient Error AfterUserDelete: " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
            }
        }

        #endregion

        #region Properties

        public string LoginUrl => SecureCookie ? _urlApi.Absolute("~/samlauthn").Replace("http:", "https:") : _urlApi.Absolute("~/samlauthn");
        public string IdpUrl => Configuration.GetString("idpUrl");
        public SamlBinding IdpBindingType => Enum.TryParse(Configuration.GetString("idpBindingType"), true, out SamlBinding configuredBinding) ? configuredBinding : _idpBindingTypeDefault;
        public AuthnBinding IdpAuthRequestType => Enum.TryParse<AuthnBinding>(Configuration.GetString("idpAuthRequestType"), true, out var configuredBinding) ? configuredBinding : _idpAuthRequestTypeDefault;
        public LogoutUrlBehavior LogoutUrlBehavior => Enum.TryParse<LogoutUrlBehavior>(Configuration.GetString("logoutUrlBehavior"), true, out var configuredBehavior) ? configuredBehavior : _logoutUrlBehaviorDefault;
        public string LogoutUrl => LogoutUrlBehavior == LogoutUrlBehavior.EXTERNAL ? IdpLogoutUrl : string.Empty;
        public string IdpLogoutUrl => IdpAuthRequestType == AuthnBinding.WSFededation ? $"{IdpUrl}?wa=wsignout1.0" : Configuration.GetString("logoutUrl");
        public string AuthNCertThumbrint => Configuration.GetString("authThumbprint");
        public string SamlCookieName => Configuration.GetString("samlCookieName");
        public string clientType => string.IsNullOrEmpty(Configuration.GetString("samlCookieName")) ? "saml" : Configuration.GetString("samlCookieName");


        /// <summary>
        /// This property is used by the platform to store the current url the user was on when they clicked login or register
        /// The platform code does not ever redirect the user to this URL, its up to the AuthenticationPlugin to handle redirection
        /// In our case its important that our AuthN handler packages this return url in a way that will persist though saml auth for use
        /// at the end of our AuthenticateRequest() method.
        /// </summary>
        public string ReturnUrlParameter => SamlHelpers.ReturnUrlParameterName;
        public bool AllowTokenMatchingByEmailAddress => Configuration.GetBool("allowTokenMatchingByEmailAddress");
        //required by IAuthenticationPlugin
        public bool UseHttpContextUser => true;
        public string UserNameAttributeName => Configuration.GetString("usernameClaim");
        public string EmailAttributeName => Configuration.GetString("emailClaim");
        public bool PersistClaims => Configuration.GetBool("persistClaims");
        public bool SecureCookie => Configuration.GetBool("secureCookie");
        public X509CertificateValidationMode CertificateValidationMode => Enum.TryParse<X509CertificateValidationMode>(Configuration.GetString("issuerCertificateValidationMode"), true, out var configuredValidationMode) ? configuredValidationMode : _issuerCertificateValidationModeDefault;
        public SubjectRecipientValidationMode SubjectRecipientValidationMode => Enum.TryParse<SubjectRecipientValidationMode>(Configuration.GetString("subjectRecipientValidationMode"), true, out var configuredValidationMode) ? configuredValidationMode : _subjectRecipientValidationModeDefault;
        public string TrustedIssuerThumbprint => Configuration.GetString("issuerThumbprint");
        public int ProfileRefreshInterval => 1;
        
        object _lock = new object();

        private TokenProcessor tokenProcessor = null;
        public TokenProcessor TokenProcessor
        {
            get
            {
                if (tokenProcessor == null)
                {
                    lock (_lock)
                    {
                        if (tokenProcessor == null)
                        {
                            tokenProcessor = new TokenProcessor(this);
                        }
                    }
                }
                return tokenProcessor;
            }
        }

        #endregion

        #region INavigable

        public void RegisterUrls(IUrlController controller)
        {
            controller.AddRaw("samlresponse", "samlresponse", null, new { handlerHeader = new RequestTypeHandlerMethodConstraint("GET", "POST") },
               (c, p) =>
               {
                   var handler = new SamlResponseHandler();
                   handler.ProcessRequest(c.ApplicationInstance.Context);
               },
               new RawDefinitionOptions()
           );

            controller.AddRaw("samlauthn", "samlauthn", null, new { handlerHeader = new RequestTypeHandlerMethodConstraint("GET", "POST") },
               (c, p) =>
               {
                   var handler = new SamlAuthnHandler();
                   handler.ProcessRequest(c.ApplicationInstance.Context);
               },
               new RawDefinitionOptions()
           );

            controller.AddPage("saml-logout", "samllogout", null, null, "saml-logout", new PageDefinitionOptions() { DefaultPageXml = LoadPageXml("SamlLogout-Social-Site-Page") });



        }

        private static string LoadPageXml(string pageName)
        {
            var xml = new XmlDocument();
            xml.LoadXml(EmbeddedResources.GetString("Telligent.Services.SamlAuthenticationPlugin.Resources.Pages." + pageName + ".xml"));
            var xmlNode = xml.SelectSingleNode("theme/contentFragmentPages/contentFragmentPage");
            return xmlNode != null ? xmlNode.OuterXml : String.Empty;
        }

        #endregion

        #region Authentication
        
        protected virtual void ProcessReturnUrl()
        {
            var returnUrl = SamlHelpers.GetCookieReturnUrl();

            SamlHelpers.ClearCookieReturnUrl();

            if (string.IsNullOrEmpty(returnUrl))
            {
                returnUrl = _coreUrlsApi.Home();
            }

            if (!string.IsNullOrEmpty(returnUrl) && SamlHelpers.IsPathOnSameServer(returnUrl, HttpContext.Current.Request.Url))
                HttpContext.Current.Response.Redirect(returnUrl, true);

            HttpContext.Current.Response.Redirect(_coreUrlsApi.Home(), true);
        }



        #endregion

        #region IOAuthClient

        /// <summary>
        /// Used if no returnurl is present on the querystring, its important that any return url points back to the login page
        /// For OAuth processing to work properly, any further reuturn url must be encoded
        /// </summary>
        public string CallbackUrl
        {
            get
            {
                return _coreUrlsApi.LogIn(new CoreUrlLoginOptions() { ReturnToCurrentUrl = false }) + "?oauth_data_token_key=TOKEN";
            }
            set
            {

            }
        }

        public string ClientLogoutScript
        {
            get
            {
                //Identity server (wsfed?wa=signout1.0) sends request "samlresponse/wa=wsignoutcleanup1.0"(passive logout) and after that we should just reload page
                if (LogoutUrlBehavior == LogoutUrlBehavior.IFRAME && IdpAuthRequestType == AuthnBinding.WSFededation)
                    return String.Format(@"<div style=""display:none""><iframe id=""saml-logout"" width=""0"" height=""0"" src=""{0}"" onload=""window.location.reload();""></iframe></div>", IdpLogoutUrl);

                if (LogoutUrlBehavior == LogoutUrlBehavior.IFRAME)
                    return String.Format(@"<div style=""display:none""><iframe id=""saml-logout"" width=""0"" height=""0"" src=""{0}"" onload=""jQuery(document).trigger('oauthsignout');""></iframe></div>", IdpLogoutUrl);

                if (LogoutUrlBehavior == LogoutUrlBehavior.EXTERNAL && IdpAuthRequestType == AuthnBinding.WSFededation && !string.IsNullOrWhiteSpace(IdpLogoutUrl))
                    return String.Format(@"<script type='text/javascript'>window.location='{0}&wreply={1}';</script>", IdpLogoutUrl, _urlApi.Absolute("~/logout"));

                return string.Empty;
            }
        }

        public string ClientName
        {
            get { return PluginName; }
        }

        public string ClientType
        {
            get { return clientType; }
        }

        public string ConsumerKey
        {
            get { return string.Empty; }
        }

        public string ConsumerSecret
        {
            get { return string.Empty; }
        }

        public bool Enabled
        {
            get { return true; }
        }

        public string GetAuthorizationLink()
        {
            //append the current querystring to the login url
            try
            {
                if (HttpContext.Current != null && HttpContext.Current.Request != null)
                {
                    var currentUrlParts = HttpContext.Current.Request.RawUrl.Split('?');
                    if (currentUrlParts.Length > 0) //we have a querstring
                    {
                        if (LoginUrl.Contains("?"))
                            return string.Concat(LoginUrl, "&", currentUrlParts[1]);

                        return string.Concat(LoginUrl, "?", currentUrlParts[1]);
                    }
                }
            }
            catch { }
            return LoginUrl;
        }

        public string IconUrl
        {
            get
            {
                try
                {
                    var configuredIconUrl = Configuration.GetString("iconUrl");
                    if (!string.IsNullOrEmpty(configuredIconUrl))
                        return configuredIconUrl;

                    return SamlHelpers.GetWebResourceUrl(this.GetType(), "Telligent.Services.SamlAuthenticationPlugin.Resources.Images.saml.png");
                }
                catch
                {
                    return SamlHelpers.GetWebResourceUrl(this.GetType(), "Telligent.Services.SamlAuthenticationPlugin.Resources.Images.saml.png");
                }
            }
        }

        public string Privacy
        {
            get { return string.Empty; }
        }


        public OAuthData ProcessLogin(HttpContextBase context)
        {
            var apiExceptions = Apis.Get<IExceptions>();
            if (!Enabled)
                return null;

            //should have a SamlOAuthClient.oauthTokeyQuerystringKey which corresponds to the current cookie to decrypt
            var tokenKey = HttpContext.Current.Request[oauthTokeyQuerystringKey];
            if (!string.IsNullOrEmpty(tokenKey))
            {
                var samlTokenData = SamlTokenData.GetTokenDataFromDatabase(tokenKey);
                if (samlTokenData == null)
                {
                    apiExceptions.Log(new ArgumentException(
                        "The SAML token was not found in the HttpContext.Current.Request, or could not be extracted.  Please ensure cookies are enabled and try again."));

                    ProcessReturnUrl();
                }

                //Store our token key so we can retrieve it later to raise the SamlUserCreated and SamlAuthenticated events and delete it
                var afterAuthenticatedCookie = new HttpCookie(clientType, tokenKey) {HttpOnly = true, Expires = DateTime.Now.AddHours(8)};
                CookieHelper.AddCookie(afterAuthenticatedCookie);
                
                //this object is stored in temporary storage by the oauth handler, its guid is placed into the return url into the "TOKEN" placeholder.
                //the expectation of this processing is the return url at this time is to the login page, and that any login based return url should be double encoded
                return samlTokenData.GetOAuthData();

            }

            //if this is not a sign-in response, we should probably redirect to login.aspx
            apiExceptions.Log(new ArgumentException("The SAML token was not found in the HttpContext.Current.Request, please check the configuration and try again"));
            return null;
        }
        
        public string ThemeColor
        {
            get { return "006699"; }
        }

        #endregion

        #region IScriptedContentFragmentFactoryDefaultProvider Members

        private readonly Guid Identifier = new Guid("a699e912b5654ef98d195877c8f9eb41");

        public Guid ScriptedContentFragmentFactoryDefaultIdentifier
        {
            get { return Identifier; }
        }

        #endregion

        #region IInstallablePlugin Members

        object lockObject = new object();

        private void InitializeScheama()
        {
            if (PersistClaims)
            {
                lock (lockObject)
                {
                    try
                    {
                        //Ensure SAML SQL tables are present
                        if (!SqlData.IsInstalled())
                            SqlData.Install();
                        else if (SqlData.NeedsUpgrade())
                            SqlData.Upgrade();
                    }
                    catch (Exception ex)
                    {
                        _eventLogApi.Write("SamlOAuthClient Error InitializeScheama (you may need to manually run the sql install script): " + ex.Message + " : " + ex.StackTrace, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 1, EventType = "Error" });
                    }
                }
            }
        }

        //notes on guids
        //evolutionGuid = "aa8056256ecb481bae92f2db9f87e893";
        //fijiGuid = "7e987e474b714b01ba29b4336720c446";
        //socialGuid = "3fc3f82483d14ec485ef92e206116d49";
        //enterpriseGuid = "424eb7d9138d417b994b64bff44bf274";

        //blogThemeTypeID = new Guid("a3b17ab0-af5f-11dd-a350-1fcf55d89593");
        //groupThemeTypeID = new Guid("c6108064-af65-11dd-b074-de1a56d89593");
        //siteThemeTypeID = new Guid("0c647246-6735-42f9-875d-c8b991fe739b");
        void IInstallablePlugin.Install(Version lastInstalledVersion)
        {
            #region Install Widgets

            FactoryDefaultScriptedContentFragmentProviderFiles.DeleteAllFiles(this);

            //install default widgets and supplementary files
            var definitionFiles = new string[] {
                "SamlLoginAutoSelect-Widget.xml"
                ,"SamlLogout-Widget.xml"
            };

            foreach (var definitionFile in definitionFiles)
                using (var stream = EmbeddedResources.GetStream("Telligent.Services.SamlAuthenticationPlugin.Resources.Widgets." + definitionFile))
                    FactoryDefaultScriptedContentFragmentProviderFiles.AddUpdateDefinitionFile(this, definitionFile, stream);

            ContentFragments.Enable(ThemeTypes.Site, ContentFragments.GetScriptedContentFragmentTypeString(new Guid("63b5fbf0d2db41eaa165c27ac43ee0f7"))); //Login Auto Select
            ContentFragments.Enable(ThemeTypes.Site, ContentFragments.GetScriptedContentFragmentTypeString(new Guid("31728beb334e420e84200cc6f81d109c"))); //Logout

            #endregion

            #region Insert Widgets Into existing themes and pages

            foreach (var theme in Themes.List(ThemeTypes.Site))
            {

                //add the saml auto select widget to the login page

                if (theme.Name == "3fc3f82483d14ec485ef92e206116d49")
                {
                    //Add CaseList to User profile page after Activity List
                    InsertWidget(theme
                        , "common-login"
                        , false
                        , "Telligent.Evolution.ScriptedContentFragments.ScriptedContentFragment, Telligent.Evolution.ScriptedContentFragments::b1db6b71c0be43b58925e469eb6315a4"
                        , ContentFragmentPlacement.Before
                        , "content"
                        , "Telligent.Evolution.ScriptedContentFragments.ScriptedContentFragment, Telligent.Evolution.ScriptedContentFragments::63b5fbf0d2db41eaa165c27ac43ee0f7"
                        , ""
                        , "no-wrapper responsive-1");
                }
            }


            #endregion

            #region Create Database Table if required
            InitializeScheama();
            #endregion
        }

        void InsertWidget(Evolution.Extensibility.UI.Version1.Theme theme, string pageName, bool isCustom, string existingContentFragmentType, ContentFragmentPlacement placement, string regionName, string contentFragmentType, string contentFragmentConfiguration, string contentFragmentWrappingFormat)
        {
            ThemePageContentFragments.RemoveFromDefault(theme, pageName, isCustom, contentFragmentType);
            ThemePageContentFragments.InsertInDefault(theme, pageName, isCustom, existingContentFragmentType, placement, regionName, contentFragmentType, contentFragmentConfiguration, contentFragmentWrappingFormat);
        }

        void IInstallablePlugin.Uninstall()
        {

            #region Remove Widget Files

            FactoryDefaultScriptedContentFragmentProviderFiles.DeleteAllFiles(this);

            #endregion

        }

        Version IInstallablePlugin.Version
        {
            get { return GetType().Assembly.GetName().Version; }
        }
        #endregion

        public string[] Categories
        {
            get { return PluginCategories.ToArray(); }
        }
    }
}

