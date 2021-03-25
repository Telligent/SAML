using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Xml;
using System.Xml.Serialization;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;
using System.IO;
using System.Globalization;
using Telligent.Evolution.Extensibility;

namespace Telligent.Services.SamlAuthenticationPlugin
{
    public static class SamlHelpers
    {
        public const string ReturnUrlCookieName = "SamlAuthenticationReturnUrl";
        public const string ReturnUrlParameterName = "ReturnUrl";
        public const string InvitationKeyParameterName = "InvitationKey";
        public static string[] ExtensionPluginCategories = { "SAML", "External Authentication", "SAML Extension" }; //leverage this for extensions to make them easier to find

        public static bool IsSignInResponse
        {
            get
            {
                var request = HttpContext.Current.Request;
                if (request == null || request.Form == null || (request.Form["SAMLResponse"] == null
                    && !(request.Form["wresult"] != null && request.Form["wa"] != null && request.Form["wa"].Equals("wsignin1.0", StringComparison.InvariantCultureIgnoreCase))))
                {
                    return false;
                }
                return true;
            }
        }

        public static bool IsSignOutResponse
        {
            get
            {
                var request = HttpContext.Current.Request;
                if (request == null || request.QueryString == null || request.QueryString["wa"] == null || !request.QueryString["wa"].Equals("wsignoutcleanup1.0", StringComparison.InvariantCultureIgnoreCase))
                {
                    return false;
                }
                return true;
            }
        }

        public static XmlDocument SignInResponse
        {
            get
            {
                if (IsSignInResponse)
                {
                    var request = HttpContext.Current.Request;
                    string xmlTokenFromMessage =request.Form["wresult"] ??
                       Encoding.UTF8.GetString(
                           Convert.FromBase64String(request.Form["SAMLResponse"]));

                    XmlDocument samlResponse = new XmlDocument();
                    samlResponse.PreserveWhitespace = true;
                    samlResponse.LoadXml(xmlTokenFromMessage);

                    return samlResponse;
                }
                return null;
            }
        }
        
        public static ClaimsPrincipal ClaimsPrincipalContextItem
        {
            get
            {
                return (ClaimsPrincipal)HttpContext.Current.Items[typeof(ClaimsPrincipal)];
            }
            set
            {
                if (HttpContext.Current.Items[typeof(ClaimsPrincipal)] != null)
                {
                    HttpContext.Current.Items[typeof(ClaimsPrincipal)] = value;
                }
                else
                {
                    HttpContext.Current.Items.Add(typeof(ClaimsPrincipal), value);
                }

            }
        }

        public static SamlTokenData SamlTokenDataContextItem
        {
            get
            {
                return (SamlTokenData)HttpContext.Current.Items[typeof(SamlTokenData)];
            }
            set
            {
                if (HttpContext.Current.Items[typeof(SamlTokenData)] != null)
                {
                    HttpContext.Current.Items[typeof(SamlTokenData)] = value;
                }
                else
                {
                    HttpContext.Current.Items.Add(typeof(SamlTokenData), value);
                }

            }

        }

        private static void storeIClaimsPrincipalInContextItems(IEnumerable<ClaimsIdentity> identites)
        {
            ClaimsPrincipalContextItem = new ClaimsPrincipal(identites);
        }

        private static Page CachedPage
        {
            get
            {
                if (_CachedPage == null)
                    _CachedPage = new Page();
                return _CachedPage;
            }
        }
        private static Page _CachedPage;

        public static string GetWebResourceUrl(Type type, string resource)
        {
            return CachedPage.ClientScript.GetWebResourceUrl(type, resource);
        }
        
        #region Return Url

        public static void SetCookieReturnUrl(string returnUrl, Guid? invitationKey)
        {
            var returnUrlCookie = new HttpCookie(ReturnUrlCookieName);
            returnUrlCookie.Values[ReturnUrlParameterName] = returnUrl;
            if (invitationKey.HasValue && invitationKey.Value != Guid.Empty)
                returnUrlCookie.Values[InvitationKeyParameterName] = invitationKey.Value.ToString();

            HttpContext.Current.Response.Cookies.Add(returnUrlCookie);
        }


        public static string GetCookieReturnUrl()
        {
            var returnUrlCookie = HttpContext.Current.Request.Cookies[ReturnUrlCookieName];
            if (returnUrlCookie != null && returnUrlCookie.Values[ReturnUrlParameterName] != null && !string.IsNullOrEmpty(returnUrlCookie.Values[ReturnUrlParameterName]))
            {
                return returnUrlCookie.Values[ReturnUrlParameterName];
            }

            return null;
        }

        public static string GetReturnUrl()
        {
            string returnUrl = GetCookieReturnUrl();
            if (string.IsNullOrEmpty(returnUrl)) //try the querystring if its not in the cookie
                returnUrl = HttpUtility.UrlEncode(HttpContext.Current.Request[ReturnUrlParameterName]);
            if (string.IsNullOrEmpty(returnUrl)) //site root if its not in the cookie or querystring
            {
                var currentUrl = HttpContext.Current.Request.Url.PathAndQuery.Contains("samlauthn") ? "/" : HttpContext.Current.Request.Url.PathAndQuery;
                
                returnUrl = !string.IsNullOrEmpty(currentUrl) ? HttpUtility.UrlEncode(currentUrl) : "/";
            }

            return returnUrl;
        }

        public static string GetInvitationKey()
        {
            //Invitation Key
            string invitationKey = GetCookieInvitationKey().HasValue ? GetCookieInvitationKey().ToString() : null;
            // if we didnt get an invitation key from the cookie, we can check the return url
            if (string.IsNullOrEmpty(invitationKey) && !string.IsNullOrEmpty(GetReturnUrl()))
            {
                invitationKey = GetKeyValueFromUrlFragment(GetReturnUrl(), InvitationKeyParameterName);
            }

            return invitationKey;
        }

        public static string GetKeyValueFromUrlFragment(string urlFragment, string key)
        {

            if (string.IsNullOrEmpty(urlFragment) || string.IsNullOrEmpty(key))
                return null;
             

            try
            {
                urlFragment = HttpUtility.UrlDecode(urlFragment);

                if (string.IsNullOrEmpty(urlFragment) || !urlFragment.Contains("?")) //empty or no querystring to parse
                    return null;

                //if the url is more than a querystring we need to just extract the querystring
                if (urlFragment.Contains("?") && !urlFragment.StartsWith("?"))
                {
                    //trim it down (we probably could do this with new Uri(urlFragment); instead)
                    urlFragment = urlFragment.Split('?')[1];
                }

                NameValueCollection query = HttpUtility.ParseQueryString(urlFragment);

                if (!query[key].Equals(Guid.Empty.ToString(), StringComparison.InvariantCultureIgnoreCase))
                    return query[key];
            }
            catch (Exception ex)
            {
                Apis.Get<IEventLog>().Write(string.Format("ERROR trying to extract key {0} from return url provided:{1} - {2}" , key, urlFragment, ex.ToString()), new EventLogEntryWriteOptions() { Category="SAML", EventId=6018, EventType="Error" });
            }

            return null;
        }

        public static Guid? GetCookieInvitationKey()
        {
            try
            {
                HttpCookie returnUrlCookie = HttpContext.Current.Request.Cookies[ReturnUrlCookieName];
                if (returnUrlCookie != null && returnUrlCookie.Values[InvitationKeyParameterName] != null &&
                    !string.IsNullOrEmpty(returnUrlCookie.Values[InvitationKeyParameterName]))
                {

                    var paresedGuid = Guid.Parse(returnUrlCookie.Values[InvitationKeyParameterName]);
                    if (paresedGuid != Guid.Empty)
                        return paresedGuid;

                }
            }
            catch (Exception ex) 
            {
                Apis.Get<IEventLog>().Write("ERROR trying to extract Invitation from cookie:" + ex.ToString(), new EventLogEntryWriteOptions() { Category = "SAML", EventId = 6019, EventType = "Error" });
            }

            return null;
        }

        internal static bool IsPathOnSameServer(string absUriOrLocalPath, Uri currentRequestUri)
        {
            if (Uri.TryCreate(absUriOrLocalPath, UriKind.Absolute, out var uri) && !uri.IsLoopback)
            {
                var urlIsOnSameServer = string.Equals(currentRequestUri.Host, uri.Host, StringComparison.OrdinalIgnoreCase);
                return urlIsOnSameServer;
            }
            return true;
        }

        public static void ClearCookieReturnUrl()
        {
            var responseCookie = HttpContext.Current.Response.Cookies[ReturnUrlCookieName];
            if (responseCookie != null)
                responseCookie.Expires = DateTime.Now.AddYears(-30);
        }
        #endregion

        #region Invitation Key

        public static bool HasValidInvitationKey(string returnUrl)
        {
            Guid invitationKey = GetInvitationKeyfromQueryString(returnUrl);
            if (invitationKey == Guid.Empty) return false;

            return IsValidInvitationKey(invitationKey);
        }

        public static bool IsValidInvitationKey(Guid invitationKey)
        {
            try
            {

                //check to see that the invitation is present and valid
                var invite = Apis.Get<IUserInvitations>().Get(invitationKey);
                if(invite != null)
                    return !invite.HasErrors();

            }
            catch (Exception)
            {

            }

            return false;
        }


        public static Guid GetInvitationKeyFromUrl()
        {
            //look in both InvitationKey and ReturnUrl for invitation
            if (HttpContext.Current == null) return Guid.Empty;

            string invitationKeyString = null;
            if (!string.IsNullOrEmpty(HttpContext.Current.Request.QueryString[InvitationKeyParameterName]))
                invitationKeyString = HttpContext.Current.Request.QueryString[InvitationKeyParameterName];

            if (string.IsNullOrEmpty(invitationKeyString) && !string.IsNullOrEmpty(HttpContext.Current.Request.QueryString[ReturnUrlParameterName]))
                invitationKeyString = GetKeyValueFromUrlFragment(HttpContext.Current.Request.QueryString[ReturnUrlParameterName],
                                                                 InvitationKeyParameterName);

            if (string.IsNullOrEmpty(invitationKeyString)) return Guid.Empty;

            Guid invitationKey;
            if (Guid.TryParse(invitationKeyString, out invitationKey))
            {
                return invitationKey;
            }

            return Guid.Empty;
        }

        public static Guid GetInvitationKeyfromQueryString(string urlFragment)
        {
            Guid invitationKey;

            string invitationStr = GetKeyValueFromUrlFragment(urlFragment, InvitationKeyParameterName);
            if (Guid.TryParse(invitationStr, out invitationKey))
                return invitationKey;

            return Guid.Empty;

        }
        #endregion

        /// <summary>
        /// Write out hex for the thumbprint characters to make it easier to debug any non printing charcacters
        /// </summary>
        /// <param name="source"></param>
        /// <returns></returns>
        public static string ToCompositeString(string source)
        {
            var builder = new StringBuilder();
            foreach (var c in source.ToCharArray())
                builder.Append(String.Format(@"\x{0:x4}", (ushort)c));

            return builder.ToString();
        }

        public static string Protect(string text, string purpose)
        {
            if (string.IsNullOrEmpty(text))
                return null;

            byte[] stream = Encoding.UTF8.GetBytes(text);
            byte[] encodedValue = MachineKey.Protect(stream, purpose);
            return HttpServerUtility.UrlTokenEncode(encodedValue);
        }

        public static string Unprotect(string text, string purpose)
        {
            if (string.IsNullOrEmpty(text))
                return null;

            byte[] stream = HttpServerUtility.UrlTokenDecode(text);
            byte[] decodedValue = MachineKey.Unprotect(stream, purpose);
            return Encoding.UTF8.GetString(decodedValue);
        }

        /// <summary>
        /// Converts a .NET object to a string of XML. The object must be marked as Serializable or an exception
        /// will be thrown.
        /// </summary>
        /// <param name="objectToConvert">Object to convert</param>
        /// <returns>A xml string represting the object parameter. The return value will be null of the object is null</returns>
        public static string ConvertToString(object objectToConvert)
        {
            string xml = null;

            if (objectToConvert != null)
            {
                //we need the type to serialize
                Type t = objectToConvert.GetType();

                XmlSerializer ser = new XmlSerializer(t);
                //will hold the xml
                using (StringWriter writer = new StringWriter(CultureInfo.InvariantCulture))
                {
                    ser.Serialize(writer, objectToConvert);
                    xml = writer.ToString();
                    writer.Close();
                }
            }

            return xml;
        }
        /// <summary>
        /// Deserializes xml to object of type T
        /// </summary>
        /// <typeparam name="T">the type of the object</typeparam>
        /// <param name="xml">the xml representation of the object</param>
        /// <returns>a new instance of the object</returns>
        public static T Deserialize<T>(string xml) where T : new()
        {
            T customType = new T();

            XmlSerializer serializer = new XmlSerializer(typeof(T));

            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.LoadXml(xml);

            XmlNodeReader xmlNodeReader = new XmlNodeReader(xmlDocument);

            customType = (T)serializer.Deserialize(xmlNodeReader);

            return customType;
        }


        /// <summary>
        /// Adds a string to the current url determining the correct seperator character
        /// </summary>
        /// <param name="url"></param>
        /// <param name="querystring"></param>
        /// <returns></returns>
        public static string AppendQuerystring(string url, string querystring)
        {
            return AppendQuerystring(url, querystring, false);
        }
        public static string AppendQuerystring(string url, string querystring, bool urlEncoded)
        {
            string seperator = "?";
            if (url.IndexOf('?') > -1)
            {
                if (!urlEncoded)
                    seperator = "&";
                else
                    seperator = "&amp;";
            }
            return string.Concat(url, seperator, querystring);
        }
    }
}
