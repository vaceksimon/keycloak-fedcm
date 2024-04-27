package org.keycloak.fedcm;

import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * This class implements all the FedCM endpoint which are realm-based. It contains the business logic for serving the endpoints,
 * and retrieving data for it.
 *
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
public class FedCMProvider implements RealmResourceProvider {

    /**
     * Values representing relevant errors encountered during identity assertion.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">OAuth 2.0 Error Response</a>
     */
    private enum ErrorTypes {
        /** Error encountered when the client ID is unknown or the registered urls do not match */
        unauthorized_client,
        /** Error encountered when there is not user authenticated with Keycloak */
        access_denied,
        /** Error encountered when the supplied user ID does not match to the ID of an authenticated user */
        invalid_request;

        /**
         * Returns a jax-rs response corresponding to the enum value.
         *
         * @return a status code corresponding to the error type
         */
        public Response.Status getResponse() {
            if (this == unauthorized_client) {
                return Response.Status.UNAUTHORIZED;
            }
            else if (this == access_denied) {
                return Response.Status.FORBIDDEN;
            }
            else {
                return Response.Status.BAD_REQUEST;
            }
        }
    }

    /** A Keycloak session is created per request */
    private final KeycloakSession session;

    public FedCMProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    /**
     * The config file serves as a discovery device to other FedCM API endpoints provided by Keycloak.
     *
     * @see <a href="https://fedidcg.github.io/FedCM/#idp-api-config-file">FedCM API The Config File endpoint</a>
     * @return map of a Keycloak FedCM configuration file convertible to <a href="https://fedidcg.github.io/FedCM/#dictdef-identityproviderapiconfig">IdentityProviderAPIConfig</a>
     */
    @GET
    @Path(FedCMUtils.ENDPOINTCONFIG)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchConfigFile() {
        // check for the Sec-Fetch-Dest header
        FedCMUtils.checkRequestHeader(session);

        // dynamically get Keycloak's url
        URI requestURI = session.getContext().getUri().getRequestUri();
        String fedcmPath = requestURI.resolve(".").toString();
        String realmPath = requestURI.resolve("..").toString();

        // prepare a JSON with the rest of Keycloak's FedCM endpoints
        Map<String, Object> fedCMEndpoints = new HashMap<>();
        fedCMEndpoints.put("accounts_endpoint", fedcmPath + FedCMUtils.ENDPOINTACCOUNTS);
        fedCMEndpoints.put("client_metadata_endpoint", fedcmPath + FedCMUtils.ENDPOINTMETADATA);
        fedCMEndpoints.put("id_assertion_endpoint", fedcmPath + FedCMUtils.ENDPOINTIDASSERT);
        fedCMEndpoints.put("login_url", realmPath + "account");
        fedCMEndpoints.put("disconnect_endpoint", fedcmPath + FedCMUtils.ENDPOINTDISCONNECT);
        fedCMEndpoints.put("branding", getBranding());

        return Response.ok(fedCMEndpoints).type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * The accounts endpoint provides an account of a user authenticated with Keycloak
     *
     * @see <a href="https://fedidcg.github.io/FedCM/#idp-api-accounts-endpoint">FedCM API Accounts endpoint</a>
     * @return map of user information convertible to <a href="https://fedidcg.github.io/FedCM/#dictdef-identityprovideraccount">IdentityProviderAccount</a>
     */
    @GET
    @Path(FedCMUtils.ENDPOINTACCOUNTS)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchAccountsList() {
        // check for the Sec-Fetch-Dest header
        FedCMUtils.checkRequestHeader(session);

        // with the cookies sent in the request and kept in KeycloakContext get authentication information
        AuthResult authResult = (new AuthenticationManager()).authenticateIdentityCookie(session, session.getContext().getRealm());
        if (authResult == null) { // user is probably not authenticated
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        // prepare a JSON with user account information
        UserModel user = authResult.getUser();
        Map<String, Object> account = getUserAccount(user);

       Map<String, Object> accList = new HashMap<>();
        accList.put("accounts", List.of(account));
        return Response.ok(accList).type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * The client metadata endpoint provides metadata about a registered client at Keycloak. The client must exist
     *
     * @see <a href="https://fedidcg.github.io/FedCM/#idp-api-client-id-metadata-endpoint">FedCM API Client Metadata endpoint</a>
     * @param origin client header origin
     * @param clientId Keycloak specific client ID
     * @return map of client metadata convertible to <a href="https://fedidcg.github.io/FedCM/#dictdef-identityproviderclientmetadata">IdentityProviderClientMetadata</a>
     */
    @GET
    @Path(FedCMUtils.ENDPOINTMETADATA)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchClientMetadata(@HeaderParam("Origin") String origin, @QueryParam("client_id") String clientId) {
        // check for the Sec-Fetch-Dest header
        FedCMUtils.checkRequestHeader(session);

        // get client from registered in a realm
        ClientModel client = session.getContext().getRealm().getClientByClientId(clientId);
        if(client == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        if (!client.getRootUrl().equals(origin)) { // ensure client origin matches the registered origin
            return idAssertError(ErrorTypes.unauthorized_client);
        }

        // prepare a JSON with client metadata saved during client registration
        RoleModel role = client.getRole("policies");
        if (role == null) { // no policies returned is a valid response
           return Response.ok().type(MediaType.APPLICATION_JSON).build();
        }

        Map<String, String> metadata = new HashMap<>();
        metadata.put("privacy_policy_url", role.getFirstAttribute("privacy-policy"));
        metadata.put("terms_of_service_url", role.getFirstAttribute("terms-of-service"));

        return Response.ok(metadata).type(MediaType.APPLICATION_JSON).build();

    }

    /**
     * The Identity Assertion endpoint verifies authenticated user, and generates an access token for a client.
     *
     * @see <a href="https://fedidcg.github.io/FedCM/#idp-api-id-assertion-endpoint">FedCM API Identity assertion endpoint</a>
     *
     * @param origin client header origin
     * @param accountId ID of a chosen authenticated user
     * @param clientId Keycloak specific client ID
     * @param nonce client request nonce
     * @param disclosureTextShown whether user agent showed user which information will be shared with client
     * @return Encoded Access token convertible to <a href="https://fedidcg.github.io/FedCM/#dictdef-identityprovidertoken">IdentityProviderToken</a>
     */
    @POST
    @Path(FedCMUtils.ENDPOINTIDASSERT)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchIdentityAssertion(@HeaderParam("Origin") String origin,
                                           @FormParam("account_id") String accountId,
                                           @FormParam("client_id") String clientId,
                                           @FormParam("nonce") String nonce,
                                           @QueryParam("disclosure_text_shown") boolean disclosureTextShown) {
        // check for the Sec-Fetch-Dest header
        FedCMUtils.checkRequestHeader(session);

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);
        if(client == null) { // client must be registered in Keycloak
            return idAssertError(ErrorTypes.unauthorized_client);
        }

        if (!client.getRootUrl().equals(origin)) { // ensure the token is sent to the right client
            return idAssertError(ErrorTypes.unauthorized_client);
        }

        session.getContext().setClient(client);

        // with the cookies sent in the request and kept in KeycloakContext get authentication information
        AuthResult authResult = new AuthenticationManager().authenticateIdentityCookie(session, realm);
        if (authResult == null) { // user is probably not authenticated
            return idAssertError(ErrorTypes.access_denied);
        }

        UserModel user = authResult.getUser();
        if (!user.getId().equals(accountId)) { // the request user ID must match a Keycloak user ID
            return idAssertError(ErrorTypes.invalid_request);
        }

        // create a new authentication session for a user and a client
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, true);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);

        // scopes which the client wants access to
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, "openid profile email");
        AuthenticationManager.setClientScopesInSession(authSession);

        // set the client nonce to be included in the token
        UserSessionModel userSession = authResult.getSession();
        ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);
        authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        clientSessionCtx.setAttribute(OIDCLoginProtocol.NONCE_PARAM, nonce);

        // generate a token
        EventBuilder eventBuilder = new EventBuilder(realm, session);
        TokenManager tokenManager = new TokenManager();
        TokenManager.AccessTokenResponseBuilder accessTokenResponseBuilder = tokenManager.responseBuilder(realm, client, eventBuilder, session, userSession, clientSessionCtx);
        accessTokenResponseBuilder.generateAccessToken();

        // authentication successful with user consent, the client is approved for future fedcm login
        List<String> approvedClients = new ArrayList<>(user.getAttributeStream("approved_clients").toList());
        if (!approvedClients.contains(clientId)) {
            approvedClients.add(clientId);
            user.setAttribute("approved_clients", approvedClients);
        }

        return Response.ok(Map.of("token", accessTokenResponseBuilder.build().getToken()))
                .type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * The Disconnect endpoint logs out a user from a client authenticated with FedCM
     *
     * @see <a href="https://fedidcg.github.io/FedCM/#idp-api-disconnect-endpoint">FedCM API Disconnect endpoint</a>
     * @param origin client header origin
     * @param clientId Keycloak specific client ID
     * @return ID of the user signed in to Keycloak
     */
    @POST
    @Path(FedCMUtils.ENDPOINTDISCONNECT)
    @Produces(MediaType.APPLICATION_JSON)
    public Response disconnect(@HeaderParam("Origin") String origin, @FormParam("client_id") String clientId) {
        // check for the Sec-Fetch-Dest header
        FedCMUtils.checkRequestHeader(session);

        RealmModel realm = session.getContext().getRealm();
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) { // client must be registered in Keycloak
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        if (!client.getRootUrl().equals(origin)) { // ensure client origin matches the registered origin
            return idAssertError(ErrorTypes.unauthorized_client);
        }

        // with the cookies sent in the request and kept in KeycloakContext get authentication information
        AuthResult authResult = (new AuthenticationManager()).authenticateIdentityCookie(session, realm);
        if (authResult == null) { // user is probably not authenticated
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        // remove user client session and therefore logout user from client
        UserSessionModel userSession = authResult.getSession();
        userSession.removeAuthenticatedClientSessions(new LinkedList<>() {{add(client.getId());}});

        // prepare a JSON with user ID
        UserModel userModel = authResult.getUser();

        return Response.ok(Map.of("account_id", userModel.getId()))
                .header("Access-Control-Allow-Origin", origin)
                .header("Access-Control-Allow-Credentials", true)
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    /**
     * Fills Map with branding preferences of Keycloak. Currently hardcoded
     *
     * @see <a href="https://github.com/keycloak/keycloak-misc/">Keycloak Logos, Diagrams and more</a>
     * @return map of keycloak branding convertible to <a href="https://fedidcg.github.io/FedCM/#dictdef-identityproviderbranding">IdentityProviderBranding</a>
     */
    private Map<String, Object> getBranding() {
        // hardcoded branding options used to change browser's pop-up widget appearance
        Map<String, Object> branding = new HashMap<>();

        branding.put("background_color", "#3CC1E6");
        branding.put("color", "black");
        ArrayList<Map<String, Object>> icons = new ArrayList<>();
        icons.add(new HashMap<>() {{
            put("url", "https://raw.githubusercontent.com/keycloak/keycloak-misc/main/archive/logo/keycloak_icon_32px.png");
            put("size", 32);
        }});
        branding.put("icons", icons);
        branding.put("name", "Keycloak");
        return branding;
    }

    /**
     * Fills Map with user information from a given user model.
     *
     * @param user user model
     * @return map of user information convertible to <a href="https://fedidcg.github.io/FedCM/#dictdef-identityprovideraccount">IdentityProviderAccount</a>
     */
    private Map<String, Object> getUserAccount(UserModel user) {
        Map<String, Object> account = new HashMap<>();
        account.put("id", user.getId());
        account.put("given_name", user.getFirstName());
        account.put("name", user.getFirstName() + ' ' + user.getLastName());
        account.put("email", user.getEmail());
        account.put("picture", user.getFirstAttribute("picture"));
        account.put("approved_clients", user.getAttributeStream("approved_clients").toList());
        account.put("login_hints", List.of(user.getEmail()));
        return account;
    }

    /**
     * Notifies a browser about an encountered error when generating a token.
     * Leverages the <a href="https://developers.google.com/privacy-sandbox/blog/fedcm-chrome-120-updates?hl=en#error-api">FedCM Error API</a>
     *
     * @param errorType one of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">OAuth error responses</a>
     * @return response to the FedCM Error API of a user agent
     */
    private Response idAssertError(ErrorTypes errorType) {
        String fedcmPath = session.getContext().getUri().getRequestUri().resolve(".").toString();
        // uri with error details
        String errorUri = fedcmPath + "/error?error-type=" + errorType.toString();

        // prepare a JSON with error details
        Map<String, String> error = new HashMap<>() {{
            put("code", errorType.toString());
            put("url", errorUri);
        }};
        return Response
                .status(errorType.getResponse())
                .entity( Map.of("error", error))
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    /**
     * Redirects to Keycloak documentation with more information about an error encountered when generating a token.
     *
     * @param errorType one of the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">OAuth error responses</a>
     * @return a 302 redirect response to Keycloak documentation
     */
    @GET
    @Path("error")
    @Produces(MediaType.APPLICATION_JSON)
    public Response errorRedirector(@QueryParam("error-type") String errorType) {
        ErrorTypes enumErrorType = ErrorTypes.valueOf(errorType);
        Response.ResponseBuilder rb = Response.status(Response.Status.FOUND);
        switch (enumErrorType) {
            case unauthorized_client:
                rb.location(URI.create("https://www.keycloak.org/getting-started/getting-started-zip#_secure_the_first_application"));
                break;
            case access_denied:
                rb.location(URI.create("https://www.keycloak.org/getting-started/getting-started-zip#_log_in_to_the_admin_console"));
                break;
            case invalid_request:
                rb.location(URI.create("https://www.keycloak.org/guides#getting-started"));
                break;
        }
        return rb.build();
    }

    @Override
    public void close() {

    }
}
