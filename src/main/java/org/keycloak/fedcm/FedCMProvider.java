package org.keycloak.fedcm;

import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FedCMProvider implements RealmResourceProvider {

    final String ENDPOINTCONFIG   = "config.json";
    final String ENDPOINTACCOUNTS = "accounts";
    final String ENDPOINTMETADATA = "client_metadata";
    final String ENDPOINTIDASSERT = "id_assert";
    final String ENDPOINTDISCONNECT = "disconnect";

    private final KeycloakSession session;

    public FedCMProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path(ENDPOINTCONFIG)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchConfigFile() {
        // check for the Sec-Fetch-Dest header
        checkRequestHeader();

        // dynamically get Keycloak's url
        URI requestURI = session.getContext().getUri().getRequestUri();
        String fedcmPath = requestURI.resolve(".").toString();
        String realmPath = requestURI.resolve("..").toString();

        // prepare a JSON with the rest of Keycloak's FedCM endpoints
        Map<String, Object> fedCMEndpoints = new HashMap<>();
        fedCMEndpoints.put("accounts_endpoint", fedcmPath + ENDPOINTACCOUNTS);
        fedCMEndpoints.put("client_metadata_endpoint", fedcmPath + ENDPOINTMETADATA);
        fedCMEndpoints.put("id_assertion_endpoint", fedcmPath + ENDPOINTIDASSERT);
        fedCMEndpoints.put("login_url", realmPath + "account");
        fedCMEndpoints.put("disconnect_endpoint", fedcmPath + ENDPOINTDISCONNECT);
        fedCMEndpoints.put("branding", getBranding());

        return Response.ok(fedCMEndpoints).type(MediaType.APPLICATION_JSON).build();
    }

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

    @GET
    @Path(ENDPOINTACCOUNTS)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchAccountsList() {
        // check for the Sec-Fetch-Dest header
        checkRequestHeader();

        AuthResult authResult = (new AuthenticationManager()).authenticateIdentityCookie(session, session.getContext().getRealm());
        if (authResult == null) { // user is probably not authenticated
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        UserModel userModel = authResult.getUser();
        Map<String, Object> acc = new HashMap<>();
        acc.put("id", userModel.getId());
        acc.put("given_name", userModel.getFirstName());
        acc.put("name", userModel.getFirstName() + ' ' + userModel.getLastName());
        acc.put("email", userModel.getEmail());
        String picture = userModel.getFirstAttribute("picture");
        if (picture != null) {
            acc.put("picture", picture);
        }
        acc.put("approved_clients", userModel.getAttributeStream("approved_clients").toList());
        acc.put("login_hints", new ArrayList<String>() {{
            add(userModel.getEmail());
        }});

        // TODO DELETE second and madeup account just for demonstration purposes in the browser's pop-up widget
        Map<String, Object> acc2 = new HashMap<>();
        acc2.put("id", "1111");
        acc2.put("given_name", "Radek");
        acc2.put("name", "Radek Burget");
        acc2.put("email", "burgetr@fit.vut.cz");
        acc2.put("picture", "https://www.fit.vut.cz/person-photo/10467/?transparent=1");
        acc2.put("approved_clients", new ArrayList<String>() {{
            add("123");
            add("456");
        }});
        acc2.put("login_hints", new ArrayList<String>() {{
            add("burgetr@fit.vut.cz");
        }});

        Map<String, Object> accList = new HashMap<>();
        accList.put("accounts", new ArrayList<>() {{
            add(acc);
            add(acc2);
        }});
        return Response.ok(accList).type(MediaType.APPLICATION_JSON).build();
    }

    @GET
    @Path(ENDPOINTMETADATA)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchClientMetadata(@QueryParam("client_id") String client_id) {
        // check for the Sec-Fetch-Dest header
        checkRequestHeader();

        ClientModel client = session.getContext().getRealm().getClientByClientId(client_id);
        if(client == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        RoleModel role = client.getRole("policies");
        if (role == null) {
           return Response.serverError().build();
        }

        Map<String, String> metadata = new HashMap<>();
        metadata.put("privacy_policy_url", role.getFirstAttribute("privacy-policy"));
        metadata.put("terms_of_service_url", role.getFirstAttribute("terms-of-service"));

        return Response.ok(metadata).type(MediaType.APPLICATION_JSON).build();

    }

    @POST
    @Path(ENDPOINTIDASSERT)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchIdentityAssertion(@HeaderParam("Origin") String origin,
                                           @FormParam("account_id") String account_id,
                                           @FormParam("client_id") String client_id,
                                           @FormParam("nonce") String nonce,
                                           @QueryParam("disclosure_text_shown") boolean disclosure_text_shown) {
        // check for the Sec-Fetch-Dest header
        checkRequestHeader();

        RealmModel realm = session.getContext().getRealm();

        ClientModel client = realm.getClientByClientId(client_id);
        if(client == null) {
            return idAssertError("unauthorized_client", Response.Status.UNAUTHORIZED);
        }


        //todo parse origin
        if (!client.getRootUrl().equals(origin)) {
            return idAssertError("unauthorized_client", Response.Status.UNAUTHORIZED);
        }

        // todo is this the right way to do it?
        session.getContext().setClient(client);

        // todo might not be necessary and tokenManager.responseBuilder could be supplied with null instead of EventBuilder
        EventBuilder eventBuilder = new EventBuilder(realm, session);

        AuthResult authResult = new AuthenticationManager().authenticateIdentityCookie(session, realm);
        if (authResult == null) {
            return idAssertError("access_denied", Response.Status.FORBIDDEN);
        }

        UserModel user = authResult.getUser();
        if (!user.getId().equals(account_id)) {
            return idAssertError("invalid_request", Response.Status.BAD_REQUEST);
        }
        UserSessionModel userSession = authResult.getSession();


        // creating a ClientAuthenticatedSession used for ClientSessionContext
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, false);
        // AuthenticationSessionAdapter
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, "openid profile email");

        AuthenticationManager.setClientScopesInSession(authSession);


        // DefaultClientSessionContext
        ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);
        // 1) set nonce
        // todo should be set in the AuthenticationSessionModel - OIDCLoginProtocol:authenticated():230
        authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        clientSessionCtx.setAttribute(OIDCLoginProtocol.NONCE_PARAM, nonce);


        TokenManager tokenManager = new TokenManager();


        TokenManager.AccessTokenResponseBuilder accessTokenResponseBuilder = tokenManager.responseBuilder(realm, client, eventBuilder, session, userSession, clientSessionCtx);
        accessTokenResponseBuilder.generateAccessToken();
        accessTokenResponseBuilder.generateIDToken();


        Map<String, String> token = new HashMap<>();
        if (client_id.equals("example-idtoken")) {
            token.put("token", accessTokenResponseBuilder.build().getIdToken());
        } else if (client_id.equals("example-accesstoken")) {
            token.put("token", accessTokenResponseBuilder.build().getToken());
        } else {
            return idAssertError("unauthorized_client", Response.Status.UNAUTHORIZED);
        }
        List<String> approvedClients = new ArrayList<>(user.getAttributeStream("approved_clients").toList());
        if (!approvedClients.contains(client_id)) {
            approvedClients.add(client_id);
            user.setAttribute("approved_clients", approvedClients);
        }

        return Response.ok(token).type(MediaType.APPLICATION_JSON).build();
    }

    private Response idAssertError(String errorType, Response.Status responseStatus) {
        // todo Refactor
        String fedcmPath = session.getContext().getUri().getRequestUri().resolve(".").toString();
        String errorUri = fedcmPath + "/error?error-type=" + errorType;

        Map<String, String> error = new HashMap<>() {{
            put("code", errorType);
            put("url", errorUri);
        }};
        return Response.status(responseStatus).entity(new HashMap<>() {{
                    put("error", error);
                }})
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    @POST
    @Path(ENDPOINTDISCONNECT)
    @Produces(MediaType.APPLICATION_JSON)
    public Response disconnect(@HeaderParam("Origin") String client_origin, @FormParam("client_id") String client_id, @FormParam("account_hint") String account_hint) {
        // check for the Sec-Fetch-Dest header
        checkRequestHeader();
        RealmModel realm = session.getContext().getRealm();

        Map<String, String> id = new HashMap<>();
        AuthResult authResult = (new AuthenticationManager()).authenticateIdentityCookie(session, realm);
        if (authResult == null) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        // PERFORM ACTUAL KEYCLOAK LOGOUT
        UserSessionModel userSession = authResult.getSession();
        userSession.setNote(AuthenticationManager.KEYCLOAK_LOGOUT_PROTOCOL, OIDCLoginProtocol.LOGIN_PROTOCOL);
        ClientModel client = realm.getClientByClientId(client_id);
        if (client == null) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        AuthenticationManager.browserLogout(session, realm, userSession, session.getContext().getUri(), session.getContext().getConnection(), session.getContext().getRequestHeaders());


        UserModel userModel = authResult.getUser();
        id.put("account_id", userModel.getId());


        return Response.ok(id)
                .header("Access-Control-Allow-Origin", client_origin)
                .header("Access-Control-Allow-Credentials", true)
                .header("Access-Control-Allow-Headers", "Content-Type, Set-Login")
                .header("Set-Login", "logged-out")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    //TODO DEAL WITH THIS
    @GET
    @Path("logged-out")
    public Response logoutStatusAPI(@HeaderParam("Origin") String client_origin) {
        return Response.ok().header("Set-Login", "logged-out")
            .header("Access-Control-Allow-Origin", client_origin)
            .header("Access-Control-Allow-Credentials", true).type(MediaType.TEXT_PLAIN_TYPE).build();
    }

    @GET
    @Path("error")
    @Produces(MediaType.APPLICATION_JSON)
    public Response errorRedirector(@QueryParam("error-type") String error_type) {
        Response.ResponseBuilder rb = Response.status(Response.Status.FOUND);
        switch (error_type) {
            case "unauthorized_client":
                rb.location(java.net.URI.create("https://www.keycloak.org/getting-started/getting-started-zip#_secure_the_first_application"));
                break;
            case "access_denied":
                rb.location(java.net.URI.create("https://www.keycloak.org/getting-started/getting-started-zip#_log_in_to_the_admin_console"));
                break;
            case "invalid_request":
                rb.location(java.net.URI.create("https://www.youtube.com/watch?v=mPEdQjH5nFw"));
                break;
        }
        return rb.build();
    }

    private void checkRequestHeader() {
        // Each FedCM request must contain "Sec-Fetch-Dest: webidentity" header
        List<String> secFetchDest = session.getContext().getRequestHeaders().getRequestHeader("Sec-Fetch-Dest");
        if (secFetchDest.size() != 1 && !secFetchDest.contains("webidentity")) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
    }

    @Override
    public void close() {

    }
}
