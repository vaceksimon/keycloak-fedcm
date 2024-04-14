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
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class FedCMProvider implements RealmResourceProvider {

    private final String factoryID;
    private final KeycloakSession session;

    public FedCMProvider(KeycloakSession session, String factoryID) {
        this.session = session;
        this.factoryID = factoryID;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path("config.json")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchConfigFile(@HeaderParam("Sec-Fetch-Dest") String secFetchDest) {
        if (!secFetchDest.equals("webidentity")) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        KeycloakContext keycloakCtx = session.getContext();
        String server = keycloakCtx.getAuthServerUrl().toString();
        String realm = keycloakCtx.getRealm().getName();

        // fedcm endpoints
        Map<String, Object> fedCMEndpoints = new HashMap<>();
        fedCMEndpoints.put("accounts_endpoint", server + "realms/" + realm + '/' + factoryID + "/accounts");
        fedCMEndpoints.put("client_metadata_endpoint", server + "realms/" + realm + '/' + factoryID + "/client_metadata");
        fedCMEndpoints.put("id_assertion_endpoint", server + "realms/" + realm + '/' + factoryID + "/id_assert");
        fedCMEndpoints.put("login_url", server + "realms/" + realm + "/account");
        fedCMEndpoints.put("disconnect_endpoint", server + "realms/" + realm + '/' + factoryID + "/disconnect");

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

        fedCMEndpoints.put("branding", branding);
        return Response.ok(fedCMEndpoints).type(MediaType.APPLICATION_JSON).build();
    }

    @GET
    @Path("accounts")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchAccountsList(@HeaderParam("Sec-Fetch-Dest") String secFetchDest) {
        // todo store somewhere approved_clients
        // todo what to put in domain_hints

        if (!secFetchDest.equals("webidentity")) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
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
        // just a hardcoded profile picture as Keycloak doesnt support pfp by default
        acc.put("picture", "https://lh3.googleusercontent.com/a-/ALV-UjW7uuw5LcTap5TgMk9aHVl1RMm9HS79mMfhBJd8JlzkJSRIesrbkM69LF7Pw4yMYmVVUhUrl249NPd39iUQeknOT6sGRn4Y1CPbzuhHR4dIAlWT9kn69BVs2_pJc7vHjpHE50g_O6e-b_Pb80ukBweKcz9tMbO--QdcukwsS1SQJzo-ULqTri-HTfXb_wzUuwfnnIlNqWdQF70yOYBcqeqaYCrGo960dhEIzch75P1mAdvRz-ZkjbR-6_JuZZCDLz1BKuFz53AzchzaUEMtZ2um2R8Kkym1eO0zmnhN5FH0vr9BTLYZabl63TVrcbqfr8bHDx3OeH4lTdeF5JjRESVWNxermDJDlYalme3FGY6veShcsEBrDJIR2TPqLF087G2-vqk-_5RVaHAY8Y8QQ6EdrSIYc4UenJUj7tO1MTOntu5x2F8JK7MN_SvrAfK9xfz51cPGoMB8i9jCokwDjmazj8kHJ23xJ1tniq8jLe9qfS7Wl-q5Ik3bGWwZNJ7EC1zw5t7aMZwk3WPzi2jBko5ybsqzYfU-jyY6VeB8Zf_G7lb1v9bTMlrQ1yr624O5ISn71Y4i2PHH8FiEskvGvT5PhgW3iQJhQ8cEATMUu2BAh69XrldkJkbZhW8DnWeayqcem_6C6tq0DfbBMnL2KrFD5i-OzbF4vjRIMkpztNhz2yYwOATBx8q4fH8hrP2dujO98h7yUL8qawCPwbe06X-Dg635HytL5v9QpeIJnyS1Sw3QqD09FNIJ6ku5C3fJN0YfJPJ5BK-SB5LGqVks5imLzwH9wgDASV14IUx2byLlT7NE1U-jtY71hNXLqyLUv6RT2Hw3oObzlKciyRk63xp6B8QXHUnC7AZdBXE3OcQNJA3hZZIUn6f9AoD3nMc0iZx7IUZmv6a2WR1dbySTBU5Tw-OMF4LyJiPkKjs6n68gmtKixPjM7jvkYpWBRbXkrYso5GNbPH5NKgPKstW9FmRVru5M=s96-c-rg-br100");
        acc.put("approved_clients", new ArrayList<String>() {{
            // todo hardcoded, should be retrieved from Keycloak user attributes (?)
            add("123");
            add("456");
            add("example");
        }});
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
    @Path("client_metadata")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchClientMetadata(@HeaderParam("Sec-Fetch-Dest") String secFetchDest, @QueryParam("client_id") int client_id) {
        if (!secFetchDest.equals("webidentity")) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        Map<String, Object> metadata = new HashMap<>();
        // todo hardcoded, should be retrieved from Keycloak client attributes (?)
        if (client_id == 123) {
            metadata.put("privacy_policy_url", "https://www.seznam.cz/");
            metadata.put("terms_of_service_url", "https://www.seznam.cz/");
        } else {
            metadata.put("privacy_policy_url", "https://www.google.com/");
            metadata.put("terms_of_service_url", "https://www.google.com/");
        }
        return Response.ok(metadata).type(MediaType.APPLICATION_JSON).build();

    }

    @POST
    @Path("id_assert")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetchIdentityAssertion(@HeaderParam("Sec-Fetch-Dest") String secFetchDest,
                                           @HeaderParam("Origin") String origin,
                                           @FormParam("account_id") String account_id,
                                           @FormParam("client_id") String client_id,
                                           @FormParam("nonce") String nonce,
                                           @QueryParam("disclosure_text_shown") boolean disclosure_text_shown) {
        if (!secFetchDest.equals("webidentity")) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

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

        return Response.ok(token).type(MediaType.APPLICATION_JSON).build();
    }

    private Response idAssertError(String errorType, Response.Status responseStatus) {
        // todo Refactor
        KeycloakContext keycloakCtx = session.getContext();
        String serverString = keycloakCtx.getAuthServerUrl().toString();
        String realmString = keycloakCtx.getRealm().getName();
        String errorUri = serverString + "realms/" + realmString + '/' + factoryID + "/error?error-type=" + errorType;

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
    @Path("disconnect")
    @Produces(MediaType.APPLICATION_JSON)
    public Response disconnect(@HeaderParam("Sec-Fetch-Dest") String secFetchDest, @HeaderParam("Origin") String client_origin, @FormParam("client_id") String client_id, @FormParam("account_hint") String account_hint) {
        if (!secFetchDest.equals("webidentity")) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
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

        Response.ResponseBuilder rb = Response.ok(id);
        return rb.header("Access-Control-Allow-Origin", client_origin)
                .type(MediaType.APPLICATION_JSON)
                .header("Access-Control-Allow-Credentials", true)
                .build();
    }

    @GET
    @Path("error")
    @Produces(MediaType.APPLICATION_JSON)
    public Response disconnect(@QueryParam("error-type") String error_type) {
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

    @Override
    public void close() {

    }
}
