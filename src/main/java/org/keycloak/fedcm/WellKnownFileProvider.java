package org.keycloak.fedcm;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.fedcm.spi.RootResourceProvider;
import org.keycloak.models.KeycloakSession;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class implements the Well-Known file endpoint which is global, for all realms.
 *
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
public class WellKnownFileProvider implements RootResourceProvider {

    /** A Keycloak session is created per request */
    private final KeycloakSession session;

    /**
     * Currently hardcoded config file url as the size of the well-known file is limited to 1
     */
    private final String configPath = "realms/fedcm-realm/fedcm/" + FedCMUtils.ENDPOINTCONFIG;

    public WellKnownFileProvider(KeycloakSession session) {
        this.session = session;
    }

    /**
     * The well-known file serves to verify the config file provided by the client.
     *
     * @see <a href="https://fedidcg.github.io/FedCM/#idp-api-well-known">FedCM API The Well-Known File endpoint</a>
     * @return map of a Keycloak well-known file convertible to <a href="https://fedidcg.github.io/FedCM/#dictdef-identityproviderwellknown">IdentityProviderWellKnown</a>
     */
    @GET
    @Path("web-identity")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getWellKnownFile() {
        // check for the Sec-Fetch-Dest header
        FedCMUtils.checkRequestHeader(session);

        // dynamically get Keycloak's url
        String baseUri = session.getContext().getUri().getBaseUri().toString();

        // prepare a JSON with the config file for realm fedcm-realm
        Map<String, Object> providerUrls = new HashMap<>();
        providerUrls.put("provider_urls", List.of(baseUri + configPath));
        return Response.ok(providerUrls).type(MediaType.APPLICATION_JSON).build();
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {

    }
}
