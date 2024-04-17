package org.keycloak.fedcm;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.fedcm.spi.RootResourceProvider;
import org.keycloak.models.KeycloakSession;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WellKnownFileProvider implements RootResourceProvider {

    private final KeycloakSession session;

    public WellKnownFileProvider(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("web-identity")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getWellKnownFile(@HeaderParam("Sec-Fetch-Dest") String secFetchDest) {
        if (!secFetchDest.equals("webidentity")) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        Map<String, Object> providerUrls = new HashMap<>();
        providerUrls.put("provider_urls", List.of("http://localhost:8080/realms/fedcm-realm/fedcm/config.json"));
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
