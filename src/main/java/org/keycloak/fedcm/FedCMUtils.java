package org.keycloak.fedcm;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;

import java.util.List;

public class FedCMUtils {
    // endpoint names
    static final String ENDPOINTCONFIG     = "config.json";
    static final String ENDPOINTACCOUNTS   = "accounts";
    static final String ENDPOINTMETADATA   = "client_metadata";
    static final String ENDPOINTIDASSERT   = "id_assert";
    static final String ENDPOINTDISCONNECT = "disconnect";


    /**
     * Returns 400 Bad Request if "Sec-Fetch-Dest: webidentity" was not present in the request
     *
     * @throws WebApplicationException
     */
    public static void checkRequestHeader(KeycloakSession session) {
        // Each FedCM request must contain "Sec-Fetch-Dest: webidentity" header
        List<String> secFetchDest = session.getContext().getRequestHeaders().getRequestHeader("Sec-Fetch-Dest");
        if (secFetchDest.size() != 1 && !secFetchDest.contains("webidentity")) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
    }
}