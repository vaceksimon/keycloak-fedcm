package org.keycloak.fedcm;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;

import java.util.List;

/**
 * Contains constants and methods used across the FedCM-related classes.
 *
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
public class FedCMUtils {
    // endpoint names referenced in jax-rs annotations but also set in the config file endpoint
    /** Config file endpoint path */
    static final String ENDPOINTCONFIG     = "config.json";
    /** Accounts endpoint path */
    static final String ENDPOINTACCOUNTS   = "accounts";
    /** Client metadata endpoint path */
    static final String ENDPOINTMETADATA   = "client_metadata";
    /** Identity assertion endpoint path */
    static final String ENDPOINTIDASSERT   = "id_assert";
    /** Disconnect endpoint path */
    static final String ENDPOINTDISCONNECT = "disconnect";


    /**
     * Returns 400 Bad Request if "Sec-Fetch-Dest: webidentity" was not present in the request
     *
     * @param session A session containing the request context including request headers
     * @throws WebApplicationException if the header is not present, an exception is thrown
     */
    public static void checkRequestHeader(KeycloakSession session) {
        // Each FedCM request must contain "Sec-Fetch-Dest: webidentity" header
        List<String> secFetchDest = session.getContext().getRequestHeaders().getRequestHeader("Sec-Fetch-Dest");
        if (secFetchDest.size() != 1 || !secFetchDest.contains("webidentity")) {
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
    }
}