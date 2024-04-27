package org.keycloak.fedcm.spi;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.models.KeycloakSession;

/**
 * Responsible for serving JAX-RS sub-resource instances for paths relative to the root of the Keycloak RESTful API.
 *
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
@Provider
@Path("/")
public class RootResource {
    /** A Keycloak session injected by Quarkus */
    @Context
    protected KeycloakSession session;

    /**
     * Resolves the correct Provider responsible for serving the accessed path.
     *
     * @param path path relative to the root of the Keycloak RESTful API
     * @return a JAX-RS sub-resource serving the path
     */
    @Path("{path}")
    public Object resolveRootRequest(@PathParam("path") String path) {
        RootResourceProvider provider = this.session.getProvider(RootResourceProvider.class, path);
        if(provider != null) {
            Object resource = provider.getResource();
            if (resource != null) {
                return resource;
            }
        }
        throw new NotFoundException();
    }
}
