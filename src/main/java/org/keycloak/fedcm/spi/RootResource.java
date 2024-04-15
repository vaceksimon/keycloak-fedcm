package org.keycloak.fedcm.spi;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.fedcm.spi.RootResourceProvider;

@Provider
@Path("/")
public class RootResource {
    protected static final Logger logger = Logger.getLogger(RootResource.class);

    @Context
    protected KeycloakSession session;

    @Path("{path}")
    public Object resolveRootWellKnownFile(@PathParam("path") String path) {
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
