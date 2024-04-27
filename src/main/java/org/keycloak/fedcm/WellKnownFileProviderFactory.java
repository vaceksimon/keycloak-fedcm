package org.keycloak.fedcm;

import org.keycloak.Config;
import org.keycloak.fedcm.spi.RootResourceProvider;
import org.keycloak.fedcm.spi.RootResourceProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Implements a factory creating FedCM well-known file Provider instances. There is only one such factory for a Keycloak instance.
 *
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
public class WellKnownFileProviderFactory implements RootResourceProviderFactory {

    /** This ID identifies this factory is used in the path and all endpoints are served from it: "keycloak/.well-known/{endpoint}" */
    public static final String ID = ".well-known";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RootResourceProvider create(KeycloakSession session) {
        return new WellKnownFileProvider(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

}
