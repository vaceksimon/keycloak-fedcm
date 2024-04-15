package org.keycloak.fedcm;

import org.keycloak.Config;
import org.keycloak.fedcm.spi.RootResourceProvider;
import org.keycloak.fedcm.spi.RootResourceProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class WellKnownFileProviderFactory implements RootResourceProviderFactory {

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
