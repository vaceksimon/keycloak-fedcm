package org.keycloak.fedcm;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Implements a factory creating FedCM Provider instances. There is only one such factory for a Keycloak instance.
 *
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
public class FedCMProviderFactory implements RealmResourceProviderFactory {

    /** This ID identifies this factory and is also used in the path and all endpoints are served from it: "keycloak/realms/{realm-name}/fedcm/{endpoint}" */
    public static final String ID = "fedcm";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new FedCMProvider(session);
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
