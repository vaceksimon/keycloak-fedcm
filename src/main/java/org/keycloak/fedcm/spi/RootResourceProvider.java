package org.keycloak.fedcm.spi;

import org.keycloak.provider.Provider;

public interface RootResourceProvider extends Provider {
    Object getResource();
}
