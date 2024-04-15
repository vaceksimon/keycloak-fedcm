package org.keycloak.fedcm.spi;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;
import org.keycloak.fedcm.spi.RootResourceProvider;
import org.keycloak.fedcm.spi.RootResourceProviderFactory;

public class RootResourceSPI implements Spi {
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "root-restapi-extension";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return RootResourceProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return RootResourceProviderFactory.class;
    }
}
