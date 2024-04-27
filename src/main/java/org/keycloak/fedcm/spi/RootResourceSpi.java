package org.keycloak.fedcm.spi;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * A custom Spi registering the Root extension for RESTful endpoints.
 *
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
public class RootResourceSpi implements Spi {
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
