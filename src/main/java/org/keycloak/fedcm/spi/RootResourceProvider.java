package org.keycloak.fedcm.spi;

import org.keycloak.provider.Provider;

/**
 * @author <a href="mailto:xvacek10@stud.fit.vutbr.cz">Simon Vacek</a>
 */
public interface RootResourceProvider extends Provider {
    Object getResource();
}
