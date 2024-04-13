# FedCM API integration into Keycloak

# TODO
This extension can not be at this moment run as it relies on classes not available in a keycloak release. These classes
are:
- `RootResource.java`
- `RootResourceSPI.java`
- `RootResourceProvider.java`
- `RootResourceProviderFactory.java`
- and a modification of `KeycloakApplication.java` which adds `RootResource` to the classes

Fix coming soon, but it can be run by building Keycloak by yourself from my fork - link and instructions coming

Run: `./mvnw exec:exec@compile exec:exec@import-realm exec:exec@start-server`