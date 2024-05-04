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


# Running Docker distribution
1. Load the docker image
   - `docker load -i exe/keycloak.tar`
2. Set environment variable for the port of Keycloak
    - `KEYCLOAK_PORT=8180`
3. Run the Keycloak server
   - `docker run -it --name keycloak -p $KEYCLOAK_PORT:$KEYCLOAK_PORT -e KEYCLOAK_PORT=$KEYCLOAK_PORT keycloak-fedcm`
4. Stop the container
   - Control+C or `docker stop keycloak`
5. Start the stopped container again
   - `docker start -ia keycloak`
6. Remove a container
    - `docker rm keycloak`