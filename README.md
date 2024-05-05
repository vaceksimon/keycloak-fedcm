# FedCM API integration into Keycloak

This directory contains the implementation for the Bachelor thesis. \
**Name: FedCM API Integration into Keycloak** \
**Author: <a href="mailto:xvacek10@stud.fit.vutbr.cz">Šimon Vacek</a>** \
**Supervisor: <a href="mailto:burgetr@fit.vut.cz">doc. Ing. Radek Burget Ph.D.</a>**

This directory contains the source files, including the code and scripts necessary for the project and all the required project configurations. Additionally, it contains the Docker images for executing the project.

The implementation leverages the Keycloak service provider interfaces, which can be compiled and delivered separately. It, however, needs a Keycloak distribution to run. The Keycloak project is huge, takes a long time to compile, and could cause trouble with the packaging. Because minimal modifications were made to the base Keycloak codebase, Keycloak was compiled, packaged, and included in the `keycloak-dist` directory. The changes made in Keycloak are produced by `git diff commit2 commit1` and included in the file `keycloak.diff`. It can also be used to apply the patch on Keycloak itself with `patch -p1 < path/to/keycloak.diff`.

The `data` directory contains the configuration for Keycloak, ready for a demo testing of the functionality. In `docs/javadoc/`, generated API documentation will be placed once generated.

The `docker` directory contains Docker images for execution and manual testing and files used for generating them. The `keycloak.tar` and `client.tar` archives are exported Docker images. They were generated by their Dockerfiles.

As mentioned, the Keycloak distribution is in a ZIP file in `keycloak-dist`. This is used in case the project is executed with Maven. If it is, this file is decompressed, and the built fedcm extension is placed inside it during the server's start. Do not delete this ZIP file.

The `mvnw` script and `mvnw.cmd` for Windows were generated from the `pom.xml` file. The Maven wrapper scripts are the preferred method of compilation.

The `src` directory has the source code for both the main Keycloak FedCM extension, the object of this thesis, and a Javascript application for testing the FedCM functionality.
```
.
├── data
│   └── fedcm-demo.json - contains Keycloak configuration for import
├── docs
│   └── javadoc
├── docker
│   ├── client.Dockerfile      - Dockerfile used for building an image with the client application
│   ├── client.tar             - Docker image with the runnable demo client application
│   ├── entrypoint-keycloak.sh - The scipt started within the Keycloak docker container
│   ├── keycloak.Dockerfile    - Dockerfile used for building an image with Keycloak uncluding the FedCM exntension
│   └── keycloak.tar           - Docker image with the runnable Keycloak distribution including the FedCM extension
├── keycloak-dist
│   └── keycloak-999.0.0-SNAPSHOT.zip  - prepared distribution of Keycloak
├── keycloak.diff - Diff of changes done to base Keycloak
├── mvnw
├── mvnw.cmd
├── package.json
├── pom.xml
├── README.md
└── src
    ├── client-demo     - Source code for the demo client application
    │   └── ...
    └── main
        ├── java        - Source code for the keycloak-fedcm SPI extension
        │   └── ...
        └── resources   - Configuration files for the SPI extension
            └── ...
```
## Prerequisites
**This project MUST be built and run on Linux distributions as it relies on bash and other utilities.**\
**OpenJDK 17** is recommended for building.\
Maven wrapper requires the `JAVA_HOME` environment variable to be set.

## Building the project
The FedCM extension to Keycloak is a Java Maven project. For building, it uses a Maven wrapper. It can also be used for execution but is less preferred to the Docker images.

### Compile
- To compile the extension and package it in a JAR in `target/keycloak-fedcm-999.0.0-SNAPSHOT.jar` run: \
`./mvnw exec:exec@compile`

### Generate Javadocs
- To generate the API documentation, run: \
`./mvnw javadoc:javadoc`


## Running the project
**The project is run and tested locally**. Both Keycloak and the client application must be hosted on **localhost**. The default port for Keycloak is `8180` and for the client application `8080`. After successful execution, open the client application on `localhost:8080` and follow the instructions there.

### Running with Docker
This guide can be followed exactly step by step. **It is advised to not run the containers in detached mode**, especially for Keycloak which runs a script depending on user input.

The provided images do not rely on Docker. A daemonless container tool, Podman, could be used as an alternative to Docker—if Podman is preferable, substitute `docker` for `podman` in these commands.

#### Running the client application
1. Load the Docker image
   - `docker load -i docker/client.tar`
2. Set environment variable for the client application port. The application will be hosted on this port.
   - `CLIENT_PORT=8080`
3. Run the container
   - `docker run -it --name client-app -p $CLIENT_PORT:$CLIENT_PORT -e CLIENT_PORT=$CLIENT_PORT fedcm-demo-app`

If it is discovered the port for the client was wrong, the container needs to be removed and started again:
1. Stop the container
   - Control+C or `docker stop client-app`
2. Remove the container
   - `docker rm client-app`
3. Set environment variable for a different client application port.
   - `CLIENT_PORT=8080`
4. Run the container
   - `docker run -it --name client-app -p $CLIENT_PORT:$CLIENT_PORT -e CLIENT_PORT=$CLIENT_PORT fedcm-demo-app`

The container can be stopped and run again:
1. Stop the container
   - Control+C or `docker stop client-app`
2. Start the stopped container again
   - `docker start -ia client-app`

Once testing is done remove the container and the image:
1. Remove the container
   - `docker rm client-app`
2. Remove the image
   - `docker image rm fedcm-demo-app`


#### Running Keycloak
Because the chosen default ports may not be available, the container starts an interactive script that lets the user configure the ports. Three actions are defined:
- `start` - This option starts Keycloak
- `reconfigure` - This allows changing the Keycloak configuration for the client application port. It presents the user with another choice:
    - _`port`_ - port of the client application
    - `default` - restores the original configuration for Keycloak set in the Docker image.
    - _These options only change the configuration file. This configuration must be imported to work._
      - _NOTE: These operations modify the original configuration file, meaning all other data stored in Keycloak is lost if it was not in the configuration already._
- `import` - This option imports the configuration file.

1. Load the Docker image
   - `docker load -i docker/keycloak.tar`
2. Set environment variable for the port of Keycloak
   - `KEYCLOAK_PORT=8180`
3. Run the container
   - `docker run -it --name keycloak -p $KEYCLOAK_PORT:$KEYCLOAK_PORT -e KEYCLOAK_PORT=$KEYCLOAK_PORT keycloak-fedcm`

If it is discovered the port for Keycloak was wrong, the container needs to be removed and started again:
1. Stop the container
   - Control+C or `docker stop keycloak`
2. Remove the container
   - `docker rm keycloak`
3. Set environment variable for a different Keycloak port.
   - `KEYCLOAK_PORT=8180`
4. Run the container
   - `docker run -it --name keycloak -p $KEYCLOAK_PORT:$KEYCLOAK_PORT -e KEYCLOAK_PORT=$KEYCLOAK_PORT keycloak-fedcm`

The container can be stopped and run again:
1. Stop the container
   - Control+C or `docker stop keycloak`
2. Start the stopped container again
   - `docker start -ia keycloak`

Once testing is done remove the container and the image:
1. Remove the container
   - `docker rm keycloak`
2. Remove the image
   - `docker image rm keycloak-fedcm`


### Running with Maven

#### Running the client application
The client application does not use Maven. It is a plain HTML and Javascript application with some Bootstrap CSS. It needs to be served on localhost, and the default port for it is `8080`. The `http-server` package is used to serve the client. It can be downloaded from the dependencies.

1. Download the `http-server` package
    - `npm install`
2. Create an alias for the http-server executable
   - `alias http-server/node_modules/http-server/bin/http-server`
3. Run the server. Other ports than `8080` can be used, but it requires reconfiguring Keycloak, as described below.
    - `http-server ./src/client-demo/ -p 8080`

#### Running Keycloak
Before executing the Keycloak extension, the project needs to be built. The Keycloak server requires importing a configuration file with realms, users, and clients for testing. After, it can be run.

- To compile the project run:
  - `./mvnw exec:exec@compile`


- The configuration file can be modified if the client application is running on a different port than `8080`:
    - `./mvnw -Dclient.port=8080 exec:exec@reconfigure`
- If a mistake was done in the configuration, it can be restored:
    - `./mvnw exec:exec@config-default`


- To import the configuration, run:
  - `./mvnw exec:exec@import`


- This command then runs the Keycloak server. The variable for a port can be omitted for a default value, or changed.
  - `./mvnw exec:exec@start -Dkeycloak.port=8180`


- **Typically, the whole execution would look like this**:
  - `./mvnw -Dclient.port=8080 -Dkeycloak.port=8180 exec:exec@compile exec:exec@reconfigure exec:exec@import exec:exec@start`
