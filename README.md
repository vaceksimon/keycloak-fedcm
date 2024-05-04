# FedCM API integration into Keycloak

This directory contains the implementation for the Bachelor thesis. \
**Name: FedCM API Integration into Keycloak** \
**Author: <a href="mailto:xvacek10@stud.fit.vutbr.cz">Šimon Vacek</a>** \
**Supervisor: <a href="mailto:burgetr@fit.vut.cz">doc. Ing. Radek Burget Ph.D.</a>**

This directory contains the source files, including the code and scripts necessary for the project and all the required project configurations. Additionally, it contains the Docker images for executing the project.

The implementation leverages the Keycloak service provider interfaces, which can be compiled and delivered separately. It, however, needs a Keycloak distribution to run. The Keycloak project is huge, takes a long time to compile, and could cause trouble with the packaging. Because minimal modifications were made to the base Keycloak codebase, Keycloak was compiled, packaged, and included in the `keycloak-dist` directory. The changes made in Keycloak are produced by `git diff commit2 commit1` and included in the file `keycloak.diff`. It can also be used to apply the patch on Keycloak itself with `patch -p1 < path/to/keycloak.diff`.

The `data` directory contains the configuration for Keycloak, ready for a demo testing of the functionality. In `docs/javadoc/`, generated API documentation will be placed once generated.

The `docker` directory contains Docker images for execution and manual testing and files used for generating them. The `keycloak.tar` and `client.tar` archives are exported Docker images. They were generated by their Dockerfiles, which use their entrypoint bash scripts.

As mentioned, the Keycloak distribution is in a ZIP file in `keycloak-dist`. This is used in case the project is executed with Maven. If it is, this file is decompressed, and the built fedcm extension is placed inside it during the server's start. Do not delete this ZIP file.

The `mvnw` script and `mvnw.cmd` for Windows were generated from the `pom.xml` file. The maven wrapper scripts are the preferred method of compilation.

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
│   ├── entrypoint-client.sh
│   ├── entrypoint-keycloak.sh
│   ├── keycloak.Dockerfile    - Dockerfile used for building an image with Keycloak uncluding the FedCM exntension
│   └── keycloak.tar           - Docker image with the runnable Keycloak distribution including the FedCM extension
├── keycloak-dist
│   └── keycloak-999.0.0-SNAPSHOT.zip  - prepared distribution of Keycloak
├── keycloak.diff - Diff of changes done to base Keycloak
├── mvnw
├── mvnw.cmd
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
It is recommended that it be built and run on Linux distributions.


## Building the project
The FedCM extension to Keycloak is a Java Maven project. For building, it uses a maven wrapper. It can also be used for execution but is less preferred to the docker images.

### Compile
- To compile the extension and package it in a JAR in `target/keycloak-fedcm-999.0.0-SNAPSHOT.jar` run: \
`./mvnw exec:exec@compile`

### Generate Javadocs
- To generate the API documentation, run: \
`./mvnw javadoc:javadoc`


## Running the project
**The project is run and tested locally**. Both Keycloak and the client application must be hosted on **localhost**. The default port for Keycloak is `8180` and for the client application `8080`.

### Running with Docker
This guide can be followed exactly step by step. **It is advised to not run the containers in detached mode**, especially for Keycloak which runs a script depending on user input.

#### Running the client application
1. Load the docker image
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
Because the chosen default ports may not be available, the container first starts a script which lets the user configure the ports. Three actions are defined:
- `start` - This option starts Keycloak
- `import` - This option imports the original configuration, deleting all saved data in the container. It can be used, for example, when the client metadata for a first-time FedCM flow are tested again and the approved clients need to be deleted.
- `reconfigure` - Changes Keycloak configuration for the port of the client application.

1. Load the docker image
   - `docker load -i docker/keycloak.tar`
2. Set environment variable for the port of Keycloak
   - `KEYCLOAK_PORT=8180`
3. Run the container
   - `docker run -it --name keycloak -p $KEYCLOAK_PORT:$KEYCLOAK_PORT -e KEYCLOAK_PORT=$KEYCLOAK_PORT keycloak-fedcm`

If it is discovered the port for the client was wrong, the container needs to be removed and started again:
1. Stop the container
   - Control+C or `docker stop keycloak`
2. Remove the container
   - `docker rm keycloak`
3. Set environment variable for a different Keycloak port.
   - `CLIENT_PORT=8180`
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
- For executing the project, it needs to be compiled, the Keycloak server configuration imported, and finally executed. To run the project with all these operations run: \
`./mvnw exec:exec@compile exec:exec@import exec:exec@start`

