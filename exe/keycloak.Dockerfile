FROM eclipse-temurin:21

COPY keycloak-dist/keycloak-999.0.0-SNAPSHOT.zip .
RUN apt-get update && \
    apt-get install unzip -y && \
    unzip -q keycloak-999.0.0-SNAPSHOT.zip
WORKDIR keycloak-999.0.0-SNAPSHOT

COPY target/keycloak-fedcm-999.0.0-SNAPSHOT.jar ./providers
COPY data/fedcm-demo.json ./
COPY --chmod=555 exe/entrypoint.sh ./

RUN ./bin/kc.sh import --file fedcm-demo.json --optimized

ENV KEYCLOAK_PORT=8180
EXPOSE ${KEYCLOAK_PORT}
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
ENTRYPOINT ./entrypoint.sh
