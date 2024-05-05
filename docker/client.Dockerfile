FROM node:22-slim
LABEL authors="Simon Vacek"

COPY src/client-demo/ ./
RUN npm install -g http-server

ENV CLIENT_PORT=8080
EXPOSE ${CLIENT_PORT}
ENTRYPOINT http-server -p ${CLIENT_PORT}