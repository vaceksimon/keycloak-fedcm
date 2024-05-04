#!/bin/bash
echo "Starting Keycloak. If you wish to start Keycloak with an existing configuration enter start. If you wish to import configuration again and start fresh Keycloak server enter import. The import option then starts Keycloak."
read -p "Please select an action [start/import]:" ACTION
if [[ "$ACTION" == "import" ]]; then
  ./bin/kc.sh import --file fedcm-demo.json --optimized
elif [[ "$ACTION" != "start" ]]; then
  echo "Invalid option: $ACTION. Terminating."
  exit 1
fi
./bin/kc.sh start-dev --http-port $KEYCLOAK_PORT
