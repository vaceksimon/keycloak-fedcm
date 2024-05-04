#!/bin/bash
echo -e "\e[1;33mStarting Keycloak...\e[0m"
echo "If you wish to start Keycloak with an existing configuration, enter start or s."
echo "If you wish to import configuration again and start fresh Keycloak server, enter import or i."
echo "If the client application runs on a port other than 8080, enter reconfigure or r."

while true
do
  echo ""
  read -p "Please select an action [(s)tart/(i)mport/(r)econfigure]:" ACTION
  if [ "$ACTION" == "i" ] || [ "$ACTION" == "import" ]; then
    cp fedcm-demo-original.json fedcm-demo.json
    ./bin/kc.sh import --file fedcm-demo-original.json --optimized
  elif [ "$ACTION" == "r" ] || [ "$ACTION" == "reconfigure" ]; then
    read -p "Please enter the port of the client application:" CLIENT_PORT
    sed -ie "s/localhost:[0-9]*/localhost:$CLIENT_PORT/g" fedcm-demo.json
    echo -e "\e[1;32mThe port for the client application is now $CLIENT_PORT.\e[0m"
  elif [ "$ACTION" == "s" ] || [ "$ACTION" == "start" ]; then
    break
  else
    echo -e "\e[1;31mInvalid option: $ACTION.\e[0m"
  fi
done
./bin/kc.sh start-dev --http-port $KEYCLOAK_PORT
