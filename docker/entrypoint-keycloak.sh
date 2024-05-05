#!/bin/bash
echo -e "\e[1;33mStarting the interactive script...\e[0m"
echo "If you wish to start Keycloak with the last imported existing configuration, enter start or s."
echo "If the client application runs on a port other than 8080, or you want to restore the default configuration, enter reconfigure or r."
echo "If you wish to import the current configuration for the Keycloak server, enter import or i."

while true
do
    echo ""
    read -p "Please select an action [(s)tart/(r)econfigure/(i)mport]:" ACTION
    if [ "$ACTION" == "i" ] || [ "$ACTION" == "import" ]; then
        ./bin/kc.sh import --file fedcm-demo.json --optimized
    elif [ "$ACTION" == "r" ] || [ "$ACTION" == "reconfigure" ]; then
        read -p "Please enter the port of the client application (enter (d)efault for default settings):" CLIENT_PORT
        if [ "$CLIENT_PORT" == "d" ] || [ "$CLIENT_PORT" == "default" ]; then
            cp fedcm-demo-original.json fedcm-demo.json
            CLIENT_PORT=8080
        else
            sed -ie "s/localhost:[0-9]*/localhost:$CLIENT_PORT/g" fedcm-demo.json
        fi
        echo -e "\e[1;32mThe port for the client application is now $CLIENT_PORT.\e[0m"
    elif [ "$ACTION" == "s" ] || [ "$ACTION" == "start" ]; then
        break
    else
        echo -e "\e[1;31mInvalid option: $ACTION.\e[0m"
    fi
done
./bin/kc.sh start-dev --http-port $KEYCLOAK_PORT
