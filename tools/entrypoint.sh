#!/bin/sh
set -e

# Ejemplo de lógica
if [ "$MODE" = "server" ]; then
    echo "Starting OPC UA Server..."
    exec /app/server_encryption --onlySecure --allowDiscovery --pki /certs/server_pki

elif [ "$MODE" = "client" ]; then
    echo "Starting OPC UA Client..."
    exec /app/client_encryption opc.tcp://$HOST:$PORT --pki /certs/client_pki

else
    echo "Unknown MODE: $MODE"
    exit 1
fi
