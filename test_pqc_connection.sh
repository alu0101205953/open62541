#!/bin/bash
# Script para probar la conexión OPC UA con PKI post-cuántica
# Ejecuta servidor y cliente en secuencia

set -e

BUILD_DIR="./build/bin/examples"
SERVER_PKI="./server_pki"
CLIENT_PKI="./client_pki"
ENDPOINT="opc.tcp://localhost:4840"

# Verificar que los ejecutables existen
if [ ! -f "$BUILD_DIR/server_encryption" ]; then
    echo "ERROR: server_encryption no encontrado. Compila primero: cd build && make server_encryption"
    exit 1
fi

if [ ! -f "$BUILD_DIR/client_encryption" ]; then
    echo "ERROR: client_encryption no encontrado. Compila primero: cd build && make client_encryption"
    exit 1
fi

# Verificar que la PKI existe
if [ ! -f "$SERVER_PKI/ApplCerts/own/certs/server_cert.der" ]; then
    echo "ERROR: PKI del servidor no encontrada. Ejecuta primero: ./test_pqc_pki.sh"
    exit 1
fi

if [ ! -f "$CLIENT_PKI/ApplCerts/own/certs/client_cert.der" ]; then
    echo "ERROR: PKI del cliente no encontrada. Ejecuta primero: ./test_pqc_pki.sh"
    exit 1
fi

echo "═══════════════════════════════════════════════════════════════"
echo "Prueba de Conexión OPC UA Post-Cuántica"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Iniciando servidor en segundo plano..."
echo ""

# Iniciar servidor en segundo plano
"$BUILD_DIR/server_encryption" --onlySecure --allowDiscovery --pki "$SERVER_PKI" > server.log 2>&1 &
SERVER_PID=$!

# Esperar a que el servidor arranque
echo "Esperando 3 segundos para que el servidor arranque..."
sleep 3

# Verificar que el servidor sigue corriendo
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "ERROR: El servidor se detuvo inesperadamente"
    echo "Log del servidor:"
    cat server.log
    exit 1
fi

echo "✓ Servidor iniciado (PID: $SERVER_PID)"
echo ""
echo "Ejecutando cliente..."
echo ""

# Ejecutar cliente
"$BUILD_DIR/client_encryption" "$ENDPOINT" --pki "$CLIENT_PKI"
CLIENT_EXIT=$?

# Detener servidor
echo ""
echo "Deteniendo servidor..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

# Verificar resultado
if [ $CLIENT_EXIT -eq 0 ]; then
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "✓ PRUEBA EXITOSA: Cliente y servidor se conectaron correctamente"
    echo "═══════════════════════════════════════════════════════════════"
    exit 0
else
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "✗ PRUEBA FALLIDA: El cliente no pudo conectarse (código: $CLIENT_EXIT)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Log del servidor:"
    cat server.log
    exit 1
fi
