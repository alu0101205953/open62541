#!/bin/bash

# Script para probar múltiples conexiones consecutivas con certificados PQC

BIN_DIR="/Users/iris/Documents/opcua/open62541/build/bin/examples"
SERVER_CERT="server_cert_pqc.der"
SERVER_KEY="server_key_pqc.der"
CLIENT_CERT="client_cert_pqc.der"
CLIENT_KEY="client_key_pqc.der"
ENDPOINT="opc.tcp://localhost:4840"

echo "═══════════════════════════════════════════════════════════════"
echo "Prueba de Múltiples Conexiones Consecutivas PQC"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Iniciar el servidor en segundo plano
echo "Iniciando el servidor OPC UA con certificados PQC..."
"${BIN_DIR}/server_encryption" "${SERVER_CERT}" "${SERVER_KEY}" > /tmp/server_pqc_multiple.log 2>&1 &
SERVER_PID=$!
echo "Servidor iniciado con PID: ${SERVER_PID}"
echo ""

# Esperar a que el servidor se inicie completamente
sleep 3

# Contador de conexiones exitosas
SUCCESS_COUNT=0
FAIL_COUNT=0

# Probar 4 conexiones consecutivas
for i in {1..4}; do
    echo "───────────────────────────────────────────────────────────────"
    echo "Intento de conexión #${i}"
    echo "───────────────────────────────────────────────────────────────"
    
    # Conectar el cliente
    "${BIN_DIR}/client_encryption" "${ENDPOINT}" "${CLIENT_CERT}" "${CLIENT_KEY}" --serverCert "${SERVER_CERT}" > /tmp/client_pqc_${i}.log 2>&1
    CLIENT_EXIT_CODE=$?
    
    if [ "${CLIENT_EXIT_CODE}" -eq 0 ]; then
        echo "✓ Conexión #${i}: EXITOSA"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "✗ Conexión #${i}: FALLIDA (código de salida: ${CLIENT_EXIT_CODE})"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "Últimas líneas del log del cliente:"
        tail -5 /tmp/client_pqc_${i}.log
    fi
    
    echo ""
    
    # Pequeña pausa entre conexiones
    sleep 1
done

# Detener el servidor
echo "───────────────────────────────────────────────────────────────"
echo "Deteniendo el servidor..."
kill "${SERVER_PID}"
wait "${SERVER_PID}" 2>/dev/null

# Resumen
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "RESUMEN DE PRUEBAS"
echo "═══════════════════════════════════════════════════════════════"
echo "Conexiones exitosas: ${SUCCESS_COUNT}/4"
echo "Conexiones fallidas: ${FAIL_COUNT}/4"
echo ""

if [ "${FAIL_COUNT}" -eq 0 ]; then
    echo "✓✓✓ TODAS LAS CONEXIONES FUERON EXITOSAS ✓✓✓"
    exit 0
else
    echo "✗✗✗ ALGUNAS CONEXIONES FALLARON ✗✗✗"
    echo ""
    echo "Logs del servidor:"
    echo "───────────────────────────────────────────────────────────────"
    tail -20 /tmp/server_pqc_multiple.log
    exit 1
fi

