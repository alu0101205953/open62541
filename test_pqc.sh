#!/bin/bash

# Script para probar servidor y cliente con certificados PQC
# Uso: ./test_pqc.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$SCRIPT_DIR/build/bin/examples"

echo "=========================================="
echo "Prueba de Servidor y Cliente PQC"
echo "=========================================="
echo ""

# Verificar que los ejecutables existen
if [ ! -f "$EXAMPLES_DIR/server_encryption" ]; then
    echo "ERROR: No se encuentra server_encryption"
    echo "Compila primero con: cd build && make -j4"
    exit 1
fi

if [ ! -f "$EXAMPLES_DIR/client_encryption" ]; then
    echo "ERROR: No se encuentra client_encryption"
    echo "Compila primero con: cd build && make -j4"
    exit 1
fi

# Verificar que los certificados existen
if [ ! -f "$EXAMPLES_DIR/server_cert_pqc.der" ]; then
    echo "Copiando certificados al directorio de ejecución..."
    cp "$SCRIPT_DIR/server_cert_pqc.der" "$EXAMPLES_DIR/" 2>/dev/null
    cp "$SCRIPT_DIR/server_key_pqc.der" "$EXAMPLES_DIR/" 2>/dev/null
    cp "$SCRIPT_DIR/client_cert_pqc.der" "$EXAMPLES_DIR/" 2>/dev/null
    cp "$SCRIPT_DIR/client_key_pqc.der" "$EXAMPLES_DIR/" 2>/dev/null
fi

cd "$EXAMPLES_DIR"

echo "Iniciando servidor PQC en segundo plano..."
./server_encryption server_cert_pqc.der server_key_pqc.der > /tmp/server_pqc.log 2>&1 &
SERVER_PID=$!

echo "Servidor iniciado (PID: $SERVER_PID)"
echo "Esperando 3 segundos para que el servidor se inicie..."
sleep 3

echo ""
echo "Conectando cliente PQC..."
echo "=========================================="
./client_encryption opc.tcp://localhost:4840 client_cert_pqc.der client_key_pqc.der --serverCert server_cert_pqc.der

CLIENT_EXIT=$?

echo ""
echo "=========================================="
if [ $CLIENT_EXIT -eq 0 ]; then
    echo "✓ Cliente conectado exitosamente"
else
    echo "✗ Cliente falló (código de salida: $CLIENT_EXIT)"
fi

echo ""
echo "Deteniendo servidor..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "Logs del servidor:"
echo "=========================================="
tail -20 /tmp/server_pqc.log

echo ""
echo "Prueba completada"

