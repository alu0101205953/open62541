#!/bin/bash
# Script para probar la PKI post-cuántica OPC UA
# Genera CA, certificados de servidor y cliente, y prueba la conexión

set -e  # Salir si hay errores

echo "═══════════════════════════════════════════════════════════════"
echo "Prueba de PKI Post-Cuántica OPC UA"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Directorios
BUILD_DIR="./build/bin/examples"
CA_DIR="./local_ca"
SERVER_PKI="./server_pki"
CLIENT_PKI="./client_pki"
OUT_DIR="./out"

# Limpiar directorios anteriores
echo "[1/7] Limpiando directorios anteriores..."
rm -rf "$CA_DIR" "$SERVER_PKI" "$CLIENT_PKI" "$OUT_DIR"
mkdir -p "$SERVER_PKI/ApplCerts/issuer/certs"
mkdir -p "$CLIENT_PKI/ApplCerts/issuer/certs"

# Verificar que pqc_ca_tool existe
if [ ! -f "$BUILD_DIR/pqc_ca_tool" ]; then
    echo "ERROR: pqc_ca_tool no encontrado en $BUILD_DIR"
    echo "Compila primero: cd build && make pqc_ca_tool"
    exit 1
fi

# 1. Crear CA
echo ""
echo "[2/7] Creando CA post-cuántica (ML-DSA-44)..."
"$BUILD_DIR/pqc_ca_tool" init-ca
if [ $? -ne 0 ]; then
    echo "ERROR: Fallo al crear CA"
    exit 1
fi
echo "✓ CA creada: $CA_DIR/ca_cert.der, $CA_DIR/ca_key.der"

# Copiar CA a las PKI de servidor y cliente
cp "$CA_DIR/ca_cert.der" "$SERVER_PKI/ApplCerts/issuer/certs/ca_cert.der"
cp "$CA_DIR/ca_cert.der" "$CLIENT_PKI/ApplCerts/issuer/certs/ca_cert.der"
echo "✓ CA copiada a PKI de servidor y cliente"

# 2. Generar CSR del servidor
echo ""
echo "[3/7] Generando CSR del servidor..."
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Server" \
    "URI:urn:open62541.unconfigured.application"
if [ $? -ne 0 ]; then
    echo "ERROR: Fallo al generar CSR del servidor"
    exit 1
fi
echo "✓ CSR del servidor generado: $OUT_DIR/app.csr, $OUT_DIR/app_key.der"

# 3. Firmar certificado del servidor
echo ""
echo "[4/7] Firmando certificado del servidor con CA..."
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
if [ $? -ne 0 ]; then
    echo "ERROR: Fallo al firmar certificado del servidor"
    exit 1
fi
echo "✓ Certificado del servidor firmado: $OUT_DIR/app_cert.der"

# Copiar certificado y clave del servidor a su PKI
mkdir -p "$SERVER_PKI/ApplCerts/own/certs"
mkdir -p "$SERVER_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$SERVER_PKI/ApplCerts/own/certs/server_cert.der"
cp "$OUT_DIR/app_key.der" "$SERVER_PKI/ApplCerts/own/private/server_key.der"
echo "✓ Certificado y clave del servidor copiados a PKI"

# 4. Generar CSR del cliente
echo ""
echo "[5/7] Generando CSR del cliente..."
rm -f "$OUT_DIR"/*.csr "$OUT_DIR"/*_key.der "$OUT_DIR"/*_cert.der
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Client" \
    "URI:urn:open62541.unconfigured.application"
if [ $? -ne 0 ]; then
    echo "ERROR: Fallo al generar CSR del cliente"
    exit 1
fi
echo "✓ CSR del cliente generado: $OUT_DIR/app.csr, $OUT_DIR/app_key.der"

# 5. Firmar certificado del cliente
echo ""
echo "[6/7] Firmando certificado del cliente con CA..."
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
if [ $? -ne 0 ]; then
    echo "ERROR: Fallo al firmar certificado del cliente"
    exit 1
fi
echo "✓ Certificado del cliente firmado: $OUT_DIR/app_cert.der"

# Copiar certificado y clave del cliente a su PKI
mkdir -p "$CLIENT_PKI/ApplCerts/own/certs"
mkdir -p "$CLIENT_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$CLIENT_PKI/ApplCerts/own/certs/client_cert.der"
cp "$OUT_DIR/app_key.der" "$CLIENT_PKI/ApplCerts/own/private/client_key.der"
echo "✓ Certificado y clave del cliente copiados a PKI"

# 6. Verificar estructura PKI
echo ""
echo "[7/7] Verificando estructura PKI..."
echo ""
echo "Estructura PKI del servidor:"
find "$SERVER_PKI" -type f | sort
echo ""
echo "Estructura PKI del cliente:"
find "$CLIENT_PKI" -type f | sort

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "✓ PKI configurada correctamente"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Para probar:"
echo "  1. Terminal 1 - Servidor:"
echo "     $BUILD_DIR/server_encryption --pki $SERVER_PKI"
echo ""
echo "  2. Terminal 2 - Cliente:"
echo "     $BUILD_DIR/client_encryption opc.tcp://localhost:4840 --pki $CLIENT_PKI"
echo ""
echo "═══════════════════════════════════════════════════════════════"
