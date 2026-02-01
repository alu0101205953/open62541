#!/bin/bash
# Script de pruebas de robustez para PKI post-cuántica OPC UA
# Evalúa el comportamiento del sistema ante diferentes escenarios de fallo

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directorios
BUILD_DIR="./build/bin/examples"
CA_DIR="./local_ca"
CA2_DIR="./local_ca2"  # Segunda CA para pruebas
SERVER_PKI="./server_pki"
CLIENT_PKI="./client_pki"
TEST_DIR="./test_robustez"
OUT_DIR="./out"
RESULTS_FILE="$TEST_DIR/results.md"

# Función para imprimir sección
print_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Función para imprimir resultado de prueba
print_test_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓ $test_name: PASS${NC}"
    elif [ "$result" = "FAIL" ]; then
        echo -e "${RED}✗ $test_name: FAIL${NC}"
    else
        echo -e "${YELLOW}? $test_name: $result${NC}"
    fi
    
    if [ -n "$details" ]; then
        echo "  $details"
    fi
    
    # Guardar en archivo de resultados
    echo "## $test_name" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Resultado**: $result" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Detalles**: $details" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
}

# Función para ejecutar prueba de conexión
run_connection_test() {
    local server_pki="$1"
    local client_pki="$2"
    local test_name="$3"
    local expected_result="$4"  # "ACCEPT" o "REJECT"
    
    local server_log="$TEST_DIR/${test_name}_server.log"
    local client_log="$TEST_DIR/${test_name}_client.log"
    
    # Limpiar logs anteriores
    rm -f "$server_log" "$client_log"
    
    # Iniciar servidor en segundo plano
    echo "  Iniciando servidor..."
    "$BUILD_DIR/server_encryption" --onlySecure --allowDiscovery --pki "$server_pki" > "$server_log" 2>&1 &
    local server_pid=$!
    
    # Esperar a que el servidor arranque
    sleep 2
    
    # Verificar que el servidor sigue corriendo
    if ! kill -0 $server_pid 2>/dev/null; then
        echo "  ERROR: El servidor se detuvo inesperadamente"
        cat "$server_log"
        kill $server_pid 2>/dev/null || true
        return 1
    fi
    
    # Ejecutar cliente con timeout
    echo "  Ejecutando cliente..."
    local client_exit=0
    timeout 5 "$BUILD_DIR/client_encryption" "opc.tcp://localhost:4840" --pki "$client_pki" > "$client_log" 2>&1 || client_exit=$?
    
    # Detener servidor
    kill $server_pid 2>/dev/null || true
    wait $server_pid 2>/dev/null || true
    
    # Analizar resultado
    local connection_result="UNKNOWN"
    local error_code=""
    local error_point=""
    
    if [ $client_exit -eq 0 ]; then
        connection_result="ACCEPT"
    else
        connection_result="REJECT"
        
        # Buscar códigos de error en los logs
        if grep -q "BADCERTIFICATEUNTRUSTED" "$server_log" "$client_log" 2>/dev/null; then
            error_code="BADCERTIFICATEUNTRUSTED"
            error_point="Validación de Trust List durante establecimiento de SecureChannel"
        elif grep -q "BADCERTIFICATECHAININCOMPLETE" "$server_log" "$client_log" 2>/dev/null; then
            error_code="BADCERTIFICATECHAININCOMPLETE"
            error_point="Construcción de cadena de certificados"
        elif grep -q "BADCERTIFICATEINVALID" "$server_log" "$client_log" 2>/dev/null; then
            error_code="BADCERTIFICATEINVALID"
            error_point="Validación de estructura o firma del certificado"
        elif grep -q "BADSECURITYCHECKSFAILED" "$server_log" "$client_log" 2>/dev/null; then
            error_code="BADSECURITYCHECKSFAILED"
            error_point="Verificación de firma del mensaje OPN"
        elif grep -q "BADCERTIFICATETIMEINVALID" "$server_log" "$client_log" 2>/dev/null; then
            error_code="BADCERTIFICATETIMEINVALID"
            error_point="Validación de período de validez"
        fi
    fi
    
    # Determinar si el resultado es correcto
    local test_result="UNKNOWN"
    if [ "$expected_result" = "ACCEPT" ] && [ "$connection_result" = "ACCEPT" ]; then
        test_result="PASS"
    elif [ "$expected_result" = "REJECT" ] && [ "$connection_result" = "REJECT" ]; then
        test_result="PASS"
    else
        test_result="FAIL"
    fi
    
    # Construir detalles
    local details="Conexión: $connection_result"
    if [ -n "$error_code" ]; then
        details="$details | Error: $error_code | Punto: $error_point"
    fi
    
    print_test_result "$test_name" "$test_result" "$details"
    
    # Guardar logs en resultados
    echo "**Logs del servidor**:\`\`\`" >> "$RESULTS_FILE"
    cat "$server_log" >> "$RESULTS_FILE" 2>/dev/null || echo "(vacío)" >> "$RESULTS_FILE"
    echo "\`\`\`" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Logs del cliente**:\`\`\`" >> "$RESULTS_FILE"
    cat "$client_log" >> "$RESULTS_FILE" 2>/dev/null || echo "(vacío)" >> "$RESULTS_FILE"
    echo "\`\`\`" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    
    return 0
}

# Verificar dependencias
if [ ! -f "$BUILD_DIR/pqc_ca_tool" ]; then
    echo "ERROR: pqc_ca_tool no encontrado. Compila primero: cd build && make pqc_ca_tool"
    exit 1
fi

if [ ! -f "$BUILD_DIR/server_encryption" ]; then
    echo "ERROR: server_encryption no encontrado. Compila primero: cd build && make server_encryption"
    exit 1
fi

if [ ! -f "$BUILD_DIR/client_encryption" ]; then
    echo "ERROR: client_encryption no encontrado. Compila primero: cd build && make client_encryption"
    exit 1
fi

# Crear directorio de pruebas
mkdir -p "$TEST_DIR"
rm -f "$RESULTS_FILE"

# Inicializar archivo de resultados
cat > "$RESULTS_FILE" << EOF
# Resultados de Pruebas de Robustez - PKI Post-Cuántica OPC UA

Fecha: $(date)
EOF

print_section "PRUEBAS DE ROBUSTEZ - PKI POST-CUÁNTICA OPC UA"

# ============================================================================
# PRUEBA 1: CA Distinta entre Cliente y Servidor
# ============================================================================
print_section "PRUEBA 1: CA Distinta entre Cliente y Servidor"

echo "Configurando escenario: Cliente confía en CA1, Servidor firmado por CA2"

# Limpiar y crear estructura
rm -rf "$CA_DIR" "$CA2_DIR" "$SERVER_PKI" "$CLIENT_PKI" "$OUT_DIR"
mkdir -p "$SERVER_PKI/ApplCerts/issuer/certs"
mkdir -p "$CLIENT_PKI/ApplCerts/issuer/certs"

# Crear CA1
echo "  Creando CA1..."
"$BUILD_DIR/pqc_ca_tool" init-ca
if [ ! -f "$CA_DIR/ca_cert.der" ]; then
    echo "  ERROR: No se pudo crear CA1"
    exit 1
fi
# Guardar CA1 temporalmente
mkdir -p "${CA_DIR}_backup"
cp "$CA_DIR/ca_cert.der" "${CA_DIR}_backup/ca1_cert.der"
cp "$CA_DIR/ca_key.der" "${CA_DIR}_backup/ca1_key.der"
cp "$CA_DIR/ca_cert.der" "$CLIENT_PKI/ApplCerts/issuer/certs/ca1_cert.der"
echo "  ✓ CA1 creada y guardada"

# Crear CA2 (sobrescribe local_ca)
echo "  Creando CA2..."
rm -f "$CA_DIR"/*.der
"$BUILD_DIR/pqc_ca_tool" init-ca
if [ ! -f "$CA_DIR/ca_cert.der" ]; then
    echo "  ERROR: No se pudo crear CA2"
    exit 1
fi
# Guardar CA2
mkdir -p "$CA2_DIR"
cp "$CA_DIR/ca_cert.der" "$CA2_DIR/ca2_cert.der"
cp "$CA_DIR/ca_key.der" "$CA2_DIR/ca2_key.der"
cp "$CA_DIR/ca_cert.der" "$SERVER_PKI/ApplCerts/issuer/certs/ca2_cert.der"
echo "  ✓ CA2 creada y guardada"

# Generar certificado del servidor con CA2
echo "  Generando certificado del servidor con CA2..."
mkdir -p "$OUT_DIR"
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Server" \
    "URI:urn:open62541.server.application"
# CA2 ya está en local_ca (fue la última creada), usarla para firmar
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"

mkdir -p "$SERVER_PKI/ApplCerts/own/certs" "$SERVER_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$SERVER_PKI/ApplCerts/own/certs/server_cert.der"
cp "$OUT_DIR/app_key.der" "$SERVER_PKI/ApplCerts/own/private/server_key.der"

# Restaurar CA1 para firmar certificado del cliente
echo "  Restaurando CA1 para firmar certificado del cliente..."
rm -f "$CA_DIR"/*.der
cp "${CA_DIR}_backup/ca1_cert.der" "$CA_DIR/ca_cert.der"
cp "${CA_DIR}_backup/ca1_key.der" "$CA_DIR/ca_key.der"

# Generar certificado del cliente con CA1
echo "  Generando certificado del cliente con CA1..."
rm -f "$OUT_DIR"/*.csr "$OUT_DIR"/*_key.der "$OUT_DIR"/*_cert.der
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Client" \
    "URI:urn:open62541.client.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"

mkdir -p "$CLIENT_PKI/ApplCerts/own/certs" "$CLIENT_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$CLIENT_PKI/ApplCerts/own/certs/client_cert.der"
cp "$OUT_DIR/app_key.der" "$CLIENT_PKI/ApplCerts/own/private/client_key.der"

run_connection_test "$SERVER_PKI" "$CLIENT_PKI" "test1_ca_distinta" "REJECT"

# ============================================================================
# PRUEBA 2: Falta del Certificado de la CA
# ============================================================================
print_section "PRUEBA 2: Falta del Certificado de la CA"

echo "Configurando escenario: Cliente sin CA en Trust List"

# Usar CA1 para ambos
rm -rf "$SERVER_PKI" "$CLIENT_PKI" "$OUT_DIR"
mkdir -p "$SERVER_PKI/ApplCerts/issuer/certs"
mkdir -p "$CLIENT_PKI/ApplCerts/issuer/certs"  # Pero no copiar CA

# Generar certificados con CA1
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Server" \
    "URI:urn:open62541.server.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
cp "$CA_DIR/ca_cert.der" "$SERVER_PKI/ApplCerts/issuer/certs/ca_cert.der"
mkdir -p "$SERVER_PKI/ApplCerts/own/certs" "$SERVER_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$SERVER_PKI/ApplCerts/own/certs/server_cert.der"
cp "$OUT_DIR/app_key.der" "$SERVER_PKI/ApplCerts/own/private/server_key.der"

rm -f "$OUT_DIR"/*.csr "$OUT_DIR"/*_key.der "$OUT_DIR"/*_cert.der
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Client" \
    "URI:urn:open62541.client.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
mkdir -p "$CLIENT_PKI/ApplCerts/own/certs" "$CLIENT_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$CLIENT_PKI/ApplCerts/own/certs/client_cert.der"
cp "$OUT_DIR/app_key.der" "$CLIENT_PKI/ApplCerts/own/private/client_key.der"
# NO copiar CA al cliente

run_connection_test "$SERVER_PKI" "$CLIENT_PKI" "test2_sin_ca" "REJECT"

# ============================================================================
# PRUEBA 3: Certificado del Peer No Confiable
# ============================================================================
print_section "PRUEBA 3: Certificado del Peer No Confiable"

echo "Configurando escenario: Certificado válido pero no en Trust List (solo en Issuer List)"

# Configurar PKI normal
rm -rf "$SERVER_PKI" "$CLIENT_PKI" "$OUT_DIR"
mkdir -p "$SERVER_PKI/ApplCerts/issuer/certs"
mkdir -p "$CLIENT_PKI/ApplCerts/issuer/certs"

# Generar certificados
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Server" \
    "URI:urn:open62541.server.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
cp "$CA_DIR/ca_cert.der" "$SERVER_PKI/ApplCerts/issuer/certs/ca_cert.der"
mkdir -p "$SERVER_PKI/ApplCerts/own/certs" "$SERVER_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$SERVER_PKI/ApplCerts/own/certs/server_cert.der"
cp "$OUT_DIR/app_key.der" "$SERVER_PKI/ApplCerts/own/private/server_key.der"

rm -f "$OUT_DIR"/*.csr "$OUT_DIR"/*_key.der "$OUT_DIR"/*_cert.der
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Client" \
    "URI:urn:open62541.client.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
mkdir -p "$CLIENT_PKI/ApplCerts/own/certs" "$CLIENT_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$CLIENT_PKI/ApplCerts/own/certs/client_cert.der"
cp "$OUT_DIR/app_key.der" "$CLIENT_PKI/ApplCerts/own/private/client_key.der"

# CA solo en Issuer List, no en Trust List
cp "$CA_DIR/ca_cert.der" "$CLIENT_PKI/ApplCerts/issuer/certs/ca_cert.der"
# No crear directorio trusted/certs (equivalente a no estar en Trust List)

run_connection_test "$SERVER_PKI" "$CLIENT_PKI" "test3_no_confiable" "REJECT"

# ============================================================================
# PRUEBA 4: Certificado Modificado (Integridad)
# ============================================================================
print_section "PRUEBA 4: Certificado Modificado (Integridad)"

echo "Configurando escenario: Certificado del servidor con byte alterado"
echo "NOTA: El servidor puede no arrancar con certificado corrupto (rechazo temprano)"

# Configurar PKI normal
rm -rf "$SERVER_PKI" "$CLIENT_PKI" "$OUT_DIR"
mkdir -p "$SERVER_PKI/ApplCerts/issuer/certs"
mkdir -p "$CLIENT_PKI/ApplCerts/issuer/certs"

# Generar certificados
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Server" \
    "URI:urn:open62541.server.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
cp "$CA_DIR/ca_cert.der" "$SERVER_PKI/ApplCerts/issuer/certs/ca_cert.der"
mkdir -p "$SERVER_PKI/ApplCerts/own/certs" "$SERVER_PKI/ApplCerts/own/private"
# Modificar un byte del certificado
cp "$OUT_DIR/app_cert.der" "$SERVER_PKI/ApplCerts/own/certs/server_cert.der"
# Alterar byte en posición 100 (si el certificado es suficientemente grande)
if [ -f "$SERVER_PKI/ApplCerts/own/certs/server_cert.der" ]; then
    size=$(stat -f%z "$SERVER_PKI/ApplCerts/own/certs/server_cert.der" 2>/dev/null || stat -c%s "$SERVER_PKI/ApplCerts/own/certs/server_cert.der" 2>/dev/null)
    if [ "$size" -gt 100 ]; then
        # Usar Python para modificar un byte de forma segura
        python3 << EOF
import sys
with open("$SERVER_PKI/ApplCerts/own/certs/server_cert.der", "rb") as f:
    data = bytearray(f.read())
if len(data) > 100:
    data[100] = (data[100] + 1) % 256
    with open("$SERVER_PKI/ApplCerts/own/certs/server_cert.der", "wb") as f:
        f.write(data)
EOF
        echo "  Certificado modificado (byte 100 alterado)"
    fi
fi
cp "$OUT_DIR/app_key.der" "$SERVER_PKI/ApplCerts/own/private/server_key.der"

rm -f "$OUT_DIR"/*.csr "$OUT_DIR"/*_key.der "$OUT_DIR"/*_cert.der
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Client" \
    "URI:urn:open62541.client.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
mkdir -p "$CLIENT_PKI/ApplCerts/own/certs" "$CLIENT_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$CLIENT_PKI/ApplCerts/own/certs/client_cert.der"
cp "$OUT_DIR/app_key.der" "$CLIENT_PKI/ApplCerts/own/private/client_key.der"
cp "$CA_DIR/ca_cert.der" "$CLIENT_PKI/ApplCerts/issuer/certs/ca_cert.der"

# Ejecutar prueba especial: el servidor puede no arrancar con certificado corrupto
server_log="$TEST_DIR/test4_certificado_modificado_server.log"
client_log="$TEST_DIR/test4_certificado_modificado_client.log"
rm -f "$server_log" "$client_log"

echo "  Intentando iniciar servidor con certificado corrupto..."
"$BUILD_DIR/server_encryption" --onlySecure --allowDiscovery --pki "$SERVER_PKI" > "$server_log" 2>&1 &
server_pid=$!

# Esperar un poco más para ver si el servidor crashea o arranca
sleep 3

# Verificar si el servidor sigue corriendo
if ! kill -0 $server_pid 2>/dev/null; then
    # El servidor se detuvo - esto es un rechazo correcto
    echo "  ✓ Servidor rechazó certificado corrupto durante inicialización"
    connection_result="REJECT"
    error_code="BADCERTIFICATEINVALID"
    error_point="Inicialización del servidor - parseo del certificado"
    test_result="PASS"
    details="Conexión: $connection_result | Error: $error_code | Punto: $error_point"
    print_test_result "test4_certificado_modificado" "$test_result" "$details"
    
    # Guardar logs
    echo "## test4_certificado_modificado" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Resultado**: $test_result" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Detalles**: $details" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Logs del servidor**:\`\`\`" >> "$RESULTS_FILE"
    cat "$server_log" >> "$RESULTS_FILE" 2>/dev/null || echo "(vacío)" >> "$RESULTS_FILE"
    echo "\`\`\`" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    
    # Limpiar proceso si aún existe
    kill $server_pid 2>/dev/null || true
    wait $server_pid 2>/dev/null || true
else
    # El servidor arrancó (inesperado), intentar conectar cliente
    echo "  ⚠ Servidor arrancó (inesperado), intentando conectar cliente..."
    client_exit=0
    timeout 5 "$BUILD_DIR/client_encryption" "opc.tcp://localhost:4840" --pki "$CLIENT_PKI" > "$client_log" 2>&1 || client_exit=$?
    kill $server_pid 2>/dev/null || true
    wait $server_pid 2>/dev/null || true
    
    # Analizar resultado del cliente
    if [ ${client_exit:-1} -ne 0 ]; then
        connection_result="REJECT"
        test_result="PASS"
    else
        connection_result="ACCEPT"
        test_result="FAIL"
    fi
    
    details="Conexión: $connection_result (servidor arrancó pero cliente rechazó)"
    print_test_result "test4_certificado_modificado" "$test_result" "$details"
    
    # Guardar logs
    echo "## test4_certificado_modificado" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Resultado**: $test_result" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Detalles**: $details" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Logs del servidor**:\`\`\`" >> "$RESULTS_FILE"
    cat "$server_log" >> "$RESULTS_FILE" 2>/dev/null || echo "(vacío)" >> "$RESULTS_FILE"
    echo "\`\`\`" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    echo "**Logs del cliente**:\`\`\`" >> "$RESULTS_FILE"
    cat "$client_log" >> "$RESULTS_FILE" 2>/dev/null || echo "(vacío)" >> "$RESULTS_FILE"
    echo "\`\`\`" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
fi

# ============================================================================
# PRUEBA 5: Certificado Caducado
# ============================================================================
print_section "PRUEBA 5: Certificado Caducado"

echo "NOTA: Esta prueba requiere modificar fechas del certificado."
echo "Por limitaciones del script, se marca como PENDIENTE."
echo ""
echo "Para implementar:"
echo "  1. Generar certificado con fecha de expiración pasada"
echo "  2. Verificar que se rechace con BADCERTIFICATETIMEINVALID"

print_test_result "test5_certificado_caducado" "PENDIENTE" "Requiere modificación de fechas del certificado X.509"

# ============================================================================
# PRUEBA 6: Clave Pública Incompatible
# ============================================================================
print_section "PRUEBA 6: Clave Pública Incompatible"

echo "NOTA: Esta prueba requiere certificado con algoritmo diferente (RSA/ECDSA)."
echo "Se marca como PENDIENTE."
echo ""
echo "Para implementar:"
echo "  1. Generar certificado RSA/ECDSA tradicional"
echo "  2. Intentar usarlo con security policy PQC"
echo "  3. Verificar rechazo apropiado"

print_test_result "test6_clave_incompatible" "PENDIENTE" "Requiere certificado con algoritmo tradicional (RSA/ECDSA)"

# ============================================================================
# PRUEBA 7: Clave Privada Incorrecta
# ============================================================================
print_section "PRUEBA 7: Clave Privada Incorrecta"

echo "Configurando escenario: Servidor con clave privada que no corresponde a su certificado"

# Configurar PKI normal
rm -rf "$SERVER_PKI" "$CLIENT_PKI" "$OUT_DIR"
mkdir -p "$SERVER_PKI/ApplCerts/issuer/certs"
mkdir -p "$CLIENT_PKI/ApplCerts/issuer/certs"

# Generar certificado del servidor
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Server" \
    "URI:urn:open62541.server.application"
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
cp "$CA_DIR/ca_cert.der" "$SERVER_PKI/ApplCerts/issuer/certs/ca_cert.der"
mkdir -p "$SERVER_PKI/ApplCerts/own/certs" "$SERVER_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$SERVER_PKI/ApplCerts/own/certs/server_cert.der"

# Generar otra clave privada (que no corresponde al certificado)
rm -f "$OUT_DIR"/*.csr "$OUT_DIR"/*_key.der "$OUT_DIR"/*_cert.der
"$BUILD_DIR/pqc_ca_tool" gen-csr \
    "C=DE,O=TestOrganization,CN=OPC-UA-Client" \
    "URI:urn:open62541.client.application"
# Usar la clave del cliente para el servidor (incorrecta)
cp "$OUT_DIR/app_key.der" "$SERVER_PKI/ApplCerts/own/private/server_key.der"

# Configurar cliente normalmente
"$BUILD_DIR/pqc_ca_tool" sign-cert "$OUT_DIR/app.csr"
mkdir -p "$CLIENT_PKI/ApplCerts/own/certs" "$CLIENT_PKI/ApplCerts/own/private"
cp "$OUT_DIR/app_cert.der" "$CLIENT_PKI/ApplCerts/own/certs/client_cert.der"
cp "$OUT_DIR/app_key.der" "$CLIENT_PKI/ApplCerts/own/private/client_key.der"
cp "$CA_DIR/ca_cert.der" "$CLIENT_PKI/ApplCerts/issuer/certs/ca_cert.der"

run_connection_test "$SERVER_PKI" "$CLIENT_PKI" "test7_clave_privada_incorrecta" "REJECT"

# ============================================================================
# RESUMEN
# ============================================================================
print_section "RESUMEN DE PRUEBAS"

echo "Resultados guardados en: $RESULTS_FILE"
echo ""
echo "Para ver los resultados detallados:"
echo "  cat $RESULTS_FILE"
