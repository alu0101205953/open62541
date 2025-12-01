# Guía de Uso: client_encryption y server_encryption

## client_encryption

### Sintaxis

```bash
./client_encryption [endpointUrl] [client-certificate.der] [client-private-key.der] [trust-list1.der] [trust-list2.der] ... [--serverCert <server-certificate.der>]
```

### Argumentos

#### Modo 1: Sin argumentos (generación automática de certificados)
```bash
./client_encryption
```
- **Comportamiento**: Genera automáticamente certificados PQC (requiere OpenSSL 3.0+ y OQS Provider)
- **Endpoint por defecto**: `opc.tcp://localhost:4840`
- **Archivos generados**: 
  - `client_cert_pqc.der`
  - `client_key_pqc.der`
- **Nota**: Si falla la generación, el programa termina con error

#### Modo 2: Con certificados proporcionados (mínimo 4 argumentos)
```bash
./client_encryption <endpointUrl> <client-certificate.der> <client-private-key.der> [trust-list1.der] [trust-list2.der] ... [--serverCert <server-certificate.der>]
```

**Argumentos obligatorios (si se proporcionan certificados):**
1. `endpointUrl`: URL del endpoint del servidor OPC UA
   - Ejemplo: `opc.tcp://localhost:4840`
   - Ejemplo: `opc.tcp://192.168.1.100:4840`

2. `client-certificate.der`: Archivo de certificado del cliente (formato DER)
   - Debe ser un archivo válido y legible

3. `client-private-key.der`: Archivo de clave privada del cliente (formato DER)
   - Debe ser un archivo válido y legible

**Argumentos opcionales:**
- `trust-list1.der`, `trust-list2.der`, ...: Archivos de certificados de confianza (trust list)
  - Puede haber múltiples archivos de trust list
  - Se cargan en el orden especificado

- `--serverCert <server-certificate.der>`: Certificado del servidor
  - Crea un endpoint directo en la configuración del cliente
  - Si se proporciona y no hay trust list, se añade automáticamente a la trust list
  - Puede aparecer en cualquier posición después de los 3 primeros argumentos

### Ejemplos

```bash
# Modo automático (genera certificados)
./client_encryption

# Con certificados y sin trust list
./client_encryption opc.tcp://localhost:4840 client_cert.der client_key.der

# Con certificados y trust list
./client_encryption opc.tcp://localhost:4840 client_cert.der client_key.der server_cert.der

# Con certificados, trust list y certificado del servidor
./client_encryption opc.tcp://localhost:4840 client_cert.der client_key.der ca_cert.der --serverCert server_cert.der

# Múltiples trust lists
./client_encryption opc.tcp://localhost:4840 client_cert.der client_key.der ca1.der ca2.der ca3.der
```

### Notas importantes

- Si no se proporciona trust list ni `--serverCert`, el cliente acepta todos los certificados (solo para desarrollo/pruebas)
- Los certificados deben tener extensiones PQC si se usa OpenSSL con soporte PQC
- El programa verifica automáticamente y añade extensiones PQC si es necesario

---

## server_encryption

### Sintaxis

```bash
./server_encryption [server-certificate.der] [private-key.der] [trust-list1.der] [trust-list2.der] ... [--onlySecure] [--allowDiscovery] [--clientSigKey <archivo>] [--clientKemKey <archivo>]
```

### Argumentos

#### Modo 1: Sin argumentos (generación automática de certificados)
```bash
./server_encryption
```
- **Comportamiento**: Genera automáticamente certificados PQC (requiere OpenSSL 3.0+ y OQS Provider)
- **Puerto por defecto**: `4840`
- **Archivos generados**: 
  - `server_cert_pqc.der`
  - `server_key_pqc.der`
- **Nota**: Si falla la generación, el programa termina con error

#### Modo 2: Con certificados proporcionados (mínimo 2 argumentos)
```bash
./server_encryption <server-certificate.der> <private-key.der> [trust-list1.der] [trust-list2.der] ... [opciones]
```

**Argumentos obligatorios (si se proporcionan certificados):**
1. `server-certificate.der`: Archivo de certificado del servidor (formato DER)
   - Debe ser un archivo válido y legible

2. `private-key.der`: Archivo de clave privada del servidor (formato DER)
   - Debe ser un archivo válido y legible

**Argumentos opcionales:**
- `trust-list1.der`, `trust-list2.der`, ...: Archivos de certificados de confianza (trust list)
  - Puede haber múltiples archivos de trust list
  - Se cargan en el orden especificado

**Opciones:**
- `--onlySecure`: Solo permite conexiones seguras (sin política "None")
  - Por defecto, el servidor permite conexiones sin cifrado para descubrimiento

- `--allowDiscovery`: Permite descubrimiento incluso con `--onlySecure`
  - Solo funciona si se usa junto con `--onlySecure`
  - Añade la política "None" solo para descubrimiento, no para conexiones normales

- `--clientSigKey <archivo>`: Archivo con la clave pública de firma PQC del cliente
  - Requiere `--clientKemKey` también
  - Tamaño esperado: 1312 bytes (Dilithium2)
  - Se usa para registrar claves PQC remotas del cliente

- `--clientKemKey <archivo>`: Archivo con la clave pública KEM PQC del cliente
  - Requiere `--clientSigKey` también
  - Tamaño esperado: 1184 bytes (Kyber768)
  - Se usa para registrar claves PQC remotas del cliente

### Ejemplos

```bash
# Modo automático (genera certificados)
./server_encryption

# Con certificados y sin trust list
./server_encryption server_cert.der server_key.der

# Con certificados y trust list
./server_encryption server_cert.der server_key.der client_cert.der

# Solo conexiones seguras
./server_encryption server_cert.der server_key.der --onlySecure

# Solo conexiones seguras pero permite descubrimiento
./server_encryption server_cert.der server_key.der --onlySecure --allowDiscovery

# Con claves PQC del cliente
./server_encryption server_cert.der server_key.der --clientSigKey client_sig_key.der --clientKemKey client_kem_key.der

# Combinación completa
./server_encryption server_cert.der server_key.der ca1.der ca2.der --onlySecure --allowDiscovery --clientSigKey client_sig.der --clientKemKey client_kem.der
```

### Notas importantes

- El servidor acepta todos los certificados por defecto (solo para desarrollo/pruebas)
- El puerto por defecto es `4840` (no configurable desde línea de comandos)
- Las opciones pueden aparecer en cualquier orden
- `--clientSigKey` y `--clientKemKey` deben usarse juntos
- El servidor se detiene con `SIGINT` (Ctrl+C) o `SIGTERM`

---

## Requisitos comunes

### Para generación automática de certificados:
- OpenSSL 3.0 o superior
- OQS Provider instalado y disponible
- Las bibliotecas OQS deben estar enlazadas

### Formatos de archivo:
- Todos los certificados y claves deben estar en formato DER (`.der`)
- Los archivos deben ser legibles y válidos

### Seguridad:
- Los certificados auto-generados se guardan en el directorio actual
- En producción, use certificados firmados por una CA de confianza
- No use "aceptar todos los certificados" en producción

