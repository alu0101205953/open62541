# Flujo Completo de la Aplicación OPC UA con PKI FileStore y Políticas PQC

## Resumen Ejecutivo

Esta aplicación implementa un sistema OPC UA completo (cliente y servidor) que utiliza una infraestructura de clave pública (PKI) basada en almacenamiento en archivos (FileStore) y políticas de seguridad post-cuánticas (PQC). El sistema gestiona certificados firmados por una Autoridad Certificadora (CA) y proporciona un flujo completo de validación, aceptación y rechazo de certificados durante la comunicación segura.

---

## Fase 1: Inicialización de la Aplicación

### 1.1 Inicialización del Servidor

Al iniciar el servidor, la aplicación realiza las siguientes acciones:

1. **Verificación de la estructura PKI**: El sistema verifica que existe la estructura de directorios necesaria para el FileStore. Si no existe, la crea recursivamente. La estructura incluye:
   - Directorio raíz del PKI
   - `ApplCerts/own/certs/` - Certificados propios del servidor
   - `ApplCerts/own/private/` - Claves privadas del servidor
   - `ApplCerts/issuer/certs/` - Certificados de la CA emisora
   - `ApplCerts/issuer/crl/` - Listas de revocación de certificados (CRL)
   - `ApplCerts/trusted/` - Certificados de entidades confiables
   - `ApplCerts/rejected/` - Certificados rechazados

2. **Validación de certificados propios**: El sistema verifica que el certificado del servidor (`server_cert.der`) y su clave privada (`server_key.der`) existen en las ubicaciones esperadas. Si faltan, la inicialización falla con un error indicando que se deben generar externamente usando herramientas de CA.

3. **Carga de certificados y claves**: Una vez validada la estructura, el sistema carga el certificado y la clave privada del servidor desde el FileStore en memoria para su uso durante la operación.

### 1.2 Inicialización del Cliente

El cliente sigue un proceso similar:

1. **Creación de estructura PKI del cliente**: Se crea o verifica la estructura de directorios en una ubicación separada (por defecto `./client_pki`), con la misma organización que el servidor.

2. **Validación de certificados propios**: Se verifica la existencia del certificado del cliente (`client_cert.der`) y su clave privada (`client_key.der`).

3. **Carga de certificados**: El cliente carga sus propios certificados y claves desde el FileStore.

---

## Fase 2: Configuración de PKI y Políticas de Seguridad

### 2.1 Configuración del Servidor

Una vez cargados los certificados, el servidor configura su infraestructura de seguridad:

(Hay dos grupos porque OPC UA separa seguridad del canal y autenticación de sesión, aunque ambos usen el mismo certificado físico y el mismo FileStore.)

1. **Configuración de FileStore para canales seguros**: Se establece un grupo de certificados para la validación de canales seguros (SecureChannel PKI). Este grupo se vincula al FileStore y gestiona:
   - Certificados confiables para canales seguros
   - Certificados de emisores (CA)
   - Listas de revocación
   - Certificados rechazados

2. **Configuración de FileStore para sesiones**: Se establece un segundo grupo de certificados para la autenticación de sesiones (Session PKI), que gestiona certificados de usuario y autenticación a nivel de sesión.

3. **Configuración de políticas de seguridad PQC**: El sistema inicializa una política de seguridad post-cuántica que envuelve la funcionalidad criptográfica estándar. Esta política:
   - Utiliza algoritmos de firma post-cuánticos (Dilithium)
   - Utiliza algoritmos de encapsulación de claves (KEM) post-cuánticos (Kyber)
   - Se integra con el FileStore para gestionar certificados PQC

4. **Envoltorio de políticas con FileStore**: La política PQC se envuelve con funcionalidad de FileStore, permitiendo que las operaciones de certificados se persistan automáticamente en el sistema de archivos.

5. **Registro de endpoints**: El servidor registra los endpoints disponibles, cada uno asociado con la política de seguridad PQC configurada.

### 2.2 Configuración del Cliente

El cliente configura su infraestructura de manera similar:

1. **Configuración de FileStore del cliente**: Se establece el grupo de verificación de certificados del cliente, vinculado a su propio FileStore.

2. **Configuración de políticas PQC**: El cliente inicializa la misma política PQC que el servidor, asegurando compatibilidad.

3. **Configuración de políticas de autenticación**: Si se requiere autenticación por certificado a nivel de sesión, se configuran políticas de autenticación adicionales también con soporte PQC y FileStore.

---

## Fase 3: Arranque y Conexión

### 3.1 Arranque del Servidor

1. **Inicio del servidor**: El servidor inicia su bucle principal de eventos, comenzando a escuchar en el puerto configurado (por defecto 4840).

2. **Carga inicial de certificados confiables**: El sistema carga desde el FileStore todos los certificados que están en el directorio `trusted`, así como los certificados de emisores en `issuer/certs`. Estos certificados se mantienen en memoria para validaciones rápidas.

3. **Monitoreo del FileStore (opcional)**: En sistemas Linux, el servidor puede configurar monitoreo del sistema de archivos (inotify) para detectar cambios en los certificados y recargarlos automáticamente.

### 3.2 Conexión del Cliente

1. **Inicialización de la conexión**: El cliente inicia el proceso de conexión al servidor, especificando la URL del endpoint.

2. **Descubrimiento de endpoints (si es necesario)**: Si el cliente no tiene un endpoint preconfigurado, puede realizar una consulta de descubrimiento para obtener la lista de endpoints disponibles del servidor, incluyendo sus políticas de seguridad.

3. **Selección de endpoint**: El cliente selecciona un endpoint que coincida con su política de seguridad PQC configurada.

---

## Fase 4: Handshake Seguro y Validación de Certificados

### 4.0 Funciones de Dilithium y Kyber en la Comunicación

Antes de describir el handshake, es importante entender cómo los algoritmos post-cuánticos Dilithium y Kyber intervienen en cada fase de la comunicación:

#### Dilithium: Firma Digital Post-Cuántica

**Dilithium** es un algoritmo de firma digital post-cuántico (Dilithium2 en esta implementación) que reemplaza a los algoritmos clásicos como RSA o ECDSA. Su función principal es:

1. **Autenticación e Integridad**: Dilithium se usa para firmar digitalmente todos los mensajes importantes, garantizando que:
   - El mensaje proviene realmente del remitente (autenticación)
   - El mensaje no ha sido modificado en tránsito (integridad)

2. **Uso en el Handshake**:
   - **Mensaje OpenSecureChannel (OPN) del cliente**: El cliente firma el mensaje OPN con su clave privada Dilithium antes de enviarlo al servidor
   - **Mensaje OpenSecureChannel (OPN) del servidor**: El servidor firma su respuesta OPN con su clave privada Dilithium
   - **Verificación mutua**: Cada parte verifica la firma del otro usando la clave pública Dilithium extraída del certificado del remitente

3. **Uso durante la Operación Normal**:
   - Todos los mensajes OPC UA (Read, Write, Subscribe, etc.) son firmados con Dilithium
   - El receptor verifica cada firma antes de procesar el mensaje
   - Si la verificación falla, el mensaje se rechaza

4. **Características Técnicas**:
   - Tamaño de firma: 2420 bytes (significativamente mayor que RSA/ECDSA, pero seguro contra computación cuántica)
   - Tamaño de clave pública: 1312 bytes
   - Tamaño de clave privada: 2560 bytes
   - Las claves públicas Dilithium se almacenan como extensiones en los certificados X.509

#### Kyber: Intercambio de Claves Post-Cuántico

**Kyber** es un algoritmo KEM (Key Encapsulation Mechanism) post-cuántico (Kyber768 en esta implementación) que reemplaza a los algoritmos clásicos como RSA-OAEP o ECDH. Su función principal es:

1. **Intercambio de Claves Seguro**: Kyber permite que dos partes establezcan un secreto compartido sin intercambiar directamente las claves privadas:
   - Una parte (el emisor) usa la clave pública Kyber del receptor para generar un secreto compartido
   - El receptor puede recuperar el mismo secreto compartido usando su clave privada Kyber
   - Este secreto compartido se usa luego para derivar claves simétricas de cifrado

2. **Uso en el Handshake (Cifrado Asimétrico)**:
   - **Primer mensaje OPN del cliente**: 
     - Si el cliente ya tiene el certificado del servidor, puede usar la clave pública Kyber del servidor para cifrar el mensaje
     - Si no tiene el certificado aún, envía el mensaje solo firmado (sin cifrar)
   - **Respuesta OPN del servidor**:
     - El servidor siempre cifra su respuesta usando la clave pública Kyber del cliente (extraída del certificado del cliente en el mensaje OPN)
   - **Proceso de encapsulación/descapsulación**:
     - El emisor ejecuta `KEM_encaps` con la clave pública Kyber del receptor, generando:
       - Un ciphertext (texto cifrado) de 1088 bytes
       - Un secreto compartido de 32 bytes
     - El receptor ejecuta `KEM_decaps` con su clave privada Kyber y el ciphertext, recuperando el mismo secreto compartido de 32 bytes
     - El payload del mensaje se cifra mediante XOR con el secreto compartido

3. **Derivación de Claves Simétricas**:
   - Una vez establecido el secreto compartido mediante Kyber, se usa para derivar claves simétricas mediante PSHA256 (Pseudo-Random Function con SHA-256)
   - Se derivan múltiples claves:
     - Clave de cifrado simétrico (AES-256) para cifrar mensajes
     - Clave de firma simétrica (HMAC-SHA256) para autenticación de mensajes
     - Vectores de inicialización (IV) para el cifrado
   - La derivación usa los nonces intercambiados durante el handshake para garantizar unicidad

4. **Uso durante la Operación Normal**:
   - Después del handshake, la comunicación usa principalmente cifrado simétrico (AES-256) derivado de Kyber
   - Sin embargo, Kyber puede usarse nuevamente cuando se renueva el token de seguridad del canal
   - Cada renovación de token puede generar un nuevo secreto compartido mediante Kyber

5. **Características Técnicas**:
   - Tamaño de ciphertext: 1088 bytes
   - Tamaño de secreto compartido: 32 bytes
   - Tamaño de clave pública: 1184 bytes
   - Tamaño de clave privada: 2400 bytes
   - Las claves públicas Kyber se almacenan como extensiones en los certificados X.509

#### Flujo Integrado: Dilithium + Kyber

En la práctica, ambos algoritmos trabajan juntos:

1. **Durante el Handshake**:
   ```
   Cliente → Servidor (OPN):
   - Mensaje firmado con Dilithium (clave privada del cliente)
   - Mensaje cifrado con Kyber (clave pública del servidor, si está disponible)
   - Certificado del cliente incluido (contiene claves públicas Dilithium y Kyber)
   
   Servidor → Cliente (OPN Response):
   - Respuesta firmada con Dilithium (clave privada del servidor)
   - Respuesta cifrada con Kyber (clave pública del cliente)
   - Certificado del servidor incluido (contiene claves públicas Dilithium y Kyber)
   ```

2. **Validación Mutua**:
   - Cada parte extrae las claves públicas Dilithium y Kyber del certificado del otro
   - Verifica la firma Dilithium del mensaje recibido
   - Descifra el mensaje usando su propia clave privada Kyber
   - Valida el certificado contra el FileStore

3. **Establecimiento de Claves Simétricas**:
   - El secreto compartido de Kyber se combina con los nonces intercambiados
   - Se derivan claves simétricas mediante PSHA256
   - Estas claves se usan para toda la comunicación posterior

4. **Comunicación Normal**:
   - Los mensajes se firman con HMAC-SHA256 (usando la clave simétrica derivada)
   - Los mensajes se cifran con AES-256-CBC (usando la clave simétrica derivada)
   - La autenticación inicial mediante Dilithium garantiza que las claves simétricas fueron establecidas con el peer correcto

### 4.1 Establecimiento del Canal Seguro (OpenSecureChannel)

El proceso de establecimiento del canal seguro sigue estos pasos:

1. **Solicitud OpenSecureChannel (OPN) del cliente**:
   - El cliente construye un mensaje OPN que incluye:
     - URI de la política de seguridad (PQC)
     - Modo de seguridad deseado (SignAndEncrypt)
     - Certificado del cliente (en el header de seguridad asimétrico)
     - Thumbprint del certificado del servidor esperado
   - El mensaje se firma usando la clave privada del cliente con algoritmos PQC
   - El mensaje se envía al servidor

2. **Recepción y validación en el servidor**:
   - El servidor recibe el mensaje OPN y extrae el certificado del cliente
   - El servidor identifica la política de seguridad solicitada (PQC) y verifica que está disponible
   - El servidor verifica que el thumbprint del certificado del servidor en el mensaje coincide con su propio certificado
   - El servidor extrae el certificado hoja (leaf certificate) del cliente de la cadena de certificados enviada

3. **Validación del certificado del cliente**:
   - El servidor consulta su FileStore para verificar el certificado del cliente:
     - Verifica si el certificado está en la lista de certificados confiables
     - Verifica la cadena de certificados contra los certificados de emisores (CA) almacenados
     - Verifica que el certificado no esté en la lista de revocación (CRL)
     - Verifica la validez temporal del certificado
   - Si el certificado no es confiable, el servidor puede:
     - Rechazar la conexión inmediatamente, o
     - Mover el certificado a la carpeta `rejected` y notificar al administrador

4. **Configuración del canal en el servidor**:
   - Si la validación es exitosa, el servidor configura el canal seguro con:
     - La política de seguridad PQC
     - El certificado remoto (cliente) para futuras validaciones
     - El contexto criptográfico necesario para la comunicación

5. **Respuesta OpenSecureChannel del servidor**:
   - El servidor construye una respuesta OPN que incluye:
     - El certificado del servidor (con claves públicas Dilithium y Kyber)
     - Un nonce criptográfico
     - Información del token de seguridad del canal
   - La respuesta se firma con la clave privada Dilithium del servidor
   - La respuesta se cifra usando la clave pública Kyber del cliente (extraída del certificado recibido)
   - La respuesta se envía al cliente

6. **Validación en el cliente**:
   - El cliente recibe la respuesta y extrae el certificado del servidor
   - El cliente valida el certificado del servidor contra su FileStore:
     - Verifica que está en certificados confiables o puede ser validado contra una CA conocida
     - Verifica que no está revocado
     - Verifica la validez temporal
   - Si la validación falla, el cliente puede rechazar la conexión o mover el certificado a `rejected`

7. **Establecimiento del contexto criptográfico**:
   - Una vez validados mutuamente los certificados, tanto cliente como servidor establecen el contexto criptográfico para el canal:
     - El secreto compartido generado mediante Kyber durante el cifrado/descifrado de los mensajes OPN se almacena temporalmente
     - Este secreto compartido se combina con los nonces intercambiados para derivar claves simétricas mediante PSHA256:
       - Clave de cifrado AES-256 para mensajes
       - Clave de firma HMAC-SHA256 para autenticación
       - Vectores de inicialización (IV) para el cifrado
     - Las claves públicas Dilithium y Kyber del peer se almacenan para futuras validaciones
     - El canal seguro queda establecido y listo para uso con comunicación simétrica derivada de Kyber

### 4.2 Creación de Sesión

Después del establecimiento del canal seguro:

1. **Solicitud CreateSession del cliente**:
   - El cliente envía una solicitud de creación de sesión que incluye:
     - El certificado del cliente (para autenticación a nivel de sesión)
     - Un nonce del cliente
     - Información de la aplicación cliente

2. **Validación adicional en el servidor**:
   - El servidor verifica que el certificado en CreateSession coincide con el certificado usado en el canal seguro
   - Si se requiere autenticación por certificado a nivel de sesión, el servidor valida el certificado contra el Session PKI FileStore
   - El servidor genera un nonce de servidor y un token de autenticación de sesión

3. **Respuesta CreateSession**:
   - El servidor responde con:
     - El ID de sesión
     - El nonce del servidor
     - El token de autenticación
     - El certificado del servidor (para verificación)
   - La respuesta se firma usando el contexto del canal seguro

4. **Activación de la sesión**:
   - El cliente valida la respuesta y activa la sesión
   - A partir de este punto, todas las operaciones OPC UA (lectura, escritura, suscripciones) se realizan sobre esta sesión segura

---

## Fase 5: Flujo de Validación de Certificados PQC

Cuando un certificado PQC es recibido durante la comunicación (por ejemplo, en un mensaje OpenSecureChannel), el sistema realiza una validación exhaustiva que incluye verificaciones específicas para algoritmos post-cuánticos. Este proceso es más complejo que la validación de certificados tradicionales porque debe verificar tanto la firma del certificado (que puede estar firmado con Dilithium) como las extensiones que contienen las claves públicas PQC.

### 5.1 Detección de Certificado PQC

El proceso comienza detectando si el certificado es PQC:

1. **Verificación del algoritmo de firma del certificado**:
   - El sistema analiza el OID (Object Identifier) del algoritmo de firma del certificado
   - Si el OID corresponde a un algoritmo PQC (como ML-DSA-44/Dilithium2), se marca como certificado PQC-firmado
   - Si el certificado está firmado con RSA o ECDSA pero contiene extensiones PQC, se trata como certificado híbrido

2. **Verificación de extensiones PQC**:
   - El sistema busca extensiones específicas en el certificado:
     - OID `1.3.6.1.4.1.55336.1.1` para la clave pública Dilithium
     - OID `1.3.6.1.4.1.55336.1.2` para la clave pública Kyber
   - Si ambas extensiones están presentes, el certificado tiene soporte PQC completo

### 5.2 Recarga del FileStore

Antes de validar el certificado, el sistema asegura que tiene la información más actualizada:

1. **Recarga del almacén de confianza**:
   - Se recargan desde el FileStore todos los certificados confiables (`trusted`)
   - Se recargan todos los certificados de emisores CA (`issuer/certs`)
   - Se recargan las listas de revocación (CRL) desde `issuer/crl`
   - Esta recarga garantiza que cualquier cambio reciente en el FileStore se refleje en memoria

2. **Preparación de estructuras de datos**:
   - Los certificados se organizan en estructuras de datos en memoria para búsqueda rápida
   - Se crean índices por nombre de sujeto y emisor para facilitar la búsqueda de la cadena de certificados

### 5.3 Verificación de Firma PQC (si aplica)

Si el certificado está firmado con un algoritmo PQC (Dilithium), se realiza una verificación específica:

1. **Identificación del emisor**:
   - Se extrae el nombre del emisor (issuer) del certificado
   - Se busca el certificado de la CA emisora en:
     - Primero en `issuerCertificates` (certificados de CA cargados desde `issuer/certs`)
     - Si no se encuentra, se busca en `trustedCertificates` (certificados confiables)
   - Si no se encuentra ningún emisor y el certificado es auto-firmado (subject == issuer), se procede con verificación auto-firmada

2. **Verificación de la firma del certificado**:
   - **Para certificados firmados por CA**:
     - Se obtiene la clave pública del certificado de la CA emisora
     - Se verifica la firma del certificado usando la clave pública de la CA
     - OpenSSL (con OQS Provider) maneja automáticamente la verificación de firmas Dilithium
   - **Para certificados auto-firmados**:
     - Se verifica que el nombre del sujeto coincida con el nombre del emisor
     - Se obtiene la clave pública del propio certificado
     - Se verifica la firma usando la clave pública del certificado
   - Si la verificación de firma falla, el proceso se aborta inmediatamente con `BADCERTIFICATEINVALID`

3. **Resultado de la verificación PQC**:
   - Si la verificación de firma PQC falla, el certificado se rechaza inmediatamente
   - Si la verificación de firma PQC es exitosa, se continúa con las demás validaciones

### 5.4 Extracción de Claves Públicas PQC

Una vez verificada la firma del certificado, se extraen las claves públicas PQC:

1. **Extracción del certificado hoja (leaf certificate)**:
   - Si el certificado viene en una cadena, se extrae solo el primer certificado (el certificado hoja)
   - Se maneja tanto formato DER como PEM

2. **Extracción de la clave pública Dilithium**:
   - Se busca la extensión con OID `1.3.6.1.4.1.55336.1.1`
   - Se verifica que la extensión contenga exactamente 1312 bytes (tamaño de clave pública Dilithium2)
   - Se copia la clave pública a un buffer para uso posterior
   - Si la extensión no existe o tiene tamaño incorrecto, la validación falla

3. **Extracción de la clave pública Kyber**:
   - Se busca la extensión con OID `1.3.6.1.4.1.55336.1.2`
   - Se verifica que la extensión contenga exactamente 1184 bytes (tamaño de clave pública Kyber768)
   - Se copia la clave pública a un buffer para uso posterior
   - Si la extensión no existe o tiene tamaño incorrecto, la validación falla

4. **Validación de completitud**:
   - Ambas claves públicas (Dilithium y Kyber) deben estar presentes y ser válidas
   - Si falta alguna, el certificado se rechaza con `BADSECURITYCHECKSFAILED`

### 5.5 Validación de Estructura y Uso

El sistema valida la estructura básica del certificado:

1. **Validación de estructura**:
   - Se verifica que el certificado pueda ser parseado correctamente
   - Se verifica que el certificado tenga todos los campos requeridos
   - Si la estructura es inválida, se rechaza con `BADCERTIFICATEINVALID`

2. **Validación de uso del certificado**:
   - Se verifica que el certificado NO tenga el flag de CA (Certificate Authority)
   - Los certificados de aplicación OPC UA deben ser certificados de usuario final, no certificados de CA
   - Si el certificado tiene flag de CA, se rechaza con `BADCERTIFICATEUSENOTALLOWED`

### 5.6 Construcción y Validación de la Cadena de Certificados

El sistema construye y valida la cadena completa de certificados:

1. **Construcción de la cadena**:
   - Comenzando desde el certificado hoja, se busca el certificado del emisor
   - Se repite el proceso recursivamente hasta encontrar:
     - Un certificado auto-firmado (fin de la cadena)
     - Un certificado en la lista de confianza
     - Se alcanza el límite máximo de profundidad de cadena

2. **Validaciones en cada nivel de la cadena**:
   - **Período de validez**: Se verifica que cada certificado en la cadena esté dentro de su período de validez (notBefore y notAfter)
   - **Uso del emisor como CA**: Se verifica que los emisores intermedios tengan permisos para actuar como CA
   - **Firma del certificado**: Se verifica que cada certificado esté correctamente firmado por su emisor
   - **Revocación**: Se verifica que ningún certificado en la cadena esté en las listas de revocación (CRL)

3. **Verificación de firma en cada nivel**:
   - Para cada certificado en la cadena, se verifica su firma usando la clave pública de su emisor
   - Si el certificado es PQC-firmado, OpenSSL con OQS Provider maneja la verificación automáticamente
   - Si cualquier firma en la cadena falla, se rechaza toda la cadena

4. **Detección de bucles**:
   - El sistema detecta si hay bucles infinitos en la cadena de certificados
   - Si se detecta un bucle, se rechaza con `BADCERTIFICATECHAININCOMPLETE`

### 5.7 Verificación de Confianza

Una vez construida y validada la cadena, se verifica la confianza:

1. **Búsqueda en lista de confianza**:
   - Si la cadena termina en un certificado auto-firmado, se verifica si ese certificado está en la lista de certificados confiables
   - Se compara el certificado raíz con todos los certificados en `trustedCertificates`
   - Si se encuentra una coincidencia exacta, el certificado es confiable

2. **Verificación en FileStore**:
   - Se verifica si el certificado hoja está directamente en el directorio `trusted` del FileStore
   - Si está en `trusted`, se considera confiable independientemente de la cadena
   - Si no está en `trusted`, se requiere que la cadena termine en un certificado confiable

3. **Resultado de confianza**:
   - Si el certificado o su cadena termina en un certificado confiable: `UA_STATUSCODE_GOOD`
   - Si la cadena es válida pero no termina en confianza: `BADCERTIFICATEUNTRUSTED`
   - Si la cadena es inválida: varios códigos de error según el tipo de fallo

### 5.8 Gestión de Certificados Rechazados

Si el certificado falla cualquier validación:

1. **Guardado en directorio rejected**:
   - Se genera un nombre de archivo basado en el CN (Common Name) del sujeto y el thumbprint del certificado
   - Formato: `CN[Thumbprint]` (ejemplo: `OPC-UA-Client[0E73F497A47FF2E1E1FA32C8E84050FCD92B4899]`)
   - El certificado se guarda en `ApplCerts/rejected/certs/`
   - Si el archivo ya existe, no se sobrescribe (para evitar duplicados)

2. **Registro en lista de rechazados en memoria**:
   - El certificado se agrega a la lista de rechazados en memoria
   - Esta lista se persiste al FileStore cuando hay cambios

3. **Propósito del almacenamiento**:
   - Permite auditoría de intentos de conexión con certificados inválidos
   - Facilita la detección de reintentos con certificados previamente rechazados
   - Permite a los administradores revisar y potencialmente mover certificados a `trusted` si es apropiado

### 5.9 Resumen del Flujo Completo

El flujo completo de validación de un certificado PQC sigue esta secuencia:

```
1. Recepción del certificado
   ↓
2. Detección de tipo PQC (algoritmo de firma + extensiones)
   ↓
3. Recarga del FileStore (certificados confiables, emisores, CRL)
   ↓
4. [Si es PQC-firmado] Verificación de firma PQC con CA emisora
   ↓
5. Extracción de claves públicas Dilithium y Kyber de extensiones
   ↓
6. Validación de estructura y uso del certificado
   ↓
7. Construcción de cadena de certificados (recursiva)
   ├─ Validación de período de validez en cada nivel
   ├─ Verificación de firma en cada nivel
   ├─ Verificación de revocación en cada nivel
   └─ Detección de bucles
   ↓
8. Verificación de confianza (certificado en trusted o cadena termina en confiable)
   ↓
9. [Si falla] Guardado en rejected/ y registro en lista de rechazados
   ↓
10. Resultado: UA_STATUSCODE_GOOD (confiable) o código de error específico
```

Este proceso garantiza que solo se acepten certificados PQC que:
- Estén correctamente firmados (con Dilithium si es PQC-firmado)
- Contengan las claves públicas PQC requeridas (Dilithium y Kyber)
- Tengan una cadena de certificados válida y completa
- Terminen en un certificado confiable o estén directamente en la lista de confianza
- No estén revocados ni expirados

---

## Fase 6: Operación Normal

Durante la operación normal:

1. **Comunicación segura**: Todos los mensajes entre cliente y servidor son:
   - Firmados usando HMAC-SHA256 con claves simétricas derivadas del secreto compartido de Kyber
   - Cifrados usando AES-256-CBC con claves simétricas derivadas del secreto compartido de Kyber
   - La autenticación inicial mediante Dilithium durante el handshake garantiza que las claves simétricas fueron establecidas con el peer correcto
   - Validados contra los certificados almacenados en el FileStore

2. **Renovación de tokens**: Los tokens de seguridad del canal tienen un tiempo de vida limitado. Cuando expiran:
   - Se realiza un nuevo handshake (OpenSecureChannel renew)
   - Se validan nuevamente los certificados (usando Dilithium para verificar firmas)
   - Se genera un nuevo secreto compartido mediante Kyber (si es necesario)
   - Se derivan nuevas claves simétricas a partir del nuevo secreto compartido
   - Se establece un nuevo token sin interrumpir la sesión

3. **Gestión de sesiones**: Las sesiones pueden:
   - Ser activadas y desactivadas
   - Ser cerradas por timeout o por solicitud
   - Mantener suscripciones y monitoreo de datos

---

## Fase 5: Flujo de Validación de Certificados PQC

Cuando un certificado PQC es recibido durante la comunicación (por ejemplo, en un mensaje OpenSecureChannel), el sistema realiza una validación exhaustiva que incluye verificaciones específicas para algoritmos post-cuánticos. Este proceso es más complejo que la validación de certificados tradicionales porque debe verificar tanto la firma del certificado (que puede estar firmado con Dilithium) como las extensiones que contienen las claves públicas PQC.

### 5.1 Detección de Certificado PQC

El proceso comienza detectando si el certificado es PQC:

1. **Verificación del algoritmo de firma del certificado**:
   - El sistema analiza el OID (Object Identifier) del algoritmo de firma del certificado
   - Si el OID corresponde a un algoritmo PQC (como ML-DSA-44/Dilithium2), se marca como certificado PQC-firmado
   - Si el certificado está firmado con RSA o ECDSA pero contiene extensiones PQC, se trata como certificado híbrido

2. **Verificación de extensiones PQC**:
   - El sistema busca extensiones específicas en el certificado:
     - OID `1.3.6.1.4.1.55336.1.1` para la clave pública Dilithium
     - OID `1.3.6.1.4.1.55336.1.2` para la clave pública Kyber
   - Si ambas extensiones están presentes, el certificado tiene soporte PQC completo

### 5.2 Recarga del FileStore

Antes de validar el certificado, el sistema asegura que tiene la información más actualizada:

1. **Recarga del almacén de confianza**:
   - Se recargan desde el FileStore todos los certificados confiables (`trusted`)
   - Se recargan todos los certificados de emisores CA (`issuer/certs`)
   - Se recargan las listas de revocación (CRL) desde `issuer/crl`
   - Esta recarga garantiza que cualquier cambio reciente en el FileStore se refleje en memoria

2. **Preparación de estructuras de datos**:
   - Los certificados se organizan en estructuras de datos en memoria para búsqueda rápida
   - Se crean índices por nombre de sujeto y emisor para facilitar la búsqueda de la cadena de certificados

### 5.3 Verificación de Firma PQC (si aplica)

Si el certificado está firmado con un algoritmo PQC (Dilithium), se realiza una verificación específica:

1. **Identificación del emisor**:
   - Se extrae el nombre del emisor (issuer) del certificado
   - Se busca el certificado de la CA emisora en:
     - Primero en `issuerCertificates` (certificados de CA cargados desde `issuer/certs`)
     - Si no se encuentra, se busca en `trustedCertificates` (certificados confiables)
   - Si no se encuentra ningún emisor y el certificado es auto-firmado (subject == issuer), se procede con verificación auto-firmada

2. **Verificación de la firma del certificado**:
   - **Para certificados firmados por CA**:
     - Se obtiene la clave pública del certificado de la CA emisora
     - Se verifica la firma del certificado usando la clave pública de la CA
     - OpenSSL (con OQS Provider) maneja automáticamente la verificación de firmas Dilithium
   - **Para certificados auto-firmados**:
     - Se verifica que el nombre del sujeto coincida con el nombre del emisor
     - Se obtiene la clave pública del propio certificado
     - Se verifica la firma usando la clave pública del certificado
   - Si la verificación de firma falla, el proceso se aborta inmediatamente con `BADCERTIFICATEINVALID`

3. **Resultado de la verificación PQC**:
   - Si la verificación de firma PQC falla, el certificado se rechaza inmediatamente
   - Si la verificación de firma PQC es exitosa, se continúa con las demás validaciones

### 5.4 Extracción de Claves Públicas PQC

Una vez verificada la firma del certificado, se extraen las claves públicas PQC:

1. **Extracción del certificado hoja (leaf certificate)**:
   - Si el certificado viene en una cadena, se extrae solo el primer certificado (el certificado hoja)
   - Se maneja tanto formato DER como PEM

2. **Extracción de la clave pública Dilithium**:
   - Se busca la extensión con OID `1.3.6.1.4.1.55336.1.1`
   - Se verifica que la extensión contenga exactamente 1312 bytes (tamaño de clave pública Dilithium2)
   - Se copia la clave pública a un buffer para uso posterior
   - Si la extensión no existe o tiene tamaño incorrecto, la validación falla

3. **Extracción de la clave pública Kyber**:
   - Se busca la extensión con OID `1.3.6.1.4.1.55336.1.2`
   - Se verifica que la extensión contenga exactamente 1184 bytes (tamaño de clave pública Kyber768)
   - Se copia la clave pública a un buffer para uso posterior
   - Si la extensión no existe o tiene tamaño incorrecto, la validación falla

4. **Validación de completitud**:
   - Ambas claves públicas (Dilithium y Kyber) deben estar presentes y ser válidas
   - Si falta alguna, el certificado se rechaza con `BADSECURITYCHECKSFAILED`

### 5.5 Validación de Estructura y Uso

El sistema valida la estructura básica del certificado:

1. **Validación de estructura**:
   - Se verifica que el certificado pueda ser parseado correctamente
   - Se verifica que el certificado tenga todos los campos requeridos
   - Si la estructura es inválida, se rechaza con `BADCERTIFICATEINVALID`

2. **Validación de uso del certificado**:
   - Se verifica que el certificado NO tenga el flag de CA (Certificate Authority)
   - Los certificados de aplicación OPC UA deben ser certificados de usuario final, no certificados de CA
   - Si el certificado tiene flag de CA, se rechaza con `BADCERTIFICATEUSENOTALLOWED`

### 5.6 Construcción y Validación de la Cadena de Certificados

El sistema construye y valida la cadena completa de certificados:

1. **Construcción de la cadena**:
   - Comenzando desde el certificado hoja, se busca el certificado del emisor
   - Se repite el proceso recursivamente hasta encontrar:
     - Un certificado auto-firmado (fin de la cadena)
     - Un certificado en la lista de confianza
     - Se alcanza el límite máximo de profundidad de cadena

2. **Validaciones en cada nivel de la cadena**:
   - **Período de validez**: Se verifica que cada certificado en la cadena esté dentro de su período de validez (notBefore y notAfter)
   - **Uso del emisor como CA**: Se verifica que los emisores intermedios tengan permisos para actuar como CA
   - **Firma del certificado**: Se verifica que cada certificado esté correctamente firmado por su emisor
   - **Revocación**: Se verifica que ningún certificado en la cadena esté en las listas de revocación (CRL)

3. **Verificación de firma en cada nivel**:
   - Para cada certificado en la cadena, se verifica su firma usando la clave pública de su emisor
   - Si el certificado es PQC-firmado, OpenSSL con OQS Provider maneja la verificación automáticamente
   - Si cualquier firma en la cadena falla, se rechaza toda la cadena

4. **Detección de bucles**:
   - El sistema detecta si hay bucles infinitos en la cadena de certificados
   - Si se detecta un bucle, se rechaza con `BADCERTIFICATECHAININCOMPLETE`

### 5.7 Verificación de Confianza

Una vez construida y validada la cadena, se verifica la confianza:

1. **Búsqueda en lista de confianza**:
   - Si la cadena termina en un certificado auto-firmado, se verifica si ese certificado está en la lista de certificados confiables
   - Se compara el certificado raíz con todos los certificados en `trustedCertificates`
   - Si se encuentra una coincidencia exacta, el certificado es confiable

2. **Verificación en FileStore**:
   - Se verifica si el certificado hoja está directamente en el directorio `trusted` del FileStore
   - Si está en `trusted`, se considera confiable independientemente de la cadena
   - Si no está en `trusted`, se requiere que la cadena termine en un certificado confiable

3. **Resultado de confianza**:
   - Si el certificado o su cadena termina en un certificado confiable: `UA_STATUSCODE_GOOD`
   - Si la cadena es válida pero no termina en confianza: `BADCERTIFICATEUNTRUSTED`
   - Si la cadena es inválida: varios códigos de error según el tipo de fallo

### 5.8 Gestión de Certificados Rechazados

Si el certificado falla cualquier validación:

1. **Guardado en directorio rejected**:
   - Se genera un nombre de archivo basado en el CN (Common Name) del sujeto y el thumbprint del certificado
   - Formato: `CN[Thumbprint]` (ejemplo: `OPC-UA-Client[0E73F497A47FF2E1E1FA32C8E84050FCD92B4899]`)
   - El certificado se guarda en `ApplCerts/rejected/certs/`
   - Si el archivo ya existe, no se sobrescribe (para evitar duplicados)

2. **Registro en lista de rechazados en memoria**:
   - El certificado se agrega a la lista de rechazados en memoria
   - Esta lista se persiste al FileStore cuando hay cambios

3. **Propósito del almacenamiento**:
   - Permite auditoría de intentos de conexión con certificados inválidos
   - Facilita la detección de reintentos con certificados previamente rechazados
   - Permite a los administradores revisar y potencialmente mover certificados a `trusted` si es apropiado

### 5.9 Resumen del Flujo Completo

El flujo completo de validación de un certificado PQC sigue esta secuencia:

```
1. Recepción del certificado
   ↓
2. Detección de tipo PQC (algoritmo de firma + extensiones)
   ↓
3. Recarga del FileStore (certificados confiables, emisores, CRL)
   ↓
4. [Si es PQC-firmado] Verificación de firma PQC con CA emisora
   ↓
5. Extracción de claves públicas Dilithium y Kyber de extensiones
   ↓
6. Validación de estructura y uso del certificado
   ↓
7. Construcción de cadena de certificados (recursiva)
   ├─ Validación de período de validez en cada nivel
   ├─ Verificación de firma en cada nivel
   ├─ Verificación de revocación en cada nivel
   └─ Detección de bucles
   ↓
8. Verificación de confianza (certificado en trusted o cadena termina en confiable)
   ↓
9. [Si falla] Guardado en rejected/ y registro en lista de rechazados
   ↓
10. Resultado: UA_STATUSCODE_GOOD (confiable) o código de error específico
```

Este proceso garantiza que solo se acepten certificados PQC que:
- Estén correctamente firmados (con Dilithium si es PQC-firmado)
- Contengan las claves públicas PQC requeridas (Dilithium y Kyber)
- Tengan una cadena de certificados válida y completa
- Terminen en un certificado confiable o estén directamente en la lista de confianza
- No estén revocados ni expirados

---

## Fase 7: Shutdown y Liberación de Recursos

### 7.1 Shutdown del Servidor

Cuando el servidor recibe una señal de cierre (SIGINT, SIGTERM) o se solicita el cierre:

1. **Cambio de estado**: El servidor cambia su estado a "STOPPING"

2. **Cierre de componentes**:
   - Se detienen todas las tareas de mantenimiento (housekeeping)
   - Se cierran todos los canales seguros activos:
     - Se envía un mensaje de cierre a cada cliente conectado
     - Se liberan los recursos de cada canal
     - Se limpian los contextos criptográficos
   - Se cierran todas las sesiones activas
   - Se cierran todas las conexiones de red

3. **Persistencia de estado del FileStore**:
   - Se escriben al FileStore cualquier cambio pendiente en las listas de confianza
   - Se intenta persistir cualquier cambio pendiente en las listas de certificados
   - Se sincronizan las listas de certificados confiables con el disco

4. **Limpieza de políticas de seguridad**:
   - Se liberan los recursos de las políticas PQC
   - Se limpian los contextos criptográficos
   - Se liberan las claves privadas de memoria (con limpieza segura)

5. **Limpieza del FileStore**:
   - Se cierran los grupos de certificados (SecureChannel PKI y Session PKI)
   - Se liberan los recursos del FileStore
   - Se cierra cualquier monitoreo del sistema de archivos

6. **Limpieza general**:
   - Se liberan todos los endpoints
   - Se limpia la configuración del servidor
   - Se detiene el bucle de eventos
   - El servidor cambia a estado "STOPPED"

### 7.2 Desconexión del Cliente

Cuando el cliente se desconecta:

1. **Cierre de sesión**: Si hay una sesión activa:
   - Se envía un mensaje de cierre de sesión al servidor
   - Se liberan los recursos de la sesión

2. **Cierre del canal seguro**:
   - Se envía un mensaje de cierre del canal al servidor
   - Se limpian los contextos criptográficos
   - Se liberan las claves temporales

3. **Persistencia del FileStore del cliente**:
   - Se guardan los cambios en las listas de certificados
   - Se asegura que los certificados rechazados estén guardados

4. **Limpieza de políticas**:
   - Se liberan las políticas PQC del cliente
   - Se limpian las claves privadas de memoria

5. **Cierre de conexión de red**:
   - Se cierra la conexión TCP
   - Se liberan los recursos de red

6. **Limpieza final**:
   - Se libera la configuración del cliente
   - Se detiene el bucle de eventos del cliente

---

## Resumen del Flujo Completo

El flujo completo de la aplicación OPC UA con PKI FileStore y PQC sigue esta secuencia:

1. **Inicialización**: Cliente y servidor verifican y cargan sus certificados desde el FileStore
2. **Configuración**: Se configuran las políticas PQC y los grupos de certificados vinculados al FileStore
3. **Arranque**: El servidor inicia y carga certificados confiables; el cliente se prepara para conectar
4. **Handshake**: Cliente y servidor intercambian y validan certificados usando el FileStore, estableciendo un canal seguro con criptografía PQC
5. **Sesión**: Se crea una sesión segura sobre el canal establecido
6. **Operación**: La comunicación se realiza con cifrado y firma PQC, con validación continua de certificados
7. **Gestión de certificados**: Los certificados se aceptan o rechazan automáticamente, almacenándose en el FileStore según corresponda
8. **Shutdown**: Se cierran todas las conexiones, se persisten los cambios en el FileStore, y se liberan todos los recursos criptográficos

Este sistema proporciona una infraestructura completa de seguridad post-cuántica para OPC UA, con gestión persistente de certificados y validación automática en cada etapa de la comunicación.
