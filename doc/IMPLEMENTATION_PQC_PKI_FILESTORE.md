# Implementación de soporte post-cuántico (PQC), PKI y FileStore en open62541

## Informe técnico comparativo: versión base vs. versión modificada

**Objetivo:** Reconstruir y documentar, paso a paso, las modificaciones relevantes realizadas para soporte post-cuántico (PQC), PKI y FileStore en open62541, como base para la sección "Implementation" de un artículo científico.

**Convención:** Para cada cambio se indica la **justificación concreta**: qué fallo o limitación ocurría sin el cambio, qué código o especificación lo exige, y qué consecuencia tiene la modificación (código de error, invariante preservado, o flujo habilitado).

---

## 1. Creación inicial de una política de seguridad PQC (stub)

### 1.1 Por qué fue necesario crear una política nueva

En open62541 original, las políticas de seguridad se implementan como plugins que rellenan la estructura `UA_SecurityPolicy` (definida en `include/open62541/plugin/securitypolicy.h`). Las políticas estándar (Basic256Sha256, Aes256Sha256RsaPss, EccNistP256, etc.) dependen de primitivas clásicas: RSA para firma/cifrado asimétrico y ECC para ECDH. No existe en el estándar OPC UA ni en la implementación base una política que use algoritmos resistentes a ordenadores cuánticos.

Se introdujo una **nueva política** identificada por el URI `http://example.org/SecurityPolicy#PQC` para:

- No modificar el comportamiento de las políticas existentes.
- Permitir coexistencia de políticas clásicas y PQC en el mismo servidor/cliente.
- Cumplir la API de plugin (`UA_SecurityPolicy`, módulos asimétrico, simétrico y de canal).

**Justificación concreta:** En la versión base, `UA_SecureChannel_setSecurityPolicy` y el flujo de cifrado asumen que `channel->securityPolicy` tiene todos los punteros de función no nulos (sign, verify, encrypt, decrypt, getLocalSignatureSize, getRemoteBlockSize, etc.). Si se reutilizara una política existente (p. ej. Basic256Sha256) y se intentara sustituir solo las claves por PQC, fallaría porque: (1) `EVP_PKEY` de OpenSSL para RSA no puede contener claves Dilithium/Kyber; (2) los tamaños de firma (2420 vs ~256 bytes) y de bloque de cifrado (1088 bytes KEM vs bloques RSA) son incompatibles con el cálculo de `encryptedLength` y los buffers en `signAndEncryptAsym`. Por tanto, una política nueva evita invocar código RSA/ECC con tamaños PQC y garantiza que `getRemoteBlockSize() == 0` cuando aún no hay certificado remoto se maneje explícitamente en el núcleo.

### 1.2 Funcionalidades mínimas implementadas al principio

La política PQC se implementa en **`plugins/crypto/openssl/securitypolicy_pqc.c`** y se expone mediante **`UA_SecurityPolicy_PQC()`** (aprox. líneas 3820–3942).

**Funcionalidades mínimas:**

- **Estructuras de contexto:**  
  - `Policy_Context_PQC`: claves Dilithium2 (firma) y Kyber768 (KEM), thumbprint local, flags de inicialización, secreto temporal KEM, contador de referencias.  
  - `PQC_ChannelContext`: certificado remoto, claves simétricas derivadas, claves públicas remotas Dilithium/Kyber.

- **Módulos obligatorios de la API:**  
  - **Asimétrico:** `makeCertificateThumbprint`, `compareCertificateThumbprint`, algoritmo de firma (Dilithium2), algoritmo de cifrado (Kyber768).  
  - **Simétrico:** `generateNonce`, `generateKey` (derivación desde secreto KEM), stubs de cifrado/firma simétricos (AES-256/HMAC-SHA256) para mensajes MSG tras el handshake.  
  - **Canal:** `newContext`, `deleteContext`, `compareCertificate`, setters de claves simétricas.

- **URI y nivel:**  
  - `policyUri = "http://example.org/SecurityPolicy#PQC"`, `securityLevel = 30`.

**Justificación de cada módulo:**  
- **Asimétrico (thumbprint, sign, encrypt):** El núcleo en `ua_securechannel_crypto.c` llama a `makeCertificateThumbprint` para comparar el certificado del servidor con el esperado y a `compareCertificateThumbprint` al procesar el OPN; sin ellos se obtendría `UA_STATUSCODE_BADINTERNALERROR` o comparaciones incorrectas. La firma y el cifrado asimétrico son obligatorios para OPN con SecurityMode Sign o SignAndEncrypt (OPC UA Part 6).  
- **Simétrico (generateKey, generateNonce):** Tras el handshake OPN, los mensajes MSG usan claves simétricas derivadas; `generateKey` se invoca con el secreto compartido y los nonces. Si `generateKey` no estuviera implementado (NULL), `pqc_sym_generateKey` devolvería error al derivar claves y el primer mensaje simétrico fallaría con `UA_STATUSCODE_BADSECURITYCHECKSFAILED` (véase `ua_securechannel_crypto.c`, comprobación de `hasTemporarySharedSecret` para PQC).  
- **Canal (newContext, deleteContext, compareCertificate):** Cada SecureChannel necesita un contexto por canal; sin `newContext` el canal no podría almacenar las claves remotas Dilithium/Kyber ni las claves simétricas derivadas. `compareCertificate` se usa al revalidar el certificado remoto.

### 1.3 Partes del framework de políticas reutilizadas

- **API de `UA_SecurityPolicy`:** Se reutiliza íntegramente la estructura y los punteros a función (sign, verify, encrypt, decrypt, thumbprint, newContext, etc.).
- **Thumbprint:** Se usa `UA_Openssl_X509_GetCertificateThumbprint()` (desde `securitypolicy_common`) para el certificado local; el thumbprint sigue siendo SHA-1 según OPC UA.
- **Flujo de canal seguro:** El núcleo (`ua_securechannel.c`, `ua_securechannel_crypto.c`) no asume un algoritmo concreto; las ramas PQC se añadieron donde el tamaño de firma/cifrado o el flujo de datos difieren (certificado vacío inicial, cifrado no por bloques, etc.).

### 1.4 Limitaciones de esta primera versión

- **Certificados:** Inicialmente se asumía certificado con extensiones PQC (OID Dilithium/Kyber). Certificados solo RSA/ECC no llevan esas extensiones y no pueden usarse con esta política sin modificarlos (`UA_PQC_EnsureCertificateExtensions`) o generar nuevos con `UA_PQC_CreateCertificate` / `UA_PQC_CreateCertificateWithOQSProvider`.
- **Clave privada:** Formatos soportados: (1) PEM/DER con RSA/ECC + PQC al final del buffer; (2) solo PQC (4960 bytes: Dilithium 2560 + Kyber 2400). Cualquier otro tamaño se ignora silenciosamente en `pqc_set_local_from_params`.
- **Primer OPN:** Si el certificado remoto aún no está disponible (cliente antes de recibir OPN del servidor), `getRemoteBlockSize` devuelve 0 y el mensaje se envía solo firmado, sin cifrado KEM.
- **Dependencia:** Requiere **liboqs** y, para certificados firmados con Dilithium, **OpenSSL 3.x** con OQS Provider.

---

## 2. Integración progresiva de primitivas criptográficas post-cuánticas

### 2.1 Sustitución de RSA/ECC por Dilithium y Kyber

- **Firma:** RSA/ECDSA se sustituyen por **Dilithium2** (ML-DSA-44 en liboqs). Constantes en `securitypolicy_pqc.c`: `PQC_SIG_SIGNATURE_LEN` (2420), `PQC_SIG_PUBLIC_KEY_LEN` (1312), `PQC_SIG_SECRET_KEY_LEN` (2560). Funciones: `pqc_sign`, `pqc_verify` (aprox. 3001–3160), usando `OQS_SIG_sign` / `OQS_SIG_verify`.
- **Cifrado asimétrico / establecimiento de clave:** En lugar de RSA-OAEP o ECDH, se usa **Kyber768** como KEM. Constantes: `PQC_KEM_CIPHERTEXT_LEN` (1088), claves pública/privada 1184/2400 bytes, shared secret 32 bytes. Funciones: `pqc_encrypt` (KEM encaps), `pqc_decrypt` (KEM decaps); el payload luego se cifra con AES-256 derivado del shared secret.

### 2.2 Cambios en firmas, cifrado y derivación de claves

- **Firma:** El mensaje a firmar es el mismo que en políticas clásicas (headers + SequenceHeader + payload). La firma se escribe en un buffer de 2420 bytes; el llamador debe preasignar ese tamaño (`getLocalSignatureSize` / `getRemoteSignatureSize`).
- **Cifrado PQC:** No hay cifrado por bloques RSA. En `pqc_encrypt`: se escribe el ciphertext KEM (1088 bytes) al inicio del buffer de datos; a continuación va el payload cifrado con AES-256 (IV y clave derivados del shared secret). En `pqc_decrypt`: se lee el KEM ciphertext, se hace decaps, se deriva la clave simétrica y se descifra in-place, moviendo el resultado al inicio del buffer (`memmove`).
- **Derivación:** `pqc_sym_generateKey` (aprox. 2509–2600): usa el shared secret KEM y los nonces (local y remoto) según el orden canónico (comparación de nonces) y genera claves simétricas para HMAC-SHA256 y AES-256 mediante una función tipo PRF (hash del secreto + semilla). Si no hay `temporarySharedSecret` (aún no se ha hecho decaps en este canal), devuelve error.  
  **Justificación:** OPC UA Part 6 exige que las claves simétricas del canal se deriven de un secreto compartido y los nonces de forma determinista; ambas partes deben obtener las mismas claves. El shared secret en PQC proviene del KEM (decaps en el receptor, encaps en el emisor); hasta que una parte no haya ejecutado decrypt (decaps), no hay `temporarySharedSecret`. Si `generateKey` se llamara antes (p. ej. por un bug en el orden de procesamiento), devolver error evita derivar claves desde un buffer vacío o no inicializado, que daría claves incorrectas y fallos de descifrado o verificación de firma en el otro extremo. La comprobación en `ua_securechannel_crypto.c` (comentario sobre "hasTemporarySharedSecret" para PQC) asegura que no se intente enviar mensajes simétricos antes de que el handshake asimétrico haya establecido el secreto.

### 2.3 Adaptaciones en buffers, tamaños y estructuras internas

- **Margen para headers:** En `ua_securechannel_crypto.c`, `hideBytesAsym()` (aprox. 305–327): para certificados grandes (p. ej. PQC > 5000 bytes) se añade un margen extra al header de seguridad para evitar desbordes en la codificación binaria (`margin += (sp->localCertificate.length / 4) + 5100`).  
  **Justificación:** El `AsymmetricAlgorithmSecurityHeader` se codifica en binario con `UA_encodeBinaryInternal`; el campo `senderCertificate` es un ByteString con prefijo de longitud Int32. Para un certificado de ~6685 bytes, la codificación puede requerir más espacio del calculado con la fórmula fija (p. ej. 64 bytes de margen). Sin este margen, `header_pos_mutable` podría superar `buf_end` durante la codificación y provocar escritura fuera de rango o fallo de aserción en `UA_encodeBinaryInternal`. El comentario en código indica explícitamente: *"For PQC certificates (~6-7KB), add proportional margin"*.

- **Longitud del mensaje OPN (PQC):** En `prependHeadersAsym`, si la política es PQC, `encryptedLength = totalLength + kemCtLength` (sin bloques RSA). En `signAndEncryptAsym` (aprox. 415–528): se construye un buffer nuevo sin “gap”, se firma sobre headers + SequenceHeader + payload (sin gap), se actualiza `messageSize` en el header TCP, se copia el payload y se llama a `encrypt`; para PQC, `encrypt` espera que los primeros 1088 bytes del buffer sean para el KEM ciphertext.  
  **Justificación:** En políticas RSA, el payload se cifra en bloques y el buffer tiene un “gap” reservado entre el header y el payload para dejar sitio al padding y a los bloques cifrados. En PQC no hay bloques; el cifrado es KEM + AES sobre el payload contiguo. Si se usara la misma fórmula que RSA (`encryptedLength = totalLength + blocks * (encryptedBlockSize - plainTextBlockSize)`), el tamaño sería erróneo y el receptor rechazaría el mensaje por longitud incorrecta. Además, la firma debe calcularse sobre el mensaje *final* (con `messageSize` ya correcto en el header TCP); por eso se actualiza el header antes de firmar (líneas 457–462 en ua_securechannel_crypto.c) y se usa un buffer temporal para firmar sin el gap, ya que el gap no existirá en el mensaje enviado.

- **Padding:** En `padChunk` (aprox. 371–378): si `plainTextBlockSize == 0` (PQC), no se aplica padding; las políticas por bloques siguen usando padding como antes.  
  **Justificación:** PQC devuelve 0 en `getRemotePlainTextBlockSize` porque el cifrado no es por bloques RSA. Si se aplicara el padding estándar (bytes de relleno hasta alinear al bloque), se escribiría un bucle con `paddingLength` muy grande o indefinido (división por cero o comportamiento errático). La comprobación `if(plainTextBlockSize == 0) return;` evita ese camino.

- **Tamaño enviado en el header TCP (PQC):** En `ua_securechannel.c` (aprox. 1043–1053), al enviar el mensaje OPN, si la política es PQC se asigna `encryptedLength = buf.length`; en el resto de políticas se usa el valor precalculado `encryptedLength`.  
  **Justificación:** En políticas RSA, `signAndEncryptAsym` cifra in-place y no cambia el tamaño del buffer; el valor calculado en `prependHeadersAsym` coincide con el tamaño final. En PQC, `signAndEncryptAsym` asigna un *nuevo* buffer (`UA_malloc(newTotalLength)`), copia headers + espacio para KEM ciphertext + payload cifrado, hace `buf->data = newBuf`, `buf->length = newTotalLength` y libera el buffer antiguo. Si se usara el `encryptedLength` precalculado (que incluía el “gap” reservado para bloques RSA), sería menor que el tamaño real del mensaje; `messageHeader.messageSize` enviado al receptor indicaría un tamaño incorrecto, el receptor leería menos bytes de los enviados y el siguiente mensaje se interpretaría mal (corrupción de protocolo o cierre de conexión). Por eso el código establece explícitamente: *"For PQC, buf.length is already set correctly by signAndEncryptAsym to newTotalLength"*.

### 2.4 Funciones nuevas de encapsulación y verificación

- **Extracción de claves desde certificado:** `pqc_extract_pubkeys_from_cert_der_internal` / `pqc_extract_pubkeys_from_cert_der`: buscan extensiones X.509 con OID Dilithium (`1.3.6.1.4.1.55336.1.1`) y Kyber (`1.3.6.1.4.1.55336.1.2`) y rellenan los buffers de claves públicas en el contexto.  
  **Justificación:** La clave pública estándar del X509 (SubjectPublicKeyInfo) en certificados PQC puede ser RSA/ECC (híbrido) o no existir (certificado solo PQC); en cualquier caso, las claves Dilithium y Kyber usadas para firma y KEM están solo en extensiones personalizadas. Sin esta extracción, `pqc_verify` y `pqc_encrypt` no tendrían las claves remotas y fallarían con "remote Dilithium/Kyber public key is not initialized". La función soporta tanto DER como PEM y extrae el primer certificado de una cadena para usar el leaf.

- **Actualización del certificado remoto en el canal:** `UA_PQCChannel_updateRemoteCertificate` (exportada en `securitypolicy_pqc.h`): re-parsea el certificado remoto y actualiza las claves públicas Dilithium/Kyber en el `PQC_ChannelContext`; usada en el cliente tras recibir el OPN del servidor (en `ua_client_connect.c`).  
  **Justificación:** En el cliente, el contexto de canal se crea con certificado vacío (`allowEmptyCert`); en ese momento no hay claves remotas. El certificado del servidor llega en el mensaje OPN de respuesta (campo `senderCertificate` del AsymmetricAlgorithmSecurityHeader). Si no se actualizara el contexto al procesar ese OPN, `getRemoteBlockSize()` seguiría devolviendo 0 y no se podría cifrar ningún mensaje posterior; además, la verificación de la firma del OPN requiere la clave pública Dilithium del servidor, que se obtiene precisamente al parsear ese certificado. La llamada a `UA_PQCChannel_updateRemoteCertificate` en el flujo de procesamiento del OPN (ua_client_connect.c, tras extraer `serverCert` del header) es por tanto obligatoria para que el canal PQC sea usable tras el handshake.

- **Registro manual de claves remotas:** `UA_PQCPolicy_registerRemoteKeys`: permite inyectar claves públicas de firma y KEM sin certificado (útil en pruebas).  
  **Justificación:** En tests o entornos donde no se usa un certificado X.509 completo (p. ej. claves generadas por liboqs directamente), hace falta un camino para establecer las claves remotas en el contexto sin parsear un certificado; sin esta función, solo se podrían usar certificados con extensiones PQC.

**Justificación del ajuste de chunk tras descifrado PQC (unpackPayloadOPN, ua_securechannel.c; decryptAndVerifyChunk, ua_securechannel_crypto.c):** En políticas RSA, el descifrado es in-place y el payload descifrado queda en la misma posición relativa (tras los headers). En PQC, `pqc_decrypt` hace `memmove` para mover los datos descifrados al inicio del buffer `cipher` (que apunta a `chunk->data + offset`). Tras `decryptAndVerifyChunk`, `chunk->length` se actualiza a `cipher.length + offset`, pero `chunk->bytes.data` sigue apuntando al inicio del chunk (incluye headers). Si no se ajustara, el decodificador leería desde el inicio del chunk (headers) en lugar de desde el inicio de los datos descifrados; el SequenceHeader se decodificaría mal y se obtendría error de parsing o requestId/sequenceNumber incorrectos. Por eso en `unpackPayloadOPN` (aprox. 1484–1495) para PQC se hace `chunk->bytes.data += offset_before_decrypt` y `chunk->bytes.length -= offset_before_decrypt`, y luego `offset = 0` para decodificar el SequenceHeader desde el inicio de los datos descifrados. En `decryptAndVerifyChunk`, el comentario indica explícitamente que para PQC el payload descifrado queda en `cipher.data` y que `chunk->length` debe reflejarlo; sin esa coordinación, el siguiente paso (verificación de firma y decodificación) fallaría.

---

## 3. Soporte para certificados PQC sin PKI

### 3.1 Validación de certificados en la versión original

En la versión base, la verificación de certificados la realiza el backend del certificado (p. ej. `plugins/crypto/openssl/certificategroup.c`). La función interna `verifyCertificate` (aprox. 628–671):

1. Recarga certificados si `reloadRequired`.
2. Parsea el certificado con OpenSSL (`openSSLLoadCertificateStack`).
3. Comprueba uso (no CA para certificados de aplicación).
4. Construye la cadena con `openSSL_verifyChain`, que usa `X509_verify` y las claves públicas de los emisores en el store (RSA/ECC).

Para certificados firmados con **Dilithium**, `X509_verify` con el store estándar falla porque OpenSSL no reconoce el OID de firma PQC sin el OQS Provider y, además, los emisores en el store son objetos X509 con claves clásicas.

**Justificación concreta:** En `openSSL_verifyChain` (certificategroup.c), se llama a `X509_verify(leaf, pubkey)` donde `pubkey` es la clave pública del emisor. Para un certificado firmado con ML-DSA-44 (Dilithium2), el OID del algoritmo de firma en el certificado no es ni RSA ni ECDSA. OpenSSL sin OQS Provider devuelve fallo en `X509_verify` (p. ej. "unsupported algorithm"), lo que se traduce en `UA_STATUSCODE_BADCERTIFICATEINVALID` y el certificado se añade a la lista de rechazados. Por tanto, era necesario un camino alternativo que detectara firma PQC y usara `EVP_PKEY_verify` con el OQS Provider (como hace `UA_PQC_VerifyCertificateSignature`) en lugar de depender de `X509_verify` del store.

### 3.2 Adaptación para certificados con extensiones PQC

- **Detección:**  
  - `UA_PQC_HasCertificatePQCExtensions(certificate, logger)`: comprueba la presencia de las extensiones OID Dilithium y Kyber en el certificado (en `securitypolicy_pqc.c`).  
  - `UA_PQC_IsCertificatePQCSigned(certificate, logger)`: inspecciona el OID del algoritmo de firma del certificado y lo compara con los OID conocidos de algoritmos PQC (p. ej. ML-DSA-44) usando `UA_PQC_IsAlgorithmAvailable`.

- **Políticas ofrecidas:** En `ua_config_default.c`, `addAllSecurityPolicies` (aprox. 914–948): si `UA_PQC_HasCertificatePQCExtensions(&certificate, logging)` es verdadero, solo se añaden la política PQC y SecurityPolicy#None; no se añaden Basic256Sha256, Aes256Sha256RsaPss, etc., porque un certificado solo PQC no tiene clave RSA/ECC.  
  **Justificación:** Si se intentara añadir Basic256Sha256 con un certificado que solo tiene extensiones PQC (sin SubjectPublicKeyInfo RSA/ECC), `UA_Policy_New_Context` en securitypolicy_basic256sha256.c llamaría a `UA_OpenSSL_LoadPrivateKey`; el buffer de clave privada PQC-only (4960 bytes) no es PEM/DER de una clave RSA, por lo que el parsing fallaría y la política no se inicializaría. Además, `UA_Openssl_X509_GetCertificateThumbprint` sí funciona con certificados PQC (usa la estructura X509 general), pero las políticas RSA necesitan `EVP_PKEY` RSA para firmar/cifrar; al no existir esa clave en el certificado, cualquier operación de canal fallaría. Filtrar por `isPQCCert` evita ofrecer políticas que no pueden funcionar y evita errores de inicialización en cascada.

### 3.3 Modificaciones en parsing, verificación y almacenamiento

- **Parsing:** El certificado se sigue parseando con OpenSSL (DER/PEM). Las claves PQC no se leen de la clave pública estándar del X509, sino de las extensiones personalizadas (Dilithium/Kyber).
- **Verificación de firma PQC:** Se añade `UA_PQC_VerifyCertificateSignature(certificate, issuerCert, logger)` en `securitypolicy_pqc.c`: usa el OQS Provider para verificar la firma del certificado con la clave pública del emisor (o autofirma si `issuerCert == NULL`). El emisor debe ser un X509 cuya clave pública sea Dilithium (cargada por el OQS Provider).
- **Almacenamiento:** Sin PKI, los certificados se siguen guardando como ByteString (en memoria o en FileStore). El formato de archivo (DER/PEM) no cambia; solo el contenido incluye extensiones PQC y, en el caso “full PQC”, firma Dilithium.

### 3.4 Canal seguro solo con certificados PQC

- **Servidor:** Configura una política PQC con certificado y clave privada PQC (o híbridos extendidos con `UA_PQC_EnsureCertificateExtensions`). El cliente recibe ese certificado en el endpoint (GetEndpoints) o en el OPN.
- **Cliente:** En `ua_client_connect.c`, al procesar la respuesta OPN se llama a `UA_PQCChannel_updateRemoteCertificate` con el certificado del servidor (aprox. 2583–2597), de modo que el contexto de canal tenga las claves públicas Dilithium/Kyber del servidor y pueda verificar firmas y cifrar con Kyber.
- **Apertura con certificado vacío:** En `ua_securechannel.c`, `UA_SecureChannel_setSecurityPolicy` (aprox. 76–84): para la política PQC se permite `remoteCertificate` vacío (`allowEmptyCert`); el contexto se crea con certificado vacío y se actualiza después con `UA_PQCChannel_updateRemoteCertificate` cuando llega el certificado real.  
  **Justificación:** En la versión base, `newContext(securityPolicy, remoteCertificate, &channelContext)` recibe siempre un certificado no vacío para políticas distintas de None; si `remoteCertificate->length == 0`, políticas como Basic256Sha256 intentarían parsear una clave pública vacía y fallarían. Para el cliente PQC, en el momento de abrir el canal aún no se ha recibido el mensaje OPN del servidor (que contiene el certificado del servidor); si se exigiera certificado no vacío, el cliente no podría ni siquiera enviar el primer OPN (con SecurityPolicy#PQC) y se produciría un deadlock. Permitir certificado vacío solo para PQC permite crear el contexto con `remoteSigPublicKeyValid == false` y `remoteKemPublicKeyValid == false`; entonces `getRemoteBlockSize` devuelve 0 y el primer mensaje se envía solo firmado; al recibir la respuesta OPN, el cliente llama a `UA_PQCChannel_updateRemoteCertificate` y a partir de ahí ya puede cifrar.

---

## 4. Incorporación de infraestructura PKI

### 4.1 Cambios para soportar cadenas de confianza

El store subyacente sigue siendo el MemoryCertStore (en FileStore, `context->store` es un MemoryCertStore poblado desde disco). La cadena se construye en `openSSL_verifyChain` (openssl/certificategroup.c): se busca un emisor cuyo subject coincida con el issuer del certificado en las listas `issuerCertificates` y `trustedCertificates`. Para certificados PQC firmados por una CA Dilithium, ese emisor debe estar cargado en el store y su clave pública debe ser usable por el OQS Provider.

### 4.2 Adaptaciones para certificados firmados por CA post-cuántica

En **`plugins/crypto/ua_certificategroup_filestore.c`**, `FileCertStore_verifyCertificate` (aprox. 1074–1315):

1. **Recarga previa:** Se llama a `reloadAndWriteTrustStore(certGroup)` antes de verificar, para que las listas en memoria (incluidas `issuerCertificates`) estén actualizadas desde disco.
2. **Detección PQC:** Si `UA_PQC_IsCertificatePQCSigned(certificate, certGroup->logging)` es verdadero:
   - Se parsea el certificado y se obtiene el nombre del emisor.
   - Se busca el emisor en `memStore->issuerCertificates` y, si no está, en `memStore->trustedCertificates` (comparación por `X509_NAME_cmp`).
   - Si el certificado es autofirmado (subject == issuer), se pasa `issuerCA = NULL` a la verificación PQC.
3. **Verificación de firma:** Se llama a `UA_PQC_VerifyCertificateSignature(certificate, issuerCA, certGroup->logging)`. Si falla, se devuelve `UA_STATUSCODE_BADCERTIFICATEINVALID` y el certificado puede acabar en la lista de rechazados.
4. **Certificados no PQC:** Si no está firmado con PQC, se sigue el flujo habitual (`reloadTrustStore` y luego la verificación estándar del MemoryCertStore).

### 4.3 Gestión de emisores, CRL y validación jerárquica

- **Emisores:** La CA PQC (certificado Dilithium) debe colocarse en el directorio de emisores del FileStore (p. ej. `issuer/certs/`) para que al recargar se cargue en `issuerCertificates` y esté disponible para `UA_PQC_VerifyCertificateSignature`.
- **CRL:** El flujo de CRL no está extendido específicamente para PQC; se reutiliza el mismo mecanismo de listas CRL del MemoryCertStore. La verificación de revocación sigue dependiendo de que OpenSSL/OQS soporte el algoritmo de la firma del CRL.
- **Validación jerárquica:** La lógica de cadena (uno o más niveles de CA) sigue siendo la de open62541 (buscar emisor por nombre); la diferencia es que cada eslabón firmado con Dilithium debe verificarse con `UA_PQC_VerifyCertificateSignature` en lugar de `X509_verify` cuando se detecta que es PQC.

### 4.4 Problemas encontrados y soluciones

- **Orden de recarga:** Para PQC se necesita tener ya cargados los emisores antes de verificar. En FileStore, `verifyCertificate` se llamaba después de `reloadTrustStore`, pero el MemoryCertStore solo aplicaba `reloadCertificates` dentro de `verifyCertificate` cuando `reloadRequired` era true. Solución: en `reloadAndWriteTrustStore` se fuerza una recarga llamando a `verifyCertificate` con un certificado “dummy” inválido (1 byte 0x00) para disparar `reloadCertificates` y rellenar las pilas X509; luego se elimina ese dummy de la lista de rechazados (aprox. 431–499 en ua_certificategroup_filestore.c).  
  **Justificación:** En el flujo original, `reloadAndWriteTrustStore` hace `readTrustStore` → `setTrustList`; `setTrustList` en MemoryCertStore solo actualiza `trustList` (TrustListDataType) y marca `reloadRequired = true`. Las pilas `trustedCertificates` e `issuerCertificates` (STACK_OF(X509)) se rellenan en `reloadCertificates`, que solo se invoca desde `verifyCertificate` cuando `reloadRequired` es true. Por tanto, la primera vez que se verifica un certificado PQC, si no se ha llamado antes a `verifyCertificate`, las pilas pueden estar vacías o desactualizadas. Al buscar el emisor en `memStore->issuerCertificates` no se encontraría ningún X509 y se pasaría `issuerCA = NULL`; para un certificado firmado por una CA (no autofirmado), `UA_PQC_VerifyCertificateSignature(certificate, NULL, ...)` devuelve error (en código: "Certificate is not self-signed but no issuer provided"). Forzar una llamada a `verifyCertificate` con un dummy hace que se ejecute `reloadCertificates`, se rellenen las pilas desde `trustList`, y la siguiente verificación PQC ya tenga los emisores disponibles. El dummy se elimina de rejected para no persistir un “certificado” inválido en disco.

- **Estructura interna del MemoryCertStore:** FileStore necesita acceder a `issuerCertificates` y `trustedCertificates` (pilas X509) del store en memoria. Se duplica la definición de la estructura `MemoryCertStore` (trustList, rejectedCertificates, trustedCertificates, issuerCertificates, crls, etc.) en ua_certificategroup_filestore.c para poder obtener el emisor X509 y pasarlo a `UA_PQC_VerifyCertificateSignature` (opaque como `void *issuerCert`).  
  **Justificación:** La API pública de CertificateGroup no expone el tipo interno del store; `certGroup->context` es el FileCertStore, y dentro de él `context->store` es un puntero a otro CertificateGroup (MemoryCertStore) cuyo `context` es el MemoryCertStore con las pilas X509. No existe una función en la API como `getIssuerCertificateByName`; por tanto, para implementar la verificación PQC en el FileStore había que (1) conocer el layout del MemoryCertStore, (2) hacer cast de `context->store->context` a ese tipo, y (3) iterar sobre las pilas para encontrar el X509 cuyo subject coincide con el issuer del certificado. La duplicación de la estructura es la única forma de acceder a esos campos sin añadir nuevas funciones públicas al plugin de certificategroup en memoria (que es código openssl y no debería depender de PQC). La firma de `UA_PQC_VerifyCertificateSignature` acepta `void *issuerCert` para no incluir `<openssl/x509.h>` en el header público de securitypolicy_pqc.h.

---

## 5. Modificaciones en la fase de Discovery y selección de endpoints

### 5.1 Discovery en open62541 original

El cliente obtiene la lista de endpoints con **GetEndpoints** (o FindServers + GetEndpoints). Cada `UA_EndpointDescription` incluye `endpointUrl`, `securityPolicyUri`, `securityMode`, `serverCertificate` (cuando aplica), etc. El cliente elige un endpoint y luego abre el SecureChannel con esa política y ese certificado de servidor.

### 5.2 Conflictos al introducir políticas PQC

- **Certificado de servidor vacío en la descripción:** Algunos servidores o configuraciones pueden no incluir `serverCertificate` en el endpoint para la política PQC en la primera respuesta GetEndpoints (o la URL de discovery puede ser SecurityPolicy#None). Entonces el cliente tiene `securityPolicyUri = PQC` pero `serverCertificate.length == 0`.
- **Inicialización del canal:** Si se intenta crear el contexto de canal con política PQC y certificado remoto vacío, el código original podía rechazarlo. Además, para cifrar con Kyber se necesita la clave pública del servidor, que viene del certificado.  
  **Justificación:** En `UA_SecureChannel_setSecurityPolicy` (ua_securechannel.c), antes de la modificación PQC, si `remoteCertificate` era NULL o de longitud 0 para una política que no fuera None, el código podía pasar ese ByteString a `newContext`. En `pqc_channel_newContext`, si se recibe certificado vacío, se inicializa el contexto con `remoteSigPublicKeyValid = false` y `remoteKemPublicKeyValid = false`; no se llama a `pqc_extract_pubkeys_from_cert_der` porque no hay datos que parsear. Sin la rama `allowEmptyCert`, el núcleo no habría permitido `remoteCertificate` vacío y habría devuelto error antes de llamar a `newContext`, impidiendo que el cliente abra un canal PQC cuando el endpoint no incluye certificado en GetEndpoints.

### 5.3 Adaptación de la negociación de endpoints

- **Endpoint “no configurado” para PQC:** En `ua_client_connect.c`, `endpointUnconfigured` (aprox. 118–137): si el endpoint tiene `securityPolicyUri == PQC` y `serverCertificate.length == 0`, se considera no configurado (`return true`). Así, el cliente no marca la conexión como completa hasta tener certificado de servidor (p. ej. tras un GetEndpoints que sí lo incluya o tras recibir el primer OPN).  
  **Justificación:** `isFullyConnected` usa `endpointUnconfigured(&client->endpoint)` para decidir si la conexión está lista. Si no se considerara “no configurado” un endpoint PQC sin certificado, el cliente podría marcar la conexión como completa con un canal abierto con None (o con PQC pero sin clave remota), y la aplicación podría intentar enviar mensajes cifrados; al no tener la clave Kyber del servidor, `pqc_encrypt` fallaría o se enviarían mensajes solo firmados de forma inconsistente. Tratar ese caso como no configurado obliga a que el flujo de conexión siga (p. ej. GetEndpoints de nuevo o procesamiento del OPN) hasta disponer del certificado y actualizar el contexto con `UA_PQCChannel_updateRemoteCertificate`.

- **Dos fases de conexión:** Se permite conectar primero con SecurityPolicy#None para discovery. En `initSecurityPolicy` (aprox. 2268–2334): si la política seleccionada es PQC y `client->endpoint.serverCertificate.length == 0`, se hace fallback a SecurityPolicy#None solo para esa fase; se usa un `tempNonePolicy` si no hay ya None en la config. La descripción del endpoint se conserva, de modo que un GetEndpoints posterior puede devolver el certificado y entonces reconectar con PQC.  
  **Justificación:** Si en esa situación se intentara inicializar el canal con la política PQC y certificado vacío, en versiones sin la rama `allowEmptyCert` en el núcleo fallaría. Incluso con `allowEmptyCert`, el servidor podría exigir que el primer mensaje de conexión use la política del endpoint (PQC); si el cliente enviara OPN con None porque no tiene certificado, el servidor podría rechazar la conexión por política no coincidente. El fallback a None permite al menos establecer un canal de discovery (GetEndpoints, FindServers) sin cifrado; cuando la aplicación o el flujo obtiene el endpoint con certificado (p. ej. misma URL pero respuesta con serverCertificate), se puede reconectar seleccionando de nuevo el endpoint PQC y entonces `serverCertificate.length > 0` y se usa la política PQC correctamente. Sin este fallback, escenarios donde GetEndpoints no incluye el certificado en la primera respuesta dejarían al cliente sin forma de progresar.

- **Selección de UserTokenPolicy con PQC:** En `activateSessionAsync` (aprox. 1094–1123), si no se encuentra un UserTokenPolicy por el policyId habitual, se busca explícitamente un token de tipo CERTIFICATE cuyo `securityPolicyUri` sea el URI PQC, para autenticación por certificado con la política correcta.  
  **Justificación:** La función `findUserTokenPolicy` puede buscar por `policyId` configurado en el cliente. Si el servidor envía un endpoint PQC con un `policyId` para el token de certificado que no coincide con el configurado (o el cliente no tiene policyId para PQC), `findUserTokenPolicy` devolvería NULL y se devolvería `UA_STATUSCODE_BADINTERNALERROR` ("Could not find a matching UserTokenPolicy"). Añadir un segundo bucle que busque por `tokenType == UA_USERTOKENTYPE_CERTIFICATE` y `securityPolicyUri == PQC` asegura que, cuando el endpoint es PQC, se use el UserTokenPolicy de certificado asociado a esa política aunque el policyId no coincida, permitiendo ActivateSession con identidad por certificado en entornos PQC.

### 5.4 Filtrado de políticas incompatibles

- En el **servidor**, `addAllSecurityPolicies` ya filtra: certificado con solo extensiones PQC → solo se ofrecen PQC y None.
- En el **cliente**, la elección del endpoint la hace la aplicación o la lógica de “mejor” política; no hay un filtro automático adicional en el discovery más allá de no considerar “configurado” un endpoint PQC sin certificado.

---

## 6. Integración del FileStore

### 6.1 Diseño original del almacenamiento de certificados

El **CertificateGroup** por defecto con FileStore (`UA_CertificateGroup_Filestore`) en `plugins/crypto/ua_certificategroup_filestore.c` mantiene una estructura de directorios:

- `trusted/` – certificados de confianza  
- `issuer/` – certificados de emisores (CA)  
- `rejected/` – certificados rechazados (para revisión manual)  
- Para la aplicación propia: `ApplCerts/own/certs` y `ApplCerts/own/private`

Internamente usa un **MemoryCertStore** (`context->store`); los datos se cargan desde disco (readTrustStore, readCertificates, etc.) y se escriben al actualizar listas (writeCertificates, ensureRejectedDirectoryExists, etc.).

### 6.2 Extensiones para certificados PQC

- **Tamaño de certificados:** Los certificados PQC (con extensiones y, en su caso, firma Dilithium) son mucho más grandes (~6–7 KB). Las rutinas de lectura/escritura siguen siendo `readFileToByteString` / `writeByteStringToFile` (ua_filestore_common.c); no hay límite rígido de tamaño en el FileStore.  
  **Justificación:** En la versión base, los certificados típicos RSA/ECC tienen unos pocos cientos o ~1–2 KB. Si el FileStore o el código de codificación binaria hubieran asumido un tamaño máximo (p. ej. 4 KB), los certificados PQC no cabrían o se truncarían. Al no imponer un tope en `readFileToByteString` ni en las estructuras UA_ByteString, los certificados PQC se leen y escriben correctamente; el único ajuste necesario fue el margen extra en `hideBytesAsym` para la codificación del header (véase sección 2.3).
- **Nombres de archivo:** `getCertFileName` usa thumbprint SHA-1 y nombre del subject (CN) para generar el nombre de archivo. Se validan thumbprint y subject no vacíos para evitar nombres inválidos (aprox. 137–200 en ua_certificategroup_filestore.c).  
  **Justificación:** En código se comprueba explícitamente: si `thumbprintRet != UA_STATUSCODE_GOOD` o `thumbprint.length == 0`, o si `subjectRet != UA_STATUSCODE_GOOD` o `subjectName.length == 0`, se devuelve `UA_STATUSCODE_BADINTERNALERROR` y no se escribe ningún archivo. Sin esta validación, certificados malformados o con subject vacío podrían generar nombres como `[]` o rutas inválidas, provocando fallos en `writeByteStringToFile` o en listados posteriores del directorio. El comentario en código indica: *"CRITICAL: Validate that subName and thumbprintBuffer are not empty ... This prevents creating filenames like \"[]\" or \"[thumbprint]\""*.

- **Persistencia de listas:** `reloadAndWriteTrustStore` lee desde los directorios, rellena `UA_TrustListDataType` y llama a `context->store->setTrustList`; luego fuerza la recarga interna del MemoryCertStore (incluidas pilas X509) para que la verificación PQC tenga emisores disponibles.  
  **Justificación:** Sin la recarga forzada (con el certificado dummy), la primera verificación de un certificado PQC firmado por CA tendría las pilas X509 vacías y fallaría como se describió en la sección 4.4. Llamar a `reloadAndWriteTrustStore` al inicio de `FileCertStore_verifyCertificate` (antes de la rama PQC) garantiza que, tanto para certificados PQC como no PQC, el store en memoria refleje el estado en disco; así se evita usar una lista de confianza obsoleta si el administrador acaba de añadir la CA en `issuer/certs/`.

### 6.3 Cambios en rutas, persistencia y recarga

- **Rutas:** No se añaden rutas nuevas específicas para PQC; se usan las mismas carpetas trusted/issuer/rejected. La CA PQC se coloca en `issuer/certs/` (p. ej. `ca_cert.der`).
- **Recarga:** Para PQC, en cada `FileCertStore_verifyCertificate` se llama primero a `reloadAndWriteTrustStore` (o al menos se asegura que el store esté actualizado) para que los certificados de confianza y emisores estén en memoria antes de buscar el emisor y llamar a `UA_PQC_VerifyCertificateSignature`.  
  **Justificación:** Sin esta recarga al inicio de `FileCertStore_verifyCertificate`, la primera verificación de un certificado PQC firmado por CA tendría las pilas X509 del MemoryCertStore vacías o desactualizadas (porque `reloadCertificates` solo se ejecuta dentro de `verifyCertificate` del MemoryCertStore cuando `reloadRequired` es true, y eso ocurre tras `setTrustList`). Al buscar el emisor en `memStore->issuerCertificates` no se encontraría el X509 de la CA y se pasaría `issuerCA = NULL`; para un certificado no autofirmado, `UA_PQC_VerifyCertificateSignature(certificate, NULL, ...)` devuelve error ("Certificate is not self-signed but no issuer provided"). Llamar a `reloadAndWriteTrustStore` antes de la rama PQC garantiza que las listas en disco (trusted/, issuer/) estén reflejadas en memoria antes de cualquier verificación.

- **Rejected:** Si la verificación falla (incluida la verificación PQC), el certificado se escribe en `rejected/` con el mismo mecanismo que en la versión base (getCertFileName, writeByteStringToFile, ensureRejectedDirectoryExists).  
  **Justificación:** Mantener el mismo flujo que la versión base permite que el administrador revise los certificados rechazados (p. ej. por firma PQC inválida o emisor no encontrado) y los mueva manualmente a trusted/ si decide confiar en ellos; sin escribir en rejected/, no quedaría registro de qué certificados fallaron y por qué.

### 6.4 Manejo de rejected/trusted/issuer con PQC

- **Trusted:** Certificados que pasan la verificación (incluida la firma PQC cuando aplica) se consideran válidos; si no estaban ya en la lista de confianza, el flujo estándar puede añadirlos según la configuración.
- **Issuer:** La CA PQC debe estar en `issuer/certs/`; al recargar, se cargan en `issuerCertificates` del MemoryCertStore y se usan para `UA_PQC_VerifyCertificateSignature` cuando el certificado a verificar está firmado por esa CA.
- **Rejected:** Cualquier certificado que falle la verificación (estructura, cadena, o firma PQC) puede acabar en rejected; el código evita duplicados comprobando si el archivo ya existe antes de escribir.

---

## 7. Integración de CA y gestión automatizada de certificados

### 7.1 Integración de la CA en el flujo

La **herramienta de línea de comandos** `examples/encryption/pqc_ca_tool.c` proporciona:

- **init-ca:** Genera una CA con clave Dilithium (ML-DSA-44) y Kyber, y escribe `ca_cert.der` y `ca_key.der` (p. ej. en `local_ca/`).
- **gen-csr:** Genera un CSR con subject y SAN, usando Dilithium+Kyber; escribe CSR y clave privada (p. ej. `out/app.csr`, `out/app_key.der`).
- **sign-cert:** Firma un CSR con la CA (Dilithium), generando el certificado firmado (p. ej. `out/app_cert.der`).

El script **test_pqc_pki.sh** automatiza: crear CA, generar CSR servidor/cliente, firmar con la CA, copiar certificados y claves a `server_pki/` y `client_pki/` en la estructura ApplCerts/own y issuer.

**Justificación de la CA y del script:** Sin una CA PQC (certificado firmado con Dilithium), los certificados de servidor y cliente tendrían que ser autofirmados; la verificación en FileStore acepta autofirmados pasando `issuerCA = NULL` a `UA_PQC_VerifyCertificateSignature`, pero en entornos con múltiples aplicaciones o renovación de certificados es preferible una cadena de confianza. La herramienta pqc_ca_tool reutiliza las mismas primitivas (OQS Provider, liboqs) que la pila open62541, de modo que los certificados generados son compatibles con la verificación PQC del FileStore. El script test_pqc_pki.sh coloca la CA en `issuer/certs/` de ambas PKI para que, al arrancar servidor y cliente con FileStore, la recarga cargue la CA en `issuerCertificates` y la verificación de los certificados firmados por esa CA tenga éxito; sin copiar la CA a issuer/, la verificación fallaría con "Issuer CA not found".

### 7.2 Cambios en generación, firma y validación

- **Generación:** En open62541 se exponen `UA_PQC_CreateCertificate`, `UA_PQC_CreateCertificateWithOQSProvider`, `UA_PQC_CreateCSR` (securitypolicy_pqc.h/c). La CA tool usa OpenSSL + OQS Provider para generar la CA y firmar; los certificados resultantes están firmados con Dilithium y contienen extensiones Kyber/Dilithium.
- **Firma por la CA:** `UA_PQC_SignCSRWithCA` y `UA_PQC_SignCertificateWithCA` permiten firmar CSR o certificado con una CA (cert + clave privada CA en formato DER/PEM); la clave privada de la CA debe ser Dilithium para firma PQC.
- **Validación:** En runtime, la validación la hace el CertificateGroup (FileStore o Memory) como se describió en la sección 4: detección de firma PQC y llamada a `UA_PQC_VerifyCertificateSignature` con el emisor adecuado.

### 7.3 Automatización del trust management

- **test_pqc_pki.sh:** Copia `ca_cert.der` a `server_pki/ApplCerts/issuer/certs/` y `client_pki/ApplCerts/issuer/certs/`, de modo que servidor y cliente tengan la CA en su store de emisores. Los certificados propios (server_cert.der, client_cert.der) y las claves (server_key.der, client_key.der) se colocan en own/certs y own/private.
- **Trust manual:** Mover certificados de `rejected/` a `trusted/` sigue siendo manual; no hay servicio GDS modificado para PQC en el código analizado.

### 7.4 Impacto en seguridad operativa

- **Secretos de la CA:** La clave privada de la CA (`ca_key.der`) debe protegerse; la herramienta no implementa HSM ni cifrado de clave por defecto.
- **Renovación:** La renovación de certificados sigue siendo por CSR + sign-cert; no hay automatización integrada en el servidor/cliente para renovar antes de caducar.
- **Revocación:** CRL y comprobación de revocación siguen dependiendo del backend OpenSSL/MemoryCertStore; no hay extensión específica para CRL firmadas con Dilithium más allá de lo que soporte el provider.

---

## 8. Refinamiento final y estabilización

### 8.1 Eliminación de logs redundantes

En el código hay muchos `UA_LOG_DEBUG` / `UA_LOG_INFO` con prefijos como `[TRACE-OPN]`, `[FILESTORE-PQC]`, `[FILESTORE-PQC-DIAG]`, `[TRACE-CERT]`, `[TRACE-UTP-CERT]`. Sirven para depuración; en producción se pueden reducir con niveles de log (solo ERROR/WARNING) sin cambiar lógica.

### 8.2 Refactorizaciones

- **Política PQC:** Un único archivo `securitypolicy_pqc.c` concentra contexto, sign/verify, encrypt/decrypt, derivación de claves, thumbprint, newContext/deleteContext, y carga de claves desde certificado y buffer privado. La separación entre “policy context” y “channel context” sigue el patrón de otras políticas (p. ej. Basic256Sha256).
- **Cliente:** La lógica PQC en `ua_client_connect.c` está concentrada en: `endpointUnconfigured`, `initSecurityPolicy` (fallback a None), `activateSessionAsync` (búsqueda de UserTokenPolicy PQC), procesamiento del OPN (actualización del certificado remoto y thumbprint), y asignación dinámica de buffers para firmas con certificados grandes (signClientSignature, etc.).

### 8.3 Manejo de errores específicos de PQC

- **Claves no inicializadas:** Si tras cargar certificado y clave privada las claves Dilithium/Kyber no se marcan como inicializadas (p. ej. certificado sin extensiones o clave privada de tamaño no reconocido), `UA_SecurityPolicy_PQC` devuelve `UA_STATUSCODE_BADCERTIFICATEINVALID` y no se añade la política.  
  **Justificación:** Si se permitiera inicializar la política con claves no listas, la primera operación de firma (`pqc_sign`) fallaría porque `pc->sigKeysInitialized` sería false y no se podría llamar a `OQS_SIG_sign`; la primera operación de cifrado o descifrado fallaría por `kemKeysInitialized` false. Devolver error en `UA_SecurityPolicy_PQC` evita exponer una política a medio configurar y permite que la aplicación o el config detecten el problema al arrancar (p. ej. certificado corrupto o clave en formato incorrecto).

- **Firma remota no disponible:** En `pqc_verify`, si `remoteSigPublicKeyValid` es falso se devuelve error; en `pqc_encrypt`, si la clave Kyber remota no está disponible se puede no cifrar (getRemoteBlockSize == 0) o devolver error según el camino.  
  **Justificación:** Sin la comprobación en `pqc_verify`, se llamaría a `OQS_SIG_verify` con un buffer `remoteSigPublicKey` sin inicializar (posiblemente ceros), lo que daría verificación fallida o comportamiento indefinido. Devolver error explícito ("remote Dilithium public key is not initialized") permite depurar. En `pqc_encrypt`, devolver 0 en `getRemoteBlockSize` cuando no hay clave Kyber remota hace que el núcleo no reserve espacio para cifrado y envíe el mensaje solo firmado (primer OPN del cliente); si en cambio se devolviera error en `encrypt`, el canal no se abriría. La elección de "no cifrar pero firmar" en ese caso es intencionada para permitir el handshake.

- **Verificación de certificado PQC:** Si `UA_PQC_VerifyCertificateSignature` falla en FileStore, se devuelve `UA_STATUSCODE_BADCERTIFICATEINVALID` y el certificado puede escribirse en rejected.  
  **Justificación:** No aceptar certificados con firma PQC inválida mantiene la garantía de que solo se confía en certificados cuya cadena de firma es correcta. Escribir en rejected permite al administrador inspeccionar el certificado y, si procede, moverlo a trusted tras verificación manual (o corregir la CA/emisor).

### 8.4 Mejora del flujo de inicialización

- **Orden de operaciones en FileStore:** Recarga de trust store → detección PQC → búsqueda de emisor en issuer/trusted → verificación de firma PQC → resto de la verificación estándar (trust list, etc.).
- **Canal:** Permitir certificado remoto vacío en `UA_SecureChannel_setSecurityPolicy` para PQC evita fallos en el primer handshake; la actualización con `UA_PQCChannel_updateRemoteCertificate` tras recibir el OPN completa el contexto.
- **Cliente:** Fallback a SecurityPolicy#None cuando se elige PQC pero aún no hay certificado de servidor permite que el discovery continúe y que una segunda conexión use PQC con el certificado ya disponible.

### 8.5 Compatibilidad con certificados clásicos

- **Configuración híbrida:** Si el certificado tiene clave RSA/ECC y además extensiones PQC (añadidas con `UA_PQC_EnsureCertificateExtensions`), se pueden ofrecer tanto políticas clásicas como PQC; `addAllSecurityPolicies` en ese caso añade todas las políticas (Basic256Sha256, Aes256Sha256RsaPss, PQC, None, etc.).
- **Clave privada:** Se soporta el formato “RSA/ECC + PQC al final” del buffer para usar el mismo certificado (con extensiones PQC) con políticas clásicas (RSA) y PQC (Dilithium+Kyber).
- **Solo PQC:** Certificados solo PQC (firma Dilithium, sin clave RSA) solo permiten política PQC y None; la clave privada puede ser solo el blob 4960 bytes (Dilithium+Kyber). En `ua_config_default.c`, al cargar desde FileStore, si el certificado es PQC y la clave tiene longitud 4960, se copia la clave sin intentar descifrarla con OpenSSL (aprox. 2047–2056).  
  **Justificación:** El blob 4960 bytes no es PEM ni DER de una clave OpenSSL; es el formato crudo Dilithium (2560) + Kyber (2400) que escribe `UA_PQC_CreateCSR` o la herramienta pqc_ca_tool. Si se pasara a `UA_CertificateUtils_decryptPrivateKey`, OpenSSL fallaría al parsear (no reconoce ese formato) y se pediría contraseña o se devolvería error. La rama `if(isPQCCert && privateKey->length == 4960)` evita ese camino y hace `UA_ByteString_copy(privateKey, &decryptedPrivateKey)` directamente, de modo que la política PQC reciba el buffer tal cual en `pqc_set_local_from_params` y extraiga Dilithium y Kyber por posición fija (primeros 2560, siguientes 2400 bytes).

---

## Resumen de archivos y funciones clave

| Área | Archivo(s) | Funciones / puntos clave |
|------|------------|---------------------------|
| Política PQC | `plugins/crypto/openssl/securitypolicy_pqc.c`, `plugins/include/open62541/plugin/securitypolicy_pqc.h` | `UA_SecurityPolicy_PQC`, `pqc_sign`/`pqc_verify`, `pqc_encrypt`/`pqc_decrypt`, `pqc_sym_generateKey`, `pqc_extract_pubkeys_from_cert_der`, `UA_PQC_*` (certificados, CSR, verificación) |
| Canal seguro | `src/ua_securechannel.c`, `src/ua_securechannel_crypto.c` | Certificado vacío PQC, `prependHeadersAsym`/`signAndEncryptAsym`/`hideBytesAsym`/`padChunk`, `decryptAndVerifyChunk`, `unpackPayloadOPN` (ajuste de chunk para PQC) |
| Cliente | `src/client/ua_client_connect.c` | `endpointUnconfigured`, `initSecurityPolicy` (fallback None), `activateSessionAsync` (UserTokenPolicy PQC), actualización de canal con certificado servidor, buffers dinámicos para firmas grandes |
| Configuración | `plugins/ua_config_default.c` | `addAllSecurityPolicies` (detección PQC, políticas ofrecidas), carga de clave PQC-only (4960 bytes) en configuración FileStore |
| FileStore certificados | `plugins/crypto/ua_certificategroup_filestore.c` | `FileCertStore_verifyCertificate` (recarga, detección PQC, búsqueda emisor, `UA_PQC_VerifyCertificateSignature`), `reloadAndWriteTrustStore` (recarga forzada con dummy) |
| FileStore políticas | `plugins/crypto/ua_securitypolicy_filestore.c` | Wrapper sobre política interna (incluida PQC); sin cambios específicos PQC más allá de delegar en la política interna |
| CA / PKI | `examples/encryption/pqc_ca_tool.c`, `test_pqc_pki.sh` | init-ca, gen-csr, sign-cert; script de despliegue en server_pki/client_pki |
| Build | `CMakeLists.txt` | Búsqueda de liboqs (OQS_LIBRARY, OQS_INCLUDE_DIR), enlace con open62541 |

---

## Decisiones de diseño y compromisos

- **URI de política no estándar:** `http://example.org/SecurityPolicy#PQC` permite experimentación sin chocar con URIs OPC UA estándar; una futura estandarización podría definir otro URI. **Justificación:** Los URIs estándar (p. ej. `http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256`) están reservados; usar un URI de ejemplo evita conflictos con implementaciones que filtren por URI y permite identificar claramente la política experimental en logs y en GetEndpoints.

- **OIDs propios para extensiones:** Dilithium/Kyber usan OIDs 1.3.6.1.4.1.55336.1.1 y 1.3.6.1.4.1.55336.1.2; son coherentes con la práctica de “enterprise” para extensiones no estándar. **Justificación:** No existe aún un OID estándar IANA/ITU-T para claves públicas Dilithium/Kyber en extensiones X.509; usar un OID bajo el arco 1.3.6.1.4.1 (enterprise) evita colisiones y permite que tanto el emisor como el receptor reconozcan las extensiones de forma unívoca en el parsing (véase `OBJ_txt2obj(OID_DILITHIUM_PUB, 1)` en securitypolicy_pqc.c).

- **Primer OPN sin cifrado:** Permitir enviar el primer OPN solo firmado (cuando getRemoteBlockSize == 0) simplifica el handshake pero reduce la confidencialidad del primer mensaje; es un compromiso aceptable para el establecimiento del canal. **Justificación:** Sin esta opción, el cliente no podría enviar el primer OPN con política PQC hasta tener el certificado del servidor; pero en muchos flujos el certificado del servidor solo se obtiene en la respuesta OPN o en GetEndpoints. Exigir cifrado en el primer OPN crearía un deadlock. La integridad del primer mensaje queda protegida por la firma; la confidencialidad se alcanza a partir del siguiente mensaje, cuando ya hay shared secret.

- **Duplicación de estructura MemoryCertStore en FileStore:** Necesaria para acceder a las pilas X509 sin exponer el tipo en la API pública; implica mantener ambas definiciones alineadas si cambia el certificategroup en memoria. **Justificación:** El plugin FileStore está en `plugins/crypto/` y el MemoryCertStore en `plugins/crypto/openssl/`; no se quiso añadir una función pública tipo `getIssuerCertificateByName` al CertificateGroup porque obligaría a exponer tipos OpenSSL en la API. La duplicación de la estructura es el mínimo cambio para poder iterar sobre `issuerCertificates` y `trustedCertificates` desde FileStore; si en el futuro se refactoriza el certificategroup, habría que actualizar la estructura duplicada en ua_certificategroup_filestore.c.

- **Dependencia liboqs + OpenSSL 3 + OQS Provider:** La solución no es “solo OpenSSL” ni “solo liboqs”; híbrido para certificados (RSA/ECC + extensiones PQC) reduce la dependencia del OQS Provider en algunos escenarios. **Justificación:** liboqs proporciona las primitivas Dilithium/Kyber de forma estable; OpenSSL 3.x con OQS Provider permite firmar/verificar certificados X.509 con Dilithium sin reimplementar la capa X.509. Para entornos donde el OQS Provider no está disponible, `UA_PQC_CreateCertificate` (firma RSA/ECC + extensiones PQC) permite generar certificados compatibles con la política PQC sin Dilithium en la firma del certificado; las operaciones de canal siguen usando Dilithium/Kyber vía liboqs.

Este documento refleja el estado del código analizado y puede usarse como base para la sección "Implementation" de un artículo científico, citando los archivos y funciones indicados.
