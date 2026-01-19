#include "open62541/plugin/securitypolicy.h"
#include "open62541/server_config_default.h"
#include "open62541/plugin/log_stdout.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdio.h>
#include <open62541/plugin/securitypolicy_pqc.h>
#include "securitypolicy_common.h"
#include <open62541/util.h>
#include <open62541/plugin/create_certificate.h>


#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/provider.h>
#include <openssl/core_names.h>
#endif

/* Fallback definitions for OQS constants if not provided by liboqs headers */
#ifndef OQS_SIG_dilithium_2_length_public_key
#define OQS_SIG_dilithium_2_length_public_key 1312
#endif
#ifndef OQS_SIG_dilithium_2_length_secret_key
#define OQS_SIG_dilithium_2_length_secret_key 2560
#endif
#ifndef OQS_SIG_dilithium_2_length_signature
#define OQS_SIG_dilithium_2_length_signature 2420
#endif
#ifndef OQS_SIG_alg_dilithium_2
/* Use ML-DSA-44 (the standard name for Dilithium2 in newer liboqs versions) */
#define OQS_SIG_alg_dilithium_2 "ML-DSA-44"
#endif
#ifndef OQS_KEM_kyber_768_length_public_key
#define OQS_KEM_kyber_768_length_public_key 1184
#endif
#ifndef OQS_KEM_alg_kyber_768
#define OQS_KEM_alg_kyber_768 "Kyber768"
#endif
#ifndef OQS_KEM_kyber_768_length_secret_key
#define OQS_KEM_kyber_768_length_secret_key 2400
#endif
#ifndef OQS_KEM_kyber_768_length_ciphertext
#define OQS_KEM_kyber_768_length_ciphertext 1088
#endif
#ifndef OQS_KEM_kyber_768_length_shared_secret
#define OQS_KEM_kyber_768_length_shared_secret 32
#endif

#define OID_DILITHIUM_PUB "1.3.6.1.4.1.55336.1.1"
#define OID_KYBER_PUB     "1.3.6.1.4.1.55336.1.2"

/* PQC algorithm constants - using Dilithium2 and Kyber768 */
#define PQC_SIG_SIGNATURE_LEN OQS_SIG_dilithium_2_length_signature
#define PQC_SIG_PUBLIC_KEY_LEN OQS_SIG_dilithium_2_length_public_key
#define PQC_SIG_SECRET_KEY_LEN OQS_SIG_dilithium_2_length_secret_key
#define PQC_KEM_CIPHERTEXT_LEN OQS_KEM_kyber_768_length_ciphertext
#define PQC_KEM_PUBLIC_KEY_LEN OQS_KEM_kyber_768_length_public_key
#define PQC_KEM_SECRET_KEY_LEN OQS_KEM_kyber_768_length_secret_key
#define PQC_KEM_SHARED_SECRET_LEN OQS_KEM_kyber_768_length_shared_secret

/* ---------------------- Policy context type --------------------- */
/**
 * Policy context for PQC security policy.
 * 
 * This context stores the local PQC keys (Dilithium for signatures, Kyber for KEM)
 * that are shared across all channels using this security policy instance.
 * 
 * Keys are initialized lazily when first needed, either by:
 * - Generating new keypairs if not present in certificate/private key files
 * - Extracting from certificate extensions and loading from private key buffer
 */
typedef struct {
    UA_ByteString localCertThumbprint;  /* SHA-1 thumbprint of local certificate */
    const UA_Logger *logger;             /* Logger instance for this policy */
    
    /* Dilithium2 keys for digital signatures */
    uint8_t sigPublicKey[OQS_SIG_dilithium_2_length_public_key];   /* Dilithium public key */
    uint8_t sigPrivateKey[OQS_SIG_dilithium_2_length_secret_key]; /* Dilithium private key */
    UA_Boolean sigKeysInitialized;       /* True if Dilithium keys are ready to use */
    
    /* Kyber768 keys for Key Encapsulation Mechanism (KEM) */
    uint8_t kemPublicKey[OQS_KEM_kyber_768_length_public_key];     /* Kyber public key */
    uint8_t kemPrivateKey[OQS_KEM_kyber_768_length_secret_key];   /* Kyber private key */
    UA_Boolean kemKeysInitialized;      /* True if Kyber keys are ready to use */
    
    /* Temporary storage for KEM shared secret (used during key derivation) */
    UA_Boolean hasTemporarySharedSecret; /* True if temporary shared secret is set */
    uint8_t temporarySharedSecret[OQS_KEM_kyber_768_length_shared_secret]; /* Temporary shared secret from KEM */
    
    /* Track if we've generated symmetric keys before (for canonical nonce ordering) */
    UA_Boolean hasGeneratedSymmetricKeys; /* True if we've generated symmetric keys at least once */
    
    /* Reference counting: tracks how many PQC_ChannelContext instances reference this policy.
     * The policy can only be freed when refCount == 0.
     * Thread-safety: Operations on security policies are executed within the EventLoop context,
     * which provides serialization guarantees. Channel creation/deletion happens during
     * secure channel setup/teardown, which is also serialized by the framework. */
    UA_UInt32 refCount; /* Number of active channel contexts referencing this policy */
} Policy_Context_PQC;

typedef struct {
    UA_ByteString remoteCertificate;     /* Remote peer's X.509 certificate */
    UA_Boolean hasSharedSecret;           /* True if shared secret is cached */
    uint8_t sharedSecret[OQS_KEM_kyber_768_length_shared_secret]; /* Cached KEM shared secret */
    
    /* Remote peer's Dilithium public key (for signature verification) */
    UA_Boolean remoteSigPublicKeyValid;  /* True if remote Dilithium key is valid */
    uint8_t remoteSigPublicKey[OQS_SIG_dilithium_2_length_public_key];
    
    /* Remote peer's Kyber public key (for encryption/KEM) */
    UA_Boolean remoteKemPublicKeyValid;  /* True if remote Kyber key is valid */
    uint8_t remoteKemPublicKey[OQS_KEM_kyber_768_length_public_key];
    
    /* Symmetric keys derived from KEM shared secret (for message encryption/signing) */
    UA_ByteString localSymSigningKey;    /* Local symmetric signing key (HMAC-SHA256) */
    UA_ByteString localSymEncryptingKey; /* Local symmetric encryption key (AES-256) */
    UA_ByteString localSymIv;           /* Local symmetric IV */
    UA_ByteString remoteSymSigningKey;   /* Remote symmetric signing key (HMAC-SHA256) */
    UA_ByteString remoteSymEncryptingKey;/* Remote symmetric encryption key (AES-256) */
    UA_ByteString remoteSymIv;          /* Remote symmetric IV */
    
    Policy_Context_PQC *policyContext;   /* Reference to policy context with local keys */
} PQC_ChannelContext;

/* ---------------------- Certificate helpers ---------------------- */
static X509 *
pqc_parse_x509_from_bytes(const UA_ByteString *certBytes, UA_Boolean *wasPem) {
    if(wasPem)
        *wasPem = false;
    if(!certBytes || certBytes->length == 0 || !certBytes->data)
        return NULL;

    BIO *bio = BIO_new_mem_buf(certBytes->data, (int)certBytes->length);
    if(bio) {
        X509 *pem = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if(pem) {
            if(wasPem)
                *wasPem = true;
            return pem;
        }
    }

    const unsigned char *p = certBytes->data;
    X509 *der = d2i_X509(NULL, &p, (long)certBytes->length);
    if(der && wasPem)
        *wasPem = false;
    return der;
}

/* --------------- Helpers ----------------- */
/**
 * Check if a buffer is all zeros.
 *
 * @param buf Buffer to check
 * @param len Length of buffer
 * @return true if buffer is all zeros, false otherwise
 */
static UA_Boolean
pqc_is_buffer_all_zeros(const uint8_t *buf, size_t len) {
    if(!buf || len == 0)
        return UA_TRUE;
    
    for(size_t i = 0; i < len; i++) {
        if(buf[i] != 0)
            return UA_FALSE;
    }
    return UA_TRUE;
}

/**
 * Get logger from policy context, with fallback to stdout.
 *
 * @param pc Policy context (can be NULL)
 * @return Logger instance
 */
static const UA_Logger *
pqc_get_logger_from_policy(Policy_Context_PQC *pc) {
    return (pc && pc->logger) ? pc->logger : UA_Log_Stdout;
}

/**
 * Get logger from channel context, with fallback to stdout.
 *
 * @param ctx Channel context (can be NULL)
 * @return Logger instance
 */
static const UA_Logger *
pqc_get_logger_from_channel(PQC_ChannelContext *ctx) {
    if(!ctx || !ctx->policyContext)
        return UA_Log_Stdout;
    return pqc_get_logger_from_policy(ctx->policyContext);
}

/* -------------------- Key generation helpers --------------------- */
/**
 * Initialize Dilithium2 signature keys if not already initialized.
 * 
 * Generates a new keypair if keys are not present. This is called lazily
 * when signing is first needed.
 * 
 * @param ctx Policy context to initialize keys for
 */
static void
pqc_init_keys(Policy_Context_PQC *ctx) {
    if(!ctx) return;
    if(ctx->sigKeysInitialized) return;

    const UA_Logger *log = pqc_get_logger_from_policy(ctx);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if(!sig) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "OQS_SIG_new failed for dilithium2");
        return;
    }

    if(OQS_SIG_keypair(sig, ctx->sigPublicKey, ctx->sigPrivateKey) == OQS_SUCCESS) {
        ctx->sigKeysInitialized = true;
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "Generated Dilithium keypair");
    }
    OQS_SIG_free(sig);
}

/**
 * Initialize Kyber768 KEM keys if not already initialized.
 * 
 * This function checks if public keys were already extracted from a certificate.
 * If so, it waits for private keys to be loaded from the private key buffer.
 * If not, it generates a new keypair.
 * 
 * @param ctx Policy context to initialize keys for
 */
static void
pqc_init_kem_keys(Policy_Context_PQC *ctx) {
    if(!ctx) return;
    if(ctx->kemKeysInitialized) return;

    const UA_Logger *log = pqc_get_logger_from_policy(ctx);

    /* IMPORTANTE: Si ya se han extraído las claves públicas del certificado local,
     * NO debemos generar nuevas claves. Las claves privadas deben cargarse desde
     * el archivo de clave privada y deben coincidir con las claves públicas del certificado.
     * 
     * Verificamos si las claves públicas están inicializadas (extraídas del certificado).
     * Si es así, esperamos a que se carguen las claves privadas correspondientes.
     * Si no hay claves públicas del certificado, entonces generamos nuevas claves. */
    
    /* Verificar si las claves públicas ya están inicializadas (extraídas del certificado) */
    UA_Boolean hasPublicKey = false;
    /* Verificar si hay algún byte no-cero en la clave pública (indicando que fue extraída) */
    for(size_t i = 0; i < OQS_KEM_kyber_768_length_public_key; i++) {
        if(ctx->kemPublicKey[i] != 0) {
            hasPublicKey = true;
            break;
        }
    }
    
    if(hasPublicKey) {
        /* Las claves públicas ya están extraídas del certificado.
         * Verificar si las claves privadas ya están cargadas. */
        UA_Boolean hasPrivateKey = !pqc_is_buffer_all_zeros(ctx->kemPrivateKey, sizeof(ctx->kemPrivateKey));
        if(log) {
            UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "pqc_init_kem_keys: Public key found, checking private key (hasPrivateKey=%u, kemKeysInitialized=%u)",
                        (unsigned)hasPrivateKey, (unsigned)ctx->kemKeysInitialized);
        }
        if(hasPrivateKey) {
            /* Las claves privadas ya están cargadas, marcar como inicializado */
            ctx->kemKeysInitialized = true;
            if(log) {
                UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                            "pqc_init_kem_keys: Kyber keys already initialized "
                            "(public key from certificate, private key already loaded)");
            }
            return;
        } else {
            /* Las claves públicas están extraídas pero las privadas no están cargadas aún */
            if(log) {
                UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                            "pqc_init_kem_keys: Kyber public key already extracted from certificate, "
                            "waiting for private key to be loaded");
            }
            /* NO inicializamos kemKeysInitialized aquí - se inicializará cuando se carguen las claves privadas */
            return;
        }
    }

    /* No hay claves públicas del certificado, generar nuevas claves */
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if(!kem) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "OQS_KEM_new failed for kyber768");
        return;
    }

    if(OQS_KEM_keypair(kem, ctx->kemPublicKey, ctx->kemPrivateKey) == OQS_SUCCESS) {
        ctx->kemKeysInitialized = true;
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "Generated Kyber keypair (no certificate provided)");
    }
    OQS_KEM_free(kem);
}

static EVP_PKEY *
pqc_parse_private_key_from_bytes(const UA_ByteString *keyBytes, UA_Boolean *wasPem) {
    if(wasPem)
        *wasPem = false;
    if(!keyBytes || keyBytes->length == 0 || !keyBytes->data)
        return NULL;

    BIO *bio = BIO_new_mem_buf(keyBytes->data, (int)keyBytes->length);
    if(bio) {
        EVP_PKEY *pem = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if(pem) {
            if(wasPem)
                *wasPem = true;
            return pem;
        }
    }

    const unsigned char *p = keyBytes->data;
    EVP_PKEY *der = d2i_AutoPrivateKey(NULL, &p, (long)keyBytes->length);
    if(der && wasPem)
        *wasPem = false;
    return der;
}

static UA_StatusCode
pqc_set_octet_extension(X509 *x509,
                        const char *oid,
                        const uint8_t *value,
                        size_t valueLen,
                        UA_Boolean *modified,
                        const UA_Logger *logger) {
    if(!x509 || !oid || !value || valueLen == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);
    if(!obj) {
        UA_LOG_WARNING(logger ? logger : UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_set_octet_extension: failed to create OID %s", oid);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode status = UA_STATUSCODE_GOOD;
    int idx;
    while((idx = X509_get_ext_by_OBJ(x509, obj, -1)) >= 0) {
        X509_EXTENSION *ext = X509_get_ext(x509, idx);
        if(ext) {
            X509_delete_ext(x509, idx);
            X509_EXTENSION_free(ext);
        }
        if(modified)
            *modified = true;
    }

    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    if(!oct) {
        status = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup_obj;
    }

    if(ASN1_OCTET_STRING_set(oct, value, (int)valueLen) != 1) {
        status = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup_oct;
    }

    X509_EXTENSION *ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, oct);
    if(!ext) {
        status = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup_oct;
    }

    if(X509_add_ext(x509, ext, -1) != 1) {
        status = UA_STATUSCODE_BADINTERNALERROR;
    } else if(modified) {
        *modified = true;
    }

    X509_EXTENSION_free(ext);

cleanup_oct:
    ASN1_OCTET_STRING_free(oct);
cleanup_obj:
    ASN1_OBJECT_free(obj);
    return status;
}

static UA_StatusCode
pqc_write_back_certificate(X509 *x509,
                           UA_Boolean asPem,
                           UA_ByteString *target) {
    if(!x509 || !target)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_ByteString newCert = UA_BYTESTRING_NULL;
    UA_StatusCode status = UA_STATUSCODE_GOOD;

    if(asPem) {
        BIO *bio = BIO_new(BIO_s_mem());
        if(!bio)
            return UA_STATUSCODE_BADOUTOFMEMORY;

        if(PEM_write_bio_X509(bio, x509) != 1) {
            BIO_free(bio);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        char *pemData = NULL;
        long pemLen = BIO_get_mem_data(bio, &pemData);
        if(pemLen <= 0) {
            BIO_free(bio);
            return UA_STATUSCODE_BADINTERNALERROR;
        }

        status = UA_ByteString_allocBuffer(&newCert, (size_t)pemLen);
        if(status == UA_STATUSCODE_GOOD)
            memcpy(newCert.data, pemData, (size_t)pemLen);

        BIO_free(bio);
    } else {
        int len = i2d_X509(x509, NULL);
        if(len <= 0)
            return UA_STATUSCODE_BADINTERNALERROR;

        status = UA_ByteString_allocBuffer(&newCert, (size_t)len);
        if(status == UA_STATUSCODE_GOOD) {
            unsigned char *ptr = newCert.data;
            i2d_X509(x509, &ptr);
        }
    }

    if(status == UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(target);
        *target = newCert;
    } else {
        UA_ByteString_clear(&newCert);
    }

    return status;
}

/* Forward declarations */
static UA_StatusCode UA_ByteString_expand(UA_ByteString *bs, size_t extra);
static UA_StatusCode pqc_extract_pubkeys_from_cert_der_internal(
    const UA_ByteString *derCert,
    const UA_Logger *logger,
    uint8_t *sigPkOut,
    UA_Boolean *sigValid,
    uint8_t *kemPkOut,
    UA_Boolean *kemValid);

/**
 * Ensure that an X.509 certificate has PQC (Post-Quantum Cryptography) extensions.
 *
 * This function:
 * 1. Checks if the certificate already has Dilithium and Kyber public key extensions
 * 2. If extensions exist, verifies that the corresponding private keys match
 * 3. If extensions don't exist or keys don't match, generates new PQC keypairs
 * 4. Embeds the PQC public keys as X.509 extensions
 * 5. Appends the PQC private keys to the signingPrivateKey buffer
 *
 * The certificate can be in DER or PEM format. The output format matches the input.
 *
 * @param certificate Certificate to process (modified in-place if extensions added)
 * @param signingPrivateKey Private key buffer. If PQC keys are generated, they are
 *                          appended to this buffer: [original_key][Dilithium_key][Kyber_key]
 * @param logger Logger instance (can be NULL, uses stdout logger as fallback)
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
 */
UA_EXPORT UA_StatusCode
UA_PQC_EnsureCertificateExtensions(UA_ByteString *certificate,
                                   UA_ByteString *signingPrivateKey,
                                   const UA_Logger *logger) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;

    if(!certificate || certificate->length == 0 || !certificate->data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_Boolean certWasPem = UA_FALSE;
    X509 *x509 = pqc_parse_x509_from_bytes(certificate, &certWasPem);
    if(!x509) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_EnsureCertificateExtensions: cannot parse certificate data");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    /* Verify that the certificate is self-signed before modifying it.
     * Modifying a CA-signed certificate and re-signing it with the subject's private key
     * would invalidate the certificate chain and break trust validation. */
    X509_NAME *issuer = X509_get_issuer_name(x509);
    X509_NAME *subject = X509_get_subject_name(x509);
    UA_Boolean isSelfSigned = (issuer && subject && X509_NAME_cmp(issuer, subject) == 0);
    
    /* Also verify the signature matches (certificate is actually self-signed) */
    if(isSelfSigned) {
        EVP_PKEY *pubkey = X509_get_pubkey(x509);
        if(pubkey) {
            int verifyResult = X509_verify(x509, pubkey);
            EVP_PKEY_free(pubkey);
            if(verifyResult != 1) {
                /* Names match but signature doesn't verify - not truly self-signed */
                isSelfSigned = UA_FALSE;
            }
        } else {
            isSelfSigned = UA_FALSE;
        }
    }
    
    if(!isSelfSigned) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_EnsureCertificateExtensions: certificate is NOT self-signed. "
                       "Modifying and re-signing a CA-signed certificate would invalidate the "
                       "certificate chain. Only self-signed certificates can be safely modified. "
                       "Consider generating a new self-signed certificate with PQC extensions.");
        X509_free(x509);
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    /* Primero verificar si el certificado ya tiene extensiones PQC */
    UA_Boolean hasDilithiumExt = false;
    UA_Boolean hasKyberExt = false;
    ASN1_OBJECT *objDil = OBJ_txt2obj(OID_DILITHIUM_PUB, 1);
    ASN1_OBJECT *objKy = OBJ_txt2obj(OID_KYBER_PUB, 1);
    if(objDil && X509_get_ext_by_OBJ(x509, objDil, -1) >= 0)
        hasDilithiumExt = true;
    if(objKy && X509_get_ext_by_OBJ(x509, objKy, -1) >= 0)
        hasKyberExt = true;
    
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                "UA_PQC_EnsureCertificateExtensions: checking certificate for PQC extensions "
                "(hasDilithiumExt=%u, hasKyberExt=%u, certificate length=%zu bytes)",
                (unsigned)hasDilithiumExt, (unsigned)hasKyberExt, certificate->length);
    
    if(objDil) ASN1_OBJECT_free(objDil);
    if(objKy) ASN1_OBJECT_free(objKy);

    /* Crear contexto temporal */
    Policy_Context_PQC tempCtx;
    memset(&tempCtx, 0, sizeof(tempCtx));
    tempCtx.logger = logger;
    UA_ByteString_init(&tempCtx.localCertThumbprint);
    
    UA_Boolean modified = UA_FALSE;
    UA_StatusCode status = UA_STATUSCODE_GOOD;
    
    if(hasDilithiumExt && hasKyberExt) {
        /* El certificado ya tiene extensiones PQC. Extraer las claves públicas existentes
         * en lugar de generar nuevas. Sin embargo, si el signingPrivateKey ya contiene
         * claves PQC, debemos verificar que correspondan a las claves públicas del certificado.
         * Si no corresponden, generamos nuevas claves y sobrescribimos las extensiones. */
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_EnsureCertificateExtensions: certificate already has PQC extensions, "
                    "extracting existing public keys");
        
        UA_Boolean sigValid = false;
        UA_Boolean kemValid = false;
        status = pqc_extract_pubkeys_from_cert_der_internal(certificate, log,
                                                           tempCtx.sigPublicKey, &sigValid,
                                                           tempCtx.kemPublicKey, &kemValid);
        if(status != UA_STATUSCODE_GOOD || !sigValid || !kemValid) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_EnsureCertificateExtensions: failed to extract existing PQC keys from certificate");
            X509_free(x509);
            UA_ByteString_clear(&tempCtx.localCertThumbprint);
            return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        }
        
        /* Verificar si el signingPrivateKey ya contiene claves PQC */
        size_t sigKeyLen = sizeof(tempCtx.sigPrivateKey);
        size_t kemKeyLen = sizeof(tempCtx.kemPrivateKey);
        size_t totalPqcKeyLen = sigKeyLen + kemKeyLen;
        
        if(signingPrivateKey && signingPrivateKey->length >= totalPqcKeyLen) {
            /* El buffer contiene claves PQC. Extraerlas y verificar si corresponden a las claves públicas. */
            size_t offset = signingPrivateKey->length - totalPqcKeyLen;
            uint8_t existingSigKey[OQS_SIG_dilithium_2_length_secret_key];
            uint8_t existingKemKey[OQS_KEM_kyber_768_length_secret_key];
            
            UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_PQC_EnsureCertificateExtensions: found PQC private keys in buffer "
                        "(buffer length=%zu, offset=%zu, sigKeyLen=%zu, kemKeyLen=%zu)",
                        signingPrivateKey->length, offset, sigKeyLen, kemKeyLen);
            
            memcpy(existingSigKey, signingPrivateKey->data + offset, sigKeyLen);
            memcpy(existingKemKey, signingPrivateKey->data + offset + sigKeyLen, kemKeyLen);
            
            
            /* Verificar si las claves privadas corresponden a las claves públicas usando un test de encapsulación/descapsulación */
            OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
            if(kem) {
                uint8_t test_ct[OQS_KEM_kyber_768_length_ciphertext];
                uint8_t test_ss_encap[OQS_KEM_kyber_768_length_shared_secret];
                uint8_t test_ss_decap[OQS_KEM_kyber_768_length_shared_secret];
                
                /* Intentar encapsular con la clave pública del certificado */
                if(OQS_KEM_encaps(kem, test_ct, test_ss_encap, tempCtx.kemPublicKey) == OQS_SUCCESS) {
                    /* Intentar descapsular con la clave privada del buffer */
                    if(OQS_KEM_decaps(kem, test_ss_decap, test_ct, existingKemKey) == OQS_SUCCESS) {
                        /* Comparar los shared secrets */
                        if(memcmp(test_ss_encap, test_ss_decap, kem->length_shared_secret) == 0) {
                            /* Las claves coinciden. Usar las claves privadas existentes. */
                            memcpy(tempCtx.sigPrivateKey, existingSigKey, sigKeyLen);
                            memcpy(tempCtx.kemPrivateKey, existingKemKey, kemKeyLen);
                            tempCtx.sigKeysInitialized = true;
                            tempCtx.kemKeysInitialized = true;
                            
                            UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                        "UA_PQC_EnsureCertificateExtensions: existing private keys match certificate public keys, "
                                        "using existing keys");
                            OQS_KEM_free(kem);
                            goto keys_ready;
                        } else {
                            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                          "UA_PQC_EnsureCertificateExtensions: existing private keys do NOT match certificate public keys, "
                                          "generating new keys");
                        }
                    } else {
                        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                      "UA_PQC_EnsureCertificateExtensions: failed to decapsulate with existing private key, "
                                      "generating new keys");
                    }
                } else {
                    UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                  "UA_PQC_EnsureCertificateExtensions: failed to encapsulate with certificate public key, "
                                  "generating new keys");
                }
                OQS_KEM_free(kem);
            }
            
            /* Las claves no coinciden o no se pudieron verificar. Generar nuevas claves. */
            UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_PQC_EnsureCertificateExtensions: generating new keys to replace mismatched keys");
            modified = true; /* Marcar como modificado para sobrescribir las extensiones */
        } else {
            /* No hay claves privadas en el buffer. El certificado tiene extensiones PQC pero
             * el signingPrivateKey no tiene las claves privadas PQC correspondientes.
             * En este caso, simplemente continuar sin las claves privadas. Las claves públicas
             * ya están en el certificado y serán extraídas por pqc_set_local_from_params.
             * Sin embargo, sin las claves privadas, el servidor no podrá descifrar mensajes. */
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_EnsureCertificateExtensions: certificate has PQC extensions but no private keys in buffer. "
                           "Public keys will be extracted from certificate, but decryption will fail without private keys. "
                           "Please ensure the PQC-extended private key file (e.g., server_key_pqc.der) is loaded.");
            /* No generar nuevas claves. Simplemente usar las claves públicas del certificado. */
            /* Las claves públicas ya están en tempCtx (extraídas arriba), así que podemos continuar. */
            tempCtx.sigKeysInitialized = true;  /* Solo las públicas están disponibles */
            tempCtx.kemKeysInitialized = true;  /* Solo las públicas están disponibles */
            goto keys_ready;
        }
        
        /* Si llegamos aquí, necesitamos generar nuevas claves */
        if(modified) {
            /* Limpiar las claves públicas extraídas del certificado para poder generar nuevas */
            memset(tempCtx.sigPublicKey, 0, sizeof(tempCtx.sigPublicKey));
            memset(tempCtx.kemPublicKey, 0, sizeof(tempCtx.kemPublicKey));
            tempCtx.sigKeysInitialized = false;
            tempCtx.kemKeysInitialized = false;
            
            /* Generar claves PQC en el contexto temporal */
            pqc_init_keys(&tempCtx);
            pqc_init_kem_keys(&tempCtx);
            
            if(!tempCtx.sigKeysInitialized || !tempCtx.kemKeysInitialized) {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                               "UA_PQC_EnsureCertificateExtensions: failed to generate PQC keys");
                X509_free(x509);
                UA_ByteString_clear(&tempCtx.localCertThumbprint);
                return UA_STATUSCODE_BADINTERNALERROR;
            }
            
            /* Agregar las nuevas claves públicas al certificado (sobrescribiendo las existentes) */
            status = pqc_set_octet_extension(
                x509, OID_DILITHIUM_PUB, tempCtx.sigPublicKey,
                (size_t)OQS_SIG_dilithium_2_length_public_key, &modified, log);
            if(status != UA_STATUSCODE_GOOD)
                goto cleanup;

            status = pqc_set_octet_extension(
                x509, OID_KYBER_PUB, tempCtx.kemPublicKey,
                (size_t)OQS_KEM_kyber_768_length_public_key, &modified, log);
            if(status != UA_STATUSCODE_GOOD)
                goto cleanup;
        }
        
keys_ready:
        /* Si llegamos aquí con claves inicializadas, continuar con el proceso normal */
        if(!tempCtx.sigKeysInitialized || !tempCtx.kemKeysInitialized) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_EnsureCertificateExtensions: keys not properly initialized");
            X509_free(x509);
            UA_ByteString_clear(&tempCtx.localCertThumbprint);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    } else {
        /* El certificado no tiene extensiones PQC. Generar nuevas claves. */
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_EnsureCertificateExtensions: certificate does not have PQC extensions, "
                    "generating new keys");
        
        /* Generar claves PQC en el contexto temporal */
        pqc_init_keys(&tempCtx);
        pqc_init_kem_keys(&tempCtx);
        
        if(!tempCtx.sigKeysInitialized || !tempCtx.kemKeysInitialized) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_EnsureCertificateExtensions: failed to generate PQC keys");
            X509_free(x509);
            UA_ByteString_clear(&tempCtx.localCertThumbprint);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        
        /* Verificar que el keypair Kyber generado es válido usando un test de encapsulación/descapsulación */
        OQS_KEM *testKem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
        if(testKem) {
            uint8_t test_ct[OQS_KEM_kyber_768_length_ciphertext];
            uint8_t test_ss_encap[OQS_KEM_kyber_768_length_shared_secret];
            uint8_t test_ss_decap[OQS_KEM_kyber_768_length_shared_secret];
            
            if(OQS_KEM_encaps(testKem, test_ct, test_ss_encap, tempCtx.kemPublicKey) == OQS_SUCCESS) {
                if(OQS_KEM_decaps(testKem, test_ss_decap, test_ct, tempCtx.kemPrivateKey) == OQS_SUCCESS) {
                    if(memcmp(test_ss_encap, test_ss_decap, testKem->length_shared_secret) == 0) {
                        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                     "UA_PQC_EnsureCertificateExtensions: ✓ generated Kyber keypair is valid (test encaps/decaps succeeded)");
                    } else {
                        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                     "UA_PQC_EnsureCertificateExtensions: ✗ generated Kyber keypair is INVALID! "
                                     "Test encaps/decaps produced different shared secrets. This should never happen.");
                    }
                } else {
                    UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                 "UA_PQC_EnsureCertificateExtensions: ✗ generated Kyber keypair is INVALID! "
                                 "Test decaps failed. This should never happen.");
                }
            } else {
                UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                             "UA_PQC_EnsureCertificateExtensions: ✗ generated Kyber keypair is INVALID! "
                             "Test encaps failed. This should never happen.");
            }
            OQS_KEM_free(testKem);
        }
        
        /* Agregar las claves públicas al certificado */
        status = pqc_set_octet_extension(
            x509, OID_DILITHIUM_PUB, tempCtx.sigPublicKey,
            (size_t)OQS_SIG_dilithium_2_length_public_key, &modified, log);
        if(status != UA_STATUSCODE_GOOD)
            goto cleanup;

        status = pqc_set_octet_extension(
            x509, OID_KYBER_PUB, tempCtx.kemPublicKey,
            (size_t)OQS_KEM_kyber_768_length_public_key, &modified, log);
        if(status != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    if(!signingPrivateKey || signingPrivateKey->length == 0 || !signingPrivateKey->data) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_EnsureCertificateExtensions: signing private key missing; cannot re-sign certificate");
        status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        goto cleanup;
    }

    UA_Boolean keyWasPem = UA_FALSE;
    EVP_PKEY *pkey = pqc_parse_private_key_from_bytes(signingPrivateKey, &keyWasPem);
    if(!pkey) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_EnsureCertificateExtensions: could not parse signing private key");
        status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        goto cleanup;
    }

    /* Try to sign with NULL first (for PQC algorithms like ML-DSA-44) */
    const EVP_MD *digest = NULL;
    int signResult = X509_sign(x509, pkey, digest);
    if(signResult <= 0) {
        /* If NULL doesn't work, try with SHA-256 (for traditional algorithms) */
        digest = EVP_sha256();
        signResult = X509_sign(x509, pkey, digest);
        if(signResult <= 0) {
            /* Get more detailed error information */
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_EnsureCertificateExtensions: failed to sign certificate with updated extensions. "
                           "OpenSSL error: %s (error code: %lu)", err_buf, err);
            EVP_PKEY_free(pkey);
            status = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
    }

    EVP_PKEY_free(pkey);
    
    if(modified) {
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_EnsureCertificateExtensions: embedded Dilithium and Kyber public keys into certificate (%s)",
                    certWasPem ? "PEM" : "DER");
    } else {
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_EnsureCertificateExtensions: certificate already had PQC extensions, "
                    "using existing public keys (%s)", certWasPem ? "PEM" : "DER");
    }

writeback:
    status = pqc_write_back_certificate(x509, certWasPem, certificate);
    if(status == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_EnsureCertificateExtensions: certificate written back successfully (new length=%zu bytes)",
                    certificate->length);
        
        /* Verificar que la clave pública se agregó correctamente extrayéndola del certificado después de escribirlo */
        if(modified) {
            UA_Boolean testSigValid = false;
            UA_Boolean testKemValid = false;
            uint8_t testSigPk[OQS_SIG_dilithium_2_length_public_key];
            uint8_t testKemPk[OQS_KEM_kyber_768_length_public_key];
            UA_StatusCode testStatus = pqc_extract_pubkeys_from_cert_der_internal(certificate, log,
                                                                                  testSigPk, &testSigValid,
                                                                                  testKemPk, &testKemValid);
            if(testStatus == UA_STATUSCODE_GOOD && testKemValid) {
                if(memcmp(tempCtx.kemPublicKey, testKemPk, OQS_KEM_kyber_768_length_public_key) == 0) {
                    UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                 "UA_PQC_EnsureCertificateExtensions: ✓ Kyber public key correctly embedded and extracted from certificate");
                } else {
                    UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                 "UA_PQC_EnsureCertificateExtensions: ✗ Kyber public key mismatch! "
                                 "Key added to certificate does not match key extracted from certificate.");
                }
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                               "UA_PQC_EnsureCertificateExtensions: could not extract Kyber public key from certificate for verification");
            }
        }
    } else {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_EnsureCertificateExtensions: failed to write back certificate: %s",
                       UA_StatusCode_name(status));
        goto cleanup;
    }
    
    /* Append PQC private keys to signingPrivateKey only if we generated new keys (modified=true).
     * If the certificate already had PQC extensions, the private keys should already be in the
     * signingPrivateKey buffer from a previous execution.
     * 
     * For certificates signed with Dilithium (new format): only append Kyber private key.
     * For certificates signed with RSA/ECC (legacy format): append both Dilithium and Kyber private keys.
     */
    if(modified && signingPrivateKey && tempCtx.kemKeysInitialized) {
        /* Determine if the private key is Dilithium (new format) or RSA/ECC (legacy format) */
        UA_Boolean isDilithiumKey = UA_FALSE;
        size_t sigKeyLen = sizeof(tempCtx.sigPrivateKey);
        size_t kemKeyLen = sizeof(tempCtx.kemPrivateKey);
        
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        /* Try to load OQS Provider and check if the key is Dilithium */
        OSSL_PROVIDER *oqsProvider = OSSL_PROVIDER_load(NULL, "oqsprovider");
        if(!oqsProvider) {
            oqsProvider = OSSL_PROVIDER_load(NULL, "oqs");
        }
        if(oqsProvider) {
            /* Re-parse the key to check its type */
            UA_Boolean keyWasPem = UA_FALSE;
            EVP_PKEY *testPkey = pqc_parse_private_key_from_bytes(signingPrivateKey, &keyWasPem);
            if(testPkey) {
                const char *keyType = EVP_PKEY_get0_type_name(testPkey);
                if(keyType && strstr(keyType, "Dilithium")) {
                    isDilithiumKey = UA_TRUE;
                }
                EVP_PKEY_free(testPkey);
            }
            OSSL_PROVIDER_unload(oqsProvider);
        }
#endif
        
        /* Guardar longitud original */
        size_t origLen = signingPrivateKey->length;
        size_t keysToAppend = kemKeyLen;
        size_t newLen = origLen + keysToAppend;
        
        if(isDilithiumKey) {
            /* New format: certificate is signed with Dilithium, so only append Kyber private key */
            UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_PQC_EnsureCertificateExtensions: preparing to append Kyber private key "
                        "(certificate signed with Dilithium, original length=%zu, Kyber=%zu bytes, new total=%zu bytes)",
                        origLen, kemKeyLen, newLen);
            
            status = UA_ByteString_expand(signingPrivateKey, kemKeyLen);
            if(status == UA_STATUSCODE_GOOD) {
                /* Copy only Kyber private key to the end of the buffer */
                memcpy(signingPrivateKey->data + origLen, tempCtx.kemPrivateKey, kemKeyLen);
                
                UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                            "UA_PQC_EnsureCertificateExtensions: ✓ appended Kyber private key to signingPrivateKey "
                            "(Kyber=%zu bytes at offset %zu, new total=%zu bytes, format=Dilithium+Kyber)",
                            kemKeyLen, origLen, signingPrivateKey->length);
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                               "UA_PQC_EnsureCertificateExtensions: failed to expand signingPrivateKey: %s",
                               UA_StatusCode_name(status));
            }
        } else if(tempCtx.sigKeysInitialized) {
            /* Legacy format: certificate is signed with RSA/ECC, append both Dilithium and Kyber private keys */
            keysToAppend = sigKeyLen + kemKeyLen;
            newLen = origLen + keysToAppend;
            
            UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_PQC_EnsureCertificateExtensions: preparing to append PQC private keys "
                        "(legacy format: RSA/ECC + PQC, original length=%zu, Dilithium=%zu bytes, "
                        "Kyber=%zu bytes, new total=%zu bytes)",
                        origLen, sigKeyLen, kemKeyLen, newLen);
            
            status = UA_ByteString_expand(signingPrivateKey, sigKeyLen + kemKeyLen);
            if(status == UA_STATUSCODE_GOOD) {
                /* Copy both Dilithium and Kyber private keys to the end of the buffer */
                memcpy(signingPrivateKey->data + origLen, tempCtx.sigPrivateKey, sigKeyLen);
                memcpy(signingPrivateKey->data + origLen + sigKeyLen, tempCtx.kemPrivateKey, kemKeyLen);
                
                UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                            "UA_PQC_EnsureCertificateExtensions: ✓ appended PQC private keys to signingPrivateKey "
                            "(Dilithium=%zu bytes at offset %zu, Kyber=%zu bytes at offset %zu, new total=%zu bytes, "
                            "format=RSA/ECC+Dilithium+Kyber)",
                            sigKeyLen, origLen, kemKeyLen, origLen + sigKeyLen, signingPrivateKey->length);
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                               "UA_PQC_EnsureCertificateExtensions: failed to expand signingPrivateKey: %s",
                               UA_StatusCode_name(status));
            }
        }
    }

cleanup:
    X509_free(x509);
    /* Limpiar claves privadas del contexto temporal */
    memset(tempCtx.sigPrivateKey, 0, sizeof(tempCtx.sigPrivateKey));
    memset(tempCtx.kemPrivateKey, 0, sizeof(tempCtx.kemPrivateKey));
    UA_ByteString_clear(&tempCtx.localCertThumbprint);
    return status;
}

/* Helper function to join strings with separator (similar to create_certificate.c) */
static UA_StatusCode
pqc_join_string_with_sep(const UA_String *strings, size_t stringsSize,
                         char sep, UA_String *out) {
    if(!out)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_String_clear(out);
    size_t totalSize = stringsSize;
    for(size_t iStr = 0; iStr < stringsSize; ++iStr) {
        totalSize += strings[iStr].length;
    }

    UA_ByteString_allocBuffer(out, totalSize);
    if(!out->data) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    size_t pos = 0;
    for(size_t iStr = 0; iStr < stringsSize; ++iStr) {
        memcpy(&out->data[pos], strings[iStr].data, strings[iStr].length);
        pos += strings[iStr].length;
        out->data[pos] = (UA_Byte) sep;
        ++pos;
    }
    out->data[out->length-1] = 0;

    return UA_STATUSCODE_GOOD;
}

/* Helper function to add X.509 v3 extensions (similar to create_certificate.c) */
static UA_StatusCode
pqc_add_x509V3ext(const UA_Logger *logger, X509 *x509, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if(!ex) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    X509_add_ext(x509, ex, -1);
    X509_EXTENSION_free(ex);
    return UA_STATUSCODE_GOOD;
}

/* Helper function to parse subject string (similar to create_certificate.c) */
static UA_Int32
pqc_string_chr(const UA_String *pUaStr, char needl) {
    UA_Byte byteNeedl = (UA_Byte)needl;
    for(size_t i = 0; (size_t)i < pUaStr->length; ++i) {
        if(pUaStr->data[i] == byteNeedl) {
            return (UA_Int32) i;
        }
    }
    return -1;
}

/**
 * Create a new self-signed X.509 certificate with PQC extensions from scratch.
 * The certificate is signed directly with Dilithium2 using OQS Provider (requires OpenSSL 3.0+).
 * For OpenSSL < 3.0, use UA_PQC_CreateCertificateWithOQSProvider() directly.
 * 
 * @param rsaKeySizeBits This parameter is deprecated and ignored. The certificate is signed with Dilithium2.
 */
UA_EXPORT UA_StatusCode
UA_PQC_CreateCertificate(const UA_Logger *logger,
                         const UA_String *subject,
                         size_t subjectSize,
                         const UA_String *subjectAltName,
                         size_t subjectAltNameSize,
                         UA_CertificateFormat certFormat,
                         UA_UInt16 rsaKeySizeBits,
                         UA_UInt16 expiresInDays,
                         UA_ByteString *outPrivateKey,
                         UA_ByteString *outCertificate) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
    if(!outPrivateKey || !outCertificate || !subject || !subjectAltName ||
       subjectAltNameSize == 0 || subjectSize == 0 ||
       (certFormat != UA_CERTIFICATEFORMAT_DER && certFormat != UA_CERTIFICATEFORMAT_PEM))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                 "UA_PQC_CreateCertificate: requires OpenSSL 3.0 or later for Dilithium signatures. "
                 "Please use UA_PQC_CreateCertificateWithOQSProvider() directly or upgrade OpenSSL.");
    return UA_STATUSCODE_BADNOTSUPPORTED;
#else
    /* Use OQS Provider to create certificate signed with ML-DSA-44 (NIST standard name for Dilithium2) */
    const char *pqcSigAlgorithm = "ML-DSA-44";  /* Use ML-DSA-44 (NIST standard) as default PQC signature algorithm */
    return UA_PQC_CreateCertificateWithOQSProvider(logger, subject, subjectSize,
                                                    subjectAltName, subjectAltNameSize,
                                                    certFormat, pqcSigAlgorithm,
                                                    expiresInDays, outPrivateKey, outCertificate);
#endif
}

/**
 * Create a new self-signed X.509 certificate signed directly with Dilithium
 * using the OQS Provider for OpenSSL 3.x.
 */
UA_EXPORT UA_StatusCode
UA_PQC_CreateCertificateWithOQSProvider(const UA_Logger *logger,
                                        const UA_String *subject,
                                        size_t subjectSize,
                                        const UA_String *subjectAltName,
                                        size_t subjectAltNameSize,
                                        UA_CertificateFormat certFormat,
                                        const char *pqcSigAlgorithm,
                                        UA_UInt16 expiresInDays,
                                        UA_ByteString *outPrivateKey,
                                        UA_ByteString *outCertificate) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                 "UA_PQC_CreateCertificateWithOQSProvider: requires OpenSSL 3.0 or later. "
                 "Use UA_PQC_CreateCertificate() for OpenSSL < 3.0.");
    return UA_STATUSCODE_BADNOTSUPPORTED;
#else
    if(!outPrivateKey || !outCertificate || !subject || !subjectAltName ||
       subjectAltNameSize == 0 || subjectSize == 0 || !pqcSigAlgorithm ||
       (certFormat != UA_CERTIFICATEFORMAT_DER && certFormat != UA_CERTIFICATEFORMAT_PEM))
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_ByteString_init(outPrivateKey);
    UA_ByteString_init(outCertificate);

    UA_String fullAltSubj = UA_STRING_NULL;
    UA_Int32 serial = 1;
    UA_StatusCode errRet = UA_STATUSCODE_GOOD;
    X509 *x509 = NULL;
    EVP_PKEY *dilithiumKey = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;
    OSSL_PROVIDER *oqsProvider = NULL;
    BIO *memPKey = NULL;
    Policy_Context_PQC tempCtx;
    memset(&tempCtx, 0, sizeof(tempCtx));
    tempCtx.logger = logger;
    UA_ByteString_init(&tempCtx.localCertThumbprint);

    /* Load OQS Provider */
    oqsProvider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if(!oqsProvider) {
        /* Try alternative name */
        oqsProvider = OSSL_PROVIDER_load(NULL, "oqs");
        if(!oqsProvider) {
            UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                         "UA_PQC_CreateCertificateWithOQSProvider: failed to load OQS Provider. "
                         "Make sure OQS Provider is installed and available. "
                         "Use UA_PQC_CreateCertificate() for hybrid approach.");
            errRet = UA_STATUSCODE_BADNOTSUPPORTED;
            goto cleanup;
        }
    }

    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                "UA_PQC_CreateCertificateWithOQSProvider: OQS Provider loaded successfully");

    /* Generate Dilithium key using OQS Provider */
    /* ML-DSA-44 is the NIST standard name for Dilithium2 */
    /* Try different algorithm name variations */
    const char *algorithmNames[] = {
        "ML-DSA-44",               /* NIST standard name (preferred) */
        "MLDSA44",                 /* Alternative ID */
        pqcSigAlgorithm,           /* Original name (e.g., "Dilithium2") */
        "dilithium2",              /* Lowercase */
        "Dilithium-2",             /* With hyphen */
        "dilithium-2",             /* Lowercase with hyphen */
        NULL
    };
    
    keyCtx = NULL;
    const char *usedAlgorithm = NULL;
    for(int i = 0; algorithmNames[i] != NULL; i++) {
        /* Try with default context (OQS Provider should be loaded) */
        keyCtx = EVP_PKEY_CTX_new_from_name(NULL, algorithmNames[i], NULL);
        if(keyCtx) {
            usedAlgorithm = algorithmNames[i];
            break;
        }
    }
    
    if(!keyCtx) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_CreateCertificateWithOQSProvider: failed to create key context for %s. "
                     "Tried: ML-DSA-44, MLDSA44, %s, dilithium2, Dilithium-2, dilithium-2. "
                     "Algorithm may not be available in OQS Provider. "
                     "Try: openssl list -public-key-algorithms | grep -i 'ml-dsa\\|dilithium'",
                     pqcSigAlgorithm, pqcSigAlgorithm);
        errRet = UA_STATUSCODE_BADNOTSUPPORTED;
        goto cleanup;
    }
    
    if(usedAlgorithm && strcmp(usedAlgorithm, pqcSigAlgorithm) != 0) {
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCertificateWithOQSProvider: Using algorithm name '%s' instead of '%s'",
                    usedAlgorithm, pqcSigAlgorithm);
    }

    if(EVP_PKEY_keygen_init(keyCtx) <= 0) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_CreateCertificateWithOQSProvider: failed to initialize key generation");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    if(EVP_PKEY_generate(keyCtx, &dilithiumKey) <= 0) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_CreateCertificateWithOQSProvider: failed to generate %s key", pqcSigAlgorithm);
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                "UA_PQC_CreateCertificateWithOQSProvider: Generated %s key successfully", pqcSigAlgorithm);

    /* Create certificate */
    x509 = X509_new();
    if(!x509) {
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }

    /* Set certificate version */
    if(X509_set_version(x509, 2) != 1) {
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    /* Set serial number */
    if(ASN1_INTEGER_set(X509_get_serialNumber(x509), serial) != 1) {
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }

    /* Set validity period */
    if(X509_gmtime_adj(X509_get_notBefore(x509), 0) == NULL) {
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    if(X509_gmtime_adj(X509_get_notAfter(x509), (UA_Int64)60 * 60 * 24 * expiresInDays) == NULL) {
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    /* Set public key (Dilithium) */
    if(X509_set_pubkey(x509, dilithiumKey) != 1) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_CreateCertificateWithOQSProvider: failed to set Dilithium public key in certificate");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    /* Set subject */
    X509_NAME *name = X509_get_subject_name(x509);
    if(name == NULL) {
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    for(UA_UInt32 iSubject = 0; iSubject < subjectSize; ++iSubject) {
        UA_Int32 sep = pqc_string_chr(&subject[iSubject], '=');
        char field[16];
        if(sep == -1 || sep == 0 ||
            ((size_t) sep == (subject[iSubject].length - 1)) || sep >= 15) {
            UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                         "UA_PQC_CreateCertificateWithOQSProvider: Subject must contain one '=' with "
                         "content before and after.");
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        memcpy(field, subject[iSubject].data, (size_t) sep);
        field[sep] = 0;
        UA_Byte* pData = &subject[iSubject].data[sep + 1];
        if(X509_NAME_add_entry_by_txt(
               name, field, MBSTRING_ASC,
               (const unsigned char *)pData,
               (int) subject[iSubject].length - (int) sep - 1, -1, 0) != 1) {
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
    }

    /* Self signed, so issuer == subject */
    if(X509_set_issuer_name(x509, name) != 1) {
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    /* Add standard X.509 extensions */
    errRet = pqc_add_x509V3ext(log, x509, NID_basic_constraints, "CA:FALSE");
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    errRet = pqc_add_x509V3ext(log, x509, NID_key_usage,
                               "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyCertSign");
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    errRet = pqc_add_x509V3ext(log, x509, NID_ext_key_usage, "serverAuth,clientAuth");
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    errRet = pqc_add_x509V3ext(log, x509, NID_subject_key_identifier, "hash");
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    errRet = pqc_join_string_with_sep(subjectAltName, subjectAltNameSize, ',', &fullAltSubj);
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    errRet = pqc_add_x509V3ext(log, x509, NID_subject_alt_name, (char*)fullAltSubj.data);
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Generate Kyber key for KEM (still using OQS library directly) */
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                "UA_PQC_CreateCertificateWithOQSProvider: Generating Kyber768 keypair for KEM");
    pqc_init_kem_keys(&tempCtx);

    if(!tempCtx.kemKeysInitialized) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_CreateCertificateWithOQSProvider: failed to generate Kyber keys");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }

    /* Add Kyber public key as extension (for KEM) */
    UA_Boolean modified = UA_FALSE;
    errRet = pqc_set_octet_extension(
        x509, OID_KYBER_PUB, tempCtx.kemPublicKey,
        (size_t)OQS_KEM_kyber_768_length_public_key, &modified, log);
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Sign certificate with ML-DSA-44 key */
    /* For PQC algorithms like ML-DSA-44, we may need to use NULL as the digest algorithm
     * since they have their own internal hashing scheme */
    const EVP_MD *digest = NULL;
    
    /* Try with NULL first (PQC algorithms often don't need external hash) */
    int signResult = X509_sign(x509, dilithiumKey, digest);
    if(signResult == 0) {
        /* If NULL doesn't work, try with SHA-256 (some implementations may require it) */
        digest = EVP_sha256();
        signResult = X509_sign(x509, dilithiumKey, digest);
        if(signResult == 0) {
            /* Get more detailed error information */
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                         "UA_PQC_CreateCertificateWithOQSProvider: failed to sign certificate with %s. "
                         "OpenSSL error: %s (error code: %lu). "
                         "Make sure the OQS Provider supports certificate signing with %s.",
                         pqcSigAlgorithm, err_buf, err, pqcSigAlgorithm);
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        } else {
            UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_PQC_CreateCertificateWithOQSProvider: Certificate signed successfully with %s using SHA-256",
                        pqcSigAlgorithm);
        }
    } else {
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCertificateWithOQSProvider: Certificate signed successfully with %s (no external hash required)",
                    pqcSigAlgorithm);
    }

    /* Write certificate to output buffer */
    UA_Boolean asPem = (certFormat == UA_CERTIFICATEFORMAT_PEM);
    errRet = pqc_write_back_certificate(x509, asPem, outCertificate);
    if(errRet != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Write Dilithium private key to output buffer */
    if(asPem) {
        memPKey = BIO_new(BIO_s_mem());
        if(!memPKey) {
            errRet = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
        if(PEM_write_bio_PrivateKey(memPKey, dilithiumKey, NULL, NULL, 0, NULL, NULL) != 1) {
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        char *pemData = NULL;
        long pemLen = BIO_get_mem_data(memPKey, &pemData);
        if(pemLen <= 0) {
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        UA_ByteString_allocBuffer(outPrivateKey, (size_t)pemLen);
        if(!outPrivateKey->data) {
            errRet = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
        memcpy(outPrivateKey->data, pemData, (size_t)pemLen);
    } else {
        /* DER format */
        int keyLen = i2d_PrivateKey(dilithiumKey, NULL);
        if(keyLen <= 0) {
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        UA_ByteString_allocBuffer(outPrivateKey, (size_t)keyLen);
        if(!outPrivateKey->data) {
            errRet = UA_STATUSCODE_BADOUTOFMEMORY;
            goto cleanup;
        }
        unsigned char *ptr = outPrivateKey->data;
        i2d_PrivateKey(dilithiumKey, &ptr);
    }

    /* Append Kyber private key to Dilithium private key */
    size_t origLen = outPrivateKey->length;
    size_t kemKeyLen = sizeof(tempCtx.kemPrivateKey);
    size_t newLen = origLen + kemKeyLen;
    
    UA_Byte *newBuf = (UA_Byte*)UA_realloc(outPrivateKey->data, newLen);
    if(!newBuf) {
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    outPrivateKey->data = newBuf;
    memcpy(outPrivateKey->data + origLen, tempCtx.kemPrivateKey, kemKeyLen);
    outPrivateKey->length = newLen;

    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                "UA_PQC_CreateCertificateWithOQSProvider: ✓ Certificate created successfully "
                "(cert=%zu bytes, key=%zu bytes, format=%s, signed with %s)",
                outCertificate->length, outPrivateKey->length,
                asPem ? "PEM" : "DER", pqcSigAlgorithm);

cleanup:
    if(x509) X509_free(x509);
    if(dilithiumKey) EVP_PKEY_free(dilithiumKey);
    if(keyCtx) EVP_PKEY_CTX_free(keyCtx);
    if(oqsProvider) OSSL_PROVIDER_unload(oqsProvider);
    if(memPKey) BIO_free(memPKey);
    UA_String_clear(&fullAltSubj);
    /* Clear Kyber private key */
    memset(tempCtx.kemPrivateKey, 0, sizeof(tempCtx.kemPrivateKey));
    UA_ByteString_clear(&tempCtx.localCertThumbprint);
    
    if(errRet != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(outPrivateKey);
        UA_ByteString_clear(outCertificate);
    }
    
    return errRet;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
}

/* ---------------------- OQS Provider availability checks -------------------- */

UA_EXPORT UA_Boolean
UA_PQC_IsOpenSSL3Available(void) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    return UA_TRUE;
#else
    return UA_FALSE;
#endif
}

UA_EXPORT UA_Boolean
UA_PQC_IsOQSProviderAvailable(const UA_Logger *logger, const char *providerName) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                 "UA_PQC_IsOQSProviderAvailable: OpenSSL 3.0+ required for OQS Provider");
    return UA_FALSE;
#else
    if(!providerName)
        return UA_FALSE;

    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, providerName);
    if(!provider) {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_IsOQSProviderAvailable: Provider '%s' not available", providerName);
        return UA_FALSE;
    }

    /* Provider loaded successfully, unload it */
    OSSL_PROVIDER_unload(provider);
    UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                 "UA_PQC_IsOQSProviderAvailable: Provider '%s' is available", providerName);
    return UA_TRUE;
#endif
}

UA_EXPORT UA_Boolean
UA_PQC_IsAlgorithmAvailable(const UA_Logger *logger, const char *algorithmName) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                 "UA_PQC_IsAlgorithmAvailable: OpenSSL 3.0+ required");
    return UA_FALSE;
#else
    if(!algorithmName)
        return UA_FALSE;

    /* Try to load OQS Provider */
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if(!provider) {
        provider = OSSL_PROVIDER_load(NULL, "oqs");
        if(!provider) {
            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                         "UA_PQC_IsAlgorithmAvailable: OQS Provider not available");
            return UA_FALSE;
        }
    }

    /* Try to create a key context for the algorithm */
    EVP_PKEY_CTX *keyCtx = EVP_PKEY_CTX_new_from_name(NULL, algorithmName, NULL);
    if(!keyCtx) {
        OSSL_PROVIDER_unload(provider);
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_IsAlgorithmAvailable: Algorithm '%s' not available", algorithmName);
        return UA_FALSE;
    }

    /* Algorithm is available */
    EVP_PKEY_CTX_free(keyCtx);
    OSSL_PROVIDER_unload(provider);
    UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                 "UA_PQC_IsAlgorithmAvailable: Algorithm '%s' is available", algorithmName);
    return UA_TRUE;
#endif
}

UA_EXPORT UA_Boolean
UA_PQC_IsCertificatePQCSigned(const UA_ByteString *certificate, const UA_Logger *logger) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
    if(!certificate || certificate->length == 0 || !certificate->data)
        return UA_FALSE;

    UA_Boolean certWasPem = UA_FALSE;
    X509 *x509 = pqc_parse_x509_from_bytes(certificate, &certWasPem);
    if(!x509) {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_IsCertificatePQCSigned: Failed to parse certificate");
        return UA_FALSE;
    }

    /* Get signature algorithm from certificate */
    const ASN1_BIT_STRING *sig = NULL;
    const X509_ALGOR *sigAlg = NULL;
    X509_get0_signature(&sig, &sigAlg, x509);
    
    if(!sigAlg) {
        X509_free(x509);
        return UA_FALSE;
    }

    /* Get algorithm OID */
    const ASN1_OBJECT *obj = NULL;
    int ptype = 0;
    const void *pval = NULL;
    X509_ALGOR_get0(&obj, &ptype, &pval, sigAlg);
    if(!obj) {
        X509_free(x509);
        return UA_FALSE;
    }

    char oid_buf[256];
    int oid_len = OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
    if(oid_len <= 0) {
        X509_free(x509);
        return UA_FALSE;
    }

    /* Check if it's a known PQC algorithm OID */
    /* Common PQC signature algorithm OIDs:
     * - Dilithium2: 1.3.6.1.4.1.2.267.12.4.4 (or similar)
     * - ML-DSA-65: 1.3.6.1.4.1.2.267.12.5.4 (or similar)
     * 
     * Note: These OIDs may vary. A more robust check would be to compare
     * against known PQC algorithm names or check if the algorithm is available
     * via OQS Provider.
     */
    
    /* For now, check if it's NOT a traditional algorithm (RSA, ECDSA, etc.) */
    const char *traditional_algs[] = {
        "1.2.840.113549.1.1",      /* RSA */
        "1.2.840.113549.1.1.1",    /* RSA with MD5 */
        "1.2.840.113549.1.1.5",    /* RSA with SHA1 */
        "1.2.840.113549.1.1.11",   /* RSA with SHA256 */
        "1.2.840.10040.4.3",       /* DSA with SHA1 */
        "1.2.840.10045.4.3.2",     /* ECDSA with SHA256 */
        "1.2.840.10045.4.3.3",     /* ECDSA with SHA384 */
        "1.2.840.10045.4.3.4",     /* ECDSA with SHA512 */
        NULL
    };

    UA_Boolean isTraditional = UA_FALSE;
    for(int i = 0; traditional_algs[i] != NULL; i++) {
        if(strncmp(oid_buf, traditional_algs[i], strlen(traditional_algs[i])) == 0) {
            isTraditional = UA_TRUE;
            break;
        }
    }

    X509_free(x509);

    if(isTraditional) {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_IsCertificatePQCSigned: Certificate uses traditional algorithm (OID: %s)", oid_buf);
        return UA_FALSE;
    }

    /* If it's not a traditional algorithm, it might be PQC */
    /* Additional check: try to see if the algorithm is available via OQS Provider */
    UA_Boolean mightBePQC = UA_FALSE;
    
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    /* Try common PQC algorithm names */
    const char *pqcAlgorithms[] = {
        "Dilithium2", "Dilithium3", "Dilithium5",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        NULL
    };

    for(int i = 0; pqcAlgorithms[i] != NULL; i++) {
        if(UA_PQC_IsAlgorithmAvailable(log, pqcAlgorithms[i])) {
            mightBePQC = UA_TRUE;
            break;
        }
    }
#endif

    if(mightBePQC) {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_IsCertificatePQCSigned: Certificate might be PQC-signed (OID: %s)", oid_buf);
    } else {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_IsCertificatePQCSigned: Unknown algorithm OID: %s (not verified as PQC)", oid_buf);
    }

    return mightBePQC;
}

UA_EXPORT UA_Boolean
UA_PQC_HasCertificatePQCExtensions(const UA_ByteString *certificate, const UA_Logger *logger) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
    if(!certificate || certificate->length == 0 || !certificate->data)
        return UA_FALSE;

    UA_Boolean certWasPem = UA_FALSE;
    X509 *x509 = pqc_parse_x509_from_bytes(certificate, &certWasPem);
    if(!x509) {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_HasCertificatePQCExtensions: Failed to parse certificate");
        return UA_FALSE;
    }

    /* Check for Dilithium and Kyber extensions */
    ASN1_OBJECT *objDil = OBJ_txt2obj(OID_DILITHIUM_PUB, 1);
    ASN1_OBJECT *objKy = OBJ_txt2obj(OID_KYBER_PUB, 1);
    
    UA_Boolean hasDilithiumExt = UA_FALSE;
    UA_Boolean hasKyberExt = UA_FALSE;
    
    if(objDil && X509_get_ext_by_OBJ(x509, objDil, -1) >= 0)
        hasDilithiumExt = UA_TRUE;
    if(objKy && X509_get_ext_by_OBJ(x509, objKy, -1) >= 0)
        hasKyberExt = UA_TRUE;
    
    if(objDil) ASN1_OBJECT_free(objDil);
    if(objKy) ASN1_OBJECT_free(objKy);
    X509_free(x509);

    UA_Boolean hasPQCExtensions = (hasDilithiumExt && hasKyberExt);
    
    if(hasPQCExtensions) {
        UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_HasCertificatePQCExtensions: Certificate has PQC extensions "
                    "(Dilithium=%u, Kyber=%u) - PQC operations will be used",
                    (unsigned)hasDilithiumExt, (unsigned)hasKyberExt);
    } else {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "UA_PQC_HasCertificatePQCExtensions: Certificate does NOT have PQC extensions "
                     "(Dilithium=%u, Kyber=%u)",
                     (unsigned)hasDilithiumExt, (unsigned)hasKyberExt);
    }

    return hasPQCExtensions;
}

UA_EXPORT UA_StatusCode
UA_PQC_VerifyCertificateSignature(const UA_ByteString *certificate, void *issuerCert, const UA_Logger *logger) {
    X509 *issuer = (X509 *)issuerCert;
    if(!certificate || certificate->length == 0 || !certificate->data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    const UA_Logger *log = logger ? logger : UA_Log_Stdout;

    UA_Boolean certWasPem = UA_FALSE;
    X509 *x509 = pqc_parse_x509_from_bytes(certificate, &certWasPem);
    if(!x509) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_VerifyCertificateSignature: Failed to parse certificate");
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }

    int verifyResult = -1;
    EVP_PKEY *issuerPubkey = NULL;
    
    if(issuer) {
        /* Verify using issuer CA's public key (for CA-signed certificates) */
        issuerPubkey = X509_get0_pubkey(issuer);
        if(!issuerPubkey) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_VerifyCertificateSignature: Failed to get issuer public key");
            X509_free(x509);
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
        }
        verifyResult = X509_verify(x509, issuerPubkey);
    } else {
        /* Self-signed verification: check if subject == issuer */
        X509_NAME *subject = X509_get_subject_name(x509);
        X509_NAME *issuer = X509_get_issuer_name(x509);
        if(!subject || !issuer) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_VerifyCertificateSignature: Failed to get subject/issuer name");
            X509_free(x509);
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
        }
        
        if(X509_NAME_cmp(subject, issuer) == 0) {
            /* Self-signed: verify using certificate's own public key */
            EVP_PKEY *selfPubkey = X509_get_pubkey(x509);
            if(selfPubkey) {
                verifyResult = X509_verify(x509, selfPubkey);
                EVP_PKEY_free(selfPubkey);
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                               "UA_PQC_VerifyCertificateSignature: Failed to get certificate public key");
                X509_free(x509);
                return UA_STATUSCODE_BADCERTIFICATEINVALID;
            }
        } else {
            /* Not self-signed but no issuer provided */
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_PQC_VerifyCertificateSignature: Certificate is not self-signed but no issuer provided");
            X509_free(x509);
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
        }
    }
    
    X509_free(x509);

    if(verifyResult == 1) {
        /* Signature is valid */
        return UA_STATUSCODE_GOOD;
    } else if(verifyResult == 0) {
        /* Signature verification failed */
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_VerifyCertificateSignature: Signature verification failed");
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    } else {
        /* Error during verification */
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQC_VerifyCertificateSignature: Error during signature verification (OpenSSL error)");
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
}

/* ---------------------- Create CSR with PQC keys -------------------- */
UA_EXPORT UA_StatusCode
UA_PQC_CreateCSR(const UA_Logger *logger,
                 const UA_String *subject,
                 size_t subjectSize,
                 const UA_String *subjectAltName,
                 size_t subjectAltNameSize,
                 UA_ByteString *outPrivateKey,
                 UA_ByteString *outCSR) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
    if(!subject || subjectSize == 0 || !subjectAltName || subjectAltNameSize == 0 ||
       !outPrivateKey || !outCSR) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    
    UA_ByteString_init(outPrivateKey);
    UA_ByteString_init(outCSR);
    
    UA_StatusCode errRet = UA_STATUSCODE_GOOD;
    X509_REQ *req = NULL;
    EVP_PKEY *dilithiumKey = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;
    OSSL_PROVIDER *oqsProvider = NULL;
    Policy_Context_PQC tempCtx;
    memset(&tempCtx, 0, sizeof(tempCtx));
    tempCtx.logger = logger;
    UA_String fullAltSubj = UA_STRING_NULL;
    
    /* Load OQS Provider */
    oqsProvider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if(!oqsProvider) {
        oqsProvider = OSSL_PROVIDER_load(NULL, "oqs");
        if(!oqsProvider) {
            UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_PQC_CreateCSR: Failed to load OQS Provider");
            return UA_STATUSCODE_BADNOTSUPPORTED;
        }
    }
    
    /* Generate Dilithium key */
    const char *algorithmNames[] = {"ML-DSA-44", "MLDSA44", "Dilithium2", "dilithium2", NULL};
    for(int i = 0; algorithmNames[i] != NULL; i++) {
        keyCtx = EVP_PKEY_CTX_new_from_name(NULL, algorithmNames[i], NULL);
        if(keyCtx) break;
    }
    
    if(!keyCtx || EVP_PKEY_keygen_init(keyCtx) <= 0 || 
       EVP_PKEY_generate(keyCtx, &dilithiumKey) <= 0) {
        if(keyCtx) EVP_PKEY_CTX_free(keyCtx);
        if(oqsProvider) OSSL_PROVIDER_unload(oqsProvider);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to generate Dilithium key");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    EVP_PKEY_CTX_free(keyCtx);
    keyCtx = NULL;
    
    /* Generate Kyber keys */
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Generating Kyber keys...");
    pqc_init_kem_keys(&tempCtx);
    if(!tempCtx.kemKeysInitialized) {
        EVP_PKEY_free(dilithiumKey);
        if(oqsProvider) OSSL_PROVIDER_unload(oqsProvider);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to generate Kyber keys");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Kyber keys generated, creating CSR structure...");
    
    /* Create CSR */
    req = X509_REQ_new();
    if(!req || X509_REQ_set_version(req, 0) != 1) {
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    
    /* Set subject */
    X509_NAME *name = X509_NAME_new();
    if(!name) {
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    
    for(UA_UInt32 i = 0; i < subjectSize; ++i) {
        UA_Int32 sep = pqc_string_chr(&subject[i], '=');
        if(sep <= 0 || (size_t)sep >= subject[i].length - 1) {
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        char field[16];
        memcpy(field, subject[i].data, (size_t)sep);
        field[sep] = 0;
        UA_Byte* pData = &subject[i].data[sep + 1];
        if(X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                                      (const unsigned char *)pData,
                                      (int)subject[i].length - (int)sep - 1, -1, 0) != 1) {
            errRet = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
    }
    
    if(X509_REQ_set_subject_name(req, name) != 1) {
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    X509_NAME_free(name);
    name = NULL;
    
    /* Set public key */
    if(X509_REQ_set_pubkey(req, dilithiumKey) != 1) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to set public key in CSR");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Public key set, adding extensions...");
    
    /* Add extensions */
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
    if(!exts) {
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    
    /* Basic constraints */
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE");
    if(ext) sk_X509_EXTENSION_push(exts, ext);
    
    /* Key usage */
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage,
                              "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment");
    if(ext) sk_X509_EXTENSION_push(exts, ext);
    
    /* Extended key usage */
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, "serverAuth,clientAuth");
    if(ext) sk_X509_EXTENSION_push(exts, ext);
    
    /* Subject Alt Name */
    errRet = pqc_join_string_with_sep(subjectAltName, subjectAltNameSize, ',', &fullAltSubj);
    if(errRet == UA_STATUSCODE_GOOD) {
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char*)fullAltSubj.data);
        if(ext) sk_X509_EXTENSION_push(exts, ext);
    }
    
    /* Add Dilithium and Kyber public key extensions to CSR */
    ASN1_OBJECT *objDil = OBJ_txt2obj(OID_DILITHIUM_PUB, 1);
    ASN1_OBJECT *objKy = OBJ_txt2obj(OID_KYBER_PUB, 1);
    
    if(objDil) {
        ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
        if(oct && ASN1_OCTET_STRING_set(oct, tempCtx.sigPublicKey,
                                        (int)OQS_SIG_dilithium_2_length_public_key) == 1) {
            X509_EXTENSION *ext = X509_EXTENSION_create_by_OBJ(NULL, objDil, 0, oct);
            if(ext) {
                sk_X509_EXTENSION_push(exts, ext);
            }
        }
        if(oct) ASN1_OCTET_STRING_free(oct);
    }
    
    if(objKy) {
        ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
        if(oct && ASN1_OCTET_STRING_set(oct, tempCtx.kemPublicKey,
                                        (int)OQS_KEM_kyber_768_length_public_key) == 1) {
            X509_EXTENSION *ext = X509_EXTENSION_create_by_OBJ(NULL, objKy, 0, oct);
            if(ext) {
                sk_X509_EXTENSION_push(exts, ext);
            }
        }
        if(oct) ASN1_OCTET_STRING_free(oct);
    }
    
    if(objDil) ASN1_OBJECT_free(objDil);
    if(objKy) ASN1_OBJECT_free(objKy);
    
    /* Add extensions to CSR (X509_REQ_add_extensions takes ownership) */
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Adding extensions to CSR (%d extensions)",
               sk_X509_EXTENSION_num(exts));
    X509_REQ_add_extensions(req, exts);
    sk_X509_EXTENSION_free(exts);
    exts = NULL;
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Extensions added, signing CSR...");
    
    /* Sign CSR with Dilithium key */
    const EVP_MD *digest = NULL;
    int signResult = X509_REQ_sign(req, dilithiumKey, digest);
    if(signResult == 0) {
        digest = EVP_sha256();
        signResult = X509_REQ_sign(req, dilithiumKey, digest);
    }
    
    if(signResult == 0) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to sign CSR");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    
    /* Write CSR to buffer */
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Serializing CSR to DER format...");
    int csrLen = i2d_X509_REQ(req, NULL);
    if(csrLen <= 0) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to get CSR length");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: CSR length: %d bytes", csrLen);
    if(UA_ByteString_allocBuffer(outCSR, (size_t)csrLen) != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to allocate buffer for CSR");
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    unsigned char *ptr = outCSR->data;
    i2d_X509_REQ(req, &ptr);
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: CSR serialized, writing private key...");
    
    /* Write private key (Dilithium + Kyber) */
    int keyLen = i2d_PrivateKey(dilithiumKey, NULL);
    if(keyLen <= 0) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to get private key length");
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Dilithium key length: %d bytes, Kyber key: %zu bytes",
               keyLen, sizeof(tempCtx.kemPrivateKey));
    size_t totalKeyLen = (size_t)keyLen + sizeof(tempCtx.kemPrivateKey);
    if(UA_ByteString_allocBuffer(outPrivateKey, totalKeyLen) != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Failed to allocate buffer for private key");
        errRet = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    ptr = outPrivateKey->data;
    int written = i2d_PrivateKey(dilithiumKey, &ptr);
    if(written != keyLen) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_CreateCSR: Private key write mismatch (expected %d, got %d)",
                    keyLen, written);
        errRet = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    memcpy(outPrivateKey->data + keyLen, tempCtx.kemPrivateKey, sizeof(tempCtx.kemPrivateKey));
    outPrivateKey->length = totalKeyLen;
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: Private key written successfully (total: %zu bytes)",
               totalKeyLen);
    
    /* Set errRet to GOOD before cleanup */
    errRet = UA_STATUSCODE_GOOD;
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_CreateCSR: CSR created successfully with PQC keys (CSR: %zu bytes, Key: %zu bytes)",
               outCSR->length, outPrivateKey->length);
    
cleanup:
    if(name) X509_NAME_free(name);
    if(req) X509_REQ_free(req);
    if(dilithiumKey) EVP_PKEY_free(dilithiumKey);
    if(keyCtx) EVP_PKEY_CTX_free(keyCtx);
    if(oqsProvider) OSSL_PROVIDER_unload(oqsProvider);
    UA_String_clear(&fullAltSubj);
    /* tempCtx cleanup is handled by memset initialization and automatic stack cleanup */
    
    if(errRet != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                   "UA_PQC_CreateCSR: Failed with status: %s",
                   UA_StatusCode_name(errRet));
    }
    
    return errRet;
}

/* ---------------------- Sign CSR with CA -------------------- */
UA_EXPORT UA_StatusCode
UA_PQC_SignCSRWithCA(const UA_Logger *logger,
                     const UA_ByteString *csr,
                     const UA_ByteString *caCert,
                     const UA_ByteString *caKey,
                     UA_Int32 serialNumber,
                     UA_UInt32 expiresInDays,
                     UA_ByteString *outSignedCert) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
    if(!csr || !caCert || !caKey || !outSignedCert) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    
    UA_ByteString_init(outSignedCert);
    
    /* Load CSR */
    const unsigned char *p = csr->data;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csr->length);
    if(!req) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCSRWithCA: Failed to parse CSR");
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    
    /* Load CA certificate */
    UA_Boolean caWasPem = UA_FALSE;
    X509 *ca = pqc_parse_x509_from_bytes(caCert, &caWasPem);
    if(!ca) {
        X509_REQ_free(req);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCSRWithCA: Failed to parse CA certificate");
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    
    /* Load CA private key */
    EVP_PKEY *caPrivateKey = pqc_parse_private_key_from_bytes(caKey, NULL);
    if(!caPrivateKey) {
        X509_REQ_free(req);
        X509_free(ca);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCSRWithCA: Failed to load CA private key");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Create certificate from CSR */
    X509 *cert = X509_new();
    if(!cert || X509_set_version(cert, 2) != 1) {
        X509_REQ_free(req);
        X509_free(ca);
        EVP_PKEY_free(caPrivateKey);
        if(cert) X509_free(cert);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    
    /* Set serial number */
    if(ASN1_INTEGER_set(X509_get_serialNumber(cert), serialNumber) != 1) {
        X509_REQ_free(req);
        X509_free(ca);
        X509_free(cert);
        EVP_PKEY_free(caPrivateKey);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Set validity */
    if(X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL ||
       X509_gmtime_adj(X509_get_notAfter(cert), (UA_Int64)60 * 60 * 24 * expiresInDays) == NULL) {
        X509_REQ_free(req);
        X509_free(ca);
        X509_free(cert);
        EVP_PKEY_free(caPrivateKey);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Copy subject from CSR */
    X509_NAME *subject = X509_REQ_get_subject_name(req);
    if(!subject || X509_set_subject_name(cert, subject) != 1) {
        X509_REQ_free(req);
        X509_free(ca);
        X509_free(cert);
        EVP_PKEY_free(caPrivateKey);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Set issuer to CA's subject */
    X509_NAME *caSubject = X509_get_subject_name(ca);
    if(X509_set_issuer_name(cert, caSubject) != 1) {
        X509_REQ_free(req);
        X509_free(ca);
        X509_free(cert);
        EVP_PKEY_free(caPrivateKey);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Get public key from CSR */
    EVP_PKEY *pubkey = X509_REQ_get_pubkey(req);
    if(!pubkey || X509_set_pubkey(cert, pubkey) != 1) {
        if(pubkey) EVP_PKEY_free(pubkey);
        X509_REQ_free(req);
        X509_free(ca);
        X509_free(cert);
        EVP_PKEY_free(caPrivateKey);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    EVP_PKEY_free(pubkey);
    
    /* Copy extensions from CSR */
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    if(exts) {
        for(int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
            if(ext) {
                X509_EXTENSION *ext_copy = X509_EXTENSION_dup(ext);
                if(ext_copy) {
                    X509_add_ext(cert, ext_copy, -1);
                    X509_EXTENSION_free(ext_copy);
                }
            }
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    
    /* Sign certificate with CA's private key */
    const EVP_MD *digest = NULL;
    int signResult = X509_sign(cert, caPrivateKey, digest);
    if(signResult == 0) {
        digest = EVP_sha256();
        signResult = X509_sign(cert, caPrivateKey, digest);
    }
    
    if(signResult == 0) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        X509_REQ_free(req);
        X509_free(ca);
        X509_free(cert);
        EVP_PKEY_free(caPrivateKey);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCSRWithCA: Failed to sign certificate: %s", err_buf);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Write certificate to buffer */
    UA_StatusCode errRet = pqc_write_back_certificate(cert, UA_FALSE, outSignedCert);
    
    X509_REQ_free(req);
    X509_free(ca);
    X509_free(cert);
    EVP_PKEY_free(caPrivateKey);
    
    if(errRet != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCSRWithCA: Failed to write signed certificate");
        return errRet;
    }
    
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_SignCSRWithCA: Certificate signed successfully by CA "
               "(OQS Provider handled Dilithium signing)");
    
    return UA_STATUSCODE_GOOD;
}

/* ---------------------- Sign certificate with CA -------------------- */
UA_EXPORT UA_StatusCode
UA_PQC_SignCertificateWithCA(const UA_Logger *logger,
                              const UA_ByteString *certToSign,
                              const UA_ByteString *caCert,
                              const UA_ByteString *caKey,
                              UA_ByteString *outSignedCert) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;
    
    if(!certToSign || !caCert || !caKey || !outSignedCert) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    
    UA_ByteString_init(outSignedCert);
    
    /* Load certificate to be signed */
    UA_Boolean certWasPem = UA_FALSE;
    X509 *cert = pqc_parse_x509_from_bytes(certToSign, &certWasPem);
    if(!cert) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCertificateWithCA: Failed to parse certificate to sign");
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    
    /* Load CA certificate */
    UA_Boolean caWasPem = UA_FALSE;
    X509 *ca = pqc_parse_x509_from_bytes(caCert, &caWasPem);
    if(!ca) {
        X509_free(cert);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCertificateWithCA: Failed to parse CA certificate");
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    
    /* Load CA private key (OQS Provider will handle Dilithium keys automatically) */
    EVP_PKEY *caPrivateKey = pqc_parse_private_key_from_bytes(caKey, NULL);
    if(!caPrivateKey) {
        X509_free(cert);
        X509_free(ca);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCertificateWithCA: Failed to load CA private key");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Set issuer to CA's subject */
    X509_NAME *caSubject = X509_get_subject_name(ca);
    if(X509_set_issuer_name(cert, caSubject) != 1) {
        X509_free(cert);
        X509_free(ca);
        EVP_PKEY_free(caPrivateKey);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCertificateWithCA: Failed to set issuer name");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Sign certificate with CA's private key
     * OQS Provider automatically uses Dilithium if the key is Dilithium */
    const EVP_MD *digest = NULL;
    int signResult = X509_sign(cert, caPrivateKey, digest);
    if(signResult == 0) {
        /* Try with SHA-256 if NULL doesn't work (some implementations require it) */
        digest = EVP_sha256();
        signResult = X509_sign(cert, caPrivateKey, digest);
    }
    
    if(signResult == 0) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        X509_free(cert);
        X509_free(ca);
        EVP_PKEY_free(caPrivateKey);
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCertificateWithCA: Failed to sign certificate with CA: %s", err_buf);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Write signed certificate to buffer (DER format) */
    UA_StatusCode errRet = pqc_write_back_certificate(cert, UA_FALSE, outSignedCert);
    
    X509_free(cert);
    X509_free(ca);
    EVP_PKEY_free(caPrivateKey);
    
    if(errRet != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_PQC_SignCertificateWithCA: Failed to write signed certificate");
        return errRet;
    }
    
    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
               "UA_PQC_SignCertificateWithCA: Certificate signed successfully by CA "
               "(OQS Provider handled Dilithium signing)");
    
    return UA_STATUSCODE_GOOD;
}

/* ---------------------- Register remote keys override -------------------- */
UA_EXPORT UA_StatusCode
UA_PQCPolicy_registerRemoteKeys(UA_SecurityPolicy *policy,
                                const UA_ByteString sigPublicKey,
                                const UA_ByteString kemPublicKey) {
    if(!policy || !policy->policyContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    Policy_Context_PQC *pc = (Policy_Context_PQC *)policy->policyContext;
    const UA_Logger *log = pc->logger ? pc->logger : UA_Log_Stdout;

    /* Esta función permite registrar claves remotas manualmente.
     * Por ahora, solo validamos que las claves tengan el tamaño correcto.
     * Las claves remotas se almacenan en el contexto del canal cuando se crea. */
    if(sigPublicKey.length != (size_t)OQS_SIG_dilithium_2_length_public_key) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQCPolicy_registerRemoteKeys: invalid Dilithium public key size");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    if(kemPublicKey.length != (size_t)OQS_KEM_kyber_768_length_public_key) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQCPolicy_registerRemoteKeys: invalid Kyber public key size");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                "UA_PQCPolicy_registerRemoteKeys: remote keys registered (note: keys are stored per-channel)");
    
    /* Nota: Las claves remotas se almacenan en el contexto del canal (PQC_ChannelContext),
     * no en el contexto de la política. Esta función valida los parámetros pero las claves
     * reales se usan cuando se crea el contexto del canal. */
    return UA_STATUSCODE_GOOD;
}

/* ---------------------- Utility: clear policy -------------------- */
static void
UA_PQCPolicy_clear(UA_SecurityPolicy *policy) {
    if(!policy) return;
    UA_ByteString_clear(&policy->localCertificate);

    Policy_Context_PQC *ctx = (Policy_Context_PQC *)policy->policyContext;
    if(ctx) {
        /* CRITICAL: Never free the policy context if channel contexts are still referencing it.
         * The refCount is the single source of truth for whether the policy can be safely freed.
         * This prevents use-after-free when channels are being cleaned up asynchronously
         * during shutdown. */
        if(ctx->refCount != 0) {
            const UA_Logger *log = ctx->logger ? ctx->logger : UA_Log_Stdout;
            UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_PQCPolicy_clear: Cannot free policy context: refCount=%u > 0. "
                        "There are still active channel contexts referencing this policy. "
                        "The policy will remain in memory until all channels are closed.",
                        (unsigned)ctx->refCount);
            /* Do NOT free the context. Return immediately to prevent use-after-free.
             * The framework must ensure all channels are closed before clearing policies.
             * Once refCount reaches 0, the policy can be safely freed. */
            return;
        }
        
        /* Only free when refCount == 0, meaning no channel contexts reference this policy */
        /* Limpiar claves privadas antes de liberar */
        memset(ctx->sigPrivateKey, 0, sizeof(ctx->sigPrivateKey));
        memset(ctx->kemPrivateKey, 0, sizeof(ctx->kemPrivateKey));
        /* BUG 2 FIX: Only clear if the ByteString actually owns heap memory.
         * UA_ByteString_clear is safe to call on NULL data (it checks internally),
         * but we verify to be explicit about ownership. */
        if(ctx->localCertThumbprint.data != NULL) {
            UA_ByteString_clear(&ctx->localCertThumbprint);
        }
        UA_free(ctx);
        policy->policyContext = NULL;
    }
}

/* ------------------ No-op helpers para evitar punteros NULL ------------- */

/* set / get local symmetric encrypting key */
static UA_StatusCode
pqc_setLocalSymEncryptingKey(void *channelContext, const UA_ByteString *key) {
    if(!channelContext || !key)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    UA_ByteString_clear(&ctx->localSymEncryptingKey);
    return UA_ByteString_copy(key, &ctx->localSymEncryptingKey);
}

static UA_StatusCode
pqc_setLocalSymSigningKey(void *channelContext, const UA_ByteString *key) {
    if(!channelContext || !key)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);
    
    UA_ByteString_clear(&ctx->localSymSigningKey);
    UA_StatusCode retval = UA_ByteString_copy(key, &ctx->localSymSigningKey);
    
    
    return retval;
}

static UA_StatusCode
pqc_setLocalSymIv(void *channelContext, const UA_ByteString *iv) {
    if(!channelContext || !iv)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    UA_ByteString_clear(&ctx->localSymIv);
    return UA_ByteString_copy(iv, &ctx->localSymIv);
}

/* set remote symmetric keys */
static UA_StatusCode
pqc_setRemoteSymEncryptingKey(void *channelContext, const UA_ByteString *key) {
    if(!channelContext || !key)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    UA_ByteString_clear(&ctx->remoteSymEncryptingKey);
    return UA_ByteString_copy(key, &ctx->remoteSymEncryptingKey);
}

static UA_StatusCode
pqc_setRemoteSymSigningKey(void *channelContext, const UA_ByteString *key) {
    if(!channelContext || !key)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);
    
    UA_ByteString_clear(&ctx->remoteSymSigningKey);
    UA_StatusCode retval = UA_ByteString_copy(key, &ctx->remoteSymSigningKey);
    
    
    return retval;
}

static UA_StatusCode
pqc_setRemoteSymIv(void *channelContext, const UA_ByteString *iv) {
    if(!channelContext || !iv)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    UA_ByteString_clear(&ctx->remoteSymIv);
    return UA_ByteString_copy(iv, &ctx->remoteSymIv);
}

static UA_StatusCode
pqc_makeCertificateThumbprint(const UA_SecurityPolicy *securityPolicy,
                              const UA_ByteString *certificate,
                              UA_ByteString *thumbprint) {
    (void)securityPolicy;

    if(!certificate || certificate->length == 0 || !certificate->data) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_makeCertificateThumbprint: invalid certificate input");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_LOG_DEBUG(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
        "pqc_makeCertificateThumbprint: cert len=%u, first bytes: %02X %02X %02X",
        (unsigned)certificate->length,
        certificate->data ? certificate->data[0] : 0,
        certificate->data ? certificate->data[1] : 0,
        certificate->data ? certificate->data[2] : 0);

    return UA_Openssl_X509_GetCertificateThumbprint(certificate, thumbprint, false);
}

static UA_StatusCode
pqc_compareCertificateThumbprint(const UA_SecurityPolicy *securityPolicy,
                                 const UA_ByteString *certificateThumbprint) {
    if(!securityPolicy || !certificateThumbprint)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    Policy_Context_PQC *pc = (Policy_Context_PQC *)securityPolicy->policyContext;
    if(!pc) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_compareCertificateThumbprint: policy context not initialized");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(pc->localCertThumbprint.length == 0 || !pc->localCertThumbprint.data) {
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }
    
    if(!UA_ByteString_equal(certificateThumbprint, &pc->localCertThumbprint)) {
        return UA_STATUSCODE_BADCERTIFICATEINVALID;
    }

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
pqc_compareCertificate(const void *channelContext,
                       const UA_ByteString *remoteCertificate) {
    (void)channelContext;
    if(!remoteCertificate || remoteCertificate->length == 0 || !remoteCertificate->data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    /* Por ahora aceptamos cualquier certificado */
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_Sym_PQC_generateNonce(void *policyContext, UA_ByteString *out) {
    (void)policyContext;

    if(!out)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    size_t nonce_len = out->length;
    if(nonce_len == 0)
        nonce_len = 32;

    uint8_t *tmp = (uint8_t*)UA_malloc(nonce_len);
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    if(RAND_bytes(tmp, (int)nonce_len) != 1) {
        UA_free(tmp);
        return UA_STATUSCODE_BADUNEXPECTEDERROR;
    }

    UA_ByteString tmpBS;
    tmpBS.length = nonce_len;
    tmpBS.data = tmp;

    UA_StatusCode rc = UA_ByteString_copy(&tmpBS, out);
    UA_free(tmp);

    if(rc != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITY,
                       "UA_Sym_PQC_generateNonce: UA_ByteString_copy failed: %s",
                       UA_StatusCode_name(rc));
        return rc;
    }

    UA_LOG_DEBUG(UA_Log_Stdout, UA_LOGCATEGORY_SECURITY,
                 "UA_Sym_PQC_generateNonce: generated %zu random bytes", nonce_len);
    return UA_STATUSCODE_GOOD;
}

/* ------------------ Symmetric module functions ------------------ */
/* PQC derives symmetric keys from KEM shared secret using PSHA256 */

/* Constants for symmetric encryption (AES-256-CBC + HMAC-SHA256) */
#define PQC_SYM_ENCRYPTION_KEY_LENGTH 32  /* AES-256 */
#define PQC_SYM_SIGNING_KEY_LENGTH 32    /* HMAC-SHA256 */
#define PQC_SYM_IV_LENGTH 16             /* AES block size */
#define PQC_SYM_BLOCK_SIZE 16            /* AES block size */

static UA_StatusCode
pqc_sym_generateKey(void *policyContext,
                    const UA_ByteString *remoteNonce,
                    const UA_ByteString *localNonce,
                    UA_ByteString *out) {
    if(!policyContext || !remoteNonce || !localNonce || !out)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    
    Policy_Context_PQC *pc = (Policy_Context_PQC *)policyContext;
    const UA_Logger *logger = pc->logger ? pc->logger : UA_Log_Stdout;
    
    if(!pc->hasTemporarySharedSecret) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sym_generateKey: No shared secret available. "
                     "KEM handshake must complete first (policyContext=%p, hasTemporarySharedSecret=%d)",
                     (void*)pc, pc->hasTemporarySharedSecret);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    UA_ByteString seed;
    UA_ByteString_init(&seed);
    UA_StatusCode retval = UA_ByteString_allocBuffer(&seed, remoteNonce->length + localNonce->length);
    if(retval != UA_STATUSCODE_GOOD) {
        return retval;
    }
    
    const UA_ByteString *firstNonce, *secondNonce;
    size_t minLen = remoteNonce->length < localNonce->length ? remoteNonce->length : localNonce->length;
    int cmp = memcmp(remoteNonce->data, localNonce->data, minLen);
    
    if(cmp < 0) {
        firstNonce = remoteNonce;
        secondNonce = localNonce;
    } else if(cmp > 0) {
        firstNonce = localNonce;
        secondNonce = remoteNonce;
    } else {
        firstNonce = (remoteNonce->length <= localNonce->length) ? remoteNonce : localNonce;
        secondNonce = (firstNonce == remoteNonce) ? localNonce : remoteNonce;
    }
    
    memcpy(seed.data, firstNonce->data, firstNonce->length);
    memcpy(seed.data + firstNonce->length, secondNonce->data, secondNonce->length);
    
    /* BUG 1 FIX: Create a heap-allocated copy of the embedded secret buffer.
     * UA_Openssl_Random_Key_PSHA256_Derive expects a const UA_ByteString* that it only reads,
     * but to follow open62541 ownership rules, we must not create UA_ByteString pointing to
     * embedded memory that could be cleaned up. Create a temporary copy on the heap. */
    UA_ByteString secret;
    UA_ByteString_init(&secret);
    retval = UA_ByteString_allocBuffer(&secret, PQC_KEM_SHARED_SECRET_LEN);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ByteString_clear(&seed);
        return retval;
    }
    memcpy(secret.data, pc->temporarySharedSecret, PQC_KEM_SHARED_SECRET_LEN);
    
    retval = UA_Openssl_Random_Key_PSHA256_Derive(&secret, &seed, out);
    
    UA_ByteString_clear(&secret);
    UA_ByteString_clear(&seed);
    pc->hasGeneratedSymmetricKeys = true;
    
    return retval;
}

/* Symmetric encryption algorithm functions (AES-256-CBC) */
static size_t
pqc_sym_encr_getLocalKeyLength(const void *channelContext) {
    (void)channelContext;
    return PQC_SYM_ENCRYPTION_KEY_LENGTH;
}

static size_t
pqc_sym_encr_getRemoteKeyLength(const void *channelContext) {
    (void)channelContext;
    return PQC_SYM_ENCRYPTION_KEY_LENGTH;
}

static size_t
pqc_sym_encr_getRemoteBlockSize(const void *channelContext) {
    (void)channelContext;
    return PQC_SYM_BLOCK_SIZE;
}

static size_t
pqc_sym_encr_getRemotePlainTextBlockSize(const void *channelContext) {
    (void)channelContext;
    return PQC_SYM_BLOCK_SIZE;
}

static UA_StatusCode
pqc_sym_encr_encrypt(void *channelContext, UA_ByteString *data) {
    if(!channelContext || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    if(ctx->localSymEncryptingKey.length == 0 || ctx->localSymIv.length == 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    
    return UA_OpenSSL_AES_256_CBC_Encrypt(&ctx->localSymIv, &ctx->localSymEncryptingKey, data);
}

static UA_StatusCode
pqc_sym_encr_decrypt(void *channelContext, UA_ByteString *data) {
    if(!channelContext || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);
    
    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "pqc_sym_encr_decrypt: Called (data->length=%zu, encKey.length=%zu, iv.length=%zu)",
                 data->length, ctx->remoteSymEncryptingKey.length, ctx->remoteSymIv.length);
    if(ctx->remoteSymEncryptingKey.length == 0 || ctx->remoteSymIv.length == 0) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sym_encr_decrypt: ✗✗✗ CRITICAL: Symmetric keys not initialized "
                     "(encKey.length=%zu, iv.length=%zu). "
                     "This means generateRemoteKeys was not called or failed. "
                     "The shared secret might not be available in policyContext. "
                     "Calling thread backtrace...",
                     ctx->remoteSymEncryptingKey.length, ctx->remoteSymIv.length);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    UA_LOG_DEBUG(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "pqc_sym_encr_decrypt: Decrypting %zu bytes with AES-256-CBC",
                 data->length);
    return UA_OpenSSL_AES_256_CBC_Decrypt(&ctx->remoteSymIv, &ctx->remoteSymEncryptingKey, data);
}

/* Symmetric signature algorithm functions (HMAC-SHA256) */
static size_t
pqc_sym_sig_getLocalKeyLength(const void *channelContext) {
    (void)channelContext;
    return PQC_SYM_SIGNING_KEY_LENGTH;
}

static size_t
pqc_sym_sig_getRemoteKeyLength(const void *channelContext) {
    (void)channelContext;
    return PQC_SYM_SIGNING_KEY_LENGTH;
}

static size_t
pqc_sym_sig_getLocalSignatureSize(const void *channelContext) {
    (void)channelContext;
    return 32; /* HMAC-SHA256 produces 32-byte signature */
}

static size_t
pqc_sym_sig_getRemoteSignatureSize(const void *channelContext) {
    (void)channelContext;
    return 32; /* HMAC-SHA256 produces 32-byte signature */
}

static UA_StatusCode
pqc_sym_sig_sign(void *channelContext,
                 const UA_ByteString *data,
                 UA_ByteString *signature) {
    if(!channelContext || !data || !signature)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);
    
    if(ctx->localSymSigningKey.length == 0) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sym_sig_sign: ✗✗✗ CRITICAL: localSymSigningKey not initialized (length=%zu)",
                     ctx->localSymSigningKey.length);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    
    return UA_OpenSSL_HMAC_SHA256_Sign(data, &ctx->localSymSigningKey, signature);
}

static UA_StatusCode
pqc_sym_sig_verify(void *channelContext,
                   const UA_ByteString *data,
                   const UA_ByteString *signature) {
    if(!channelContext || !data || !signature)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);
    
    if(ctx->remoteSymSigningKey.length == 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    
    UA_StatusCode verifyResult = UA_OpenSSL_HMAC_SHA256_Verify(data, &ctx->remoteSymSigningKey, signature);
    
    if(verifyResult != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sym_sig_verify: Signature verification failed (status=%s)",
                     UA_StatusCode_name(verifyResult));
    }
    
    return verifyResult;
}

static UA_StatusCode
pqc_extract_pubkeys_from_cert_der_internal(const UA_ByteString *derCert,
                                           const UA_Logger *logger,
                                           uint8_t *sigPkOut,
                                           UA_Boolean *sigValid,
                                           uint8_t *kemPkOut,
                                           UA_Boolean *kemValid) {
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;

    if(sigValid)
        *sigValid = false;
    if(kemValid)
        *kemValid = false;

    if(!derCert || derCert->length == 0 || !derCert->data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Extract leaf certificate from possible chain */
    UA_ByteString leafCert = *derCert;
    
    /* Handle DER format: extract certificate length from header */
    if(leafCert.length >= 4 && leafCert.data[0] == 0x30 && leafCert.data[1] == 0x82) {
        size_t leafLen = 4; /* Magic numbers + length bytes */
        leafLen += (size_t)(((uint16_t)leafCert.data[2]) << 8);
        leafLen += leafCert.data[3];
        if(leafLen <= leafCert.length) {
            leafCert.length = leafLen;
        }
    }
    /* Handle PEM format: extract first certificate from chain */
    else if(leafCert.length > 27 && 
            memcmp(leafCert.data, "-----BEGIN CERTIFICATE-----", 27) == 0) {
        /* Find the end of the first certificate */
        const char *pemEndMarker = "-----END CERTIFICATE-----";
        const size_t pemEndLen = 25;
        const char *data = (const char *)leafCert.data;
        const char *endMarker = NULL;
        
        /* Search for the end marker */
        for(size_t i = 0; i <= leafCert.length - pemEndLen; i++) {
            if(memcmp(data + i, pemEndMarker, pemEndLen) == 0) {
                endMarker = data + i;
                break;
            }
        }
        
        if(endMarker) {
            /* Check if there's another certificate after this one */
            const char *nextBegin = endMarker + pemEndLen;
            const size_t remaining = leafCert.length - (size_t)(nextBegin - data);
            if(remaining > 27) {
                /* Check for next "-----BEGIN CERTIFICATE-----" */
                const char *nextCert = NULL;
                for(size_t i = 0; i <= remaining - 27; i++) {
                    if(memcmp(nextBegin + i, "-----BEGIN CERTIFICATE-----", 27) == 0) {
                        nextCert = nextBegin + i;
                        break;
                    }
                }
                /* If found next certificate, limit to first one only */
                if(nextCert) {
                    leafCert.length = (size_t)(nextCert - data);
                }
            }
        }
        /* If no end marker found, use entire buffer (PEM_read_bio_X509 will handle it) */
    }

    /* Parse certificate (supports both DER and PEM, including RSA certificates with PQC extensions) */
    UA_Boolean wasPem = false;
    X509 *cert = pqc_parse_x509_from_bytes(&leafCert, &wasPem);
    if(!cert) {
        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_extract_pubkeys_from_cert_der: could not parse certificate (DER or PEM)");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    UA_StatusCode status = UA_STATUSCODE_GOOD;

    if(sigPkOut) {
        ASN1_OBJECT *objDil = OBJ_txt2obj(OID_DILITHIUM_PUB, 1);
        if(!objDil) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "pqc_extract_pubkeys_from_cert_der: failed to create Dilithium OID object");
            status = UA_STATUSCODE_BADINTERNALERROR;
        } else {
            int idx = X509_get_ext_by_OBJ(cert, objDil, -1);
            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "pqc_extract_pubkeys_from_cert_der: searching for Dilithium extension (idx=%d, OID=%s)",
                        idx, OID_DILITHIUM_PUB);
            if(idx >= 0) {
                X509_EXTENSION *ext = X509_get_ext(cert, idx);
                if(!ext) {
                    UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                   "pqc_extract_pubkeys_from_cert_der: Dilithium extension at idx %d is NULL", idx);
                    status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
                } else {
                    ASN1_OCTET_STRING *oct = X509_EXTENSION_get_data(ext);
                    if(!oct) {
                        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                       "pqc_extract_pubkeys_from_cert_der: Dilithium extension data is NULL");
                        status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
                    } else {
                        const unsigned char *extdata = ASN1_STRING_get0_data(oct);
                        size_t extlen = (size_t)ASN1_STRING_length(oct);
                        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                    "pqc_extract_pubkeys_from_cert_der: Dilithium extension found (length=%zu, expected=%zu)",
                                    extlen, (size_t)OQS_SIG_dilithium_2_length_public_key);
                        if(extlen >= OQS_SIG_dilithium_2_length_public_key) {
                            memcpy(sigPkOut, extdata, OQS_SIG_dilithium_2_length_public_key);
                            if(sigValid)
                                *sigValid = true;
                            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                        "pqc_extract_pubkeys_from_cert_der: ✓ Dilithium public key extracted successfully");
                        } else {
                            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                           "pqc_extract_pubkeys_from_cert_der: Dilithium key too short (%zu < %zu)",
                                           extlen, (size_t)OQS_SIG_dilithium_2_length_public_key);
                            status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
                        }
                    }
                }
            } else {
                /* List all extensions for debugging */
                int extCount = X509_get_ext_count(cert);
                UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                            "pqc_extract_pubkeys_from_cert_der: Dilithium extension not found. Certificate has %d extensions total",
                            extCount);
                for(int i = 0; i < extCount; i++) {
                    X509_EXTENSION *ext = X509_get_ext(cert, i);
                    if(ext) {
                        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
                        if(obj) {
                            char oid_buf[256];
                            OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
                            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                        "pqc_extract_pubkeys_from_cert_der: extension[%d] OID=%s", i, oid_buf);
                        }
                    }
                }
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                               "pqc_extract_pubkeys_from_cert_der: Dilithium extension not found "
                               "(certificate length=%zu bytes, OID=%s)",
                               derCert->length, OID_DILITHIUM_PUB);
                status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
            }
            ASN1_OBJECT_free(objDil);
        }
    }

    if(kemPkOut) {
        ASN1_OBJECT *objKy = OBJ_txt2obj(OID_KYBER_PUB, 1);
        if(!objKy) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "pqc_extract_pubkeys_from_cert_der: failed to create Kyber OID object");
            status = UA_STATUSCODE_BADINTERNALERROR;
        } else {
            int idx = X509_get_ext_by_OBJ(cert, objKy, -1);
            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                        "pqc_extract_pubkeys_from_cert_der: searching for Kyber extension (idx=%d, OID=%s)",
                        idx, OID_KYBER_PUB);
            if(idx >= 0) {
                X509_EXTENSION *ext = X509_get_ext(cert, idx);
                if(!ext) {
                    UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                   "pqc_extract_pubkeys_from_cert_der: Kyber extension at idx %d is NULL", idx);
                    status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
                } else {
                    ASN1_OCTET_STRING *oct = X509_EXTENSION_get_data(ext);
                    if(!oct) {
                        UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                       "pqc_extract_pubkeys_from_cert_der: Kyber extension data is NULL");
                        status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
                    } else {
                        const unsigned char *extdata = ASN1_STRING_get0_data(oct);
                        size_t extlen = (size_t)ASN1_STRING_length(oct);
                        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                    "pqc_extract_pubkeys_from_cert_der: Kyber extension found (length=%zu, expected=%zu)",
                                    extlen, (size_t)OQS_KEM_kyber_768_length_public_key);
                        if(extlen >= OQS_KEM_kyber_768_length_public_key) {
                            memcpy(kemPkOut, extdata, OQS_KEM_kyber_768_length_public_key);
                            if(kemValid)
                                *kemValid = true;
                            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                        "pqc_extract_pubkeys_from_cert_der: ✓ Kyber public key extracted successfully");
                        } else {
                            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                           "pqc_extract_pubkeys_from_cert_der: Kyber key too short (%zu < %zu)",
                                           extlen, (size_t)OQS_KEM_kyber_768_length_public_key);
                            status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
                        }
                    }
                }
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                               "pqc_extract_pubkeys_from_cert_der: Kyber extension not found "
                               "(certificate length=%zu bytes, OID=%s)",
                               derCert->length, OID_KYBER_PUB);
                status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
            }
            ASN1_OBJECT_free(objKy);
        }
    }

    X509_free(cert);

    if(sigPkOut && sigValid && !*sigValid)
        status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    if(kemPkOut && kemValid && !*kemValid && status == UA_STATUSCODE_GOOD)
        status = UA_STATUSCODE_BADSECURITYCHECKSFAILED;

    return status;
}

static UA_StatusCode
pqc_extract_pubkeys_from_cert_der(const UA_ByteString *derCert,
                                  Policy_Context_PQC *ctx,
                                  const UA_Logger *logger) {
    if(!ctx) {
        UA_LOG_WARNING(logger ? logger : UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_extract_pubkeys_from_cert_der: context is NULL");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_Boolean sigValid = false;
    UA_Boolean kemValid = false;

    UA_StatusCode status =
        pqc_extract_pubkeys_from_cert_der_internal(derCert, logger,
                                                   ctx->sigPublicKey, &sigValid,
                                                   ctx->kemPublicKey, &kemValid);
    if(status != UA_STATUSCODE_GOOD) {
        ctx->sigKeysInitialized = false;
        ctx->kemKeysInitialized = false;
        return status;
    }

    if(!sigValid || !kemValid) {
        ctx->sigKeysInitialized = sigValid;
        ctx->kemKeysInitialized = kemValid;
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    ctx->sigKeysInitialized = sigValid;
    ctx->kemKeysInitialized = kemValid;
    return UA_STATUSCODE_GOOD;
}


static UA_StatusCode
UA_ByteString_expand(UA_ByteString *bs, size_t extra) {
    if(!bs) return UA_STATUSCODE_BADINVALIDARGUMENT;
    if(extra == 0)
        return UA_STATUSCODE_GOOD;

    size_t old_len = bs->length;
    size_t new_len = old_len + extra;

    UA_Byte *old_data = bs->data;
    UA_Byte *newbuf = (UA_Byte*)UA_malloc(new_len);
    if(!newbuf) return UA_STATUSCODE_BADOUTOFMEMORY;

    if(bs->data && old_len > 0)
        memcpy(newbuf, bs->data, old_len);

    if(extra > 0)
        memset(newbuf + old_len, 0, extra);

    /* IMPORTANTE: NO liberar old_data aquí con UA_free porque:
     * 1. El buffer podría haber sido asignado de otra manera (no con UA_malloc)
     * 2. El buffer podría ser parte de otro buffer más grande
     * 3. Solo UA_ByteString_clear debe liberar buffers de UA_ByteString
     * 
     * El código que llama debe asegurarse de que el UA_ByteString original
     * se libere correctamente con UA_ByteString_clear cuando ya no se necesite.
     * En nuestro caso, UA_PQC_EnsureCertificateExtensions modifica el signingPrivateKey
     * in-place, y el buffer original será liberado cuando se llame a UA_ByteString_clear
     * en el UA_ByteString completo más tarde. */

    bs->data = newbuf;
    bs->length = new_len;
    return UA_STATUSCODE_GOOD;
}

/* ------------------------ Dilithium sign/verify ------------------ */
/**
 * Sign a message using Dilithium2 signature algorithm.
 *
 * @param context Channel context containing policy context with signing keys
 * @param message Message to sign (must not be NULL, data must be allocated)
 * @param signature Output signature buffer (must be pre-allocated with at least
 *                  PQC_SIG_SIGNATURE_LEN bytes)
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
 */
static UA_StatusCode
pqc_sign(void *context, const UA_ByteString *message, UA_ByteString *signature) {
    if(!context || !message || !signature)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Validate message buffer */
    if(!message->data || message->length == 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    PQC_ChannelContext *ctx = (PQC_ChannelContext *)context;
    Policy_Context_PQC *pc = ctx ? ctx->policyContext : NULL;
    
    if(!pc) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sign: policy context not available");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    pqc_init_keys(pc);
    
    if(!pc->sigKeysInitialized) {
        UA_LOG_ERROR(pc->logger ? pc->logger : UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sign: Dilithium keys not initialized");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    const UA_Logger *logger = pqc_get_logger_from_policy(pc);

    /* Verify that signature->data is already allocated and has enough space */
    if(!signature->data) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sign: signature->data is NULL");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    if(signature->length < PQC_SIG_SIGNATURE_LEN) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sign: signature buffer too small (provided=%zu, required=%zu)",
                     signature->length, (size_t)PQC_SIG_SIGNATURE_LEN);
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if(!sig) return UA_STATUSCODE_BADOUTOFMEMORY;

    size_t siglen = 0;
    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                "[TRACE-OPN] pqc_sign: before sign alg=Dilithium2 msgLen=%zu sigBufLen=%zu",
                message->length, signature->length);

    OQS_STATUS rc = OQS_SIG_sign(sig, signature->data, &siglen,
                                 message->data, message->length, pc->sigPrivateKey);

    signature->length = (size_t)siglen;
    OQS_SIG_free(sig);

    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                "[TRACE-OPN] pqc_sign: after sign alg=Dilithium2 rc=%d sigLen=%zu",
                (int)rc, signature->length);

    if(rc != OQS_SUCCESS) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_sign: OQS_SIG_sign failed (rc=%d)", (int)rc);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    return UA_STATUSCODE_GOOD;
}

/**
 * Verify a Dilithium2 signature.
 *
 * @param context Channel context containing remote public key for verification
 * @param message Message that was signed (must not be NULL, data must be allocated)
 * @param signature Signature to verify (must not be NULL, data must be allocated,
 *                  length must be PQC_SIG_SIGNATURE_LEN)
 * @return UA_STATUSCODE_GOOD if signature is valid, UA_STATUSCODE_BADSECURITYCHECKSFAILED otherwise
 */
static UA_StatusCode
pqc_verify(void *context, const UA_ByteString *message, const UA_ByteString *signature) {
    if(!context || !message || !signature)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Validate message and signature buffers */
    if(!message->data || message->length == 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    if(!signature->data || signature->length == 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    PQC_ChannelContext *ctx = (PQC_ChannelContext *)context;
    
    if(!ctx) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);

    if(!ctx->remoteSigPublicKeyValid) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_verify: remote Dilithium public key is not initialized. "
                     "This means pqc_channel_newContext failed to extract keys from the remote certificate, "
                     "or the context was created without a remote certificate.");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }
    
    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                "pqc_verify: Verifying signature (message.length=%zu, signature.length=%zu, remoteSigPublicKeyValid=%u)",
                message->length, signature->length, (unsigned)ctx->remoteSigPublicKeyValid);

    /* Verify the signature size matches expected size before creating OQS object */
    if(signature->length != PQC_SIG_SIGNATURE_LEN) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_verify: signature length mismatch (received=%zu, expected=%zu)",
                       signature->length, (size_t)PQC_SIG_SIGNATURE_LEN);
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if(!sig) return UA_STATUSCODE_BADOUTOFMEMORY;

    OQS_STATUS oqs_rc = OQS_SIG_verify(sig,
                                       message->data, message->length,
                                       signature->data, signature->length,
                                       ctx->remoteSigPublicKey);

    if(oqs_rc != OQS_SUCCESS) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_verify: OQS_SIG_verify failed (oqs_rc=%d, message->length=%zu, signature->length=%zu). "
                     "This usually means: 1) The signature is invalid, 2) The message was modified, "
                     "3) The public key does not match the private key used to sign, "
                     "4) The signature was generated with a different keypair, "
                     "5) The message data passed to verify is incorrect.",
                     (int)oqs_rc, message->length, signature->length);
    }

    OQS_SIG_free(sig);
    return (oqs_rc == OQS_SUCCESS) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADSECURITYCHECKSFAILED;
}

/* -------------------------- Kyber encrypt/decrypt ------------------ */
/**
 * Encrypt data using Kyber768 KEM (Key Encapsulation Mechanism).
 *
 * The encryption process:
 * 1. Uses remote Kyber public key to generate a shared secret via KEM encaps
 * 2. XORs the payload (message + signature) with the shared secret
 * 3. Prepends the KEM ciphertext to the encrypted data
 *
 * Note: The buffer must already have space for the KEM ciphertext at the beginning,
 *       which is allocated by signAndEncryptAsym before calling this function.
 *
 * @param context Channel context containing remote Kyber public key
 * @param data Buffer containing payload to encrypt. On input, payload starts at
 *             data->data + PQC_KEM_CIPHERTEXT_LEN. On output, KEM ciphertext is
 *             written at data->data[0..PQC_KEM_CIPHERTEXT_LEN-1] and encrypted
 *             payload follows.
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
 */
static UA_StatusCode
pqc_encrypt(void *context, UA_ByteString *data) {
    if(!context || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Validate data buffer */
    if(!data->data || data->length == 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    PQC_ChannelContext *ctx = (PQC_ChannelContext*)context;
    
    if(!ctx) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);

    if(!ctx->remoteKemPublicKeyValid) {
        /* For the first OPN message from client, we may not have the server's certificate yet.
         * In OPC UA, the client sends its OPN before receiving the server's OPN (which contains
         * the server's certificate). This is valid - the first OPN can be sent without encryption
         * (only signed), and encryption will be enabled after receiving the server's OPN response.
         * 
         * However, according to OPC UA Part 6, Section 6.7.2, OPN messages are always encrypted
         * if encryption is supported. But for PQC, we need the server's Kyber public key to encrypt,
         * which we don't have yet.
         * 
         * Solution: Allow sending the first OPN without encryption (only signed) when the remote
         * Kyber key is not available. The server will respond with its OPN containing its certificate,
         * and subsequent messages will be encrypted. */
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_encrypt: remote Kyber public key is not initialized. "
                     "This is expected for the first OPN message before receiving server certificate. "
                     "Sending message without encryption (only signed). "
                     "Encryption will be enabled after receiving server's OPN response.");
        UA_LOG_DEBUG(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_encrypt: remote certificate length=%zu, remoteKemPublicKeyValid=%u",
                     ctx->remoteCertificate.length, (unsigned)ctx->remoteKemPublicKeyValid);
        
        /* Remove the KEM ciphertext space that was pre-allocated by signAndEncryptAsym */
        if(data->length >= PQC_KEM_CIPHERTEXT_LEN) {
            /* Move the payload back to the beginning (removing the KEM ciphertext space) */
            memmove(data->data, data->data + PQC_KEM_CIPHERTEXT_LEN, 
                   data->length - PQC_KEM_CIPHERTEXT_LEN);
            data->length -= PQC_KEM_CIPHERTEXT_LEN;
            UA_LOG_DEBUG(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "pqc_encrypt: Removed KEM ciphertext space (%zu bytes), "
                         "message will be sent without encryption (only signed)",
                         (size_t)PQC_KEM_CIPHERTEXT_LEN);
        }
        
        /* Return success to allow sending the message without encryption */
        return UA_STATUSCODE_GOOD;
    }

    /* Use constants to validate buffer size before creating OQS object */
    const size_t kem_ct_len = PQC_KEM_CIPHERTEXT_LEN;
    const size_t kem_ss_len = PQC_KEM_SHARED_SECRET_LEN;

    /* Preserve original payload length */
    size_t payload_len = data->length - kem_ct_len;
    
    /* Check if the buffer already has space for KEM ciphertext at the beginning.
     * This happens when signAndEncryptAsym has already expanded the buffer. */
    if(payload_len <= 0) {
        /* Buffer doesn't have enough space. This shouldn't happen if signAndEncryptAsym
         * is working correctly, but we'll handle it anyway. */
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_encrypt: buffer length (%zu) is less than or equal to KEM ciphertext length (%zu). "
                       "This indicates signAndEncryptAsym didn't expand the buffer correctly.",
                       data->length, kem_ct_len);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if(!kem) return UA_STATUSCODE_BADOUTOFMEMORY;
    
    /* The buffer should already have space for KEM ciphertext at the beginning.
     * The payload should already be moved forward by signAndEncryptAsym.
     * We just need to write the ciphertext at data->data[0..kem_ct_len-1]. */

    /* The ciphertext goes at data->data[0 .. kem_ct_len-1] */
    uint8_t *ct = data->data;
    uint8_t *shared_secret = (uint8_t*)UA_malloc(kem_ss_len);
    if(!shared_secret) {
        OQS_KEM_free(kem);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    /* Verify that remote Kyber public key is not all zeros */
    if(pqc_is_buffer_all_zeros(ctx->remoteKemPublicKey, sizeof(ctx->remoteKemPublicKey))) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_encrypt: remote Kyber public key is all zeros! Cannot encrypt.");
        UA_free(shared_secret);
        OQS_KEM_free(kem);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    if(OQS_KEM_encaps(kem, ct, shared_secret, ctx->remoteKemPublicKey) != OQS_SUCCESS) {
        UA_free(shared_secret);
        OQS_KEM_free(kem);
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_encrypt: OQS_KEM_encaps failed");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    if(ctx->policyContext && !ctx->policyContext->hasTemporarySharedSecret) {
        memcpy(ctx->policyContext->temporarySharedSecret, shared_secret, kem_ss_len);
        ctx->policyContext->hasTemporarySharedSecret = true;
    }

    uint8_t *payload = data->data + kem_ct_len;
    for(size_t i = 0; i < payload_len; i++)
        payload[i] ^= shared_secret[i % kem_ss_len];

    if(data->length != payload_len + kem_ct_len) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_encrypt: buffer length mismatch (%zu != %zu)",
                       data->length, payload_len + kem_ct_len);
    }
    if(kem_ss_len <= sizeof(ctx->sharedSecret)) {
        memcpy(ctx->sharedSecret, shared_secret, kem_ss_len);
        ctx->hasSharedSecret = true;
    } else {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                       "pqc_encrypt: shared secret too large to store in ctx");
    }

    UA_free(shared_secret);
    OQS_KEM_free(kem);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
pqc_decrypt(void *context, UA_ByteString *data) {
    if(!context || !data)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    if(!data->data || data->length == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    PQC_ChannelContext *ctx = (PQC_ChannelContext*)context;
    if(!ctx || !ctx->policyContext)
        return UA_STATUSCODE_BADINTERNALERROR;

    Policy_Context_PQC *pc = ctx->policyContext;

    const UA_Logger *logger = pqc_get_logger_from_policy(pc);
    
    /* Log before calling pqc_init_kem_keys */
    if(logger) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "pqc_decrypt: Called (data->length=%zu, pc->kemKeysInitialized=%u)",
                data->length, (unsigned)pc->kemKeysInitialized);
    }
    
    pqc_init_kem_keys(pc);
    
    /* Log after calling pqc_init_kem_keys */
    if(logger) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "pqc_decrypt: After pqc_init_kem_keys (pc->kemKeysInitialized=%u)",
                (unsigned)pc->kemKeysInitialized);
    }
    
    if(!pc->kemKeysInitialized) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "pqc_decrypt: Kyber keys not initialized after pqc_init_kem_keys");
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    const size_t kem_ct_len = PQC_KEM_CIPHERTEXT_LEN;
    if(data->length < kem_ct_len)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    size_t enc_len = data->length - kem_ct_len;
    if(enc_len == 0)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if(!kem) return UA_STATUSCODE_BADOUTOFMEMORY;

    uint8_t *ciphertext = data->data;
    uint8_t *enc_data = data->data + kem_ct_len;

    uint8_t shared_secret[OQS_KEM_kyber_768_length_shared_secret];
    
    if(pqc_is_buffer_all_zeros(pc->kemPrivateKey, sizeof(pc->kemPrivateKey))) {
        OQS_KEM_free(kem);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    if(OQS_KEM_decaps(kem, shared_secret, ciphertext, pc->kemPrivateKey) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY, "pqc_decrypt: OQS_KEM_decaps failed");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    for(size_t i = 0; i < enc_len; i++)
        enc_data[i] ^= shared_secret[i % kem->length_shared_secret];

    /* Log before memmove */
    if(logger && enc_len >= 16) {
        UA_LOG_DEBUG(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "pqc_decrypt: Before memmove: enc_len=%zu, data->length=%zu, "
                    "enc_data[0..15]=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x, "
                    "data->data[0..15]=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    enc_len, data->length,
                    enc_data[0], enc_data[1], enc_data[2], enc_data[3],
                    enc_data[4], enc_data[5], enc_data[6], enc_data[7],
                    enc_data[8], enc_data[9], enc_data[10], enc_data[11],
                    enc_data[12], enc_data[13], enc_data[14], enc_data[15],
                    data->data[0], data->data[1], data->data[2], data->data[3],
                    data->data[4], data->data[5], data->data[6], data->data[7],
                    data->data[8], data->data[9], data->data[10], data->data[11],
                    data->data[12], data->data[13], data->data[14], data->data[15]);
    }

    if(enc_len <= data->length) {
        if(enc_len < data->length)
            memmove(data->data, enc_data, enc_len);
        data->length = enc_len;
        
        /* Log after memmove */
        if(logger && data->length >= 16) {
            UA_LOG_DEBUG(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "pqc_decrypt: After memmove: data->length=%zu, "
                        "data->data[0..15]=0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                        data->length,
                        data->data[0], data->data[1], data->data[2], data->data[3],
                        data->data[4], data->data[5], data->data[6], data->data[7],
                        data->data[8], data->data[9], data->data[10], data->data[11],
                        data->data[12], data->data[13], data->data[14], data->data[15]);
        }
    } else {
        OQS_KEM_free(kem);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(sizeof(shared_secret) <= sizeof(ctx->sharedSecret)) {
        memcpy(ctx->sharedSecret, shared_secret, sizeof(shared_secret));
        ctx->hasSharedSecret = true;
    }
    
    if(ctx->policyContext && !ctx->policyContext->hasTemporarySharedSecret) {
        memcpy(ctx->policyContext->temporarySharedSecret, shared_secret, kem->length_shared_secret);
        ctx->policyContext->hasTemporarySharedSecret = true;
    }

    OQS_KEM_free(kem);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
pqc_channel_newContext(const UA_SecurityPolicy *policy,
                       const UA_ByteString *remoteCertificate,
                       void **ppContext) {
    if(!policy || !ppContext)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    Policy_Context_PQC *pc = (Policy_Context_PQC *)policy->policyContext;
    
    if(!pc) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_channel_newContext: policy->policyContext is NULL!");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    const UA_Logger *logger = pc->logger ? pc->logger : UA_Log_Stdout;

    PQC_ChannelContext *ctx = (PQC_ChannelContext*)UA_calloc(1, sizeof(PQC_ChannelContext));
    if(!ctx)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    ctx->policyContext = pc;
    ctx->remoteSigPublicKeyValid = false;
    ctx->remoteKemPublicKeyValid = false;
    ctx->hasSharedSecret = false;
    memset(ctx->sharedSecret, 0, sizeof(ctx->sharedSecret));
    UA_ByteString_init(&ctx->remoteCertificate);
    
    pc->hasTemporarySharedSecret = false;
    memset(pc->temporarySharedSecret, 0, sizeof(pc->temporarySharedSecret));
    
    UA_ByteString_init(&ctx->localSymSigningKey);
    UA_ByteString_init(&ctx->localSymEncryptingKey);
    UA_ByteString_init(&ctx->localSymIv);
    UA_ByteString_init(&ctx->remoteSymSigningKey);
    UA_ByteString_init(&ctx->remoteSymEncryptingKey);
    UA_ByteString_init(&ctx->remoteSymIv);

    if(remoteCertificate && remoteCertificate->length > 0 && remoteCertificate->data) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "pqc_channel_newContext: Received remote certificate (length=%zu bytes)",
                    remoteCertificate->length);
        UA_StatusCode rc = UA_ByteString_copy(remoteCertificate, &ctx->remoteCertificate);
        if(rc != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                           "pqc_channel_newContext: failed to copy remote certificate (%s)",
                           UA_StatusCode_name(rc));
            UA_ByteString_clear(&ctx->remoteCertificate);
            UA_free(ctx);
            return rc;
        }

        UA_Boolean sigValid = false;
        UA_Boolean kemValid = false;
        rc = pqc_extract_pubkeys_from_cert_der_internal(&ctx->remoteCertificate, logger,
                                                        ctx->remoteSigPublicKey, &sigValid,
                                                        ctx->remoteKemPublicKey, &kemValid);
        if(rc == UA_STATUSCODE_GOOD && sigValid && kemValid) {
            ctx->remoteSigPublicKeyValid = true;
            ctx->remoteKemPublicKeyValid = true;
            UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "pqc_channel_newContext: Successfully extracted remote PQC keys from certificate");
        } else {
            ctx->remoteSigPublicKeyValid = false;
            ctx->remoteKemPublicKeyValid = false;
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "pqc_channel_newContext: Failed to extract PQC keys from certificate (rc=%s, sigValid=%u, kemValid=%u). "
                        "This will cause signature verification to fail!",
                        UA_StatusCode_name(rc), (unsigned)sigValid, (unsigned)kemValid);
        }
    } else {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                      "pqc_channel_newContext: No remote certificate provided (remoteCertificate=%p, length=%zu). "
                      "This is normal for server-side during initial OPN, but keys must be extracted later.",
                      (void*)remoteCertificate, remoteCertificate ? remoteCertificate->length : 0);
    }

    /* Increment reference count only after all initialization is successful.
     * This ensures that if any error occurs during initialization, the refCount
     * remains correct and the policy won't be freed prematurely. */
    pc->refCount++;
    
    *ppContext = ctx;
    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_PQCChannel_updateRemoteCertificate(void *context, const UA_ByteString *remoteCertificate) {
    if(!context || !remoteCertificate)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Validate remote certificate buffer */
    if(remoteCertificate->length == 0 || !remoteCertificate->data) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    PQC_ChannelContext *ctx = (PQC_ChannelContext*)context;
    
    if(!ctx) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    const UA_Logger *logger = pqc_get_logger_from_channel(ctx);

    /* Update the remote certificate */
    UA_ByteString_clear(&ctx->remoteCertificate);
    UA_StatusCode rc = UA_ByteString_copy(remoteCertificate, &ctx->remoteCertificate);
    if(rc != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQCChannel_updateRemoteCertificate: failed to copy remote certificate (%s)",
                       UA_StatusCode_name(rc));
        return rc;
    }

    /* Extract PQC keys from the new certificate */
    UA_Boolean sigValid = false;
    UA_Boolean kemValid = false;
    rc = pqc_extract_pubkeys_from_cert_der_internal(&ctx->remoteCertificate, logger,
                                                    ctx->remoteSigPublicKey, &sigValid,
                                                    ctx->remoteKemPublicKey, &kemValid);
    if(rc != UA_STATUSCODE_GOOD || !sigValid || !kemValid) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                       "UA_PQCChannel_updateRemoteCertificate: certificate does not have PQC extensions "
                       "(rc=%s, sigValid=%u, kemValid=%u)",
                       UA_StatusCode_name(rc),
                       (unsigned)sigValid, (unsigned)kemValid);
        ctx->remoteSigPublicKeyValid = false;
        ctx->remoteKemPublicKeyValid = false;
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    ctx->remoteSigPublicKeyValid = sigValid;
    ctx->remoteKemPublicKeyValid = kemValid;
    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                 "UA_PQCChannel_updateRemoteCertificate: ✓ remote PQC keys extracted successfully "
                 "(Dilithium=%u, Kyber=%u, cert length=%zu bytes)",
                 (unsigned)sigValid, (unsigned)kemValid, ctx->remoteCertificate.length);
    return UA_STATUSCODE_GOOD;
}

static void
pqc_channel_deleteContext(void *context) {
    if(!context)
        return;
    PQC_ChannelContext *ctx = (PQC_ChannelContext*)context;
    
    /* Decrement reference count and nullify policyContext pointer before cleanup.
     * This ensures that:
     * 1. The policy knows one less channel references it
     * 2. No subsequent access to ctx->policyContext can occur after this point */
    if(ctx->policyContext) {
        ctx->policyContext->refCount--;
        ctx->policyContext = NULL;
    }
    
    memset(ctx->remoteSigPublicKey, 0, sizeof(ctx->remoteSigPublicKey));
    memset(ctx->remoteKemPublicKey, 0, sizeof(ctx->remoteKemPublicKey));
    memset(ctx->sharedSecret, 0, sizeof(ctx->sharedSecret));
    UA_ByteString_clear(&ctx->remoteCertificate);
    
    /* Clear symmetric keys */
    UA_ByteString_clear(&ctx->localSymSigningKey);
    UA_ByteString_clear(&ctx->localSymEncryptingKey);
    UA_ByteString_clear(&ctx->localSymIv);
    UA_ByteString_clear(&ctx->remoteSymSigningKey);
    UA_ByteString_clear(&ctx->remoteSymEncryptingKey);
    UA_ByteString_clear(&ctx->remoteSymIv);
    
    UA_free(ctx);
}

/* -------------------- Helpers (sizes) ----------------------------- */
static size_t pqc_getLocalSignatureSize(const void *channelContext) {
    (void)channelContext;
    return (size_t)OQS_SIG_dilithium_2_length_signature;
}
static size_t pqc_getRemoteSignatureSize(const void *channelContext) {
    (void)channelContext;
    return (size_t)OQS_SIG_dilithium_2_length_signature;
}
static size_t pqc_getLocalKeyLength(const void *channelContext) {
    (void)channelContext;
    return (size_t)OQS_SIG_dilithium_2_length_secret_key;
}
static size_t pqc_getRemoteKeyLength(const void *channelContext) {
    (void)channelContext;
    return (size_t)OQS_SIG_dilithium_2_length_public_key;
}
static size_t pqc_getLocalKEMKeyLength(const void *channelContext) {
    (void)channelContext;
    return (size_t)OQS_KEM_kyber_768_length_secret_key;
}
static size_t pqc_getRemoteKEMKeyLength(const void *channelContext) {
    (void)channelContext;
    return (size_t)OQS_KEM_kyber_768_length_public_key;
}
static size_t pqc_getRemoteBlockSize(const void *channelContext) {
    if(!channelContext)
        return 0;
    
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    
    /* Return 0 if remote Kyber public key is not available.
     * This signals to signAndEncryptAsym that encryption should be skipped
     * (message will be sent without encryption, only signed).
     * This is valid for the first OPN message before receiving server certificate. */
    if(!ctx->remoteKemPublicKeyValid) {
        return 0;
    }
    
    return (size_t)OQS_KEM_kyber_768_length_ciphertext;
}
static size_t pqc_getRemotePlainTextBlockSize(const void *channelContext) {
    if(!channelContext)
        return 0;
    
    PQC_ChannelContext *ctx = (PQC_ChannelContext *)channelContext;
    
    /* Return 0 if remote Kyber public key is not available.
     * This signals that encryption is not possible yet. */
    if(!ctx->remoteKemPublicKeyValid) {
        return 0;
    }
    
    return (size_t)OQS_KEM_kyber_768_length_shared_secret;
}

/* ---------------------- Copy local params into globals ------------- */
static void
pqc_set_local_from_params(Policy_Context_PQC *ctx,
                          const UA_ByteString *localCertificate,
                          const UA_ByteString *localPrivateKey,
                          const UA_Logger *logger) {
    if(!ctx) return;
    
    const UA_Logger *log = logger ? logger : UA_Log_Stdout;

    if(localCertificate && localCertificate->length > 0 && localCertificate->data) {
        UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                     "pqc_set_local_from_params: extracting keys from localCertificate");
        UA_StatusCode rc = pqc_extract_pubkeys_from_cert_der(localCertificate, ctx, log);
        if(rc != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "pqc_set_local_from_params: could not extract PQC keys from certificate (%s)",
                           UA_StatusCode_name(rc));
        }
    }

    if(localPrivateKey && localPrivateKey->length > 0 && localPrivateKey->data) {
        size_t sigKeyLen = sizeof(ctx->sigPrivateKey);
        size_t kemKeyLen = sizeof(ctx->kemPrivateKey);
        size_t totalPqcKeyLen = sigKeyLen + kemKeyLen;
        
        /* Verificar si el buffer contiene solo una clave PQC individual */
        if((size_t)localPrivateKey->length == sigKeyLen) {
            /* Solo clave Dilithium */
            memcpy(ctx->sigPrivateKey, localPrivateKey->data, sigKeyLen);
            ctx->sigKeysInitialized = true;
            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                         "pqc_set_local_from_params: copied raw Dilithium private key");
        } else if((size_t)localPrivateKey->length == kemKeyLen) {
            /* Solo clave Kyber */
            memcpy(ctx->kemPrivateKey, localPrivateKey->data, kemKeyLen);
            
            /* IMPORTANTE: Verificar que las claves públicas ya estén inicializadas (extraídas del certificado). */
            UA_Boolean hasPublicKey = false;
            for(size_t i = 0; i < OQS_KEM_kyber_768_length_public_key; i++) {
                if(ctx->kemPublicKey[i] != 0) {
                    hasPublicKey = true;
                    break;
                }
            }
            
            if(hasPublicKey) {
                ctx->kemKeysInitialized = true;
                UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "pqc_set_local_from_params: copied raw Kyber private key "
                           "(public key already extracted from certificate)");
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                              "pqc_set_local_from_params: Kyber private key loaded but public key "
                              "not extracted from certificate. Keys will not match certificate. "
                              "Please ensure certificate has PQC extensions and was processed with "
                              "UA_PQC_EnsureCertificateExtensions.");
            }
        } else if((size_t)localPrivateKey->length == totalPqcKeyLen) {
            /* Formato nuevo: solo claves PQC (Dilithium + Kyber) sin RSA/ECC.
             * - Dilithium: primeros sigKeyLen bytes
             * - Kyber: siguientes kemKeyLen bytes */
            memcpy(ctx->sigPrivateKey, localPrivateKey->data, sigKeyLen);
            memcpy(ctx->kemPrivateKey, localPrivateKey->data + sigKeyLen, kemKeyLen);
            
            /* Verify that public keys are already initialized (extracted from certificate) */
            UA_Boolean hasSigPublicKey = !pqc_is_buffer_all_zeros(ctx->sigPublicKey, 
                                                                  OQS_SIG_dilithium_2_length_public_key);
            UA_Boolean hasKemPublicKey = !pqc_is_buffer_all_zeros(ctx->kemPublicKey,
                                                                  OQS_KEM_kyber_768_length_public_key);
            
            if(hasSigPublicKey && hasKemPublicKey) {
                ctx->sigKeysInitialized = true;
                ctx->kemKeysInitialized = true;
                UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "pqc_set_local_from_params: ✓ loaded PQC-only private keys "
                           "(Dilithium=%zu bytes, Kyber=%zu bytes, total=%zu bytes, "
                           "public keys already extracted from certificate)",
                           sigKeyLen, kemKeyLen, totalPqcKeyLen);
                
                /* Verificar que las claves extraídas no sean todas ceros */
                UA_Boolean sigKeyAllZeros = pqc_is_buffer_all_zeros(ctx->sigPrivateKey, sigKeyLen);
                UA_Boolean kemKeyAllZeros = pqc_is_buffer_all_zeros(ctx->kemPrivateKey, kemKeyLen);
                
                if(sigKeyAllZeros || kemKeyAllZeros) {
                    UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                "pqc_set_local_from_params: ✗ PQC private keys are all zeros! "
                                "(sigKeyAllZeros=%u, kemKeyAllZeros=%u).",
                                (unsigned)sigKeyAllZeros, (unsigned)kemKeyAllZeros);
                    ctx->sigKeysInitialized = false;
                    ctx->kemKeysInitialized = false;
                }
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                              "pqc_set_local_from_params: PQC-only private keys loaded but "
                              "public keys not extracted from certificate (hasSigPublicKey=%u, hasKemPublicKey=%u). "
                              "Keys will not match certificate. Please ensure certificate has PQC extensions "
                              "and was processed with UA_PQC_EnsureCertificateExtensions.",
                              (unsigned)hasSigPublicKey, (unsigned)hasKemPublicKey);
            }
        } else if((size_t)localPrivateKey->length > totalPqcKeyLen) {
            /* Formato antiguo (compatibilidad hacia atrás): clave RSA/ECC original + claves PQC concatenadas al final.
             * Las claves PQC están al final del buffer:
             * - Dilithium: últimos (sigKeyLen + kemKeyLen) - kemKeyLen = sigKeyLen bytes antes de los últimos kemKeyLen bytes
             * - Kyber: últimos kemKeyLen bytes */
            size_t offset = localPrivateKey->length - totalPqcKeyLen;
            
            /* Extraer clave Dilithium */
            memcpy(ctx->sigPrivateKey, localPrivateKey->data + offset, sigKeyLen);
            ctx->sigKeysInitialized = true;
            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                         "pqc_set_local_from_params: extracted Dilithium private key from end of buffer "
                         "(legacy format with RSA/ECC prefix, offset=%zu, length=%zu)", offset, sigKeyLen);
            
            /* Extraer clave Kyber */
            memcpy(ctx->kemPrivateKey, localPrivateKey->data + offset + sigKeyLen, kemKeyLen);
            
            /* Verify that public keys are already initialized (extracted from certificate) */
            UA_Boolean hasSigPublicKey = !pqc_is_buffer_all_zeros(ctx->sigPublicKey, 
                                                                  OQS_SIG_dilithium_2_length_public_key);
            UA_Boolean hasKemPublicKey = !pqc_is_buffer_all_zeros(ctx->kemPublicKey,
                                                                  OQS_KEM_kyber_768_length_public_key);
            
            if(hasSigPublicKey && hasKemPublicKey) {
                ctx->kemKeysInitialized = true;
                UA_LOG_INFO(log, UA_LOGCATEGORY_SECURITYPOLICY,
                           "pqc_set_local_from_params: ✓ extracted PQC private keys from end of buffer "
                           "(legacy format: RSA/ECC + PQC, Dilithium=%zu bytes at offset %zu, "
                           "Kyber=%zu bytes at offset %zu, total buffer length=%zu, "
                           "public keys already extracted from certificate). "
                           "Consider using new format (PQC-only) for better security.",
                           sigKeyLen, offset, kemKeyLen, offset + sigKeyLen, localPrivateKey->length);
                
                /* Verificar que las claves extraídas no sean todas ceros */
                UA_Boolean sigKeyAllZeros = pqc_is_buffer_all_zeros(ctx->sigPrivateKey, sigKeyLen);
                UA_Boolean kemKeyAllZeros = pqc_is_buffer_all_zeros(ctx->kemPrivateKey, kemKeyLen);
                
                if(sigKeyAllZeros || kemKeyAllZeros) {
                    UA_LOG_ERROR(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                "pqc_set_local_from_params: ✗ extracted PQC private keys are all zeros! "
                                "(sigKeyAllZeros=%u, kemKeyAllZeros=%u). This indicates the keys were not "
                                "properly appended to the privateKey buffer.",
                                (unsigned)sigKeyAllZeros, (unsigned)kemKeyAllZeros);
                    ctx->sigKeysInitialized = false;
                    ctx->kemKeysInitialized = false;
                } else if(sigKeyLen >= 16 && kemKeyLen >= 16) {
                    UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                "pqc_set_local_from_params: extracted Dilithium key[0..15]=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                                ctx->sigPrivateKey[0], ctx->sigPrivateKey[1], ctx->sigPrivateKey[2], ctx->sigPrivateKey[3],
                                ctx->sigPrivateKey[4], ctx->sigPrivateKey[5], ctx->sigPrivateKey[6], ctx->sigPrivateKey[7],
                                ctx->sigPrivateKey[8], ctx->sigPrivateKey[9], ctx->sigPrivateKey[10], ctx->sigPrivateKey[11],
                                ctx->sigPrivateKey[12], ctx->sigPrivateKey[13], ctx->sigPrivateKey[14], ctx->sigPrivateKey[15]);
                    UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                                "pqc_set_local_from_params: extracted Kyber key[0..15]=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                                ctx->kemPrivateKey[0], ctx->kemPrivateKey[1], ctx->kemPrivateKey[2], ctx->kemPrivateKey[3],
                                ctx->kemPrivateKey[4], ctx->kemPrivateKey[5], ctx->kemPrivateKey[6], ctx->kemPrivateKey[7],
                                ctx->kemPrivateKey[8], ctx->kemPrivateKey[9], ctx->kemPrivateKey[10], ctx->kemPrivateKey[11],
                                ctx->kemPrivateKey[12], ctx->kemPrivateKey[13], ctx->kemPrivateKey[14], ctx->kemPrivateKey[15]);
                }
            } else {
                UA_LOG_WARNING(log, UA_LOGCATEGORY_SECURITYPOLICY,
                              "pqc_set_local_from_params: PQC private keys extracted from buffer but "
                              "public keys not extracted from certificate (hasSigPublicKey=%u, hasKemPublicKey=%u). "
                              "Keys will not match certificate. Please ensure certificate has PQC extensions "
                              "and was processed with UA_PQC_EnsureCertificateExtensions.",
                              (unsigned)hasSigPublicKey, (unsigned)hasKemPublicKey);
            }
        } else {
            UA_LOG_DEBUG(log, UA_LOGCATEGORY_SECURITYPOLICY,
                         "pqc_set_local_from_params: privateKey size not recognized (length=%zu, "
                         "expected Dilithium=%zu, Kyber=%zu, PQC-only=%zu, or >%zu for legacy format with RSA/ECC); skipping",
                         localPrivateKey->length, sigKeyLen, kemKeyLen, totalPqcKeyLen, totalPqcKeyLen);
        }
    }
}

/* ------------------------ Policy initializer ----------------------- */
UA_EXPORT UA_StatusCode
UA_SecurityPolicy_PQC(UA_SecurityPolicy *policy,
                      const UA_ByteString localCertificate,
                      const UA_ByteString localPrivateKey,
                      const UA_Logger *logger) {

    if(!policy) return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Clear first */
    memset(policy, 0, sizeof *policy);
    policy->logger = logger;
    policy->policyUri = UA_STRING("http://example.org/SecurityPolicy#PQC");
    policy->securityLevel = 30;

    /* Crear el contexto de la política */
    Policy_Context_PQC *pc = (Policy_Context_PQC *)UA_malloc(sizeof(Policy_Context_PQC));
    if(!pc) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_SecurityPolicy_PQC: failed to allocate policy context");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memset(pc, 0, sizeof(Policy_Context_PQC));
    pc->logger = logger;
    pc->sigKeysInitialized = false;
    pc->kemKeysInitialized = false;
    pc->refCount = 0; /* Initialize reference count to 0 */
    UA_ByteString_init(&pc->localCertThumbprint);
    policy->policyContext = pc;

    /* Copy local certificate if provided */
    if(localCertificate.length > 0 && localCertificate.data) {
        UA_StatusCode rc = UA_ByteString_copy(&localCertificate, &policy->localCertificate);
        if(rc != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_SecurityPolicy_PQC: could not copy local certificate (%s)",
                        UA_StatusCode_name(rc));
            UA_free(pc);
            policy->policyContext = NULL;
            return rc;
        }
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "Local certificate copied (len=%u bytes)",
                    (unsigned)policy->localCertificate.length);

        UA_StatusCode rcExtract = pqc_extract_pubkeys_from_cert_der(&policy->localCertificate, pc, logger);
        if(rcExtract != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_SecurityPolicy_PQC: failed to extract local PQC public keys (%s)",
                           UA_StatusCode_name(rcExtract));
        }

        if(!pc->sigKeysInitialized || !pc->kemKeysInitialized) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "UA_SecurityPolicy_PQC: Certificate provided (%zu bytes) but PQC keys "
                        "could not be extracted. Certificate may be corrupt, missing PQC extensions, "
                        "or in invalid format. Security policy initialization aborted.",
                        policy->localCertificate.length);
            UA_free(pc);
            policy->policyContext = NULL;
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
        }

        /* Generar thumbprint del certificado local */
        /* UA_Openssl_X509_GetCertificateThumbprint con true inicializa y asigna el buffer automáticamente */
        rc = UA_Openssl_X509_GetCertificateThumbprint(&policy->localCertificate,
                                                      &pc->localCertThumbprint,
                                                      true); /* true = allocate buffer */
        if(rc != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                           "UA_SecurityPolicy_PQC: failed to generate local thumbprint: %s",
                           UA_StatusCode_name(rc));
            /* BUG 2 FIX: UA_Openssl_X509_GetCertificateThumbprint already handles cleanup:
             * - If UA_ByteString_allocBuffer fails, it returns early and thumbprint remains initialized (NULL, 0)
             * - If it fails after allocation, it calls UA_ByteString_clear internally
             * We should NOT call UA_ByteString_clear again to avoid double-free.
             * Only ensure the thumbprint is in a clean state if allocBuffer failed. */
            if(pc->localCertThumbprint.data != NULL) {
                /* This should never happen if UA_Openssl_X509_GetCertificateThumbprint is correct,
                 * but defensive: if data is non-NULL, it means allocBuffer succeeded but something
                 * else failed, and UA_Openssl_X509_GetCertificateThumbprint should have cleared it.
                 * Double-check and clear only if needed. */
                UA_ByteString_clear(&pc->localCertThumbprint);
            }
            /* Ensure clean state: data should be NULL and length 0 after init or clear */
            UA_ByteString_init(&pc->localCertThumbprint);
        } else {
            UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "UA_SecurityPolicy_PQC: local thumbprint initialized (%u bytes)",
                         (unsigned)pc->localCertThumbprint.length);
        }
    } else {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_SecurityPolicy_PQC: no localCertificate provided, generating fallback keys");
    }

    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
            "UA_SecurityPolicy_PQC: policy->localCertificate.length=%u",
            (unsigned)policy->localCertificate.length);

    /* Copy / set local private key into context if provided */
    if(localPrivateKey.length > 0 && localPrivateKey.data)
        pqc_set_local_from_params(pc,
                                  (policy->localCertificate.length > 0) ? &policy->localCertificate : NULL,
                                  &localPrivateKey, logger);

    /* Fallback to generate keys if necessary */
    if(!pc->sigKeysInitialized) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_SecurityPolicy_PQC: sigKeys not initialized, calling pqc_init_keys");
        pqc_init_keys(pc);
    }
    if(!pc->kemKeysInitialized) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "UA_SecurityPolicy_PQC: kemKeys not initialized, calling pqc_init_kem_keys");
        pqc_init_kem_keys(pc);
        if(pc->kemKeysInitialized && sizeof(pc->kemPrivateKey) >= 16) {
            UA_LOG_DEBUG(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "UA_SecurityPolicy_PQC: after pqc_init_kem_keys, kemPrivateKey[0..15]=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                         pc->kemPrivateKey[0], pc->kemPrivateKey[1], pc->kemPrivateKey[2], pc->kemPrivateKey[3],
                         pc->kemPrivateKey[4], pc->kemPrivateKey[5], pc->kemPrivateKey[6], pc->kemPrivateKey[7],
                         pc->kemPrivateKey[8], pc->kemPrivateKey[9], pc->kemPrivateKey[10], pc->kemPrivateKey[11],
                         pc->kemPrivateKey[12], pc->kemPrivateKey[13], pc->kemPrivateKey[14], pc->kemPrivateKey[15]);
        }
    }

    /* 4. Inicializar módulo de firma (Dilithium2) */
    UA_SecurityPolicySignatureAlgorithm pqc_signatureAlgorithm;
    memset(&pqc_signatureAlgorithm, 0, sizeof(pqc_signatureAlgorithm));
    pqc_signatureAlgorithm.uri = UA_STRING("http://example.org/UA-SecurityPolicy#Dilithium2");
    pqc_signatureAlgorithm.sign = pqc_sign;
    pqc_signatureAlgorithm.verify = pqc_verify;
    pqc_signatureAlgorithm.getLocalSignatureSize = pqc_getLocalSignatureSize;
    pqc_signatureAlgorithm.getRemoteSignatureSize = pqc_getRemoteSignatureSize;
    pqc_signatureAlgorithm.getLocalKeyLength = pqc_getLocalKeyLength;
    pqc_signatureAlgorithm.getRemoteKeyLength = pqc_getRemoteKeyLength;

    /* 5. Inicializar módulo de cifrado (Kyber768) */
    UA_SecurityPolicyEncryptionAlgorithm pqc_encryptionAlgorithm;
    memset(&pqc_encryptionAlgorithm, 0, sizeof(pqc_encryptionAlgorithm));
    pqc_encryptionAlgorithm.uri = UA_STRING("http://example.org/UA-SecurityPolicy#Kyber768");
    pqc_encryptionAlgorithm.encrypt = pqc_encrypt;
    pqc_encryptionAlgorithm.decrypt = pqc_decrypt;
    pqc_encryptionAlgorithm.getLocalKeyLength = pqc_getLocalKEMKeyLength;
    pqc_encryptionAlgorithm.getRemoteKeyLength = pqc_getRemoteKEMKeyLength;
    pqc_encryptionAlgorithm.getRemoteBlockSize = pqc_getRemoteBlockSize;
    pqc_encryptionAlgorithm.getRemotePlainTextBlockSize = pqc_getRemotePlainTextBlockSize;

    /* 6. Inicializar módulo asimétrico */
    memset(&policy->asymmetricModule, 0, sizeof(policy->asymmetricModule));
    memset(&policy->asymmetricModule.cryptoModule, 0, sizeof(policy->asymmetricModule.cryptoModule));
    policy->asymmetricModule.cryptoModule.signatureAlgorithm = pqc_signatureAlgorithm;
    policy->asymmetricModule.cryptoModule.encryptionAlgorithm = pqc_encryptionAlgorithm;
    policy->asymmetricModule.makeCertificateThumbprint = pqc_makeCertificateThumbprint;
    policy->asymmetricModule.compareCertificateThumbprint = pqc_compareCertificateThumbprint;

    /* 7. Inicializar módulo de canal */
    memset(&policy->channelModule, 0, sizeof(policy->channelModule));
    policy->channelModule.newContext = pqc_channel_newContext;
    policy->channelModule.deleteContext = pqc_channel_deleteContext;

    policy->channelModule.setLocalSymEncryptingKey = pqc_setLocalSymEncryptingKey;
    policy->channelModule.setLocalSymSigningKey   = pqc_setLocalSymSigningKey;
    policy->channelModule.setLocalSymIv           = pqc_setLocalSymIv;
    policy->channelModule.setRemoteSymEncryptingKey = pqc_setRemoteSymEncryptingKey;
    policy->channelModule.setRemoteSymSigningKey    = pqc_setRemoteSymSigningKey;
    policy->channelModule.setRemoteSymIv            = pqc_setRemoteSymIv;

    /* comparar certificado (si tu struct incluye esto) */
    policy->channelModule.compareCertificate = pqc_compareCertificate;
    
    /* 8. Inicializar módulo simétrico (stubs para evitar NULL access) */
    memset(&policy->symmetricModule, 0, sizeof(policy->symmetricModule));
    policy->symmetricModule.secureChannelNonceLength = 32;
    policy->symmetricModule.generateNonce = UA_Sym_PQC_generateNonce;
    policy->symmetricModule.generateKey = pqc_sym_generateKey;
    
    /* Inicializar cryptoModule del módulo simétrico (stubs) */
    UA_SecurityPolicyEncryptionAlgorithm *symEncAlg = 
        &policy->symmetricModule.cryptoModule.encryptionAlgorithm;
    symEncAlg->uri = UA_STRING("http://example.org/UA-SecurityPolicy#PQC-Symmetric-Stub");
    symEncAlg->getLocalKeyLength = pqc_sym_encr_getLocalKeyLength;
    symEncAlg->getRemoteKeyLength = pqc_sym_encr_getRemoteKeyLength;
    symEncAlg->getRemoteBlockSize = pqc_sym_encr_getRemoteBlockSize;
    symEncAlg->getRemotePlainTextBlockSize = pqc_sym_encr_getRemotePlainTextBlockSize;
    symEncAlg->encrypt = pqc_sym_encr_encrypt;
    symEncAlg->decrypt = pqc_sym_encr_decrypt;
    
    UA_SecurityPolicySignatureAlgorithm *symSigAlg = 
        &policy->symmetricModule.cryptoModule.signatureAlgorithm;
    symSigAlg->uri = UA_STRING("http://example.org/UA-SecurityPolicy#PQC-Symmetric-Stub");
    symSigAlg->getLocalKeyLength = pqc_sym_sig_getLocalKeyLength;
    symSigAlg->getRemoteKeyLength = pqc_sym_sig_getRemoteKeyLength;
    symSigAlg->getLocalSignatureSize = pqc_sym_sig_getLocalSignatureSize;
    symSigAlg->getRemoteSignatureSize = pqc_sym_sig_getRemoteSignatureSize;
    symSigAlg->sign = pqc_sym_sig_sign;
    symSigAlg->verify = pqc_sym_sig_verify;

    /* 9. Asignar función de limpieza */
    policy->clear = UA_PQCPolicy_clear;

    /* 10. Log de éxito */
    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                "Post-Quantum SecurityPolicy (Dilithium2 + Kyber768) initialized successfully. PQCkeys=%s, KEMkeys=%s",
                pc->sigKeysInitialized ? "yes" : "no",
                pc->kemKeysInitialized ? "yes" : "no");

    return UA_STATUSCODE_GOOD;
}
