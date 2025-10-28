#include "open62541/plugin/securitypolicy.h"
#include "open62541/server_config_default.h"
#include "open62541/plugin/log_stdout.h"
#include <oqs/oqs.h>
#include <string.h>
#include <open62541/plugin/securitypolicy_pqc.h>

static uint8_t pk_global[OQS_SIG_dilithium_2_length_public_key];
static uint8_t sk_global[OQS_SIG_dilithium_2_length_secret_key];
static UA_Boolean pqc_keys_initialized = false;

static uint8_t kem_pk_global[OQS_KEM_kyber_768_length_public_key];
static uint8_t kem_sk_global[OQS_KEM_kyber_768_length_secret_key];
static UA_Boolean kem_keys_initialized = false;

static void
pqc_init_keys(void) {
    if(pqc_keys_initialized)
        return;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if(!sig)
        return;

    if(OQS_SIG_keypair(sig, pk_global, sk_global) == OQS_SUCCESS)
        pqc_keys_initialized = true;

    OQS_SIG_free(sig);
}

static void
pqc_init_kem_keys(void) {
    if(kem_keys_initialized)
        return;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if(!kem)
        return;

    if(OQS_KEM_keypair(kem, kem_pk_global, kem_sk_global) == OQS_SUCCESS)
        kem_keys_initialized = true;

    OQS_KEM_free(kem);
}

// Dilithium sign

static UA_StatusCode
pqc_sign(void *context, const UA_ByteString *message, UA_ByteString *signature) {
    pqc_init_keys();

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if(!sig)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    signature->data = (uint8_t*)UA_malloc(sig->length_signature);
    if(!signature->data) {
        OQS_SIG_free(sig);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    size_t siglen = 0;
    OQS_STATUS rc = OQS_SIG_sign(sig, signature->data, &siglen,
                                 message->data, message->length, sk_global);

    signature->length = (size_t)siglen;
    OQS_SIG_free(sig);

    return (rc == OQS_SUCCESS) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADINTERNALERROR;
}

// Dilithium verify

static UA_StatusCode
pqc_verify(void *context, const UA_ByteString *message, const UA_ByteString *signature) {
    pqc_init_keys();

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if(!sig)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    OQS_STATUS rc = OQS_SIG_verify(sig,
                                   message->data, message->length,
                                   signature->data, signature->length,
                                   pk_global);

    OQS_SIG_free(sig);
    return (rc == OQS_SUCCESS) ? UA_STATUSCODE_GOOD : UA_STATUSCODE_BADSECURITYCHECKSFAILED;
}

// Kyber cypher

static UA_StatusCode
pqc_encrypt(void *context, UA_ByteString *data) {
    pqc_init_kem_keys();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if(!kem)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
    uint8_t shared_secret[OQS_KEM_kyber_768_length_shared_secret];

    if(OQS_KEM_encaps(kem, ciphertext, shared_secret, kem_pk_global) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* XOR simple con la clave compartida para simular cifrado simétrico */
    for(size_t i = 0; i < data->length; i++)
        data->data[i] ^= shared_secret[i % kem->length_shared_secret];

    /* Adjuntamos el ciphertext de Kyber (necesario para descifrar) */
    UA_ByteString newData;
    newData.length = data->length + kem->length_ciphertext;
    newData.data = (uint8_t*)UA_malloc(newData.length);

    memcpy(newData.data, ciphertext, kem->length_ciphertext);
    memcpy(newData.data + kem->length_ciphertext, data->data, data->length);

    UA_free(data->data);
    *data = newData;

    OQS_KEM_free(kem);
    return UA_STATUSCODE_GOOD;
}

// Kyber decypher

static UA_StatusCode
pqc_decrypt(void *context, UA_ByteString *data) {
    pqc_init_kem_keys();

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if(!kem)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    if(data->length < kem->length_ciphertext) {
        OQS_KEM_free(kem);
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    uint8_t *ciphertext = data->data;
    uint8_t *enc_data = data->data + kem->length_ciphertext;
    size_t enc_len = data->length - kem->length_ciphertext;

    uint8_t shared_secret[OQS_KEM_kyber_768_length_shared_secret];
    if(OQS_KEM_decaps(kem, shared_secret, ciphertext, kem_sk_global) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
    }

    /* XOR inverso (simétrico) para descifrar */
    for(size_t i = 0; i < enc_len; i++)
        enc_data[i] ^= shared_secret[i % kem->length_shared_secret];

    /* Reemplazar data por el texto descifrado */
    UA_ByteString newData;
    newData.length = enc_len;
    newData.data = (uint8_t*)UA_malloc(enc_len);
    memcpy(newData.data, enc_data, enc_len);

    UA_free(data->data);
    *data = newData;

    OQS_KEM_free(kem);
    return UA_STATUSCODE_GOOD;
}

// PQC Init

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_PQC(UA_SecurityPolicy *policy,
                          const UA_ByteString localCertificate,
                          const UA_ByteString localPrivateKay,
                          const UA_Logger *logger) {

    if(!policy)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* 1. Inicialización del módulo de firma */
    UA_SecurityPolicySignatureAlgorithm pqc_signatureAlgorithm;
    pqc_signatureAlgorithm.uri = UA_STRING("http://example.org/UA-SecurityPolicy#Dilithium2");
    pqc_signatureAlgorithm.sign = pqc_sign;
    pqc_signatureAlgorithm.verify = pqc_verify;
    pqc_signatureAlgorithm.getLocalSignatureSize = NULL;
    pqc_signatureAlgorithm.getRemoteSignatureSize = NULL;
    pqc_signatureAlgorithm.getLocalKeyLength = NULL;
    pqc_signatureAlgorithm.getRemoteKeyLength = NULL;

    /* 2. Inicialización del módulo de cifrado */
    UA_SecurityPolicyEncryptionAlgorithm pqc_encryptionAlgorithm;
    pqc_encryptionAlgorithm.uri = UA_STRING("http://example.org/UA-SecurityPolicy#Kyber768");
    pqc_encryptionAlgorithm.encrypt = pqc_encrypt;
    pqc_encryptionAlgorithm.decrypt = pqc_decrypt;
    pqc_encryptionAlgorithm.getLocalKeyLength = NULL;
    pqc_encryptionAlgorithm.getRemoteKeyLength = NULL;
    pqc_encryptionAlgorithm.getRemoteBlockSize = NULL;
    pqc_encryptionAlgorithm.getRemotePlainTextBlockSize = NULL;

    /* 3. Asignación del módulo completo a la política */
    memset(policy, 0, sizeof(UA_SecurityPolicy));
    policy->policyUri = UA_STRING("http://example.org/SecurityPolicy#PQC");
    policy->logger = logger;

    policy->asymmetricModule.cryptoModule.signatureAlgorithm = pqc_signatureAlgorithm;
    policy->asymmetricModule.cryptoModule.encryptionAlgorithm = pqc_encryptionAlgorithm;

    UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                "The PQC security policy with oqs is added.");


    return UA_STATUSCODE_GOOD;
}