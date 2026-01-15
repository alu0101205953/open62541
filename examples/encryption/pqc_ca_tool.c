#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <openssl/opensslv.h>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <oqs/oqs.h>

#ifndef OQS_SIG_dilithium_2_length_public_key
#define OQS_SIG_dilithium_2_length_public_key 1312
#endif
#ifndef OQS_KEM_kyber_768_length_public_key
#define OQS_KEM_kyber_768_length_public_key 1184
#endif
#ifndef OQS_KEM_kyber_768_length_secret_key
#define OQS_KEM_kyber_768_length_secret_key 2400
#endif

#define OID_DILITHIUM_PUB "1.3.6.1.4.1.55336.1.1"
#define OID_KYBER_PUB     "1.3.6.1.4.1.55336.1.2"

static OSSL_PROVIDER *oqsProvider = NULL;

static int ensureDirectory(const char *path) {
    struct stat st;
    if(stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    char *pathCopy = strdup(path);
    if(!pathCopy) return -1;
    
    char *p = pathCopy;
    if(*p == '/') p++;
    
    while(*p) {
        if(*p == '/') {
            *p = '\0';
            if(mkdir(pathCopy, 0755) != 0 && errno != EEXIST) {
                free(pathCopy);
                return -1;
            }
            *p = '/';
        }
        p++;
    }
    if(mkdir(pathCopy, 0755) != 0 && errno != EEXIST) {
        free(pathCopy);
        return -1;
    }
    free(pathCopy);
    return 0;
}

static int writeFile(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if(!f) return -1;
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? 0 : -1;
}

static int readFile(const char *path, unsigned char **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if(!f) return -1;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *data = malloc(size);
    if(!*data) {
        fclose(f);
        return -1;
    }
    size_t read = fread(*data, 1, size, f);
    fclose(f);
    *len = read;
    return 0;
}

static int loadOQSProvider(void) {
    if(oqsProvider) return 0;
    oqsProvider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if(!oqsProvider) {
        oqsProvider = OSSL_PROVIDER_load(NULL, "oqs");
    }
    return oqsProvider ? 0 : -1;
}

static void unloadOQSProvider(void) {
    if(oqsProvider) {
        OSSL_PROVIDER_unload(oqsProvider);
        oqsProvider = NULL;
    }
}

static int generateDilithiumKey(EVP_PKEY **key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
    if(!ctx) return -1;
    
    if(EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    if(EVP_PKEY_generate(ctx, key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static int generateKyberKey(uint8_t *pubKey, uint8_t *privKey) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if(!kem) return -1;
    
    if(OQS_KEM_keypair(kem, pubKey, privKey) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return -1;
    }
    
    OQS_KEM_free(kem);
    return 0;
}

static int addOctetExtension(X509 *cert, const char *oid, const uint8_t *data, size_t len) {
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);
    if(!obj) return -1;
    
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    if(!oct) {
        ASN1_OBJECT_free(obj);
        return -1;
    }
    
    if(ASN1_OCTET_STRING_set(oct, data, (int)len) != 1) {
        ASN1_OCTET_STRING_free(oct);
        ASN1_OBJECT_free(obj);
        return -1;
    }
    
    X509_EXTENSION *ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 0, oct);
    ASN1_OCTET_STRING_free(oct);
    ASN1_OBJECT_free(obj);
    
    if(!ext) return -1;
    
    if(X509_add_ext(cert, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        return -1;
    }
    
    X509_EXTENSION_free(ext);
    return 0;
}

static int init_ca(void) {
    if(loadOQSProvider() != 0) {
        fprintf(stderr, "Error: Failed to load OQS Provider\n");
        return 1;
    }
    
    if(ensureDirectory("./local_ca") != 0) {
        fprintf(stderr, "Error: Failed to create local_ca directory\n");
        return 1;
    }
    
    EVP_PKEY *caKey = NULL;
    if(generateDilithiumKey(&caKey) != 0) {
        fprintf(stderr, "Error: Failed to generate CA key\n");
        return 1;
    }
    
    X509 *caCert = X509_new();
    if(!caCert) {
        EVP_PKEY_free(caKey);
        return 1;
    }
    
    X509_set_version(caCert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(caCert), 1);
    
    X509_gmtime_adj(X509_get_notBefore(caCert), 0);
    X509_gmtime_adj(X509_get_notAfter(caCert), 60 * 60 * 24 * 3650);
    
    X509_set_pubkey(caCert, caKey);
    
    X509_NAME *name = X509_get_subject_name(caCert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"DE", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"SampleOrganization", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Open62541LocalCA", -1, -1, 0);
    
    X509_set_issuer_name(caCert, name);
    
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, caCert, caCert, NULL, NULL, 0);
    
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:TRUE,pathlen:0");
    if(ext) X509_add_ext(caCert, ext, -1);
    if(ext) X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "keyCertSign,cRLSign");
    if(ext) X509_add_ext(caCert, ext, -1);
    if(ext) X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if(ext) X509_add_ext(caCert, ext, -1);
    if(ext) X509_EXTENSION_free(ext);
    
    uint8_t dilithiumPubKey[OQS_SIG_dilithium_2_length_public_key];
    size_t pubKeyLen = sizeof(dilithiumPubKey);
    if(EVP_PKEY_get_octet_string_param(caKey, OSSL_PKEY_PARAM_PUB_KEY, dilithiumPubKey, pubKeyLen, &pubKeyLen) ||
       EVP_PKEY_get_octet_string_param(caKey, "pub", dilithiumPubKey, pubKeyLen, &pubKeyLen)) {
        addOctetExtension(caCert, OID_DILITHIUM_PUB, dilithiumPubKey, pubKeyLen);
    }
    
    if(X509_sign(caCert, caKey, NULL) == 0) {
        if(X509_sign(caCert, caKey, EVP_sha256()) == 0) {
            fprintf(stderr, "Error: Failed to sign CA certificate\n");
            X509_free(caCert);
            EVP_PKEY_free(caKey);
            return 1;
        }
    }
    
    unsigned char *certDer = NULL;
    int certLen = i2d_X509(caCert, &certDer);
    if(certLen <= 0) {
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return 1;
    }
    
    unsigned char *keyDer = NULL;
    int keyLen = i2d_PrivateKey(caKey, &keyDer);
    if(keyLen <= 0) {
        OPENSSL_free(certDer);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return 1;
    }
    
    if(writeFile("./local_ca/ca_cert.der", certDer, certLen) != 0) {
        fprintf(stderr, "Error: Failed to write CA certificate\n");
        OPENSSL_free(certDer);
        OPENSSL_free(keyDer);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return 1;
    }
    
    if(writeFile("./local_ca/ca_key.der", keyDer, keyLen) != 0) {
        fprintf(stderr, "Error: Failed to write CA key\n");
        OPENSSL_free(certDer);
        OPENSSL_free(keyDer);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return 1;
    }
    
    OPENSSL_free(certDer);
    OPENSSL_free(keyDer);
    
    if(ensureDirectory("./local_ca/crl") != 0) {
        fprintf(stderr, "Warning: Failed to create crl directory\n");
    } else {
        X509_CRL *crl = X509_CRL_new();
        if(crl) {
            X509_CRL_set_version(crl, 1);
            X509_CRL_set_issuer_name(crl, name);
            X509_gmtime_adj(X509_CRL_get_lastUpdate(crl), 0);
            X509_gmtime_adj(X509_CRL_get_nextUpdate(crl), 60 * 60 * 24 * 365);
            
            if(X509_CRL_sign(crl, caKey, NULL) == 0) {
                if(X509_CRL_sign(crl, caKey, EVP_sha256()) != 0) {
                    unsigned char *crlDer = NULL;
                    int crlLen = i2d_X509_CRL(crl, &crlDer);
                    if(crlLen > 0) {
                        writeFile("./local_ca/crl/ca.crl", crlDer, crlLen);
                        OPENSSL_free(crlDer);
                    }
                }
            }
            X509_CRL_free(crl);
        }
    }
    
    X509_free(caCert);
    EVP_PKEY_free(caKey);
    
    printf("CA created successfully: ./local_ca/ca_cert.der, ./local_ca/ca_key.der\n");
    return 0;
}

static int gen_csr(const char *subject, const char *san) {
    if(loadOQSProvider() != 0) {
        fprintf(stderr, "Error: Failed to load OQS Provider\n");
        return 1;
    }
    
    if(ensureDirectory("./out") != 0) {
        fprintf(stderr, "Error: Failed to create out directory\n");
        return 1;
    }
    
    EVP_PKEY *appKey = NULL;
    if(generateDilithiumKey(&appKey) != 0) {
        fprintf(stderr, "Error: Failed to generate application key\n");
        return 1;
    }
    
    X509_REQ *req = X509_REQ_new();
    if(!req) {
        EVP_PKEY_free(appKey);
        return 1;
    }
    
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, appKey);
    
    X509_NAME *name = X509_NAME_new();
    if(!name) {
        X509_REQ_free(req);
        EVP_PKEY_free(appKey);
        return 1;
    }
    
    char *subjCopy = strdup(subject);
    char *token = strtok(subjCopy, ",");
    while(token) {
        char *eq = strchr(token, '=');
        if(eq) {
            *eq = '\0';
            X509_NAME_add_entry_by_txt(name, token, MBSTRING_ASC, (unsigned char*)(eq+1), -1, -1, 0);
        }
        token = strtok(NULL, ",");
    }
    free(subjCopy);
    
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);
    
    if(san) {
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        if(exts) {
            X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char*)san);
            if(ext) sk_X509_EXTENSION_push(exts, ext);
            X509_REQ_add_extensions(req, exts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }
    
    if(X509_REQ_sign(req, appKey, NULL) == 0) {
        if(X509_REQ_sign(req, appKey, EVP_sha256()) == 0) {
            fprintf(stderr, "Error: Failed to sign CSR\n");
            X509_REQ_free(req);
            EVP_PKEY_free(appKey);
            return 1;
        }
    }
    
    unsigned char *csrDer = NULL;
    int csrLen = i2d_X509_REQ(req, &csrDer);
    if(csrLen <= 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(appKey);
        return 1;
    }
    
    unsigned char *keyDer = NULL;
    int keyLen = i2d_PrivateKey(appKey, &keyDer);
    if(keyLen <= 0) {
        OPENSSL_free(csrDer);
        X509_REQ_free(req);
        EVP_PKEY_free(appKey);
        return 1;
    }
    
    if(writeFile("./out/app.csr", csrDer, csrLen) != 0) {
        fprintf(stderr, "Error: Failed to write CSR\n");
        OPENSSL_free(csrDer);
        OPENSSL_free(keyDer);
        X509_REQ_free(req);
        EVP_PKEY_free(appKey);
        return 1;
    }
    
    if(writeFile("./out/app_key.der", keyDer, keyLen) != 0) {
        fprintf(stderr, "Error: Failed to write application key\n");
        OPENSSL_free(csrDer);
        OPENSSL_free(keyDer);
        X509_REQ_free(req);
        EVP_PKEY_free(appKey);
        return 1;
    }
    OPENSSL_free(csrDer);
    OPENSSL_free(keyDer);
    X509_REQ_free(req);
    EVP_PKEY_free(appKey);
    
    printf("CSR created successfully: ./out/app.csr, ./out/app_key.der\n");
    return 0;
}

static int sign_cert(const char *csrPath) {
    if(loadOQSProvider() != 0) {
        fprintf(stderr, "Error: Failed to load OQS Provider\n");
        return 1;
    }
    
    unsigned char *caCertData = NULL;
    size_t caCertLen = 0;
    if(readFile("./local_ca/ca_cert.der", &caCertData, &caCertLen) != 0) {
        fprintf(stderr, "Error: Failed to read CA certificate\n");
        return 1;
    }
    
    unsigned char *caKeyData = NULL;
    size_t caKeyLen = 0;
    if(readFile("./local_ca/ca_key.der", &caKeyData, &caKeyLen) != 0) {
        fprintf(stderr, "Error: Failed to read CA key\n");
        free(caCertData);
        return 1;
    }
    
    unsigned char *csrData = NULL;
    size_t csrLen = 0;
    if(readFile(csrPath, &csrData, &csrLen) != 0) {
        fprintf(stderr, "Error: Failed to read CSR\n");
        free(caCertData);
        free(caKeyData);
        return 1;
    }
    
    const unsigned char *p = caCertData;
    X509 *caCert = d2i_X509(NULL, &p, (long)caCertLen);
    if(!caCert) {
        fprintf(stderr, "Error: Failed to parse CA certificate\n");
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    p = caKeyData;
    EVP_PKEY *caKey = d2i_AutoPrivateKey(NULL, &p, (long)caKeyLen);
    if(!caKey) {
        fprintf(stderr, "Error: Failed to parse CA key\n");
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    p = csrData;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)csrLen);
    if(!req) {
        fprintf(stderr, "Error: Failed to parse CSR\n");
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    X509 *cert = X509_new();
    if(!cert) {
        X509_REQ_free(req);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
    
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365);
    
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(cert, X509_get_subject_name(caCert));
    
    EVP_PKEY *reqPubKey = X509_REQ_get_pubkey(req);
    if(!reqPubKey) {
        X509_free(cert);
        X509_REQ_free(req);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    X509_set_pubkey(cert, reqPubKey);
    EVP_PKEY_free(reqPubKey);
    
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, caCert, req, NULL, 0);
    
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if(ext) X509_add_ext(cert, ext, -1);
    if(ext) X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage, "digitalSignature,keyAgreement");
    if(ext) X509_add_ext(cert, ext, -1);
    if(ext) X509_EXTENSION_free(ext);
    
    STACK_OF(X509_EXTENSION) *reqExts = X509_REQ_get_extensions(req);
    if(reqExts) {
        for(int i = 0; i < sk_X509_EXTENSION_num(reqExts); i++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(reqExts, i);
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
            int nid = OBJ_obj2nid(obj);
            
            if(nid == NID_subject_alt_name) {
                X509_add_ext(cert, ext, -1);
            }
        }
        sk_X509_EXTENSION_pop_free(reqExts, X509_EXTENSION_free);
    }
    
    uint8_t kyberPubKey[OQS_KEM_kyber_768_length_public_key];
    uint8_t kyberPrivKey[OQS_KEM_kyber_768_length_secret_key];
    if(generateKyberKey(kyberPubKey, kyberPrivKey) != 0) {
        fprintf(stderr, "Error: Failed to generate Kyber key\n");
        X509_free(cert);
        X509_REQ_free(req);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    addOctetExtension(cert, OID_KYBER_PUB, kyberPubKey, OQS_KEM_kyber_768_length_public_key);
    
    if(X509_sign(cert, caKey, NULL) == 0) {
        if(X509_sign(cert, caKey, EVP_sha256()) == 0) {
            fprintf(stderr, "Error: Failed to sign certificate\n");
            X509_free(cert);
            X509_REQ_free(req);
            EVP_PKEY_free(caKey);
            X509_free(caCert);
            free(caCertData);
            free(caKeyData);
            free(csrData);
            return 1;
        }
    }
    
    unsigned char *certDer = NULL;
    int certLen = i2d_X509(cert, &certDer);
    if(certLen <= 0) {
        X509_free(cert);
        X509_REQ_free(req);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    if(ensureDirectory("./out") != 0) {
        fprintf(stderr, "Error: Failed to create out directory\n");
        OPENSSL_free(certDer);
        X509_free(cert);
        X509_REQ_free(req);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    if(writeFile("./out/app_cert.der", certDer, certLen) != 0) {
        fprintf(stderr, "Error: Failed to write signed certificate\n");
        OPENSSL_free(certDer);
        X509_free(cert);
        X509_REQ_free(req);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        free(caCertData);
        free(caKeyData);
        free(csrData);
        return 1;
    }
    
    OPENSSL_free(certDer);
    X509_free(cert);
    X509_REQ_free(req);
    EVP_PKEY_free(caKey);
    X509_free(caCert);
    free(caCertData);
    free(caKeyData);
    free(csrData);
    
    printf("Certificate signed successfully: ./out/app_cert.der\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        fprintf(stderr, "Usage: %s <init-ca|gen-csr|sign-cert> [args]\n", argv[0]);
        fprintf(stderr, "  init-ca\n");
        fprintf(stderr, "  gen-csr <subject> <san>\n");
        fprintf(stderr, "  sign-cert <csr_path>\n");
        return 1;
    }
    
    int ret = 1;
    
    if(strcmp(argv[1], "init-ca") == 0) {
        ret = init_ca();
    } else if(strcmp(argv[1], "gen-csr") == 0) {
        if(argc < 4) {
            fprintf(stderr, "Usage: %s gen-csr <subject> <san>\n", argv[0]);
            fprintf(stderr, "  subject: C=DE,O=SampleOrganization,CN=Server\n");
            fprintf(stderr, "  san: URI:urn:open62541.server.application\n");
            return 1;
        }
        ret = gen_csr(argv[2], argv[3]);
    } else if(strcmp(argv[1], "sign-cert") == 0) {
        if(argc < 3) {
            fprintf(stderr, "Usage: %s sign-cert <csr_path>\n", argv[0]);
            return 1;
        }
        ret = sign_cert(argv[2]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
    
    unloadOQSProvider();
    return ret;
}

#else /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
int main(int argc, char *argv[]) {
    fprintf(stderr, "Error: OpenSSL 3.x required (found version 0x%lx)\n", OPENSSL_VERSION_NUMBER);
    return 1;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
