/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2019 (c) Kalycito Infotech Private Limited
 *    Copyright 2021 (c) Christian von Arnim, ISW University of Stuttgart (for VDW and umati)
 *
 */

#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <string.h>
#include <open62541/plugin/securitypolicy_pqc.h>

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
#include <oqs/oqsconfig.h>
#include <oqs/oqs.h>
#include <oqs/kem_kyber.h>

#ifndef OQS_SIG_dilithium_2_length_public_key
#define OQS_SIG_dilithium_2_length_public_key 1312
#endif
#ifndef OQS_KEM_kyber_768_length_public_key
#define OQS_KEM_kyber_768_length_public_key 1184
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/provider.h>

/* Check if OpenSSL 3.x with OQS Provider is available at runtime */
static UA_Boolean isOpenSSL3WithOQSProviderAvailable(void) {
    /* Runtime check: Try to load OQS Provider */
    OSSL_PROVIDER *oqsProvider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if(!oqsProvider) {
        oqsProvider = OSSL_PROVIDER_load(NULL, "oqs");
    }
    
    if(oqsProvider) {
        OSSL_PROVIDER_unload(oqsProvider);
        return true;
    }
    
    return false;
}
#else
/* OpenSSL 3.x not available at compile time */
static UA_Boolean isOpenSSL3WithOQSProviderAvailable(void) {
    return false;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* UA_ENABLE_ENCRYPTION_OPENSSL */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#ifdef UA_ARCHITECTURE_WIN32
#include <direct.h>
#endif

#include "common.h"

UA_Boolean running = true;
static void stopHandler(int sig) {
    running = false;
}

/* Utility functions for PKI FileStore */
static bool pathExists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

static bool fileExists(const char *path) {
    return (access(path, F_OK) == 0);
}

/* Ensure directory exists, creating it recursively if needed */
static UA_StatusCode ensureDirectoryExists(const char *dirPath) {
    if(!dirPath) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    
    /* Check if directory already exists */
    struct stat st;
    if(stat(dirPath, &st) == 0) {
        if(S_ISDIR(st.st_mode)) {
            /* Directory exists */
            return UA_STATUSCODE_GOOD;
        } else {
            /* Path exists but is not a directory */
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "[FILESTORE] Path exists but is not a directory: %s", dirPath);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }
    
    /* Directory doesn't exist, create it recursively */
    /* Extract parent directory */
    char parentPath[4096] = {0};
    strncpy(parentPath, dirPath, sizeof(parentPath) - 1);
    char *lastSlash = strrchr(parentPath, '/');
    #ifdef UA_ARCHITECTURE_WIN32
    if(!lastSlash) {
        lastSlash = strrchr(parentPath, '\\');
    }
    #endif
    
    if(lastSlash) {
        *lastSlash = '\0';
        /* Recursively ensure parent directory exists */
        UA_StatusCode parentStatus = ensureDirectoryExists(parentPath);
        if(parentStatus != UA_STATUSCODE_GOOD) {
            return parentStatus;
        }
    }
    
    /* Create the directory */
    #ifdef UA_ARCHITECTURE_WIN32
    if(_mkdir(dirPath) != 0) {
        if(errno == EEXIST) {
            /* Directory was created by another process, verify it exists */
            if(stat(dirPath, &st) == 0 && S_ISDIR(st.st_mode)) {
                return UA_STATUSCODE_GOOD;
            }
        }
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create directory %s: errno=%d", dirPath, errno);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    #else
    if(mkdir(dirPath, 0777) != 0) {
        if(errno == EEXIST) {
            /* Directory was created by another process, verify it exists */
            if(stat(dirPath, &st) == 0 && S_ISDIR(st.st_mode)) {
                return UA_STATUSCODE_GOOD;
            }
        }
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create directory %s: errno=%d", dirPath, errno);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    #endif
    
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
               "[FILESTORE] Created PKI directory: %s", dirPath);
    return UA_STATUSCODE_GOOD;
}

/* Ensure PKI structure exists and server certificate is available */
/* This function MUST be called BEFORE UA_ServerConfig_setDefaultWithFilestore or UA_ServerConfig_setDefaultWithSecurityPolicies */
static UA_StatusCode ensurePKIAndServerCertificate(const UA_String *storePath) {
    if(!storePath || !storePath->data || storePath->length == 0) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Invalid storePath in ensurePKIAndServerCertificate");
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    
    /* Build paths to PKI structure */
    char rootDir[4096];
    char applCertsDir[4096];
    char ownCertsDir[4096];
    char ownPrivateDir[4096];
    char trustedDir[4096];
    char rejectedDir[4096];
    char certPath[4096];
    char keyPath[4096];
    
    snprintf(rootDir, sizeof(rootDir), "%.*s", (int)storePath->length, storePath->data);
    snprintf(applCertsDir, sizeof(applCertsDir), "%.*s/ApplCerts", (int)storePath->length, storePath->data);
    snprintf(ownCertsDir, sizeof(ownCertsDir), "%.*s/ApplCerts/own/certs", (int)storePath->length, storePath->data);
    snprintf(ownPrivateDir, sizeof(ownPrivateDir), "%.*s/ApplCerts/own/private", (int)storePath->length, storePath->data);
    snprintf(trustedDir, sizeof(trustedDir), "%.*s/ApplCerts/trusted", (int)storePath->length, storePath->data);
    snprintf(certPath, sizeof(certPath), "%.*s/ApplCerts/own/certs/server_cert.der", (int)storePath->length, storePath->data);
    snprintf(keyPath, sizeof(keyPath), "%.*s/ApplCerts/own/private/server_key.der", (int)storePath->length, storePath->data);
    
    /* Step 1: Create PKI directory structure */
    UA_StatusCode retval = ensureDirectoryExists(rootDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create root PKI directory: %s", rootDir);
        return retval;
    }
    
    retval = ensureDirectoryExists(applCertsDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create ApplCerts directory: %s", applCertsDir);
        return retval;
    }
    
    retval = ensureDirectoryExists(ownCertsDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create own/certs directory: %s", ownCertsDir);
        return retval;
    }
    
    retval = ensureDirectoryExists(ownPrivateDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create own/private directory: %s", ownPrivateDir);
        return retval;
    }
    
    retval = ensureDirectoryExists(trustedDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create trusted directory: %s", trustedDir);
        return retval;
    }
    
    /* Step 2: Check if server certificate and key exist */
    bool certExists = fileExists(certPath);
    bool keyExists = fileExists(keyPath);
    
    if(certExists && keyExists) {
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                   "[FILESTORE] Server certificate and key already exist in PKI: %s", certPath);
        return UA_STATUSCODE_GOOD;
    }
    
    /* Step 3: Generate server certificate if missing */
    if(!certExists || !keyExists) {
        /* Generate self-signed PQC certificate */
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                   "[FILESTORE] Server certificate or key missing. Generating self-signed PQC certificate...");
        
        UA_ByteString certificate = UA_BYTESTRING_NULL;
        UA_ByteString privateKey = UA_BYTESTRING_NULL;
        
        UA_String subject[3] = {
            UA_STRING_STATIC("C=DE"),
            UA_STRING_STATIC("O=SampleOrganization"),
            UA_STRING_STATIC("CN=Open62541Server@localhost")
        };
        UA_UInt32 lenSubject = 3;
        
        UA_String subjectAltName[2] = {
            UA_STRING_STATIC("DNS:localhost"),
            UA_STRING_STATIC("URI:urn:open62541.server.application")
        };
        UA_UInt32 lenSubjectAltName = 2;
        
#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
        /* Check if OpenSSL 3.x with OQS Provider is available */
        if(isOpenSSL3WithOQSProviderAvailable()) {
            UA_StatusCode certGenStatus = UA_PQC_CreateCertificateWithOQSProvider(
                UA_Log_Stdout,
                subject,
                lenSubject,
                subjectAltName,
                lenSubjectAltName,
                UA_CERTIFICATEFORMAT_DER,
                "ML-DSA-44",
                365, /* expiresInDays */
                &privateKey,
                &certificate);
            
            if(certGenStatus != UA_STATUSCODE_GOOD) {
                UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                            "[FILESTORE] Failed to generate server certificate with OQS Provider: %s",
                            UA_StatusCode_name(certGenStatus));
                UA_ByteString_clear(&certificate);
                UA_ByteString_clear(&privateKey);
                return certGenStatus;
            }
        } else {
            /* Fallback to legacy API if OQS Provider not available */
            UA_StatusCode certGenStatus = UA_PQC_CreateCertificate(
                UA_Log_Stdout, subject, lenSubject, subjectAltName, lenSubjectAltName,
                UA_CERTIFICATEFORMAT_DER,
                0,   /* rsaKeySizeBits - deprecated, ignored */
                365, /* expiresInDays */
                &privateKey,
                &certificate);
            
            if(certGenStatus != UA_STATUSCODE_GOOD) {
                UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                            "[FILESTORE] Failed to generate server certificate: %s",
                            UA_StatusCode_name(certGenStatus));
                UA_ByteString_clear(&certificate);
                UA_ByteString_clear(&privateKey);
                return certGenStatus;
            }
        }
        
        /* Step 4: Write certificate and key to PKI */
        UA_StatusCode certWriteStatus = writeFile(certPath, certificate);
        if(certWriteStatus != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "[FILESTORE] Failed to write server certificate to: %s", certPath);
            UA_ByteString_clear(&certificate);
            UA_ByteString_clear(&privateKey);
            return certWriteStatus;
        }
        
        UA_StatusCode keyWriteStatus = writeFile(keyPath, privateKey);
        if(keyWriteStatus != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "[FILESTORE] Failed to write server private key to: %s", keyPath);
            UA_ByteString_clear(&certificate);
            UA_ByteString_clear(&privateKey);
            return keyWriteStatus;
        }
        
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                   "[FILESTORE] Generated and saved server certificate to: %s", certPath);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                   "[FILESTORE] Generated and saved server private key to: %s", keyPath);
        
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
#else
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Cannot generate certificate: OpenSSL encryption not enabled");
        return UA_STATUSCODE_BADNOTSUPPORTED;
#endif
    }
    
    return UA_STATUSCODE_GOOD;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);
    /* Ignore SIGPIPE to prevent broken pipe errors when output is redirected to pipes */
    signal(SIGPIPE, SIG_IGN);
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    UA_String storePath = UA_STRING_NULL;
    bool onlySecure = false;
    bool allowDiscovery = false;
    char *clientSigKeyFile = NULL;
    char *clientKemKeyFile = NULL;
    char *pkiPathArg = NULL;
    
    /* Parse command line options FIRST to avoid flags being interpreted as paths */
    for(int argpos = 1; argpos < argc; argpos++) {
        if(strcmp(argv[argpos], "--onlySecure") == 0) {
            onlySecure = true;
            continue;
        }
        if(strcmp(argv[argpos], "--allowDiscovery") == 0) {
            allowDiscovery = true;
            continue;
        }
        if(strcmp(argv[argpos], "--clientSigKey") == 0 && argpos + 1 < argc) {
            clientSigKeyFile = argv[++argpos];
            continue;
        }
        if(strcmp(argv[argpos], "--clientKemKey") == 0 && argpos + 1 < argc) {
            clientKemKeyFile = argv[++argpos];
            continue;
        }
        if(strcmp(argv[argpos], "--pki") == 0 && argpos + 1 < argc) {
            pkiPathArg = argv[++argpos];
            continue;
        }
    }
    
    /* Determine PKI store path - use --pki argument or default to ./pki */
    if(pkiPathArg) {
        /* Defensive validation: reject paths that start with -- */
        if(strlen(pkiPathArg) >= 2 && pkiPathArg[0] == '-' && pkiPathArg[1] == '-') {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Invalid PKI path: path cannot start with '--' (got: %s). "
                         "Use --pki <path> to specify PKI directory.",
                         pkiPathArg);
            return EXIT_FAILURE;
        }
        storePath = UA_STRING(pkiPathArg);
    } else {
        /* Default to ./pki in current directory */
        storePath = UA_String_fromChars("./pki");
        if(storePath.length == 0) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Failed to allocate default PKI path");
            return EXIT_FAILURE;
        }
    }
    
    /* Ensure PKI structure exists and server certificate is available */
    /* This MUST be done BEFORE any UA_ServerConfig_setDefault* call */
    UA_StatusCode pkiStatus = ensurePKIAndServerCertificate(&storePath);
    if(pkiStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to ensure PKI structure and server certificate: %s",
                    UA_StatusCode_name(pkiStatus));
        UA_String_clear(&storePath);
        return EXIT_FAILURE;
    }
    
    /* Build paths to own certificate and private key in PKI */
    /* Standard PKI structure: {storePath}/ApplCerts/own/{certs,private} */
    char certPath[4096], keyPath[4096];
    snprintf(certPath, sizeof(certPath), "%.*s/ApplCerts/own/certs/server_cert.der",
             (int)storePath.length, storePath.data);
    snprintf(keyPath, sizeof(keyPath), "%.*s/ApplCerts/own/private/server_key.der",
             (int)storePath.length, storePath.data);
    
    /* Load certificate and private key from PKI FileStore */
    /* ensurePKIAndServerCertificate guarantees these files exist */
    bool loadedFromPKI = false;
    certificate = loadFile(certPath);
    privateKey = loadFile(keyPath);
    
    /* Validate that files were loaded successfully */
    if(certificate.length > 0 && privateKey.length > 0) {
        loadedFromPKI = true;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                   "[FILESTORE] Loaded server certificate and key from PKI: %s", certPath);
    } else {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to load certificate or private key from PKI FileStore "
                     "(files should exist after ensurePKIAndServerCertificate).");
        if(certificate.length > 0)
            UA_ByteString_clear(&certificate);
        if(privateKey.length > 0)
            UA_ByteString_clear(&privateKey);
        UA_String_clear(&storePath);
        return EXIT_FAILURE;
    }
    
    /* Certificate and key are now loaded from PKI */
    /* ensurePKIAndServerCertificate guarantees they exist */

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    if(certificate.length > 0 && privateKey.length > 0) {
        UA_Boolean certIsPQCSigned = UA_PQC_IsCertificatePQCSigned(&certificate, UA_Log_Stdout);
        UA_Boolean certHasPQCExt = UA_PQC_HasCertificatePQCExtensions(&certificate, UA_Log_Stdout);
        
        if(!certIsPQCSigned || !certHasPQCExt) {
            UA_StatusCode pqcStatus =
            UA_PQC_EnsureCertificateExtensions(&certificate, &privateKey, UA_Log_Stdout);
        if(pqcStatus != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                               "Failed to embed PQC extensions: %s",
                           UA_StatusCode_name(pqcStatus));
            }
        }
        
        /* Save auto-generated certificate AFTER adding PQC extensions */
        /* Only save if not loaded from PKI and no CLI arguments provided */
        if(!loadedFromPKI && argc < 3 && certificate.length > 0 && privateKey.length > 0) {
            const char *defaultCertPath = "server_cert_pqc.der";
            const char *defaultKeyPath = "server_key_pqc.der";
            
            UA_StatusCode certWriteStatus = writeFile(defaultCertPath, certificate);
            UA_StatusCode keyWriteStatus = writeFile(defaultKeyPath, privateKey);
            if(certWriteStatus != UA_STATUSCODE_GOOD || keyWriteStatus != UA_STATUSCODE_GOOD) {
                UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                              "Failed to save auto-generated certificate files to disk.");
            }
        }
    }
#endif

    UA_Server *server = UA_Server_new();
    if(!server) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to create server.");
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
        UA_String_clear(&storePath);
        return EXIT_FAILURE;
    }
    UA_ServerConfig *config = UA_Server_getConfig(server);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    
    /* Configure server with PKI FileStore - this sets up the PKI structure */
    /* Note: We pass NULL for certificate/privateKey here because we'll add PQC policy separately */
    /* But we need to pass them to create the PKI structure, so we use empty strings */
    UA_ByteString emptyCert = UA_BYTESTRING_NULL;
    UA_ByteString emptyKey = UA_BYTESTRING_NULL;
    
    /* First, set up basic config without security policies */
    retval = UA_ServerConfig_setMinimal(config, 4840, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to set default config: %s",
                    UA_StatusCode_name(retval));
        goto cleanup;
    }

    /* Increase buffer limits to avoid rejected messages */
    const UA_UInt32 bigBuf = 1 << 20; /* 1 MiB per TCP chunk */
    config->tcpBufSize = bigBuf;
    config->tcpMaxMsgSize = 1 << 30;  /* 1 GiB */
    config->tcpMaxChunks  = 1 << 20;  /* 1M chunks */

    /* Set up PKI FileStore */
    UA_KeyValuePair params[2];
    size_t paramsSize = 2;
    params[0].key = UA_QUALIFIEDNAME(0, "max-trust-listsize");
    UA_Variant_setScalar(&params[0].value, &config->maxTrustListSize, &UA_TYPES[UA_TYPES_UINT32]);
    params[1].key = UA_QUALIFIEDNAME(0, "max-rejected-listsize");
    UA_Variant_setScalar(&params[1].value, &config->maxRejectedListSize, &UA_TYPES[UA_TYPES_UINT32]);
    UA_KeyValueMap paramsMap;
    paramsMap.map = params;
    paramsMap.mapSize = paramsSize;

    UA_NodeId defaultApplicationGroup =
            UA_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    retval = UA_CertificateGroup_Filestore(&config->secureChannelPKI, &defaultApplicationGroup,
                                           storePath, config->logging, &paramsMap);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to configure secureChannelPKI FileStore: %s",
                    UA_StatusCode_name(retval));
        goto cleanup;
    }

    UA_NodeId defaultUserTokenGroup =
            UA_NS0ID(SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP);
    retval = UA_CertificateGroup_Filestore(&config->sessionPKI, &defaultUserTokenGroup,
                                           storePath, config->logging, &paramsMap);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to configure sessionPKI FileStore: %s",
                    UA_StatusCode_name(retval));
        goto cleanup;
    }

    /* Log PKI initialization */
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "[FILESTORE] PKI initialized at %.*s",
                (int)storePath.length, storePath.data);

    /* Ensure all PKI directories exist physically on disk */
    /* Access FileCertStore context structures to get all directory paths */
    typedef struct {
        UA_CertificateGroup *store;
        #ifdef __linux__
        int inotifyFd;
        #endif
        UA_String trustedCertFolder;
        UA_String trustedCrlFolder;
        UA_String issuerCertFolder;
        UA_String issuerCrlFolder;
        UA_String rejectedCertFolder;
        UA_String ownCertFolder;
        UA_String ownKeyFolder;
        UA_String rootFolder;
    } FileCertStore;
    
    /* Helper function to create directory from UA_String */
    char dirPath[4096] = {0};
    #define CREATE_DIR_FROM_STRING(str) do { \
        if((str).length > 0) { \
            snprintf(dirPath, sizeof(dirPath), "%.*s", \
                     (int)(str).length, (char*)(str).data); \
            UA_StatusCode dirStatus = ensureDirectoryExists(dirPath); \
            if(dirStatus != UA_STATUSCODE_GOOD) { \
                UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, \
                              "[FILESTORE] Failed to create directory: %s", dirPath); \
            } \
        } \
    } while(0)
    
    /* Create all directories for Application Certificates (secureChannelPKI) */
    if(config->secureChannelPKI.context) {
        FileCertStore *applContext = (FileCertStore *)config->secureChannelPKI.context;
        
        CREATE_DIR_FROM_STRING(applContext->trustedCertFolder);
        CREATE_DIR_FROM_STRING(applContext->trustedCrlFolder);
        CREATE_DIR_FROM_STRING(applContext->issuerCertFolder);
        CREATE_DIR_FROM_STRING(applContext->issuerCrlFolder);
        CREATE_DIR_FROM_STRING(applContext->ownCertFolder);
        CREATE_DIR_FROM_STRING(applContext->ownKeyFolder);
    }
    
    /* Create all directories for User Token Certificates (sessionPKI) */
    if(config->sessionPKI.context) {
        FileCertStore *userTokenContext = (FileCertStore *)config->sessionPKI.context;
        
        CREATE_DIR_FROM_STRING(userTokenContext->trustedCertFolder);
        CREATE_DIR_FROM_STRING(userTokenContext->trustedCrlFolder);
        CREATE_DIR_FROM_STRING(userTokenContext->issuerCertFolder);
        CREATE_DIR_FROM_STRING(userTokenContext->issuerCrlFolder);
    }
    
    #undef CREATE_DIR_FROM_STRING

    /* Persist server certificate and private key to PKI if they don't exist yet */
    if(config->secureChannelPKI.context) {
        FileCertStore *fileStoreContext = (FileCertStore *)config->secureChannelPKI.context;
        
        if(fileStoreContext && 
           fileStoreContext->ownCertFolder.length > 0 && 
           fileStoreContext->ownKeyFolder.length > 0) {
            
            /* Build full paths for certificate and key files */
            char certPath[4096] = {0};
            char keyPath[4096] = {0};
            
            /* Extract directory paths from file paths */
            char certDir[4096] = {0};
            char keyDir[4096] = {0};
            
            snprintf(certDir, sizeof(certDir), "%.*s",
                     (int)fileStoreContext->ownCertFolder.length,
                     (char*)fileStoreContext->ownCertFolder.data);
            snprintf(keyDir, sizeof(keyDir), "%.*s",
                     (int)fileStoreContext->ownKeyFolder.length,
                     (char*)fileStoreContext->ownKeyFolder.data);
            
            snprintf(certPath, sizeof(certPath), "%s/server_cert.der", certDir);
            snprintf(keyPath, sizeof(keyPath), "%s/server_key.der", keyDir);
            
            /* Persist certificate if it doesn't exist */
            if(!fileExists(certPath) && certificate.length > 0) {
                /* Ensure directory exists before writing */
                UA_StatusCode dirStatus = ensureDirectoryExists(certDir);
                if(dirStatus != UA_STATUSCODE_GOOD) {
                    UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                "[FILESTORE] Failed to ensure directory exists for certificate: %s",
                                certDir);
                } else {
                    UA_StatusCode certWriteStatus = writeFile(certPath, certificate);
                    if(certWriteStatus == UA_STATUSCODE_GOOD) {
                        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                   "[FILESTORE] Server certificate persisted to own/certs: %s",
                                   certPath);
                    } else {
                        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                      "Failed to persist server certificate to PKI: %s",
                                      UA_StatusCode_name(certWriteStatus));
                    }
                }
            }
            
            /* Persist private key if it doesn't exist */
            if(!fileExists(keyPath) && privateKey.length > 0) {
                /* Ensure directory exists before writing */
                UA_StatusCode dirStatus = ensureDirectoryExists(keyDir);
                if(dirStatus != UA_STATUSCODE_GOOD) {
                    UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                "[FILESTORE] Failed to ensure directory exists for private key: %s",
                                keyDir);
                } else {
                    UA_StatusCode keyWriteStatus = writeFile(keyPath, privateKey);
                    if(keyWriteStatus == UA_STATUSCODE_GOOD) {
                        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                   "[FILESTORE] Server private key persisted to own/private: %s",
                                   keyPath);
                    } else {
                        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                                      "Failed to persist server private key to PKI: %s",
                                      UA_StatusCode_name(keyWriteStatus));
                    }
                }
            }
        }
    }

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    /* Add PQC policy to server with filestore support */
    /* Initialize policies array */
    config->securityPoliciesSize = 0;
    config->securityPolicies = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
    if(!config->securityPolicies) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Memory allocation failed for PQC policy");
        goto cleanup;
    }
    memset(config->securityPolicies, 0, sizeof(UA_SecurityPolicy));

    /* First create the inner PQC policy */
    UA_SecurityPolicy *innerPqcPolicy = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
    if(!innerPqcPolicy) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Memory allocation failed for inner PQC policy");
        goto cleanup;
    }
    memset(innerPqcPolicy, 0, sizeof(UA_SecurityPolicy));
    
    retval = UA_SecurityPolicy_PQC(innerPqcPolicy, certificate, privateKey, UA_Log_Stdout);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to initialize inner PQC SecurityPolicy: %s",
                     UA_StatusCode_name(retval));
        UA_free(innerPqcPolicy);
        goto cleanup;
    }

    /* Wrap PQC policy with filestore */
    retval = UA_SecurityPolicy_Filestore(&config->securityPolicies[0], innerPqcPolicy, storePath);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to wrap PQC SecurityPolicy with Filestore: %s",
                     UA_StatusCode_name(retval));
        innerPqcPolicy->clear(innerPqcPolicy);
        UA_free(innerPqcPolicy);
        goto cleanup;
    }
    config->securityPoliciesSize = 1;
#endif

    /* Adds the None policy to the security policy list, but does not provide a None endpoint.
     * This enables a client to retrieve the server certificate and
     * all endpoints offered by a server. */
    if(onlySecure && allowDiscovery) {
        retval = UA_ServerConfig_addSecurityPolicyNone(config, &certificate);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Failed to add SecurityPolicyNone: %s",
                         UA_StatusCode_name(retval));
            goto cleanup;
        }
        config->securityPolicyNoneDiscoveryOnly = true;
    }

    /* Add endpoints for all security policies, including PQC */
    retval = UA_ServerConfig_addAllEndpoints(config);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to add endpoints: %s",
                     UA_StatusCode_name(retval));
        goto cleanup;
    }

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    if(clientSigKeyFile && clientKemKeyFile) {
        UA_ByteString clientSigKey = loadFile(clientSigKeyFile);
        UA_ByteString clientKemKey = loadFile(clientKemKeyFile);
        if(clientSigKey.length == (size_t)OQS_SIG_dilithium_2_length_public_key &&
           clientKemKey.length == (size_t)OQS_KEM_kyber_768_length_public_key) {
            /* Validate that security policies exist before accessing */
            if(config->securityPolicies && config->securityPoliciesSize > 0) {
                size_t idx = config->securityPoliciesSize - 1; /* Last policy (PQC) */
                UA_StatusCode rc =
                    UA_PQCPolicy_registerRemoteKeys(&config->securityPolicies[idx],
                                                    clientSigKey, clientKemKey);
                if(rc != UA_STATUSCODE_GOOD) {
                    UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                                   "Failed to register client PQC keys override: %s",
                                   UA_StatusCode_name(rc));
                }
            } else {
                UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                               "No security policies available to register client PQC keys.");
            }
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                           "Client PQC key files have unexpected size (sig=%zu, kem=%zu)",
                           (size_t)clientSigKey.length, (size_t)clientKemKey.length);
        }
        UA_ByteString_clear(&clientSigKey);
        UA_ByteString_clear(&clientKemKey);
    }
#endif

    /* Check retval before cleaning up resources */
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    if(!running)
        goto cleanup; /* received ctrl-c already */
    
    /* Certificate and privateKey are no longer needed after server initialization */
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    
    retval = UA_Server_run(server, &running);

 cleanup:
    UA_Server_delete(server);
    /* Certificate and privateKey are already cleared above, don't clear again */
    UA_String_clear(&storePath);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
