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
    
    return UA_STATUSCODE_GOOD;
}

/* Ensure PKI structure exists and verify server certificate is available.
 * Must be called before UA_ServerConfig_setDefaultWithFilestore.
 * Certificates must be created externally using pqc_ca_tool. */
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
    char issuerCertsDir[4096];
    char issuerCrlDir[4096];
    char trustedDir[4096];
    char rejectedDir[4096];
    char certPath[4096];
    char keyPath[4096];
    
    snprintf(rootDir, sizeof(rootDir), "%.*s", (int)storePath->length, storePath->data);
    snprintf(applCertsDir, sizeof(applCertsDir), "%.*s/ApplCerts", (int)storePath->length, storePath->data);
    snprintf(ownCertsDir, sizeof(ownCertsDir), "%.*s/ApplCerts/own/certs", (int)storePath->length, storePath->data);
    snprintf(ownPrivateDir, sizeof(ownPrivateDir), "%.*s/ApplCerts/own/private", (int)storePath->length, storePath->data);
    snprintf(issuerCertsDir, sizeof(issuerCertsDir), "%.*s/ApplCerts/issuer/certs", (int)storePath->length, storePath->data);
    snprintf(issuerCrlDir, sizeof(issuerCrlDir), "%.*s/ApplCerts/issuer/crl", (int)storePath->length, storePath->data);
    snprintf(trustedDir, sizeof(trustedDir), "%.*s/ApplCerts/trusted", (int)storePath->length, storePath->data);
    snprintf(certPath, sizeof(certPath), "%.*s/ApplCerts/own/certs/server_cert.der", (int)storePath->length, storePath->data);
    snprintf(keyPath, sizeof(keyPath), "%.*s/ApplCerts/own/private/server_key.der", (int)storePath->length, storePath->data);
    
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
    
    retval = ensureDirectoryExists(issuerCertsDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create issuer/certs directory: %s", issuerCertsDir);
        return retval;
    }
    
    retval = ensureDirectoryExists(issuerCrlDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create issuer/crl directory: %s", issuerCrlDir);
        return retval;
    }
    
    retval = ensureDirectoryExists(trustedDir);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create trusted directory: %s", trustedDir);
        return retval;
    }
    
    /* Verify that server certificate and key exist */
    bool certExists = fileExists(certPath);
    bool keyExists = fileExists(keyPath);
    
    if(certExists && keyExists) {
        return UA_STATUSCODE_GOOD;
    }
    
    if(!certExists || !keyExists) {
        if(!certExists) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "[FILESTORE] Missing application certificate: %s", certPath);
        }
        if(!keyExists) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "[FILESTORE] Missing application private key: %s", keyPath);
        }
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] PKI is incomplete. Use pqc_ca_tool to generate certificates externally.");
        return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
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
        /* Use UA_String_fromChars to create an owning heap copy (required for UA_String_clear) */
        storePath = UA_String_fromChars(pkiPathArg);
        if(storePath.length == 0) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Failed to allocate PKI path string");
            return EXIT_FAILURE;
        }
    } else {
        /* Default to ./pki in current directory */
        storePath = UA_String_fromChars("./pki");
        if(storePath.length == 0) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Failed to allocate default PKI path");
            return EXIT_FAILURE;
        }
    }
    
    UA_StatusCode pkiStatus = ensurePKIAndServerCertificate(&storePath);
    if(pkiStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to ensure PKI structure and server certificate: %s",
                    UA_StatusCode_name(pkiStatus));
        UA_String_clear(&storePath);
        return EXIT_FAILURE;
    }
    
    /* Build paths to own certificate and private key in PKI */
    char certPath[4096], keyPath[4096];
    snprintf(certPath, sizeof(certPath), "%.*s/ApplCerts/own/certs/server_cert.der",
             (int)storePath.length, storePath.data);
    snprintf(keyPath, sizeof(keyPath), "%.*s/ApplCerts/own/private/server_key.der",
             (int)storePath.length, storePath.data);
    
    /* Load certificate and private key from PKI FileStore */
    certificate = loadFile(certPath);
    privateKey = loadFile(keyPath);
    
    /* Validate that files were loaded successfully */
    if(certificate.length == 0 || privateKey.length == 0) {
        if(certificate.length == 0) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "[FILESTORE] Failed to load application certificate from PKI: %s", certPath);
        }
        if(privateKey.length == 0) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "[FILESTORE] Failed to load application private key from PKI: %s", keyPath);
        }
        if(certificate.length > 0)
            UA_ByteString_clear(&certificate);
        if(privateKey.length > 0)
            UA_ByteString_clear(&privateKey);
        UA_String_clear(&storePath);
        return EXIT_FAILURE;
    }

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

    /* Ensure all PKI directories exist physically on disk */
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
    
    char dirPath[4096] = {0};
    #define CREATE_DIR_FROM_STRING(str) do { \
        if((str).length > 0) { \
            snprintf(dirPath, sizeof(dirPath), "%.*s", \
                     (int)(str).length, (char*)(str).data); \
            UA_StatusCode dirStatus = ensureDirectoryExists(dirPath); \
            if(dirStatus != UA_STATUSCODE_GOOD) { \
                UA_LOG_DEBUG(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, \
                              "[FILESTORE] Failed to create directory: %s", dirPath); \
            } \
        } \
    } while(0)
    
    if(config->secureChannelPKI.context) {
        FileCertStore *applContext = (FileCertStore *)config->secureChannelPKI.context;
        
        CREATE_DIR_FROM_STRING(applContext->trustedCertFolder);
        CREATE_DIR_FROM_STRING(applContext->trustedCrlFolder);
        CREATE_DIR_FROM_STRING(applContext->issuerCertFolder);
        CREATE_DIR_FROM_STRING(applContext->issuerCrlFolder);
        CREATE_DIR_FROM_STRING(applContext->ownCertFolder);
        CREATE_DIR_FROM_STRING(applContext->ownKeyFolder);
    }
    
    if(config->sessionPKI.context) {
        FileCertStore *userTokenContext = (FileCertStore *)config->sessionPKI.context;
        
        CREATE_DIR_FROM_STRING(userTokenContext->trustedCertFolder);
        CREATE_DIR_FROM_STRING(userTokenContext->trustedCrlFolder);
        CREATE_DIR_FROM_STRING(userTokenContext->issuerCertFolder);
        CREATE_DIR_FROM_STRING(userTokenContext->issuerCrlFolder);
    }
    
    #undef CREATE_DIR_FROM_STRING

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    config->securityPoliciesSize = 0;
    config->securityPolicies = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
    if(!config->securityPolicies) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Memory allocation failed for PQC policy");
        goto cleanup;
    }
    memset(config->securityPolicies, 0, sizeof(UA_SecurityPolicy));

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

    /* Add None policy for discovery only (no None endpoint) */
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
                    UA_LOG_DEBUG(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                                   "Failed to register client PQC keys override: %s",
                                   UA_StatusCode_name(rc));
                }
            } else {
                UA_LOG_DEBUG(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                               "No security policies available to register client PQC keys");
            }
        } else {
            UA_LOG_DEBUG(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                           "Client PQC key files have unexpected size (sig=%zu, kem=%zu)",
                           (size_t)clientSigKey.length, (size_t)clientKemKey.length);
        }
        UA_ByteString_clear(&clientSigKey);
        UA_ByteString_clear(&clientKemKey);
    }
#endif

    if(retval != UA_STATUSCODE_GOOD || !running)
        goto cleanup;
    
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    
    retval = UA_Server_run(server, &running);

 cleanup:
    UA_Server_delete(server);
    UA_String_clear(&storePath);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
