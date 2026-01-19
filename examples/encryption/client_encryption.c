/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

#include <open62541/client_config_default.h>
#include <open62541/client_highlevel.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/securitypolicy_pqc.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/securitypolicy_default.h>

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
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "common.h"

#define MIN_ARGS 2

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

int main(int argc, char* argv[]) {
    /* Ignore SIGPIPE to prevent broken pipe errors when output is redirected to pipes */
    signal(SIGPIPE, SIG_IGN);
    
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    UA_String clientStorePath = UA_STRING_NULL;
    UA_Client *client = NULL;
    UA_ClientConfig *cc = NULL;
    char *endpointUrl = NULL;
    char *serverCertFile = NULL;
    char *pkiPathArg = NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    if(argc < MIN_ARGS) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Arguments missing. Required arguments are: "
                     "<opc.tcp://host:port> [--pki <path/to/pki/folder>] [--serverCert <server-cert.der>]");
        return EXIT_FAILURE;
    }

    endpointUrl = argv[1];

    /* Parse command line options */
    for(int argpos = 2; argpos < argc; argpos++) {
        if(strcmp(argv[argpos], "--pki") == 0 && argpos + 1 < argc) {
            pkiPathArg = argv[++argpos];
            continue;
        }
        if(strcmp(argv[argpos], "--serverCert") == 0 && argpos + 1 < argc) {
            serverCertFile = argv[++argpos];
            continue;
        }
    }

    /* Determine PKI store path - use --pki argument or default to ./client_pki */
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
        clientStorePath = UA_String_fromChars(pkiPathArg);
        if(clientStorePath.length == 0) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Failed to allocate PKI path string");
            return EXIT_FAILURE;
        }
    } else {
        /* Default to ./client_pki in current directory */
        clientStorePath = UA_String_fromChars("./client_pki");
        if(clientStorePath.length == 0) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Failed to allocate default PKI path");
            return EXIT_FAILURE;
        }
    }

    /* Build paths to own certificate and private key in PKI */
    char certPath[4096], keyPath[4096];
    snprintf(certPath, sizeof(certPath), "%.*s/ApplCerts/own/certs/client_cert.der",
             (int)clientStorePath.length, clientStorePath.data);
    snprintf(keyPath, sizeof(keyPath), "%.*s/ApplCerts/own/private/client_key.der",
             (int)clientStorePath.length, clientStorePath.data);
    
    /* Create PKI directory structure */
    char rootDir[4096];
    char applCertsDir[4096];
    char ownCertsDir[4096];
    char ownPrivateDir[4096];
    char issuerCertsDir[4096];
    char issuerCrlDir[4096];
    char trustedDir[4096];
    
    snprintf(rootDir, sizeof(rootDir), "%.*s", (int)clientStorePath.length, clientStorePath.data);
    snprintf(applCertsDir, sizeof(applCertsDir), "%.*s/ApplCerts", (int)clientStorePath.length, clientStorePath.data);
    snprintf(ownCertsDir, sizeof(ownCertsDir), "%.*s/ApplCerts/own/certs", (int)clientStorePath.length, clientStorePath.data);
    snprintf(ownPrivateDir, sizeof(ownPrivateDir), "%.*s/ApplCerts/own/private", (int)clientStorePath.length, clientStorePath.data);
    snprintf(issuerCertsDir, sizeof(issuerCertsDir), "%.*s/ApplCerts/issuer/certs", (int)clientStorePath.length, clientStorePath.data);
    snprintf(issuerCrlDir, sizeof(issuerCrlDir), "%.*s/ApplCerts/issuer/crl", (int)clientStorePath.length, clientStorePath.data);
    snprintf(trustedDir, sizeof(trustedDir), "%.*s/ApplCerts/trusted", (int)clientStorePath.length, clientStorePath.data);
    
    UA_StatusCode dirStatus = ensureDirectoryExists(rootDir);
    if(dirStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create root PKI directory: %s", rootDir);
        retval = dirStatus;
        goto cleanup;
    }
    
    dirStatus = ensureDirectoryExists(applCertsDir);
    if(dirStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create ApplCerts directory: %s", applCertsDir);
        retval = dirStatus;
        goto cleanup;
    }
    
    dirStatus = ensureDirectoryExists(ownCertsDir);
    if(dirStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create own/certs directory: %s", ownCertsDir);
        retval = dirStatus;
        goto cleanup;
    }
    
    dirStatus = ensureDirectoryExists(ownPrivateDir);
    if(dirStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create own/private directory: %s", ownPrivateDir);
        retval = dirStatus;
        goto cleanup;
    }
    
    dirStatus = ensureDirectoryExists(issuerCertsDir);
    if(dirStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create issuer/certs directory: %s", issuerCertsDir);
        retval = dirStatus;
        goto cleanup;
    }
    
    dirStatus = ensureDirectoryExists(issuerCrlDir);
    if(dirStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create issuer/crl directory: %s", issuerCrlDir);
        retval = dirStatus;
        goto cleanup;
    }
    
    dirStatus = ensureDirectoryExists(trustedDir);
    if(dirStatus != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "[FILESTORE] Failed to create trusted directory: %s", trustedDir);
        retval = dirStatus;
        goto cleanup;
    }
    
    /* Verify that client certificate and key exist */
    bool certExists = fileExists(certPath);
    bool keyExists = fileExists(keyPath);
    
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
        retval = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        goto cleanup;
    }
    
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
        retval = UA_STATUSCODE_BADINTERNALERROR;
        goto cleanup;
    }
    
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
               "[FILESTORE] Loaded client certificate and key from PKI: %s", certPath);

    client = UA_Client_new();
    if(!client) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to create client.");
        goto cleanup;
    }
    cc = UA_Client_getConfig(client);
    
    /* Increase buffer limits to avoid rejected messages with large PQC certificates */
    const UA_UInt32 bigBuf = 1 << 20; /* 1 MiB per TCP chunk */
    cc->localConnectionConfig.sendBufferSize = bigBuf;
    cc->localConnectionConfig.recvBufferSize = bigBuf;
    cc->localConnectionConfig.localMaxMessageSize = 1 << 30;  /* 1 GiB */
    cc->localConnectionConfig.remoteMaxMessageSize = 1 << 30;  /* 1 GiB */
    cc->localConnectionConfig.localMaxChunkCount = 1 << 20;    /* 1M chunks */
    cc->localConnectionConfig.remoteMaxChunkCount = 1 << 20;   /* 1M chunks */
    
    /* Configure client with PKI FileStore */
    retval = UA_ClientConfig_setDefaultWithFilestore(cc, &certificate, &privateKey, clientStorePath);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to configure client with PKI FileStore: %s",
                    UA_StatusCode_name(retval));
        goto cleanup;
    }

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "[FILESTORE] PKI initialized at %.*s",
                (int)clientStorePath.length, clientStorePath.data);

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
    
    /* Helper macro to create directory from UA_String */
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
    
    /* Create all directories for Application Certificates (certificateVerification) */
    /* The client uses certificateVerification instead of secureChannelPKI */
    if(cc->certificateVerification.context) {
        FileCertStore *applContext = (FileCertStore *)cc->certificateVerification.context;
        
        CREATE_DIR_FROM_STRING(applContext->trustedCertFolder);
        CREATE_DIR_FROM_STRING(applContext->trustedCrlFolder);
        CREATE_DIR_FROM_STRING(applContext->issuerCertFolder);
        CREATE_DIR_FROM_STRING(applContext->issuerCrlFolder);
        CREATE_DIR_FROM_STRING(applContext->rejectedCertFolder);
        CREATE_DIR_FROM_STRING(applContext->ownCertFolder);
        CREATE_DIR_FROM_STRING(applContext->ownKeyFolder);
    }
    
    #undef CREATE_DIR_FROM_STRING

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    /* Replace default policy with PQC with filestore support */
    if(cc->securityPolicies) {
        for(size_t i = 0; i < cc->securityPoliciesSize; i++) {
            cc->securityPolicies[i].clear(&cc->securityPolicies[i]);
        }
        UA_free(cc->securityPolicies);
        cc->securityPolicies = NULL;
        cc->securityPoliciesSize = 0;
    }

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
    cc->securityPoliciesSize = 1;
    cc->securityPolicies = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
    if(!cc->securityPolicies) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Memory allocation failed for PQC policy");
        innerPqcPolicy->clear(innerPqcPolicy);
        UA_free(innerPqcPolicy);
        goto cleanup;
    }
    memset(cc->securityPolicies, 0, sizeof(UA_SecurityPolicy));

    retval = UA_SecurityPolicy_Filestore(&cc->securityPolicies[0], innerPqcPolicy, clientStorePath);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to wrap PQC SecurityPolicy with Filestore: %s",
                     UA_StatusCode_name(retval));
        innerPqcPolicy->clear(innerPqcPolicy);
        UA_free(innerPqcPolicy);
        UA_free(cc->securityPolicies);
        cc->securityPolicies = NULL;
        cc->securityPoliciesSize = 0;
        goto cleanup;
    }
#endif

    cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
    cc->securityPolicyUri = UA_String_fromChars("http://example.org/SecurityPolicy#PQC");
    cc->endpoint.securityPolicyUri = UA_String_fromChars("http://example.org/SecurityPolicy#PQC");
    cc->endpoint.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;

    /* This demonstrates how to create a direct endpoint in the client configuration.
     * This enables connection to a server that does not include the 'None' policy
     * in its security policy list, as would be the case
     * with 'UA_ServerConfig_setDefaultWithSecureSecurityPolicies'. */
    if(serverCertFile) {
#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
        cc->endpoint.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        cc->endpoint.endpointUrl = UA_String_fromChars(endpointUrl);
        cc->endpoint.transportProfileUri = UA_String_fromChars(
            "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");
        cc->endpoint.serverCertificate = loadFile(serverCertFile);
        
        /* Validate that server certificate was loaded successfully */
        if(cc->endpoint.serverCertificate.length == 0) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Failed to load server certificate file: %s", serverCertFile);
            goto cleanup;
        }

        /* Configure user identity with certificate */
        cc->endpoint.userIdentityTokens = (UA_UserTokenPolicy *)
            UA_Array_new(1, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
        if(!cc->endpoint.userIdentityTokens) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Memory allocation failed for user identity tokens");
            goto cleanup;
        }
        cc->endpoint.userIdentityTokensSize = 1;
        cc->endpoint.userIdentityTokens[0].tokenType = UA_USERTOKENTYPE_CERTIFICATE;
        cc->endpoint.userIdentityTokens[0].policyId = UA_String_fromChars("open62541-certificate-policy-sign+encrypt#PQC");
        cc->endpoint.userIdentityTokens[0].securityPolicyUri = UA_String_fromChars("http://example.org/SecurityPolicy#PQC");

        UA_ClientConfig_setAuthenticationCert(cc, certificate, privateKey);
        
        /* Replace authSecurityPolicies with PQC (after setAuthenticationCert reconfigures them) */
        if(cc->authSecurityPolicies) {
            for(size_t i = 0; i < cc->authSecurityPoliciesSize; i++) {
                cc->authSecurityPolicies[i].clear(&cc->authSecurityPolicies[i]);
            }
            UA_free(cc->authSecurityPolicies);
            cc->authSecurityPolicies = NULL;
            cc->authSecurityPoliciesSize = 0;
        }

        UA_SecurityPolicy *innerAuthPqcPolicy = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
        if(!innerAuthPqcPolicy) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Memory allocation failed for inner PQC auth policy");
            goto cleanup;
        }
        memset(innerAuthPqcPolicy, 0, sizeof(UA_SecurityPolicy));

        retval = UA_SecurityPolicy_PQC(innerAuthPqcPolicy, certificate, privateKey, UA_Log_Stdout);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Failed to initialize inner PQC Auth SecurityPolicy: %s",
                        UA_StatusCode_name(retval));
            UA_free(innerAuthPqcPolicy);
            goto cleanup;
        }

        /* Wrap auth PQC policy with filestore */
        cc->authSecurityPoliciesSize = 1;
        cc->authSecurityPolicies = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
        if(!cc->authSecurityPolicies) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Memory allocation failed for PQC auth policy");
            innerAuthPqcPolicy->clear(innerAuthPqcPolicy);
            UA_free(innerAuthPqcPolicy);
            goto cleanup;
        }
        memset(cc->authSecurityPolicies, 0, sizeof(UA_SecurityPolicy));

        retval = UA_SecurityPolicy_Filestore(&cc->authSecurityPolicies[0], innerAuthPqcPolicy, clientStorePath);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Failed to wrap PQC Auth SecurityPolicy with Filestore: %s",
                        UA_StatusCode_name(retval));
            innerAuthPqcPolicy->clear(innerAuthPqcPolicy);
            UA_free(innerAuthPqcPolicy);
            UA_free(cc->authSecurityPolicies);
            cc->authSecurityPolicies = NULL;
            cc->authSecurityPoliciesSize = 0;
            goto cleanup;
        }
#elif defined(UA_ENABLE_ENCRYPTION_MBEDTLS)
        cc->endpoint.securityPolicyUri = UA_String_fromChars("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        cc->endpoint.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        cc->endpoint.endpointUrl = UA_String_fromChars(endpointUrl);
        cc->endpoint.serverCertificate = loadFile(serverCertFile);

        cc->endpoint.userIdentityTokensSize = 0;
        cc->endpoint.userIdentityTokens = (UA_UserTokenPolicy *)
            UA_Array_new(1, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
        if(!cc->endpoint.userIdentityTokens) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Memory allocation failed for user identity tokens");
            goto cleanup;
        }
        cc->endpoint.userIdentityTokensSize = 1;

        cc->endpoint.userIdentityTokens[0].tokenType = UA_USERTOKENTYPE_CERTIFICATE;
        cc->endpoint.userIdentityTokens[0].policyId = UA_String_fromChars("open62541-certificate-policy-sign+encrypt#Basic256Sha256");
        cc->endpoint.userIdentityTokens[0].securityPolicyUri = UA_String_fromChars("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        cc->endpoint.transportProfileUri = UA_String_fromChars("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");

        UA_ClientConfig_setAuthenticationCert(cc, certificate, privateKey);
#else
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "The provided server certificate is ignored, and therefore no specific endpoint is configured."
                    "Authentication using a certificate is only possible with mbedTLS or OpenSSL" );
#endif
    }

    retval = UA_Client_connect(client, endpointUrl);
    if(retval != UA_STATUSCODE_GOOD) {
        goto cleanup;
    }

    UA_Variant value;
    UA_Variant_init(&value);

    const UA_NodeId nodeId = UA_NS0ID(SERVER_SERVERSTATUS_CURRENTTIME);
    retval = UA_Client_readValueAttribute(client, nodeId, &value);

    if(retval == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DATETIME])) {
        UA_DateTime raw_date = *(UA_DateTime *)value.data;
        UA_DateTimeStruct dts = UA_DateTime_toStruct(raw_date);
        int result1 = fprintf(stdout, "\n");
        int result2 = fprintf(stdout, "═══════════════════════════════════════════════════════════════\n");
        int result3 = fprintf(stdout, "SUCCESS: Received server value\n");
        int result4 = fprintf(stdout, "  Server date: %u-%u-%u %u:%u:%u.%03u\n",
                dts.day, dts.month, dts.year, dts.hour, dts.min, dts.sec, dts.milliSec);
        int result5 = fprintf(stdout, "═══════════════════════════════════════════════════════════════\n");
        int result6 = fprintf(stdout, "\n");
        
        if(result1 < 0 || result2 < 0 || result3 < 0 || result4 < 0 || result5 < 0 || result6 < 0) {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                          "Failed to write output to stdout (broken pipe or I/O error). "
                          "This may occur when output is redirected to a pipe that closes early.");
        } else {
            if(fflush(stdout) != 0) {
                UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                              "Failed to flush stdout (broken pipe or I/O error).");
            }
        }
    }

    UA_Variant_clear(&value);

 cleanup:
    if(client) {
        if(cc) {
            if(cc->securityPolicyUri.data) {
                UA_String_clear(&cc->securityPolicyUri);
            }
            if(cc->endpoint.securityPolicyUri.data) {
                UA_String_clear(&cc->endpoint.securityPolicyUri);
            }
            if(cc->endpoint.endpointUrl.data) {
                UA_String_clear(&cc->endpoint.endpointUrl);
            }
            if(cc->endpoint.transportProfileUri.data) {
                UA_String_clear(&cc->endpoint.transportProfileUri);
            }
            if(cc->endpoint.userIdentityTokens && cc->endpoint.userIdentityTokensSize > 0) {
                if(cc->endpoint.userIdentityTokens[0].policyId.data) {
                    UA_String_clear(&cc->endpoint.userIdentityTokens[0].policyId);
                }
                if(cc->endpoint.userIdentityTokens[0].securityPolicyUri.data) {
                    UA_String_clear(&cc->endpoint.userIdentityTokens[0].securityPolicyUri);
                }
            }
        }
        UA_Client_delete(client);
    }
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_String_clear(&clientStorePath);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
