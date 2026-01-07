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
#endif

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

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
    
    /* Determine PKI store path - use command line argument or default to current directory */
    if(argc >= 4) {
        storePath = UA_STRING(argv[3]);
    } else {
        char storePathDir[4096];
        if(!getcwd(storePathDir, sizeof(storePathDir))) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Can't retrieve current working directory.");
            return EXIT_FAILURE;
        }
        storePath = UA_STRING(storePathDir);
    }
    
    /* Build paths to own certificate and private key in PKI */
    char certDir[4096], keyDir[4096];
    snprintf(certDir, sizeof(certDir), "%.*s/own/certs",
             (int)storePath.length, storePath.data);
    snprintf(keyDir, sizeof(keyDir), "%.*s/own/private",
             (int)storePath.length, storePath.data);
    
    char certPath[4096], keyPath[4096];
    snprintf(certPath, sizeof(certPath), "%s/server_cert.der", certDir);
    snprintf(keyPath, sizeof(keyPath), "%s/server_key.der", keyDir);
    
    /* Load certificate and private key from PKI FileStore */
    if(fileExists(certPath) && fileExists(keyPath)) {
        certificate = loadFile(certPath);
        privateKey = loadFile(keyPath);
        
        /* Validate that files were loaded successfully */
        if(certificate.length == 0 || privateKey.length == 0) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Failed to load certificate or private key from PKI FileStore.");
            if(certificate.length > 0)
                UA_ByteString_clear(&certificate);
            if(privateKey.length > 0)
                UA_ByteString_clear(&privateKey);
            return EXIT_FAILURE;
        }
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Loaded certificate and private key from PKI FileStore: %s", certPath);
    } else if(argc >= 3) {
        /* Fallback: load from command line arguments (for backward compatibility) */
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                       "Certificate or key not found in PKI FileStore. Loading from command line arguments.");
        certificate = loadFile(argv[1]);
        privateKey = loadFile(argv[2]);
        
        /* Validate that files were loaded successfully */
        if(certificate.length == 0 || privateKey.length == 0) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Failed to load certificate or private key file.");
            if(certificate.length > 0)
                UA_ByteString_clear(&certificate);
            if(privateKey.length > 0)
                UA_ByteString_clear(&privateKey);
            return EXIT_FAILURE;
        }
    } else {
        /* Generate PQC certificate directly (requires OpenSSL 3.0+ and OQS Provider) */
        UA_String subject[3] = {UA_STRING_STATIC("C=DE"),
                            UA_STRING_STATIC("O=SampleOrganization"),
                            UA_STRING_STATIC("CN=Open62541Server@localhost")};
        UA_UInt32 lenSubject = 3;
        UA_String subjectAltName[2]= {
            UA_STRING_STATIC("DNS:localhost"),
            UA_STRING_STATIC("URI:urn:open62541.server.application")
        };
        UA_UInt32 lenSubjectAltName = 2;
        
        UA_StatusCode statusCertGen = UA_PQC_CreateCertificate(
            UA_Log_Stdout, subject, lenSubject, subjectAltName, lenSubjectAltName,
            UA_CERTIFICATEFORMAT_DER,
            0,   /* rsaKeySizeBits - deprecated, ignored */
            365, /* expiresInDays */
            &privateKey,
            &certificate);

        if(statusCertGen != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Generating PQC Certificate failed: %s",
                UA_StatusCode_name(statusCertGen));
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Make sure OpenSSL 3.0+ and OQS Provider are installed and available.");
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Alternatively, provide certificate files: "
                "<server-certificate.der> <private-key.der>");
            return EXIT_FAILURE;
        }
    }

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
        if(argc < 3 && certificate.length > 0 && privateKey.length > 0) {
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

    /* Parse command line options */
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
    
    /* Configure server with PKI FileStore - this sets up the PKI structure */
    /* Note: We pass NULL for certificate/privateKey here because we'll add PQC policy separately */
    /* But we need to pass them to create the PKI structure, so we use empty strings */
    UA_ByteString emptyCert = UA_BYTESTRING_NULL;
    UA_ByteString emptyKey = UA_BYTESTRING_NULL;
    
    /* First, set up basic config without security policies */
    retval = UA_ServerConfig_setDefault(config, 4840);
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
    
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);

    if(!running)
        goto cleanup; /* received ctrl-c already */
    
    
    retval = UA_Server_run(server, &running);

 cleanup:
    UA_Server_delete(server);
    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    UA_String_clear(&storePath);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
