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

#include "common.h"

UA_Boolean running = true;
static void stopHandler(int sig) {
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    bool onlySecure = false;
    bool allowDiscovery = false;
    char *clientSigKeyFile = NULL;
    char *clientKemKeyFile = NULL;
    
    if(argc >= 3) {
            certificate = loadFile(argv[1]);
            privateKey = loadFile(argv[2]);
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
            
            writeFile(defaultCertPath, certificate);
            writeFile(defaultKeyPath, privateKey);
        }
    }
#endif

    /* Parse command line options first (before loading trust list) */
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

    /* Load the trustlist */
    /* Note: Arguments after argv[3] can be trust lists or options like --onlySecure, --allowDiscovery, etc.
     * We need to count only arguments that are trust list files */
    size_t trustListSize = 0;
    size_t trustListArgCount = 0;
    if(argc > 3) {
        /* Count arguments that are not options */
        for(int argpos = 3; argpos < argc; argpos++) {
            if(strcmp(argv[argpos], "--onlySecure") == 0 ||
               strcmp(argv[argpos], "--allowDiscovery") == 0 ||
               strcmp(argv[argpos], "--clientSigKey") == 0 ||
               strcmp(argv[argpos], "--clientKemKey") == 0) {
                if(strcmp(argv[argpos], "--clientSigKey") == 0 || strcmp(argv[argpos], "--clientKemKey") == 0) {
                    argpos++; /* Skip option value */
                }
                continue;
            }
            trustListArgCount++;
        }
        trustListSize = trustListArgCount;
    }
    
    UA_STACKARRAY(UA_ByteString, trustList, trustListSize+1);
    size_t trustListIdx = 0;
    for(int argpos = 3; argpos < argc && trustListIdx < trustListSize; argpos++) {
        if(strcmp(argv[argpos], "--onlySecure") == 0 ||
           strcmp(argv[argpos], "--allowDiscovery") == 0 ||
           strcmp(argv[argpos], "--clientSigKey") == 0 ||
           strcmp(argv[argpos], "--clientKemKey") == 0) {
            if(strcmp(argv[argpos], "--clientSigKey") == 0 || strcmp(argv[argpos], "--clientKemKey") == 0) {
                argpos++; /* Skip option value */
            }
            continue;
        }
        trustList[trustListIdx] = loadFile(argv[argpos]);
        trustListIdx++;
    }

    /* Loading of an issuer list, not used in this application */
    size_t issuerListSize = 0;
    UA_ByteString *issuerList = NULL;

    /* Revocation lists are supported, but not used for the example here */
    UA_ByteString *revocationList = NULL;
    size_t revocationListSize = 0;

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(onlySecure) {
        retval = UA_ServerConfig_setDefaultWithSecureSecurityPolicies(config, 4840,
                                                                      &certificate, &privateKey,
                                                                      trustList, trustListSize,
                                                                      issuerList, issuerListSize,
                                                                      revocationList, revocationListSize);
    } else {
        retval = UA_ServerConfig_setDefaultWithSecurityPolicies(config, 4840,
                                                                &certificate, &privateKey,
                                                                trustList, trustListSize,
                                                                issuerList, issuerListSize,
                                                                revocationList, revocationListSize);
    }

    /* Increase buffer limits to avoid rejected messages */
    const UA_UInt32 bigBuf = 1 << 20; /* 1 MiB per TCP chunk */
    config->tcpBufSize = bigBuf;
    config->tcpMaxMsgSize = 1 << 30;  /* 1 GiB */
    config->tcpMaxChunks  = 1 << 20;  /* 1M chunks */

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    /* Add PQC policy to server */
    /* Verify that the policies array is initialized */
    if(!config->securityPolicies && config->securityPoliciesSize > 0) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Security policies array is NULL but size is not zero");
        goto cleanup;
    }
    
    /* Use malloc if array is NULL, realloc if it already exists */
    UA_SecurityPolicy *tmp;
    if(config->securityPolicies == NULL) {
        tmp = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy) * (config->securityPoliciesSize + 1));
    } else {
        tmp = (UA_SecurityPolicy *)UA_realloc(config->securityPolicies,
                                               sizeof(UA_SecurityPolicy) * (config->securityPoliciesSize + 1));
    }
    if(!tmp) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Memory allocation failed for security policies array (size: %zu)",
                     config->securityPoliciesSize + 1);
        goto cleanup;
    }
    config->securityPolicies = tmp;

    /* Initialize PQC policy directly in the array */
    /* First initialize structure to zero to avoid issues */
    memset(&config->securityPolicies[config->securityPoliciesSize], 0, sizeof(UA_SecurityPolicy));
    
    retval = UA_SecurityPolicy_PQC(&config->securityPolicies[config->securityPoliciesSize],
                                   certificate, privateKey, UA_Log_Stdout);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to initialize PQC SecurityPolicy: %s",
                     UA_StatusCode_name(retval));
        /* Clean up policy if partially initialized */
        if(config->securityPolicies[config->securityPoliciesSize].clear) {
            config->securityPolicies[config->securityPoliciesSize].clear(
                &config->securityPolicies[config->securityPoliciesSize]);
        }
        if(config->securityPoliciesSize == 0) {
            UA_free(config->securityPolicies);
            config->securityPolicies = NULL;
        }
        goto cleanup;
    }

    config->securityPoliciesSize++;
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

    /* Accept all certificates */
    config->secureChannelPKI.clear(&config->secureChannelPKI);
    UA_CertificateGroup_AcceptAll(&config->secureChannelPKI);

    config->sessionPKI.clear(&config->sessionPKI);
    UA_CertificateGroup_AcceptAll(&config->sessionPKI);

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    if(clientSigKeyFile && clientKemKeyFile) {
        UA_ByteString clientSigKey = loadFile(clientSigKeyFile);
        UA_ByteString clientKemKey = loadFile(clientKemKeyFile);
        if(clientSigKey.length == (size_t)OQS_SIG_dilithium_2_length_public_key &&
           clientKemKey.length == (size_t)OQS_KEM_kyber_768_length_public_key) {
            size_t idx = config->securityPoliciesSize;
            if(idx > 0)
                idx--;
            if(config->securityPolicies && config->securityPoliciesSize > 0) {
                UA_StatusCode rc =
                    UA_PQCPolicy_registerRemoteKeys(&config->securityPolicies[idx],
                                                    clientSigKey, clientKemKey);
                if(rc != UA_STATUSCODE_GOOD) {
                    UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                                   "Failed to register client PQC keys override: %s",
                                   UA_StatusCode_name(rc));
                }
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

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    for(size_t i = 0; i < trustListSize; i++)
        UA_ByteString_clear(&trustList[i]);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    if(!running)
        goto cleanup; /* received ctrl-c already */
    
    
    retval = UA_Server_run(server, &running);

 cleanup:
    UA_Server_delete(server);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
