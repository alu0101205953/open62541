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

#include "common.h"

#define MIN_ARGS 4

int main(int argc, char* argv[]) {
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    char *endpointUrl = NULL;
    char *serverCertFile = NULL;

    if(argc >= MIN_ARGS) {
        endpointUrl = argv[1];
        /* Load certificate and private key */
        certificate = loadFile(argv[2]);
        privateKey = loadFile(argv[3]);
    } else {
        /* Generate PQC certificate directly (requires OpenSSL 3.0+ and OQS Provider) */
        UA_String subject[3] = {UA_STRING_STATIC("C=DE"),
                            UA_STRING_STATIC("O=SampleOrganization"),
                            UA_STRING_STATIC("CN=Open62541Client@localhost")};
        UA_UInt32 lenSubject = 3;
        UA_String subjectAltName[2]= {
            UA_STRING_STATIC("DNS:localhost"),
            UA_STRING_STATIC("URI:urn:open62541.unconfigured.application")
        };
        UA_UInt32 lenSubjectAltName = 2;
        
        UA_StatusCode statusCertGen = UA_PQC_CreateCertificate(
            UA_Log_Stdout, subject, lenSubject, subjectAltName, lenSubjectAltName,
            UA_CERTIFICATEFORMAT_DER,
            0,   /* rsaKeySizeBits - deprecated, ignored */
            14,  /* expiresInDays */
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
                "<client-certificate.der> <client-private-key.der>");
            return EXIT_FAILURE;
    }

        endpointUrl = "opc.tcp://localhost:4840";
    }

    /* If the server certificate is specified, a direct endpoint is created in the client configuration. */
    for(int argpos = 1; argpos < argc; argpos++) {
        if(strcmp(argv[argpos], "--serverCert") == 0) {
            argpos++;
            if(argpos < argc) {
            serverCertFile = argv[argpos];
            }
            break;
        }
    }

    /* Load the trustlist */
    /* Note: Arguments after MIN_ARGS can be trust lists or --serverCert.
     * We need to count only arguments that are NOT --serverCert */
    size_t trustListSize = 0;
    size_t trustListArgCount = 0;
    if(argc > MIN_ARGS) {
        /* Count arguments that are not --serverCert */
        for(int argpos = MIN_ARGS; argpos < argc; argpos++) {
            if(strcmp(argv[argpos], "--serverCert") == 0) {
                argpos++; /* Skip --serverCert value */
                continue;
            }
            trustListArgCount++;
        }
        trustListSize = trustListArgCount;
    }
    
    UA_STACKARRAY(UA_ByteString, trustList, trustListSize+2); /* +2 for possible server certificate */
    size_t trustListIdx = 0;
    for(int argpos = MIN_ARGS; argpos < argc && trustListIdx < trustListSize; argpos++) {
        if(strcmp(argv[argpos], "--serverCert") == 0) {
            argpos++; /* Skip --serverCert value */
            continue;
        }
        trustList[trustListIdx] = loadFile(argv[argpos]);
        trustListIdx++;
    }

    /* Revocation lists are supported, but not used for the example here */
    UA_ByteString *revocationList = NULL;
    size_t revocationListSize = 0;

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    if(certificate.length > 0 && privateKey.length > 0) {
        UA_Boolean certIsPQCSigned = UA_PQC_IsCertificatePQCSigned(&certificate, UA_Log_Stdout);
        UA_Boolean certHasPQCExt = UA_PQC_HasCertificatePQCExtensions(&certificate, UA_Log_Stdout);
        
        if(!certIsPQCSigned || !certHasPQCExt) {
        UA_StatusCode pqcStatus =
                UA_PQC_EnsureCertificateExtensions(&certificate, &privateKey, UA_Log_Stdout);
        if(pqcStatus != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                           "Failed to embed PQC extensions into client certificate: %s",
                           UA_StatusCode_name(pqcStatus));
            }
        }
            
        /* Save auto-generated certificates AFTER ensuring PQC extensions */
            /* Check if certificates were auto-generated (no arguments provided) */
        if(argc < MIN_ARGS && certificate.length > 0 && privateKey.length > 0) {
                const char *defaultCertPath = "client_cert_pqc.der";
                const char *defaultKeyPath = "client_key_pqc.der";
                
            writeFile(defaultCertPath, certificate);
            writeFile(defaultKeyPath, privateKey);
                }
            }
    
    if(serverCertFile) {
        UA_ByteString serverCert = loadFile(serverCertFile);
        if(serverCert.length > 0) {
            UA_Boolean serverCertIsPQCSigned = UA_PQC_IsCertificatePQCSigned(&serverCert, UA_Log_Stdout);
            if(serverCertIsPQCSigned && !UA_PQC_IsOQSProviderAvailable(UA_Log_Stdout, "oqsprovider") &&
                          !UA_PQC_IsOQSProviderAvailable(UA_Log_Stdout, "oqs")) {
                    UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                               "WARNING - Server uses PQC-signed certificate but client does not have OQS Provider.");
            }
            UA_ByteString_clear(&serverCert);
        }
    }
#endif

    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    
    /* Increase buffer limits to avoid rejected messages with large PQC certificates */
    const UA_UInt32 bigBuf = 1 << 20; /* 1 MiB per TCP chunk */
    cc->localConnectionConfig.sendBufferSize = bigBuf;
    cc->localConnectionConfig.recvBufferSize = bigBuf;
    cc->localConnectionConfig.localMaxMessageSize = 1 << 30;  /* 1 GiB */
    cc->localConnectionConfig.remoteMaxMessageSize = 1 << 30;  /* 1 GiB */
    cc->localConnectionConfig.localMaxChunkCount = 1 << 20;    /* 1M chunks */
    cc->localConnectionConfig.remoteMaxChunkCount = 1 << 20;   /* 1M chunks */
    
    /* If server certificate is specified but no trust list is provided,
     * add it automatically to the trust list so the client trusts it */
    if(serverCertFile) {
        UA_ByteString serverCert = loadFile(serverCertFile);
        if(serverCert.length > 0) {
            /* Check if server certificate is already in trust list */
            UA_Boolean alreadyInTrustList = UA_FALSE;
            for(size_t i = 0; i < trustListSize; i++) {
                if(UA_ByteString_equal(&trustList[i], &serverCert)) {
                    alreadyInTrustList = UA_TRUE;
                    break;
                }
            }
            
            if(!alreadyInTrustList) {
                trustList[trustListSize] = serverCert;
                trustListSize++;
            } else {
                UA_ByteString_clear(&serverCert);
            }
            }
    }
    
    UA_StatusCode retval = UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey,
        trustList, trustListSize,
        revocationList, revocationListSize);
    
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Failed to set encryption." );
        UA_Client_delete(client);
        return EXIT_FAILURE;
    }
    
    if(trustListSize == 0 && !serverCertFile) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                      "No trust list provided. Accepting all certificates (DEVELOPMENT/TESTING ONLY)");
        UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
    }

#ifdef UA_ENABLE_ENCRYPTION_OPENSSL
    /* Replace default policy with PQC - MUST be done AFTER UA_ClientConfig_setDefaultEncryption
     * because that function sets up authSecurityPolicies */
    
    /* First, replace securityPolicies */
    if(cc->securityPolicies) {
        UA_free(cc->securityPolicies);
        cc->securityPolicies = NULL;
        cc->securityPoliciesSize = 0;
    }

    cc->securityPoliciesSize = 1;
    cc->securityPolicies = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
    if(!cc->securityPolicies) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Memory allocation failed for PQC policy");
        UA_Client_delete(client);
        return EXIT_FAILURE;
    }

    retval = UA_SecurityPolicy_PQC(&cc->securityPolicies[0],
                                   certificate, privateKey,
                                   UA_Log_Stdout);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                     "Failed to initialize PQC SecurityPolicy: %s",
                     UA_StatusCode_name(retval));
        UA_Client_delete(client);
        return EXIT_FAILURE;
    }
    
    /* Note: authSecurityPolicies will be configured AFTER UA_ClientConfig_setAuthenticationCert
     * (if serverCertFile is provided) because that function reconfigures authSecurityPolicies */
#endif

    /* Secure client connect */
    cc->securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT; /* require encryption */
    cc->securityPolicyUri = UA_String_fromChars("http://example.org/SecurityPolicy#PQC");
    cc->endpoint.securityPolicyUri = UA_String_fromChars("http://example.org/SecurityPolicy#PQC");
    cc->endpoint.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT; /* ensure endpoint has the correct security mode */

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

        /* Configure user identity with certificate */
        cc->endpoint.userIdentityTokens = (UA_UserTokenPolicy *)
            UA_Array_new(1, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
        cc->endpoint.userIdentityTokensSize = 1;
        cc->endpoint.userIdentityTokens[0].tokenType = UA_USERTOKENTYPE_CERTIFICATE;
        cc->endpoint.userIdentityTokens[0].policyId = UA_String_fromChars("open62541-certificate-policy-sign+encrypt#PQC");
        cc->endpoint.userIdentityTokens[0].securityPolicyUri = UA_String_fromChars("http://example.org/SecurityPolicy#PQC");

        /* UA_ClientConfig_setAuthenticationCert will reconfigure authSecurityPolicies
         * with standard policies, so we need to replace them with PQC AFTER this call */
        UA_ClientConfig_setAuthenticationCert(cc, certificate, privateKey);
        
        /* Replace authSecurityPolicies with PQC AFTER UA_ClientConfig_setAuthenticationCert
         * because that function reconfigures authSecurityPolicies with standard policies */
        if(cc->authSecurityPolicies) {
            for(size_t i = 0; i < cc->authSecurityPoliciesSize; i++) {
                cc->authSecurityPolicies[i].clear(&cc->authSecurityPolicies[i]);
            }
            UA_free(cc->authSecurityPolicies);
            cc->authSecurityPolicies = NULL;
            cc->authSecurityPoliciesSize = 0;
        }

        cc->authSecurityPoliciesSize = 1;
        cc->authSecurityPolicies = (UA_SecurityPolicy *)UA_malloc(sizeof(UA_SecurityPolicy));
        if(!cc->authSecurityPolicies) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Memory allocation failed for PQC auth policy");
            UA_Client_delete(client);
            return EXIT_FAILURE;
        }

        retval = UA_SecurityPolicy_PQC(&cc->authSecurityPolicies[0],
                                      certificate, privateKey,
                                      UA_Log_Stdout);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Failed to initialize PQC Auth SecurityPolicy: %s",
                        UA_StatusCode_name(retval));
            UA_Client_delete(client);
            return EXIT_FAILURE;
        }
#elif defined(UA_ENABLE_ENCRYPTION_MBEDTLS)
        cc->endpoint.securityPolicyUri = UA_String_fromChars("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
        cc->endpoint.securityMode = UA_MESSAGESECURITYMODE_SIGNANDENCRYPT;
        cc->endpoint.endpointUrl = UA_String_fromChars(endpointUrl);
        cc->endpoint.serverCertificate = loadFile(serverCertFile);

        cc->endpoint.userIdentityTokensSize = 0;
        cc->endpoint.userIdentityTokens = (UA_UserTokenPolicy *)
            UA_Array_new(1, &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
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
        UA_Client_delete(client);
        return EXIT_FAILURE;
    }

    UA_ByteString_clear(&certificate);
    UA_ByteString_clear(&privateKey);
    /* Clear trust list (includes server certificate if added automatically) */
    for(size_t deleteCount = 0; deleteCount < trustListSize; deleteCount++) {
        UA_ByteString_clear(&trustList[deleteCount]);
    }

    UA_Variant value;
    UA_Variant_init(&value);

    /* NodeId of the variable holding the current time */
    const UA_NodeId nodeId = UA_NS0ID(SERVER_SERVERSTATUS_CURRENTTIME);
    retval = UA_Client_readValueAttribute(client, nodeId, &value);

    if(retval == UA_STATUSCODE_GOOD &&
       UA_Variant_hasScalarType(&value, &UA_TYPES[UA_TYPES_DATETIME])) {
        UA_DateTime raw_date = *(UA_DateTime *)value.data;
        UA_DateTimeStruct dts = UA_DateTime_toStruct(raw_date);
        fprintf(stdout, "\n");
        fprintf(stdout, "═══════════════════════════════════════════════════════════════\n");
        fprintf(stdout, "SUCCESS: Received server value\n");
        fprintf(stdout, "  Server date: %u-%u-%u %u:%u:%u.%03u\n",
                dts.day, dts.month, dts.year, dts.hour, dts.min, dts.sec, dts.milliSec);
        fprintf(stdout, "═══════════════════════════════════════════════════════════════\n");
        fprintf(stdout, "\n");
    }

    /* Clean up */
    UA_Variant_clear(&value);
    UA_Client_delete(client);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
