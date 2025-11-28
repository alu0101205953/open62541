#ifndef UA_SECURITYPOLICY_PQC_H_
#define UA_SECURITYPOLICY_PQC_H_

#include <open62541/plugin/securitypolicy.h>
#include <open62541/plugin/log.h>
#include <open62541/plugin/create_certificate.h>

_UA_BEGIN_DECLS

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_PQC(UA_SecurityPolicy *policy,
                      const UA_ByteString localCertificate,
                      const UA_ByteString localPrivateKey,
                      const UA_Logger *logger);

UA_EXPORT UA_StatusCode
UA_PQC_EnsureCertificateExtensions(UA_ByteString *certificate,
                                   UA_ByteString *signingPrivateKey,
                                   const UA_Logger *logger);

/**
 * Create a new self-signed X.509 certificate with PQC extensions from scratch.
 * This is preferred over modifying existing certificates, as it avoids re-signing
 * issues and ensures clean certificate structure.
 *
 * Uses RSA/ECC for certificate signing and adds PQC keys as extensions.
 *
 * @param logger Logger instance (can be NULL)
 * @param subject Certificate subject (e.g., "C=DE,O=SampleOrganization,CN=Server")
 * @param subjectSize Number of subject components
 * @param subjectAltName Subject alternative names (e.g., "DNS:localhost,IP:127.0.0.1")
 * @param subjectAltNameSize Number of SAN entries
 * @param certFormat Output format (DER or PEM)
 * @param rsaKeySizeBits RSA key size for certificate signing (typically 2048 or 4096)
 * @param expiresInDays Certificate validity period in days
 * @param outPrivateKey Output: RSA private key + PQC keys concatenated
 * @param outCertificate Output: Self-signed certificate with PQC extensions
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
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
                         UA_ByteString *outCertificate);

/**
 * Create a new self-signed X.509 certificate signed directly with Dilithium
 * using the OQS Provider for OpenSSL 3.x.
 *
 * This function requires:
 * - OpenSSL 3.0 or later
 * - OQS Provider installed and loaded
 * - The OQS Provider must be available in the OpenSSL context
 *
 * If the OQS Provider is not available, this function will return an error.
 * In that case, use UA_PQC_CreateCertificate() instead (hybrid approach).
 *
 * @param logger Logger instance (can be NULL)
 * @param subject Certificate subject (e.g., "C=DE,O=SampleOrganization,CN=Server")
 * @param subjectSize Number of subject components
 * @param subjectAltName Subject alternative names (e.g., "DNS:localhost,IP:127.0.0.1")
 * @param subjectAltNameSize Number of SAN entries
 * @param certFormat Output format (DER or PEM)
 * @param pqcSigAlgorithm PQC signature algorithm name (e.g., "Dilithium2", "ML-DSA-65")
 * @param expiresInDays Certificate validity period in days
 * @param outPrivateKey Output: Dilithium private key + Kyber private key concatenated
 * @param outCertificate Output: Self-signed certificate signed with Dilithium
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
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
                                        UA_ByteString *outCertificate);

UA_EXPORT UA_StatusCode
UA_PQCPolicy_registerRemoteKeys(UA_SecurityPolicy *policy,
                                const UA_ByteString sigPublicKey,
                                const UA_ByteString kemPublicKey);

/* Update the channel context with a new remote certificate (for PQC policies) */
UA_EXPORT UA_StatusCode
UA_PQCChannel_updateRemoteCertificate(void *channelContext,
                                     const UA_ByteString *remoteCertificate);

/**
 * Check if OpenSSL 3.x is available (required for OQS Provider).
 *
 * @return UA_TRUE if OpenSSL 3.0 or later is available, UA_FALSE otherwise
 */
UA_EXPORT UA_Boolean
UA_PQC_IsOpenSSL3Available(void);

/**
 * Check if the OQS Provider is available and can be loaded.
 *
 * This function attempts to load the OQS Provider and checks if it's available.
 * The provider is unloaded after the check.
 *
 * @param logger Logger instance (can be NULL)
 * @param providerName Name of the provider to check (typically "oqsprovider" or "oqs")
 * @return UA_TRUE if the provider is available, UA_FALSE otherwise
 */
UA_EXPORT UA_Boolean
UA_PQC_IsOQSProviderAvailable(const UA_Logger *logger, const char *providerName);

/**
 * Check if a specific PQC signature algorithm is available via OQS Provider.
 *
 * This function checks if a specific algorithm (e.g., "Dilithium2", "ML-DSA-65")
 * can be used for key generation through the OQS Provider.
 *
 * @param logger Logger instance (can be NULL)
 * @param algorithmName Name of the PQC algorithm to check
 * @return UA_TRUE if the algorithm is available, UA_FALSE otherwise
 */
UA_EXPORT UA_Boolean
UA_PQC_IsAlgorithmAvailable(const UA_Logger *logger, const char *algorithmName);

/**
 * Check if a certificate is signed with a PQC algorithm (e.g., Dilithium).
 *
 * This function examines the certificate's signature algorithm to determine
 * if it uses a post-quantum cryptography algorithm.
 *
 * @param certificate Certificate to check
 * @param logger Logger instance (can be NULL)
 * @return UA_TRUE if the certificate is signed with a PQC algorithm, UA_FALSE otherwise
 */
UA_EXPORT UA_Boolean
UA_PQC_IsCertificatePQCSigned(const UA_ByteString *certificate, const UA_Logger *logger);

/**
 * Check if a certificate has PQC extensions (Dilithium and Kyber public keys).
 *
 * This function checks for PQC extensions regardless of the certificate's signature algorithm.
 * A certificate can be signed with RSA/ECC (traditional) but still have PQC extensions
 * for cryptographic operations (hybrid approach).
 *
 * @param certificate Certificate to check
 * @param logger Logger instance (can be NULL)
 * @return UA_TRUE if the certificate has PQC extensions, UA_FALSE otherwise
 */
UA_EXPORT UA_Boolean
UA_PQC_HasCertificatePQCExtensions(const UA_ByteString *certificate, const UA_Logger *logger);

/**
 * Create a Certificate Signing Request (CSR) with PQC keys.
 * 
 * This function generates a CSR with Dilithium2 signing key and Kyber768 KEM key.
 * The CSR includes PQC extensions and can be signed by a CA.
 * 
 * @param logger Logger instance (can be NULL)
 * @param subject Certificate subject (e.g., ["C=DE", "O=Org", "CN=Server"])
 * @param subjectSize Number of subject components
 * @param subjectAltName Subject alternative names (e.g., ["DNS:localhost", "URI:urn:..."])
 * @param subjectAltNameSize Number of SAN entries
 * @param outPrivateKey Output: Dilithium + Kyber private keys (DER format)
 * @param outCSR Output: Certificate Signing Request (DER format)
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
 */
UA_EXPORT UA_StatusCode
UA_PQC_CreateCSR(const UA_Logger *logger,
                 const UA_String *subject,
                 size_t subjectSize,
                 const UA_String *subjectAltName,
                 size_t subjectAltNameSize,
                 UA_ByteString *outPrivateKey,
                 UA_ByteString *outCSR);

/**
 * Sign a Certificate Signing Request (CSR) with a CA certificate using PQC algorithms.
 * 
 * This function takes a CSR and creates a certificate signed by the CA.
 * The OQS Provider automatically handles Dilithium signing if the CA's private key is Dilithium.
 * 
 * @param logger Logger instance (can be NULL)
 * @param csr Certificate Signing Request (DER format)
 * @param caCert CA certificate (DER or PEM format)
 * @param caKey CA private key (DER or PEM format, must include Dilithium key for PQC signing)
 * @param serialNumber Serial number for the certificate (use 1 for first certificate)
 * @param expiresInDays Certificate validity period in days
 * @param outSignedCert Output: Certificate signed by CA (DER format)
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
 */
UA_EXPORT UA_StatusCode
UA_PQC_SignCSRWithCA(const UA_Logger *logger,
                     const UA_ByteString *csr,
                     const UA_ByteString *caCert,
                     const UA_ByteString *caKey,
                     UA_Int32 serialNumber,
                     UA_UInt32 expiresInDays,
                     UA_ByteString *outSignedCert);

/**
 * Sign a certificate with a CA certificate using PQC algorithms.
 * 
 * This function takes a certificate (typically self-signed) and signs it with
 * a CA's private key. The OQS Provider automatically handles Dilithium signing
 * if the CA's private key is a Dilithium key.
 * 
 * @param logger Logger instance (can be NULL)
 * @param certToSign Certificate to be signed (DER or PEM format)
 * @param caCert CA certificate (DER or PEM format)
 * @param caKey CA private key (DER or PEM format, must include Dilithium key for PQC signing)
 * @param outSignedCert Output: Certificate signed by CA (DER format)
 * @return UA_STATUSCODE_GOOD on success, error code otherwise
 */
UA_EXPORT UA_StatusCode
UA_PQC_SignCertificateWithCA(const UA_Logger *logger,
                              const UA_ByteString *certToSign,
                              const UA_ByteString *caCert,
                              const UA_ByteString *caKey,
                              UA_ByteString *outSignedCert);

_UA_END_DECLS

#endif /* UA_SECURITYPOLICY_PQC_H_ */
