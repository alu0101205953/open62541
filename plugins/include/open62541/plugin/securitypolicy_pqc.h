#ifndef UA_SECURITYPOLICY_PQC_H_
#define UA_SECURITYPOLICY_PQC_H_

#include <open62541/plugin/securitypolicy.h>
#include <open62541/plugin/log.h>

_UA_BEGIN_DECLS

UA_EXPORT UA_StatusCode
UA_SecurityPolicy_PQC(UA_SecurityPolicy *policy,
                      const UA_ByteString localCertificate,
                      const UA_ByteString localPrivateKey,
                      const UA_Logger *logger);

_UA_END_DECLS

#endif /* UA_SECURITYPOLICY_PQC_H_ */
