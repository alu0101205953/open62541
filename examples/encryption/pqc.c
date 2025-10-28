#include <open62541/util.h>
#include <open62541/plugin/securitypolicy.h>
#include <open62541/plugin/securitypolicy_pqc.h>
#include <stdio.h>
#include "open62541/plugin/log_stdout.h"

int main(void) {
    UA_SecurityPolicy policy;
    const UA_Logger *logger = UA_Log_Stdout;
    UA_StatusCode retval;

    // Inicializa la política PQCStub
    retval = UA_SecurityPolicy_PQC(&policy, UA_BYTESTRING_NULL, UA_BYTESTRING_NULL, logger);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Error inicializando PQCStub: 0x%08x\n", retval);
        return 1;
    }

    printf("Política PQCStub inicializada correctamente\n");
    printf("URI: %.*s\n", (int)policy.policyUri.length, policy.policyUri.data);

    // Prueba firma y verificación
    UA_ByteString message = UA_STRING_STATIC("Mensaje de prueba");
    UA_ByteString signature;
    retval = policy.asymmetricModule.cryptoModule.signatureAlgorithm.sign(NULL, &message, &signature);
    if(retval != UA_STATUSCODE_GOOD) {
        printf("Error al firmar\n");
        return 1;
    }

    printf("Firma generada (longitud %u bytes)\n", (unsigned)signature.length);

    retval = policy.asymmetricModule.cryptoModule.signatureAlgorithm.verify(NULL, &message, &signature);
    printf("Verificación: %s\n",
           retval == UA_STATUSCODE_GOOD ? "éxito" : "fallo");

    UA_ByteString_clear(&signature);

    // Prueba cifrado y descifrado
    UA_ByteString data = UA_STRING_ALLOC("Texto secreto");
    printf("Texto original: %.*s\n", (int)data.length, data.data);

    retval = policy.asymmetricModule.cryptoModule.encryptionAlgorithm.encrypt(NULL, &data);
    printf("Cifrado: %s\n",
           retval == UA_STATUSCODE_GOOD ? "ok" : "error");

    printf("Datos cifrados (hex): ");
    for(size_t i = 0; i < data.length; i++)
        printf("%02X", data.data[i]);
    printf("\n");

    retval = policy.asymmetricModule.cryptoModule.encryptionAlgorithm.decrypt(NULL, &data);
    printf("Descifrado: %s\n",
           retval == UA_STATUSCODE_GOOD ? "ok" : "error");

    printf("Texto descifrado: %.*s\n", (int)data.length, data.data);

    UA_ByteString_clear(&data);

    return 0;
}
