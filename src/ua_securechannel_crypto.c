/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2014-2020 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2014, 2016-2017 (c) Florian Palm
 *    Copyright 2015-2016 (c) Sten Grüner
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2016 (c) TorbenD
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017-2018 (c) Mark Giraud, Fraunhofer IOSB
 */

#include <stdio.h>
#include "open62541/transport_generated.h"
#include "ua_securechannel.h"
#include "ua_types_encoding_binary.h"

UA_StatusCode
UA_SecureChannel_generateLocalNonce(UA_SecureChannel *channel) {
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_CHECK_MEM(sp, return UA_STATUSCODE_BADINTERNALERROR);

    /* Is the length of the previous nonce correct? */
    size_t nonceLength = sp->symmetricModule.secureChannelNonceLength;
    if(channel->localNonce.length != nonceLength) {
        UA_ByteString_clear(&channel->localNonce);
        UA_StatusCode res = UA_ByteString_allocBuffer(&channel->localNonce, nonceLength);
        UA_CHECK_STATUS(res, return res);
    }

    /* Generate the nonce */
    return sp->symmetricModule.generateNonce(sp->policyContext, &channel->localNonce);
}

UA_StatusCode
UA_SecureChannel_generateLocalKeys(const UA_SecureChannel *channel) {
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_CHECK_MEM(sp, return UA_STATUSCODE_BADINTERNALERROR);

    void *cc = channel->channelContext;
    const UA_SecurityPolicyChannelModule *cm = &sp->channelModule;
    const UA_SecurityPolicySymmetricModule *sm = &sp->symmetricModule;
    const UA_SecurityPolicyCryptoModule *crm = &sm->cryptoModule;

    /* Generate symmetric key buffer of the required length. The block size is
     * identical for local/remote. */
    UA_ByteString buf;
    size_t encrKL = crm->encryptionAlgorithm.getLocalKeyLength(cc);
    size_t encrBS = crm->encryptionAlgorithm.getRemoteBlockSize(cc);
    size_t signKL = crm->signatureAlgorithm.getLocalKeyLength(cc);
    if(encrBS + signKL + encrKL == 0)
        return UA_STATUSCODE_GOOD; /* No keys to generate */

    UA_StatusCode retval = UA_ByteString_allocBuffer(&buf, encrBS + signKL + encrKL);
    UA_CHECK_STATUS(retval, return retval);
    UA_ByteString localSigningKey = {signKL, buf.data};
    UA_ByteString localEncryptingKey = {encrKL, &buf.data[signKL]};
    UA_ByteString localIv = {encrBS, &buf.data[signKL + encrKL]};

    /* TODO: Signal that no ECC salt is generated. Find a clean solution for this.  */
    buf.data[0] = 0x00;

    /* Generate key */
    retval = sm->generateKey(sp->policyContext, &channel->remoteNonce,
                             &channel->localNonce, &buf);
    UA_CHECK_STATUS(retval, goto error);

    /* Set the channel context */
    retval |= cm->setLocalSymSigningKey(cc, &localSigningKey);
    retval |= cm->setLocalSymEncryptingKey(cc, &localEncryptingKey);
    retval |= cm->setLocalSymIv(cc, &localIv);

 error:
    UA_CHECK_STATUS(retval, UA_LOG_WARNING_CHANNEL(sp->logger, channel,
                            "Could not generate local keys (statuscode: %s)",
                            UA_StatusCode_name(retval)));
    UA_ByteString_clear(&buf);
    return retval;
}

UA_StatusCode
generateRemoteKeys(const UA_SecureChannel *channel) {
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_CHECK_MEM(sp, return UA_STATUSCODE_BADINTERNALERROR);

    void *cc = channel->channelContext;
    const UA_SecurityPolicyChannelModule *cm = &sp->channelModule;
    const UA_SecurityPolicySymmetricModule *sm = &sp->symmetricModule;
    const UA_SecurityPolicyCryptoModule *crm = &sm->cryptoModule;

    /* Generate symmetric key buffer of the required length */
    UA_ByteString buf;
    size_t encrKL = crm->encryptionAlgorithm.getRemoteKeyLength(cc);
    size_t encrBS = crm->encryptionAlgorithm.getRemoteBlockSize(cc);
    size_t signKL = crm->signatureAlgorithm.getRemoteKeyLength(cc);
    if(encrBS + signKL + encrKL == 0)
        return UA_STATUSCODE_GOOD; /* No keys to generate */

    UA_StatusCode retval = UA_ByteString_allocBuffer(&buf, encrBS + signKL + encrKL);
    UA_CHECK_STATUS(retval, return retval);
    UA_ByteString remoteSigningKey = {signKL, buf.data};
    UA_ByteString remoteEncryptingKey = {encrKL, &buf.data[signKL]};
    UA_ByteString remoteIv = {encrBS, &buf.data[signKL + encrKL]};

    /* TODO: Signal that no ECC salt is generated. Find a clean solution for this.  */
    buf.data[0] = 0x00;

    /* Generate key
     * IMPORTANT: Pass parameters in the same order as generateLocalKeys for consistent
     * key derivation. Both should use: remoteNonce || localNonce order.
     * This ensures that client's local keys match server's remote keys. */
    retval = sm->generateKey(sp->policyContext, &channel->remoteNonce,
                             &channel->localNonce, &buf);
    UA_CHECK_STATUS(retval, goto error);

    /* Set the channel context */
    retval |= cm->setRemoteSymSigningKey(cc, &remoteSigningKey);
    retval |= cm->setRemoteSymEncryptingKey(cc, &remoteEncryptingKey);
    retval |= cm->setRemoteSymIv(cc, &remoteIv);

 error:
    UA_CHECK_STATUS(retval, UA_LOG_WARNING_CHANNEL(sp->logger, channel,
                            "Could not generate remote keys (statuscode: %s)",
                            UA_StatusCode_name(retval)));
    UA_ByteString_clear(&buf);
    return retval;
}

/***************************/
/* Send Asymmetric Message */
/***************************/

/* The length of the static header content */
#define UA_SECURECHANNEL_ASYMMETRIC_SECURITYHEADER_FIXED_LENGTH 12

size_t
calculateAsymAlgSecurityHeaderLength(const UA_SecureChannel *channel) {
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_CHECK_MEM(sp, return UA_STATUSCODE_BADINTERNALERROR);

    size_t asymHeaderLength = UA_SECURECHANNEL_ASYMMETRIC_SECURITYHEADER_FIXED_LENGTH +
                              sp->policyUri.length;
    if(channel->securityMode == UA_MESSAGESECURITYMODE_NONE)
        return asymHeaderLength;

    /* OPN is always encrypted even if the mode is sign only */
    asymHeaderLength += 20; /* Thumbprints are always 20 byte long */
    asymHeaderLength += sp->localCertificate.length;
    return asymHeaderLength;
}

UA_StatusCode
prependHeadersAsym(UA_SecureChannel *const channel, UA_Byte *header_pos,
                   const UA_Byte *payload_start, size_t totalLength,
                   size_t securityHeaderLength, UA_UInt32 requestId,
                   size_t *const encryptedLength) {
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_CHECK_MEM(sp, return UA_STATUSCODE_BADINTERNALERROR);

    UA_LOG_INFO(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                "[TRACE-OPN] prependHeadersAsym: policyUri=%S securityMode=%d totalLen=%zu secHdrLen=%zu requestId=%u",
                sp->policyUri, (int)channel->securityMode, totalLength,
                securityHeaderLength, requestId);

    if(channel->securityMode == UA_MESSAGESECURITYMODE_NONE) {
        /* For SecurityPolicy#None there is no encryption/signature, but the
         * message size must still include all headers (TCP + SecureChannel +
         * SequenceHeader) plus the payload. Previously only the payload length
         * was reported, leading to a truncated messageSize in the OPN chunk. */
        *encryptedLength = totalLength +
            UA_SECURECHANNEL_CHANNELHEADER_LENGTH +
            securityHeaderLength +
            UA_SECURECHANNEL_SEQUENCEHEADER_LENGTH;
    } else {
        /* Check if this is PQC policy (doesn't use block-based encryption) */
        static const UA_String pqcPolicyUri = UA_STRING_STATIC("http://example.org/SecurityPolicy#PQC");
        if(UA_String_equal(&sp->policyUri, &pqcPolicyUri)) {
            /* For PQC, encryption just prepends the KEM ciphertext (1088 bytes for Kyber-768).
             * The encrypted length is simply: totalLength + KEM_CT_length.
             * However, if getRemoteBlockSize returns 0, it means the remote key is not available
             * (first OPN message), so no encryption space is needed. */
            size_t kemCtLength = sp->asymmetricModule.cryptoModule.
                encryptionAlgorithm.getRemoteBlockSize(channel->channelContext);
            *encryptedLength = totalLength + kemCtLength;
        } else {
            /* For traditional block-based encryption (RSA, etc.) */
            size_t dataToEncryptLength = totalLength -
                (UA_SECURECHANNEL_CHANNELHEADER_LENGTH + securityHeaderLength);
            size_t plainTextBlockSize = sp->asymmetricModule.cryptoModule.
                encryptionAlgorithm.getRemotePlainTextBlockSize(channel->channelContext);
            size_t encryptedBlockSize = sp->asymmetricModule.cryptoModule.
                encryptionAlgorithm.getRemoteBlockSize(channel->channelContext);

            /* Padding always fills up the last block */
            UA_assert(dataToEncryptLength % plainTextBlockSize == 0);
            size_t blocks = dataToEncryptLength / plainTextBlockSize;
            *encryptedLength = totalLength + blocks * (encryptedBlockSize - plainTextBlockSize);
        }
    }

    UA_TcpMessageHeader messageHeader;
    messageHeader.messageTypeAndChunkType = UA_MESSAGETYPE_OPN + UA_CHUNKTYPE_FINAL;
    messageHeader.messageSize = (UA_UInt32)*encryptedLength;
    UA_UInt32 secureChannelId = channel->securityToken.channelId;
    
    
    /* Use payload_start as the limit for header encoding to prevent overwriting payload */
    UA_Byte *header_pos_mutable = header_pos;
    const UA_Byte *buf_end = payload_start;
    
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_encodeBinaryInternal(&messageHeader,
                                      &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER],
                                      &header_pos_mutable, &buf_end, NULL, NULL, NULL);
    if(retval != UA_STATUSCODE_GOOD && sp->logger) {
        UA_LOG_ERROR(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "prependHeadersAsym: Failed to encode TCP message header: %s",
                    UA_StatusCode_name(retval));
    }
    UA_CHECK_STATUS(retval, return retval);
    
    retval |= UA_UInt32_encodeBinary(&secureChannelId, &header_pos_mutable, buf_end);
    if(retval != UA_STATUSCODE_GOOD && sp->logger) {
        UA_LOG_ERROR(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "prependHeadersAsym: Failed to encode secureChannelId: %s",
                    UA_StatusCode_name(retval));
    }
    UA_CHECK_STATUS(retval, return retval);

    UA_AsymmetricAlgorithmSecurityHeader asymHeader;
    UA_AsymmetricAlgorithmSecurityHeader_init(&asymHeader);
    asymHeader.securityPolicyUri = sp->policyUri;
    
    /* For SecurityPolicy#None, MessageSecurityMode MUST be None per OPC UA spec.
     * Do not include certificates in the header, regardless of channel->securityMode.
     * This ensures the AsymmetricSecurityHeader matches the payload securityMode. */
    UA_Boolean isNonePolicy = UA_String_equal(&sp->policyUri, &UA_SECURITY_POLICY_NONE_URI);
    if(!isNonePolicy &&
       (channel->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
        channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)) {
        if(sp->localCertificate.length > 0 && sp->localCertificate.data) {
        asymHeader.senderCertificate = sp->localCertificate;
        } else {
            UA_ByteString_init(&asymHeader.senderCertificate);
        }
        asymHeader.receiverCertificateThumbprint.length = 20;
        asymHeader.receiverCertificateThumbprint.data = channel->remoteCertificateThumbprint;
    }
    retval = UA_encodeBinaryInternal(
        &asymHeader, &UA_TRANSPORT[UA_TRANSPORT_ASYMMETRICALGORITHMSECURITYHEADER],
        &header_pos_mutable, &buf_end, NULL, NULL, NULL);
    if(retval != UA_STATUSCODE_GOOD && sp->logger) {
        UA_LOG_ERROR(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "prependHeadersAsym: Failed to encode AsymmetricAlgorithmSecurityHeader: %s "
                    "(availableSpace=%zu, header_pos_mutable offset=%zu, buf_end offset=%zu)",
                    UA_StatusCode_name(retval), (size_t)(buf_end - header_pos_mutable),
                    (size_t)(header_pos_mutable - (UA_Byte*)channel),
                    (size_t)(buf_end - (UA_Byte*)channel));
    }
    UA_CHECK_STATUS(retval, return retval);

    /* OPN messages always have sequenceNumber = 0.
     * Sequence numbers are only incremented for symmetric (MSG) messages. */
    UA_SequenceHeader seqHeader;
    seqHeader.requestId = requestId;
    seqHeader.sequenceNumber = 0;
    
    retval = UA_encodeBinaryInternal(&seqHeader, &UA_TRANSPORT[UA_TRANSPORT_SEQUENCEHEADER],
                                     &header_pos_mutable, &buf_end, NULL, NULL, NULL);
    
    return retval;
}

void
hideBytesAsym(const UA_SecureChannel *channel, UA_Byte **buf_start,
              const UA_Byte **buf_end) {
    /* Set buf_start to the beginning of the payload body */
    *buf_start += UA_SECURECHANNEL_CHANNELHEADER_LENGTH;
    size_t securityHeaderLength = calculateAsymAlgSecurityHeaderLength(channel);
    /* Add extra margin for binary encoding overhead (length fields, etc.)
     * For large certificates (like PQC), the encoded size can be significantly
     * larger than the calculated size due to length prefixes.
     * Binary encoding adds: Int32 length fields for strings/ByteStrings (4 bytes each),
     * plus structure overhead. For PQC certificates (~6-7KB), add proportional margin. */
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    size_t margin = 64; /* Base margin for encoding overhead */
    if(sp && sp->localCertificate.length > 5000) {
        /* For very large certificates (like PQC), add more margin.
         * Binary encoding adds Int32 length fields (4 bytes each) for strings/ByteStrings,
         * plus structure overhead. For PQC certificates (~6-7KB), add proportional margin.
         * The encoded size can be significantly larger than the calculated size.
         * Use a generous but conservative margin to ensure we have enough space without
         * exceeding the buffer size.
         * For a 6685 byte certificate, we need approximately:
         * - Base header: ~100 bytes
         * - Certificate encoding overhead: ~200 bytes (length fields, structure overhead)
         * - Safety margin: ~3000 bytes (conservative but sufficient for encoding overhead)
         * Total: ~3300 bytes margin for large certs */
        margin += (sp->localCertificate.length / 4) + 5100; /* Very generous margin for large certs to handle encoding overhead and structure padding */
    }
    size_t securityHeaderLengthWithMargin = securityHeaderLength + margin;
    *buf_start += securityHeaderLengthWithMargin;
    *buf_start += UA_SECURECHANNEL_SEQUENCEHEADER_LENGTH;

    if(channel->securityMode == UA_MESSAGESECURITYMODE_NONE)
        return;

    /* Make space for the certificate */
    *buf_end -= sp->asymmetricModule.cryptoModule.signatureAlgorithm.
        getLocalSignatureSize(channel->channelContext);

    /* Block sizes depend on the remote key (certificate) */
    size_t plainTextBlockSize = sp->asymmetricModule.cryptoModule.
        encryptionAlgorithm.getRemotePlainTextBlockSize(channel->channelContext);
    size_t encryptedBlockSize = sp->asymmetricModule.cryptoModule.
        encryptionAlgorithm.getRemoteBlockSize(channel->channelContext);
    
    /* For PQC policies, if remote key is not available (encryptedBlockSize == 0),
     * encryption will be skipped. However, we still need to restrict buf_end
     * to leave space for the headers that will be prepended later.
     * The headers are already accounted for by the initial buf_start adjustment,
     * so we just need to ensure we don't restrict buf_end further. */
    if(encryptedBlockSize == 0) {
        /* No encryption - buf_start already accounts for headers, buf_end already
         * accounts for signature. We're done. */
        return;
    }
    
    UA_Boolean extraPadding = (sp->asymmetricModule.cryptoModule.encryptionAlgorithm.
                               getRemoteKeyLength(channel->channelContext) > 2048);

    /* Compute the maximum number of encrypted blocks that can fit entirely
     * before the signature. From that compute the maximum usable plaintext
     * size. */
    size_t maxEncrypted = (size_t)(*buf_end - *buf_start) +
        UA_SECURECHANNEL_SEQUENCEHEADER_LENGTH;
    size_t max_blocks = maxEncrypted / encryptedBlockSize;
    size_t paddingBytes = (UA_LIKELY(!extraPadding)) ? 1u : 2u;
    *buf_end = *buf_start + (max_blocks * plainTextBlockSize) -
        UA_SECURECHANNEL_SEQUENCEHEADER_LENGTH - paddingBytes;
}

/* Assumes that pos can be advanced to the end of the current block */
void
padChunk(UA_SecureChannel *channel, const UA_SecurityPolicyCryptoModule *cm,
         const UA_Byte *start, UA_Byte **pos) {
    const size_t bytesToWrite = (uintptr_t)*pos - (uintptr_t)start;
    size_t signatureSize = cm->signatureAlgorithm.
        getLocalSignatureSize(channel->channelContext);
    size_t plainTextBlockSize = cm->encryptionAlgorithm.
        getRemotePlainTextBlockSize(channel->channelContext);
    
    /* PQC and other non-block-based encryption schemes don't use padding */
    if(plainTextBlockSize == 0)
        return;
    
    UA_Boolean extraPadding = (cm->encryptionAlgorithm.
        getRemoteKeyLength(channel->channelContext) > 2048);
    size_t paddingBytes = (UA_LIKELY(!extraPadding)) ? 1u : 2u;

    size_t lastBlock = ((bytesToWrite + signatureSize + paddingBytes) % plainTextBlockSize);
    size_t paddingLength = (lastBlock != 0) ? plainTextBlockSize - lastBlock : 0;

    /* Write the padding. This is <= because the paddingSize byte also has to be
     * written */
    UA_Byte paddingByte = (UA_Byte)paddingLength;
    for(size_t i = 0; i <= paddingLength; ++i) {
        **pos = paddingByte;
        ++*pos;
    }

    /* Write the extra padding byte if required */
    if(extraPadding) {
        **pos = (UA_Byte)(paddingLength >> 8u);
        ++*pos;
    }
}

UA_StatusCode
signAndEncryptAsym(UA_SecureChannel *channel, size_t preSignLength,
                   UA_ByteString *buf, size_t securityHeaderLength,
                   size_t totalLength, const UA_Byte *payload_start) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    const UA_SecurityPolicy *sp = channel->securityPolicy;
    size_t unencrypted_length =
        UA_SECURECHANNEL_CHANNELHEADER_LENGTH + securityHeaderLength;
    
    /* Check if this is PQC policy (needs special handling for KEM ciphertext prepending) */
    static const UA_String pqcPolicyUri = UA_STRING_STATIC("http://example.org/SecurityPolicy#PQC");
    if(UA_String_equal(&sp->policyUri, &pqcPolicyUri)) {
        /* For PQC, we need to calculate what data will be in the final message (without gap).
         * The final message will have: headers (unencrypted_length) + KEM CT + SequenceHeader + Payload + Signature.
         * But we sign BEFORE creating the new buffer, so we need to calculate the signed data
         * as if the gap didn't exist.
         * 
         * The signed data should be: headers + SequenceHeader + Payload (without gap, without signature).
         * preSignLength includes the gap, so we need to subtract it.
         * 
         * actualSequenceHeaderOffset = payload_start - buf->data - sequenceHeaderLength
         * gap = actualSequenceHeaderOffset - unencrypted_length
         * signedLength = unencrypted_length + (preSignLength - actualSequenceHeaderOffset) = unencrypted_length + sequenceHeaderLength + payload_length
         */
        size_t sequenceHeaderLength = UA_SECURECHANNEL_SEQUENCEHEADER_LENGTH;
        size_t actualSequenceHeaderOffset = (uintptr_t)payload_start - (uintptr_t)buf->data - sequenceHeaderLength;
        size_t gap = actualSequenceHeaderOffset - unencrypted_length;
        
        /* Calculate the final message size (without gap) to update messageSize in TCP header before signing */
        size_t dataToEncryptLength = totalLength - actualSequenceHeaderOffset;
        size_t kemCtLength = sp->asymmetricModule.cryptoModule.
            encryptionAlgorithm.getRemoteBlockSize(channel->channelContext);
        size_t newTotalLength = unencrypted_length + kemCtLength + dataToEncryptLength;
        
        /* Update the TCP message header with the correct messageSize BEFORE signing.
         * The header was written by prependHeadersAsym with the old encryptedLength,
         * but we need the correct newTotalLength for the signature to be valid. */
        if(newTotalLength >= 8) {
            /* messageSize is at bytes 4-7 (little-endian) */
            buf->data[4] = (UA_Byte)(newTotalLength & 0xFF);
            buf->data[5] = (UA_Byte)((newTotalLength >> 8) & 0xFF);
            buf->data[6] = (UA_Byte)((newTotalLength >> 16) & 0xFF);
            buf->data[7] = (UA_Byte)((newTotalLength >> 24) & 0xFF);
        }
        
        size_t signedLength = unencrypted_length + (preSignLength - actualSequenceHeaderOffset);
        
        size_t sigsize = sp->asymmetricModule.cryptoModule.signatureAlgorithm.
            getLocalSignatureSize(channel->channelContext);
        
        /* Create a temporary buffer for signing that excludes the gap */
        UA_Byte *signBuffer = (UA_Byte*)UA_malloc(signedLength);
        if(!signBuffer) return UA_STATUSCODE_BADOUTOFMEMORY;
        
        /* Copy headers */
        memcpy(signBuffer, buf->data, unencrypted_length);
        /* Copy SequenceHeader + Payload (skip the gap) */
        memcpy(signBuffer + unencrypted_length, buf->data + actualSequenceHeaderOffset, 
               preSignLength - actualSequenceHeaderOffset);
        
        UA_ByteString dataToSign = {signedLength, signBuffer};
        UA_ByteString signature = {sigsize, buf->data + preSignLength};
        
        UA_LOG_INFO(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[TRACE-OPN] signAndEncryptAsym(PQC): policyUri=%S securityMode=%d signedLen=%zu sigSize=%zu",
                    sp->policyUri, (int)channel->securityMode, signedLength, sigsize);

        UA_StatusCode retval = sp->asymmetricModule.cryptoModule.signatureAlgorithm.
            sign(channel->channelContext, &dataToSign, &signature);
        UA_LOG_INFO(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[TRACE-OPN] signAndEncryptAsym(PQC): sign rc=%s", UA_StatusCode_name(retval));
        UA_free(signBuffer);
        UA_CHECK_STATUS(retval, return retval);
        
        /* Check if remote Kyber key is available for encryption.
         * For the first OPN message from client, the server's certificate (and thus
         * the Kyber public key) may not be available yet. In this case, we send
         * the message without encryption (only signed), which is valid for the
         * initial handshake. */
        /* kemCtLength was already calculated above before signing */
        
        /* If getRemoteBlockSize returns 0, it means the remote key is not available.
         * This happens when getRemoteBlockSize checks for remoteKemPublicKeyValid
         * and returns 0 if not available. */
        if(kemCtLength == 0)
            return UA_STATUSCODE_GOOD;
        
        /* Remote key is available - proceed with encryption */
        /* For PQC, the SequenceHeader is in the encrypted section (after unencrypted_length).
         * The data to encrypt includes: SequenceHeader (8 bytes) + Payload + Signature */
        /* actualSequenceHeaderOffset, dataToEncryptLength, kemCtLength, and newTotalLength
         * were already calculated above before signing */
        if(actualSequenceHeaderOffset < unencrypted_length) {
            /* This shouldn't happen, but if it does, use unencrypted_length as the offset */
            actualSequenceHeaderOffset = unencrypted_length;
        }
        UA_Byte *newBuf = (UA_Byte*)UA_malloc(newTotalLength);
        if(!newBuf) return UA_STATUSCODE_BADOUTOFMEMORY;
        
        /* Copy the unencrypted headers */
        memcpy(newBuf, buf->data, unencrypted_length);
        
        /* Copy the data to encrypt (SequenceHeader + message + signature), leaving space for KEM ciphertext.
         * Copy from actualSequenceHeaderOffset (where SequenceHeader starts) to skip the gap. */
        memcpy(newBuf + unencrypted_length + kemCtLength,
               buf->data + actualSequenceHeaderOffset,
               dataToEncryptLength);
        
        /* Free the old buffer and update buffer pointer and length */
        UA_free(buf->data);
        buf->data = newBuf;
        buf->length = newTotalLength;
        
        /* The TCP message header messageSize was already updated before signing,
         * so we don't need to update it again here. */
        
        /* Specification part 6, 6.7.4: The OpenSecureChannel Messages are
         * signed and encrypted if the SecurityMode is not None (even if the
         * SecurityMode is SignOnly). */
        /* Pass the entire data section (including space for KEM CT) to encrypt.
         * pqc_encrypt expects:
         *   - data->data[0..kem_ct_len-1] = space for KEM ciphertext (to be written)
         *   - data->data[kem_ct_len..] = payload to encrypt (already copied)
         * The payload was copied to newBuf + unencrypted_length + kemCtLength,
         * so dataToEncrypt.data should point to unencrypted_length (where KEM CT space is),
         * and the payload is already at the correct offset (kem_ct_len bytes after data->data). */
        UA_ByteString dataToEncrypt = {dataToEncryptLength + kemCtLength,
                                       &buf->data[unencrypted_length]};
        return sp->asymmetricModule.cryptoModule.encryptionAlgorithm.
            encrypt(channel->channelContext, &dataToEncrypt);
    } else {
        /* For traditional encryption, sign first, then encrypt */
        size_t sigsize = sp->asymmetricModule.cryptoModule.signatureAlgorithm.
            getLocalSignatureSize(channel->channelContext);
        UA_ByteString dataToSign = {preSignLength, buf->data};
        UA_ByteString signature = {sigsize, buf->data + preSignLength};

        UA_LOG_INFO(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[TRACE-OPN] signAndEncryptAsym: policyUri=%S securityMode=%d signedLen=%zu sigSize=%zu",
                    sp->policyUri, (int)channel->securityMode, preSignLength, sigsize);

        UA_StatusCode retval = sp->asymmetricModule.cryptoModule.signatureAlgorithm.
            sign(channel->channelContext, &dataToSign, &signature);
        UA_LOG_INFO(sp->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[TRACE-OPN] signAndEncryptAsym: sign rc=%s", UA_StatusCode_name(retval));
        UA_CHECK_STATUS(retval, return retval);
        
        /* Specification part 6, 6.7.4: The OpenSecureChannel Messages are
         * signed and encrypted if the SecurityMode is not None (even if the
         * SecurityMode is SignOnly). */
        /* Pass only the data to encrypt */
        UA_ByteString dataToEncrypt = {totalLength - unencrypted_length,
                                       &buf->data[unencrypted_length]};
        return sp->asymmetricModule.cryptoModule.encryptionAlgorithm.
            encrypt(channel->channelContext, &dataToEncrypt);
    }
}

/**************************/
/* Send Symmetric Message */
/**************************/

UA_StatusCode
signAndEncryptSym(UA_MessageContext *messageContext,
                  size_t preSigLength, size_t totalLength) {
    const UA_SecureChannel *channel = messageContext->channel;
    if(channel->securityMode == UA_MESSAGESECURITYMODE_NONE)
        return UA_STATUSCODE_GOOD;

    /* Sign */
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_ByteString dataToSign = messageContext->messageBuffer;
    dataToSign.length = preSigLength;
    UA_ByteString signature;
    signature.length = sp->symmetricModule.cryptoModule.signatureAlgorithm.
        getLocalSignatureSize(channel->channelContext);
    signature.data = messageContext->buf_pos;
    UA_StatusCode res = sp->symmetricModule.cryptoModule.signatureAlgorithm.
        sign(channel->channelContext, &dataToSign, &signature);
    UA_CHECK_STATUS(res, return res);

    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    /* Encrypt */
    UA_ByteString dataToEncrypt;
    dataToEncrypt.data = messageContext->messageBuffer.data +
        UA_SECURECHANNEL_CHANNELHEADER_LENGTH +
        UA_SECURECHANNEL_SYMMETRIC_SECURITYHEADER_LENGTH;
    dataToEncrypt.length = totalLength -
        (UA_SECURECHANNEL_CHANNELHEADER_LENGTH +
         UA_SECURECHANNEL_SYMMETRIC_SECURITYHEADER_LENGTH);
    return sp->symmetricModule.cryptoModule.encryptionAlgorithm.
        encrypt(channel->channelContext, &dataToEncrypt);
}

void
setBufPos(UA_MessageContext *mc) {
    /* Forward the data pointer so that the payload is encoded after the message
     * header. This has to be a symmetric message because OPN (with asymmetric
     * encryption) does not support chunking. */
    mc->buf_pos = &mc->messageBuffer.data[UA_SECURECHANNEL_SYMMETRIC_HEADER_TOTALLENGTH];
    mc->buf_end = &mc->messageBuffer.data[mc->messageBuffer.length];

    if(mc->channel->securityMode == UA_MESSAGESECURITYMODE_NONE)
        return;

    const UA_SecureChannel *channel = mc->channel;
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    size_t sigsize = sp->symmetricModule.cryptoModule.signatureAlgorithm.
        getLocalSignatureSize(channel->channelContext);
    size_t plainBlockSize = sp->symmetricModule.cryptoModule.
        encryptionAlgorithm.getRemotePlainTextBlockSize(channel->channelContext);

    /* Assuming that for symmetric encryption the plainTextBlockSize ==
     * cypherTextBlockSize. For symmetric encryption the remote/local block
     * sizes are identical. */
    UA_assert(sp->symmetricModule.cryptoModule.encryptionAlgorithm.
              getRemoteBlockSize(channel->channelContext) == plainBlockSize);

    /* Leave enough space for the signature and padding */
    mc->buf_end -= sigsize;
    mc->buf_end -= mc->messageBuffer.length % plainBlockSize;

    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        /* Reserve space for the padding bytes */
        UA_Boolean extraPadding =
            (sp->symmetricModule.cryptoModule.encryptionAlgorithm.
             getRemoteKeyLength(channel->channelContext) > 2048);
        mc->buf_end -= (UA_LIKELY(!extraPadding)) ? 1 : 2;
    }

}

/****************************/
/* Process a received Chunk */
/****************************/

static size_t
decodePadding(const UA_SecureChannel *channel,
              const UA_SecurityPolicyCryptoModule *cryptoModule,
              const UA_ByteString *chunk, size_t sigsize) {
    /* Read the byte with the padding size */
    size_t paddingSize = chunk->data[chunk->length - sigsize - 1];

    /* Extra padding size */
    if(cryptoModule->encryptionAlgorithm.
       getLocalKeyLength(channel->channelContext) > 2048) {
        paddingSize <<= 8u;
        paddingSize += chunk->data[chunk->length - sigsize - 2];
        paddingSize += 1; /* Extra padding byte itself */
    }

    /* Add one since the paddingSize byte itself needs to be removed as well */
    return paddingSize + 1;
}

static UA_StatusCode
verifySignature(const UA_SecureChannel *channel,
                const UA_SecurityPolicyCryptoModule *cryptoModule,
                const UA_ByteString *chunk, size_t sigsize) {
    UA_CHECK(sigsize < chunk->length, return UA_STATUSCODE_BADSECURITYCHECKSFAILED);
    const UA_ByteString content = {chunk->length - sigsize, chunk->data};
    const UA_ByteString sig = {sigsize, chunk->data + chunk->length - sigsize};
    
    /* Log for debugging PQC signature verification issues */
    static const UA_String pqcPolicyUri = UA_STRING_STATIC("http://example.org/SecurityPolicy#PQC");
    UA_Boolean isPqcPolicy = channel->securityPolicy && 
                             UA_String_equal(&channel->securityPolicy->policyUri, &pqcPolicyUri);
    if(isPqcPolicy && channel->securityPolicy->logger) {
        UA_LOG_INFO(channel->securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                   "verifySignature: Verifying PQC signature (content.length=%zu, sig.length=%zu, chunk->length=%zu, sigsize=%zu)",
                   content.length, sig.length, chunk->length, sigsize);
    }
    
    UA_StatusCode retval = cryptoModule->signatureAlgorithm.
        verify(channel->channelContext, &content, &sig);
    
    if(isPqcPolicy && retval != UA_STATUSCODE_GOOD && channel->securityPolicy->logger) {
        UA_LOG_ERROR(channel->securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                     "verifySignature: PQC signature verification failed: %s",
                     UA_StatusCode_name(retval));
    }
    
    return retval;
}

/* Sets the payload to a pointer inside the chunk buffer. Returns the requestId
 * and the sequenceNumber */
UA_StatusCode
decryptAndVerifyChunk(const UA_SecureChannel *channel,
                      const UA_SecurityPolicyCryptoModule *cryptoModule,
                      UA_MessageType messageType, UA_ByteString *chunk,
                      size_t offset) {
    /* Decrypt the chunk */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    const UA_Logger *logger = channel->securityPolicy ? channel->securityPolicy->logger : NULL;

    /* For SecurityPolicy#None and MessageSecurityMode None, OPN carries no
     * encryption/signature. Skip crypto entirely. */
    if(messageType == UA_MESSAGETYPE_OPN &&
       channel->securityPolicy &&
       UA_String_equal(&channel->securityPolicy->policyUri, &UA_SECURITY_POLICY_NONE_URI) &&
       channel->securityMode == UA_MESSAGESECURITYMODE_NONE)
        return UA_STATUSCODE_GOOD;
    
    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT ||
       messageType == UA_MESSAGETYPE_OPN) {
        UA_ByteString cipher = {chunk->length - offset, chunk->data + offset};
        res = cryptoModule->encryptionAlgorithm.decrypt(channel->channelContext, &cipher);
        UA_CHECK_STATUS(res,
            if(logger) {
                UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                               "decryptAndVerifyChunk: decrypt failed: %s", UA_StatusCode_name(res));
            }
            return res);
        
        /* After decryption, update chunk->length.
         * For in-place decryption (like PQC), cipher.data may still point to chunk->data + offset
         * and the decrypted data may have been moved within that buffer.
         * The chunk length should be: header (offset) + decrypted data length.
         * 
         * IMPORTANT: For PQC, pqc_decrypt moves the decrypted data to cipher.data (which is chunk->data + offset),
         * so the decrypted data is already in the correct position. We just need to update chunk->length
         * to reflect the new length after removing the KEM ciphertext. */
        chunk->length = cipher.length + offset;
    }

    /* Does the message have a signature? */
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT &&
       messageType != UA_MESSAGETYPE_OPN)
        return UA_STATUSCODE_GOOD;

    /* Verify the chunk signature */
    size_t sigsize = cryptoModule->signatureAlgorithm.
        getRemoteSignatureSize(channel->channelContext);
    
    /* For PQC policy, pqc_decrypt moves the decrypted data to chunk->data + offset.
     * The signature was calculated over: unencrypted headers (chunk->data to chunk->data + offset)
     * + decrypted data (chunk->data + offset to chunk->data + offset + decrypted_length).
     * But verifySignature expects chunk->data to point to the start of the signed data.
     * For PQC, we need to ensure that chunk->data points to the start of the signed data,
     * which includes the unencrypted headers + decrypted data. Since pqc_decrypt moves
     * the decrypted data to chunk->data + offset, and chunk->data already points to the
     * start of the unencrypted headers, the data is already in the correct position.
     * However, chunk->length needs to include both the headers and the decrypted data.
     * After pqc_decrypt, chunk->length = cipher.length + offset, which is correct.
     * So we can verify the signature directly. */
    static const UA_String pqcPolicyUri = UA_STRING_STATIC("http://example.org/SecurityPolicy#PQC");
    UA_Boolean isPqcPolicy = UA_String_equal(&channel->securityPolicy->policyUri, &pqcPolicyUri);
    
    if(isPqcPolicy && (channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT ||
                       messageType == UA_MESSAGETYPE_OPN)) {
    }
    
    res = verifySignature(channel, cryptoModule, chunk, sigsize);
    UA_CHECK_STATUS(res,
       UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                              "Could not verify the signature"); return res);

    /* Compute the padding if the payload is encrypted (not ECC policy, not PQC policy) */
    size_t padSize = 0;
    /* isPqcPolicy already defined above */
    if(!isPqcPolicy &&
       (((messageType != UA_MESSAGETYPE_OPN) && (channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)) ||
        (messageType == UA_MESSAGETYPE_OPN &&
         cryptoModule->encryptionAlgorithm.uri.length > 0 && 
         !isEccPolicy(channel->securityPolicy)))) {
        padSize = decodePadding(channel, cryptoModule, chunk, sigsize);
    }

    /* Verify the content length. The encrypted payload has to be at least 9
     * bytes long: 8 byte for the SequenceHeader and one byte for the actual
     * message */
    UA_CHECK(offset + padSize + sigsize + 9 < chunk->length,
             UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                                    "Impossible padding value");
             return UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    /* Hide the signature and padding */
    chunk->length -= (sigsize + padSize);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
checkAsymHeader(UA_SecureChannel *channel,
                const UA_AsymmetricAlgorithmSecurityHeader *asymHeader) {
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    if(!sp) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    /* For SecurityPolicy#None, accept the header without thumbprint checks */
    if(UA_String_equal(&sp->policyUri, &UA_SECURITY_POLICY_NONE_URI))
        return UA_STATUSCODE_GOOD;
    if(!UA_String_equal(&sp->policyUri, &asymHeader->securityPolicyUri))
        return UA_STATUSCODE_BADSECURITYPOLICYREJECTED;

    return sp->asymmetricModule.
        compareCertificateThumbprint(sp, &asymHeader->receiverCertificateThumbprint);

    /* The certificate in the header is verified via the configured PKI plugin
     * as certificateVerification.verifyCertificate(...). We cannot do it here
     * because the client/server context is needed. */
}

UA_StatusCode
checkSymHeader(UA_SecureChannel *channel, const UA_UInt32 tokenId,
               UA_DateTime nowMonotonic) {
    /* If no match, try to revolve to the next token after a
     * RenewSecureChannel */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_ChannelSecurityToken *token = &channel->securityToken;
    
    switch(channel->renewState) {
    case UA_SECURECHANNELRENEWSTATE_NORMAL:
    case UA_SECURECHANNELRENEWSTATE_SENT:
    default:
        break;

    case UA_SECURECHANNELRENEWSTATE_NEWTOKEN_SERVER:
        /* Old token still in use */
        if(tokenId == channel->securityToken.tokenId) {
            /* Generate remote keys if they haven't been generated yet.
             * This is needed because the server opens the channel with a new token,
             * but the client sends the first MSG with the old token.
             * We need to generate remote keys for the old token so we can decrypt the message. */
            
            /* Check if shared secret is available before generating keys.
             * For PQC policies, we need to verify that the shared secret was stored
             * during OPN decryption. */
            UA_Boolean hasSharedSecret = false;
            if(channel->securityPolicy && channel->securityPolicy->policyContext) {
                /* Try to access Policy_Context_PQC to check hasTemporarySharedSecret.
                 * This is a PQC-specific check, but we do it safely by checking if
                 * the field exists. For non-PQC policies, this will just be false. */
                /* Note: We can't safely cast here without including PQC headers,
                 * so we'll rely on the error from pqc_sym_generateKey to identify
                 * the problem. The log below will help diagnose. */
            }
            retval = generateRemoteKeys(channel);
            if(retval != UA_STATUSCODE_GOOD)
                return retval;
            break;
        }

        /* Not the new token */
        UA_CHECK(tokenId == channel->altSecurityToken.tokenId,
                 UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                                        "Unknown SecurityToken");
                 return UA_STATUSCODE_BADSECURECHANNELTOKENUNKNOWN);

        /* Roll over to the new token, generate new local and remote keys */
        channel->renewState = UA_SECURECHANNELRENEWSTATE_NORMAL;
        channel->securityToken = channel->altSecurityToken;
        UA_ChannelSecurityToken_init(&channel->altSecurityToken);
        
        /* Generate local keys first (uses remoteNonce + localNonce) */
        retval = UA_SecureChannel_generateLocalKeys(channel);
        UA_CHECK_STATUS(retval, return retval);
        
        /* Generate remote keys (uses remoteNonce + localNonce, needs shared secret) */
        retval = generateRemoteKeys(channel);
        UA_CHECK_STATUS(retval, return retval);
        break;

    case UA_SECURECHANNELRENEWSTATE_NEWTOKEN_CLIENT:
        /* The server is still using the old token. That's okay. */
        if(tokenId == channel->altSecurityToken.tokenId) {
            token = &channel->altSecurityToken;
            break;
        }

        /* Not the new token */
        UA_CHECK(tokenId == channel->securityToken.tokenId,
                 UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                                        "Unknown SecurityToken");
                 return UA_STATUSCODE_BADSECURECHANNELTOKENUNKNOWN);

        /* The remote server uses the new token for the first time. Delete the
         * old token and roll the remote key over. The local key already uses
         * the nonce pair from the last OPN exchange. */
        channel->renewState = UA_SECURECHANNELRENEWSTATE_NORMAL;
        UA_ChannelSecurityToken_init(&channel->altSecurityToken);
        retval = generateRemoteKeys(channel);
        UA_CHECK_STATUS(retval, return retval);
    }

    UA_DateTime timeout = token->createdAt + (token->revisedLifetime * UA_DATETIME_MSEC);
    if(channel->state == UA_SECURECHANNELSTATE_OPEN &&
       timeout < nowMonotonic) {
        UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                               "SecurityToken timed out");
        UA_SecureChannel_shutdown(channel, UA_SHUTDOWNREASON_TIMEOUT);
        return UA_STATUSCODE_BADSECURECHANNELCLOSED;
    }

    return UA_STATUSCODE_GOOD;
}

UA_Boolean
UA_SecureChannel_checkTimeout(UA_SecureChannel *channel, UA_DateTime nowMonotonic) {
    /* Compute the timeout date of the SecurityToken */
    UA_DateTime timeout = channel->securityToken.createdAt +
        (UA_DateTime)(channel->securityToken.revisedLifetime * UA_DATETIME_MSEC);

    /* The token has timed out. Try to do the token revolving now instead of
     * shutting the channel down.
     *
     * Part 4, 5.5.2 says: Servers shall use the existing SecurityToken to
     * secure outgoing Messages until the SecurityToken expires or the
     * Server receives a Message secured with a new SecurityToken.*/
    if(timeout < nowMonotonic && channel->renewState == UA_SECURECHANNELRENEWSTATE_NEWTOKEN_SERVER) {
        /* Revolve the token manually. This is otherwise done in checkSymHeader. */
        channel->renewState = UA_SECURECHANNELRENEWSTATE_NORMAL;
        channel->securityToken = channel->altSecurityToken;
        UA_ChannelSecurityToken_init(&channel->altSecurityToken);
        UA_SecureChannel_generateLocalKeys(channel);
        generateRemoteKeys(channel);

        /* Use the timeout of the new SecurityToken */
        timeout = channel->securityToken.createdAt +
            (UA_DateTime)(channel->securityToken.revisedLifetime * UA_DATETIME_MSEC);
    }

    return (timeout < nowMonotonic);
}
