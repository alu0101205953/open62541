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
 *    Copyright 2018-2019 (c) HMS Industrial Networks AB (Author: Jonas Green)
 */

#include <open62541/types.h>
#include <open62541/transport_generated.h>
#include <stdio.h>

#include "ua_securechannel.h"
#include "ua_types_encoding_binary.h"

#define UA_BITMASK_MESSAGETYPE 0x00ffffffu
#define UA_BITMASK_CHUNKTYPE 0xff000000u

const UA_String UA_SECURITY_POLICY_NONE_URI =
    {47, (UA_Byte *)"http://opcfoundation.org/UA/SecurityPolicy#None"};

UA_Boolean isEccPolicy(const UA_SecurityPolicy* const p) {
    if((0 == strncmp("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256", (const char *) p->policyUri.data, strlen("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256")))
    || (0 == strncmp("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384", (const char *) p->policyUri.data, strlen("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384")))) {
        return true;
    }

    return false;
}

void
UA_SecureChannel_init(UA_SecureChannel *channel) {
    /* Normal linked lists are initialized by zeroing out */
    memset(channel, 0, sizeof(UA_SecureChannel));
    TAILQ_INIT(&channel->chunks);
}

UA_StatusCode
UA_SecureChannel_setSecurityPolicy(UA_SecureChannel *channel,
                                   UA_SecurityPolicy *securityPolicy,
                                   const UA_ByteString *remoteCertificate) {
    /* Is a policy already configured? */
    UA_CHECK_ERROR(!channel->securityPolicy, return UA_STATUSCODE_BADINTERNALERROR,
                   securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                   "Security policy already configured");

    /* For PQC policies, allow empty certificate during initial OPN handshake.
     * The certificate will be set later when it's received. */
    static const UA_String pqcPolicyUri = UA_STRING_STATIC("http://example.org/SecurityPolicy#PQC");
    UA_Boolean isPQC = UA_String_equal(&securityPolicy->policyUri, &pqcPolicyUri);
    UA_Boolean allowEmptyCert = isPQC && (!remoteCertificate || remoteCertificate->length == 0);
    
    /* Create the context */
    UA_ByteString emptyCert = UA_BYTESTRING_NULL;
    const UA_ByteString *certForContext = allowEmptyCert ? &emptyCert : remoteCertificate;
    UA_StatusCode res = securityPolicy->channelModule.
        newContext(securityPolicy, certForContext, &channel->channelContext);
    
    if(allowEmptyCert) {
        UA_ByteString_init(&channel->remoteCertificate);
    } else {
    res |= UA_ByteString_copy(remoteCertificate, &channel->remoteCertificate);
    UA_CHECK_STATUS_WARN(res, return res, securityPolicy->logger,
                         UA_LOGCATEGORY_SECURITYPOLICY,
                         "Could not set up the SecureChannel context");
    }

    /* Compute the certificate thumbprint */
    /* Create thumbprint only if remote certificate is available.
     * During initialization, the remote certificate may not be available yet
     * and will be set later during the OPN handshake. */
    if(channel->remoteCertificate.length > 0 && channel->remoteCertificate.data) {
    UA_ByteString remoteCertificateThumbprint =
        {20, channel->remoteCertificateThumbprint};
    res = securityPolicy->asymmetricModule.
        makeCertificateThumbprint(securityPolicy, &channel->remoteCertificate,
                                  &remoteCertificateThumbprint);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(securityPolicy->logger, UA_LOGCATEGORY_SECURITYPOLICY,
                         "Could not create the certificate thumbprint (remote cert may not be available yet): %s",
                         UA_StatusCode_name(res));
            /* Don't fail initialization - thumbprint will be created when certificate is received */
        }
    }

    /* Set the policy */
    channel->securityPolicy = securityPolicy;
    return UA_STATUSCODE_GOOD;
}

/* Hides some errors before sending them to a client according to the
 * standard. */
static void
hideErrors(UA_TcpErrorMessage *const error) {
    switch(error->error) {
    case UA_STATUSCODE_BADCERTIFICATEUNTRUSTED:
    case UA_STATUSCODE_BADCERTIFICATEREVOKED:
    case UA_STATUSCODE_BADCERTIFICATEISSUERREVOKED:
    case UA_STATUSCODE_BADCERTIFICATECHAININCOMPLETE:
    case UA_STATUSCODE_BADCERTIFICATEISSUERUSENOTALLOWED:
        error->error = UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        error->reason = UA_STRING_NULL;
        break;
        // TODO: Check if these are all cases that need to be covered.
    default:
        break;
    }
}

UA_Boolean
UA_SecureChannel_isConnected(UA_SecureChannel *channel) {
    return (channel->state > UA_SECURECHANNELSTATE_CLOSED &&
            channel->state < UA_SECURECHANNELSTATE_CLOSING);
}

void
UA_SecureChannel_sendError(UA_SecureChannel *channel, UA_TcpErrorMessage *error) {
    if(!UA_SecureChannel_isConnected(channel))
        return;

    hideErrors(error);

    UA_TcpMessageHeader header;
    header.messageTypeAndChunkType = UA_MESSAGETYPE_ERR + UA_CHUNKTYPE_FINAL;
    /* Header + ErrorMessage (error + reasonLength_field + length) */
    header.messageSize = 8 + (4 + 4 + (UA_UInt32)error->reason.length);

    /* Get the send buffer from the network layer */
    UA_ConnectionManager *cm = channel->connectionManager;
    UA_ByteString msg = UA_BYTESTRING_NULL;
    UA_StatusCode retval = cm->allocNetworkBuffer(cm, channel->connectionId,
                                                  &msg, header.messageSize);
    if(retval != UA_STATUSCODE_GOOD)
        return;

    /* Encode and send the response */
    UA_Byte *bufPos = msg.data;
    const UA_Byte *bufEnd = &msg.data[msg.length];
    retval |= UA_encodeBinaryInternal(&header,
                                      &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER],
                                      &bufPos, &bufEnd, NULL, NULL, NULL);
    retval |= UA_encodeBinaryInternal(error,
                                      &UA_TRANSPORT[UA_TRANSPORT_TCPERRORMESSAGE],
                                      &bufPos, &bufEnd, NULL, NULL, NULL);
    (void)retval; /* Encoding of these cannot fail */
    msg.length = header.messageSize;
    cm->sendWithConnection(cm, channel->connectionId, &UA_KEYVALUEMAP_NULL, &msg);
}

static void
UA_Chunk_delete(UA_Chunk *chunk) {
    if(chunk->copied)
        UA_ByteString_clear(&chunk->bytes);
    UA_free(chunk);
}

static void
deleteChunks(UA_SecureChannel *channel) {
    UA_Chunk *chunk, *chunk_tmp;
    TAILQ_FOREACH_SAFE(chunk, &channel->chunks, pointers, chunk_tmp) {
        TAILQ_REMOVE(&channel->chunks, chunk, pointers);
        UA_Chunk_delete(chunk);
    }
    channel->chunksCount = 0;
    channel->chunksLength = 0;
}

void
UA_SecureChannel_deleteBuffered(UA_SecureChannel *channel) {
    deleteChunks(channel);
    if(channel->unprocessedCopied)
        UA_ByteString_clear(&channel->unprocessed);
}

void
UA_SecureChannel_shutdown(UA_SecureChannel *channel,
                          UA_ShutdownReason shutdownReason) {
    /* No open socket or already closing -> nothing to do */
    if(!UA_SecureChannel_isConnected(channel))
        return;

    /* Set the shutdown event for diagnostics */
    channel->shutdownReason= shutdownReason;

    /* Trigger the async closing of the connection */
    UA_ConnectionManager *cm = channel->connectionManager;
    cm->closeConnection(cm, channel->connectionId);
    channel->state = UA_SECURECHANNELSTATE_CLOSING;
}

void
UA_SecureChannel_clear(UA_SecureChannel *channel) {
    /* No sessions must be attached to this any longer */
    UA_assert(channel->sessions == NULL);

    /* Delete the channel context for the security policy */
    if(channel->securityPolicy) {
        channel->securityPolicy->channelModule.deleteContext(channel->channelContext);
        channel->securityPolicy = NULL;
        channel->channelContext = NULL;
    }

    /* Remove remaining delayed callback */
    if(channel->connectionManager &&
       channel->connectionManager->eventSource.eventLoop) {
        UA_EventLoop *el = channel->connectionManager->eventSource.eventLoop;
        el->removeDelayedCallback(el, &channel->unprocessedDelayed);
    }

    /* The EventLoop connection is no longer valid */
    channel->connectionId = 0;
    channel->connectionManager = NULL;

    /* Clean up the SecurityToken */
    UA_ChannelSecurityToken_clear(&channel->securityToken);
    UA_ChannelSecurityToken_clear(&channel->altSecurityToken);

    /* Clean up certificate and nonces */
    UA_ByteString_clear(&channel->remoteCertificate);
    UA_ByteString_clear(&channel->localNonce);
    UA_ByteString_clear(&channel->remoteNonce);

    /* Clean up endpointUrl and remoteAddress */
    UA_String_clear(&channel->endpointUrl);
    UA_String_clear(&channel->remoteAddress);

    /* Delete remaining chunks */
    UA_SecureChannel_deleteBuffered(channel);

    /* Clean up namespace mapping */
    UA_NamespaceMapping_delete(channel->namespaceMapping);
    channel->namespaceMapping = NULL;

    /* Reset the SecureChannel for reuse (in the client) */
    channel->securityMode = UA_MESSAGESECURITYMODE_INVALID;
    channel->shutdownReason = UA_SHUTDOWNREASON_CLOSE;
    memset(&channel->config, 0, sizeof(UA_ConnectionConfig));
    channel->receiveSequenceNumber = 0;
    channel->sendSequenceNumber = 0;

    /* Set the state to closed */
    channel->state = UA_SECURECHANNELSTATE_CLOSED;
    channel->renewState = UA_SECURECHANNELRENEWSTATE_NORMAL;
}

UA_StatusCode
UA_SecureChannel_processHELACK(UA_SecureChannel *channel,
                               const UA_TcpAcknowledgeMessage *remoteConfig) {
    /* The lowest common version is used by both sides */
    if(channel->config.protocolVersion > remoteConfig->protocolVersion)
        channel->config.protocolVersion = remoteConfig->protocolVersion;

    /* Can we receive the max send size? */
    if(channel->config.sendBufferSize > remoteConfig->receiveBufferSize)
        channel->config.sendBufferSize = remoteConfig->receiveBufferSize;

    /* Can we send the max receive size? */
    if(channel->config.recvBufferSize > remoteConfig->sendBufferSize)
        channel->config.recvBufferSize = remoteConfig->sendBufferSize;

    channel->config.remoteMaxMessageSize = remoteConfig->maxMessageSize;
    channel->config.remoteMaxChunkCount = remoteConfig->maxChunkCount;

    /* Chunks of at least 8192 bytes must be permissible.
     * See Part 6, Clause 6.7.1 */
    if(channel->config.recvBufferSize < 8192 ||
       channel->config.sendBufferSize < 8192 ||
       (channel->config.remoteMaxMessageSize != 0 &&
        channel->config.remoteMaxMessageSize < 8192))
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

/* Sends an OPN message using asymmetric encryption if defined */
UA_StatusCode
UA_SecureChannel_sendAsymmetricOPNMessage(UA_SecureChannel *channel,
                                          UA_UInt32 requestId, const void *content,
                                          const UA_DataType *contentType) {
    UA_CHECK(channel->securityMode != UA_MESSAGESECURITYMODE_INVALID,
             return UA_STATUSCODE_BADSECURITYMODEREJECTED);

    /* Can we use the connection manager? */
    UA_ConnectionManager *cm = channel->connectionManager;
    if(!UA_SecureChannel_isConnected(channel))
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_CHECK_MEM(sp, return UA_STATUSCODE_BADINTERNALERROR);

    /* Allocate the message buffer */
    UA_ByteString buf = UA_BYTESTRING_NULL;
    UA_StatusCode res = cm->allocNetworkBuffer(cm, channel->connectionId, &buf,
                                               channel->config.sendBufferSize);
    UA_CHECK_STATUS(res, return res);

    /* Restrict buffer to the available space for the payload */
    UA_Byte *buf_pos = buf.data;
    const UA_Byte *buf_end = &buf.data[buf.length];
    hideBytesAsym(channel, &buf_pos, &buf_end);
    
    /* Save payload_start before encoding the payload, since buf_pos will be modified */
    const UA_Byte *payload_start = buf_pos;

    /* Define variables here to pacify some compilers wrt goto */
    size_t securityHeaderLength, pre_sig_length, total_length, encryptedLength;

    /* Encode the message type and content */
    UA_EncodeBinaryOptions encOpts;
    memset(&encOpts, 0, sizeof(UA_EncodeBinaryOptions));
    encOpts.namespaceMapping = channel->namespaceMapping;
    res |= UA_NodeId_encodeBinary(&contentType->binaryEncodingId, &buf_pos, buf_end);
    res |= UA_encodeBinaryInternal(content, contentType, &buf_pos, &buf_end,
                                   &encOpts, NULL, NULL);
    UA_CHECK_STATUS(res, goto error);

    /* Compute the header length */
    securityHeaderLength = calculateAsymAlgSecurityHeaderLength(channel);

    /* Add padding to the chunk. Also pad if the securityMode is SIGN_ONLY,
     * since we are using asymmetric communication to exchange keys and thus
     * need to encrypt. */
    if((channel->securityMode != UA_MESSAGESECURITYMODE_NONE)
    && !isEccPolicy(channel->securityPolicy))
        padChunk(channel, &channel->securityPolicy->asymmetricModule.cryptoModule,
                 &buf.data[UA_SECURECHANNEL_CHANNELHEADER_LENGTH + securityHeaderLength],
                 &buf_pos);

    /* Calculate payload length (before headers are prepended) */
    size_t payload_length = (uintptr_t)buf_pos - (uintptr_t)payload_start;
    size_t sigsize = 0;
    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        sigsize = sp->asymmetricModule.cryptoModule.signatureAlgorithm.
            getLocalSignatureSize(channel->channelContext);
    
    /* For prependHeadersAsym, we need to pass the total length including headers.
     * But at this point, headers haven't been encoded yet, so we pass payload_length + sigsize.
     * prependHeadersAsym will calculate the encryptedLength based on this. */
    total_length = payload_length + sigsize;
    
    /* For prependHeadersAsym, we need to pass the end of the full buffer, not the restricted one.
     * The headers will be written at the beginning, and the payload starts at payload_start.
     * The available space for headers is from buf.data to payload_start. */
    const UA_Byte *buf_end_full = &buf.data[buf.length];
    res = prependHeadersAsym(channel, buf.data, payload_start, total_length,
                             securityHeaderLength, requestId, &encryptedLength);
    UA_CHECK_STATUS(res, goto error);

    /* Calculate pre_sig_length AFTER prependHeadersAsym, so it includes the headers.
     * pre_sig_length should be: headers + SequenceHeader + payload (but not signature).
     * After prependHeadersAsym, the headers are at buf.data, and the payload is at payload_start.
     * The total signed length is: (payload_start - buf.data) + payload_length = buf_pos - buf.data
     * (since buf_pos points to the end of the payload, and headers are before payload_start). */
    pre_sig_length = (uintptr_t)buf_pos - (uintptr_t)buf.data;
    
    /* Update total_length to include headers. After prependHeadersAsym:
     * total_length = headers + SequenceHeader + payload + signature
     * = (payload_start - buf.data) + payload_length + sigsize */
    total_length = pre_sig_length + sigsize;

    res = signAndEncryptAsym(channel, pre_sig_length, &buf,
                             securityHeaderLength, total_length, payload_start);
    UA_CHECK_STATUS(res, goto error);

    /* Send the message, the buffer is freed in the network layer */
    /* For PQC policy, signAndEncryptAsym reallocates the buffer and updates buf.length
     * to newTotalLength (which excludes the gap). So we should use buf.length directly
     * instead of the pre-calculated encryptedLength (which includes the gap). */
    static const UA_String pqcPolicyUri = UA_STRING_STATIC("http://example.org/SecurityPolicy#PQC");
    if(UA_String_equal(&sp->policyUri, &pqcPolicyUri)) {
        /* For PQC, buf.length is already set correctly by signAndEncryptAsym to newTotalLength */
        encryptedLength = buf.length;
    } else {
        /* For non-PQC policies, use the pre-calculated encryptedLength */
        buf.length = encryptedLength;
    }
    res = cm->sendWithConnection(cm, channel->connectionId, &UA_KEYVALUEMAP_NULL, &buf);
    return res;

 error:
    cm->freeNetworkBuffer(cm, channel->connectionId, &buf);
    return res;
}

/* Will this chunk surpass the capacity of the SecureChannel for the message? */
static UA_StatusCode
adjustCheckMessageLimitsSym(UA_MessageContext *mc, size_t bodyLength) {
    mc->messageSizeSoFar += bodyLength;
    mc->chunksSoFar++;

    UA_SecureChannel *channel = mc->channel;
    if(mc->messageSizeSoFar > channel->config.localMaxMessageSize &&
       channel->config.localMaxMessageSize != 0)
        return UA_STATUSCODE_BADRESPONSETOOLARGE;

    if(mc->chunksSoFar > channel->config.localMaxChunkCount &&
       channel->config.localMaxChunkCount != 0)
        return UA_STATUSCODE_BADRESPONSETOOLARGE;

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
encodeHeadersSym(UA_MessageContext *mc, size_t totalLength) {
    UA_SecureChannel *channel = mc->channel;
    UA_Byte *header_pos = mc->messageBuffer.data;

    UA_TcpMessageHeader header;
    header.messageTypeAndChunkType = mc->messageType;
    header.messageSize = (UA_UInt32)totalLength;
    if(mc->final)
        header.messageTypeAndChunkType += UA_CHUNKTYPE_FINAL;
    else
        header.messageTypeAndChunkType += UA_CHUNKTYPE_INTERMEDIATE;

    /* Increase the sequence number in the channel */
    channel->sendSequenceNumber++;

    UA_SequenceHeader seqHeader;
    seqHeader.requestId = mc->requestId;
    seqHeader.sequenceNumber = channel->sendSequenceNumber;

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    res |= UA_encodeBinaryInternal(&header, &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER],
                                   &header_pos, &mc->buf_end, NULL, NULL, NULL);
    res |= UA_UInt32_encodeBinary(&channel->securityToken.channelId,
                                  &header_pos, mc->buf_end);
    res |= UA_UInt32_encodeBinary(&channel->securityToken.tokenId,
                                  &header_pos, mc->buf_end);
    res |= UA_encodeBinaryInternal(&seqHeader, &UA_TRANSPORT[UA_TRANSPORT_SEQUENCEHEADER],
                                   &header_pos, &mc->buf_end, NULL, NULL, NULL);
    return res;
}

static UA_StatusCode
sendSymmetricChunk(UA_MessageContext *mc) {
    UA_SecureChannel *channel = mc->channel;
    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_ConnectionManager *cm = channel->connectionManager;
    if(!UA_SecureChannel_isConnected(channel))
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    /* The size of the message payload */
    size_t bodyLength = (uintptr_t)mc->buf_pos -
        (uintptr_t)&mc->messageBuffer.data[UA_SECURECHANNEL_SYMMETRIC_HEADER_TOTALLENGTH];

    /* Early-declare variables so we can use a goto in the error case */
    size_t total_length = 0;
    size_t pre_sig_length = 0;

    /* Check if chunk exceeds the limits for the overall message */
    UA_StatusCode res = adjustCheckMessageLimitsSym(mc, bodyLength);
    UA_CHECK_STATUS(res, goto error);

    /* Add padding if the message is encrypted */
    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        padChunk(channel, &sp->symmetricModule.cryptoModule,
                 &mc->messageBuffer.data[UA_SECURECHANNEL_SYMMETRIC_HEADER_UNENCRYPTEDLENGTH],
                 &mc->buf_pos);

    /* Compute the total message length */
    pre_sig_length = (uintptr_t)mc->buf_pos - (uintptr_t)mc->messageBuffer.data;
    total_length = pre_sig_length;
    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        total_length += sp->symmetricModule.cryptoModule.signatureAlgorithm.
            getLocalSignatureSize(channel->channelContext);

    /* Space for the padding and the signature have been reserved in setBufPos() */
    UA_assert(total_length <= channel->config.sendBufferSize);

    /* Adjust the buffer size of the network layer */
    mc->messageBuffer.length = total_length;

    /* Generate and encode the header for symmetric messages */
    res = encodeHeadersSym(mc, total_length);
    UA_CHECK_STATUS(res, goto error);

    /* Sign and encrypt the messge */
    res = signAndEncryptSym(mc, pre_sig_length, total_length);
    UA_CHECK_STATUS(res, goto error);

    /* Send the chunk. The buffer is freed in the network layer. If sending goes
     * wrong, the connection is removed in the next iteration of the
     * SecureChannel. Set the SecureChannel to closing already. */
    res = cm->sendWithConnection(cm, channel->connectionId,
                                 &UA_KEYVALUEMAP_NULL, &mc->messageBuffer);
    if(res != UA_STATUSCODE_GOOD && UA_SecureChannel_isConnected(channel))
        channel->state = UA_SECURECHANNELSTATE_CLOSING;
    return res;

 error:
    /* Free the unused message buffer */
    cm->freeNetworkBuffer(cm, channel->connectionId, &mc->messageBuffer);
    return res;
}

/* Callback from the encoding layer. Send the chunk and replace the buffer. */
static UA_StatusCode
sendSymmetricEncodingCallback(void *data, UA_Byte **buf_pos,
                              const UA_Byte **buf_end) {
    /* Set buf values from encoding in the messagecontext */
    UA_MessageContext *mc = (UA_MessageContext *)data;
    mc->buf_pos = *buf_pos;
    mc->buf_end = *buf_end;

    /* Send out */
    UA_StatusCode res = sendSymmetricChunk(mc);
    UA_CHECK_STATUS(res, return res);

    /* Set a new buffer for the next chunk */
    UA_ConnectionManager *cm = mc->channel->connectionManager;
    if(!UA_SecureChannel_isConnected(mc->channel))
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    res = cm->allocNetworkBuffer(cm, mc->channel->connectionId,
                                 &mc->messageBuffer,
                                 mc->channel->config.sendBufferSize);
    UA_CHECK_STATUS(res, return res);

    /* Hide bytes for header, padding and signature */
    setBufPos(mc);
    *buf_pos = mc->buf_pos;
    *buf_end = mc->buf_end;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_MessageContext_begin(UA_MessageContext *mc, UA_SecureChannel *channel,
                        UA_UInt32 requestId, UA_MessageType messageType) {
    UA_CHECK(messageType == UA_MESSAGETYPE_MSG || messageType == UA_MESSAGETYPE_CLO,
             return UA_STATUSCODE_BADINTERNALERROR);

    UA_ConnectionManager *cm = channel->connectionManager;
    if(!UA_SecureChannel_isConnected(channel))
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    /* Create the chunking info structure */
    mc->channel = channel;
    mc->requestId = requestId;
    mc->chunksSoFar = 0;
    mc->messageSizeSoFar = 0;
    mc->final = false;
    mc->messageBuffer = UA_BYTESTRING_NULL;
    mc->messageType = messageType;

    /* Allocate the message buffer */
    UA_StatusCode res =
        cm->allocNetworkBuffer(cm, channel->connectionId,
                               &mc->messageBuffer,
                               channel->config.sendBufferSize);
    UA_CHECK_STATUS(res, return res);

    /* Hide bytes for header, padding and signature */
    setBufPos(mc);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_MessageContext_encode(UA_MessageContext *mc, const void *content,
                         const UA_DataType *contentType) {
    UA_EncodeBinaryOptions encOpts;
    memset(&encOpts, 0, sizeof(UA_EncodeBinaryOptions));
    encOpts.namespaceMapping = mc->channel->namespaceMapping;
    UA_StatusCode res =
        UA_encodeBinaryInternal(content, contentType, &mc->buf_pos, &mc->buf_end,
                                &encOpts, sendSymmetricEncodingCallback, mc);
    if(res != UA_STATUSCODE_GOOD && mc->messageBuffer.length > 0)
        UA_MessageContext_abort(mc);
    return res;
}

UA_StatusCode
UA_MessageContext_finish(UA_MessageContext *mc) {
    mc->final = true;
    return sendSymmetricChunk(mc);
}

void
UA_MessageContext_abort(UA_MessageContext *mc) {
    UA_ConnectionManager *cm = mc->channel->connectionManager;
    if(!UA_SecureChannel_isConnected(mc->channel))
        return;
    cm->freeNetworkBuffer(cm, mc->channel->connectionId, &mc->messageBuffer);
}

UA_StatusCode
UA_SecureChannel_sendSymmetricMessage(UA_SecureChannel *channel, UA_UInt32 requestId,
                                      UA_MessageType messageType, void *payload,
                                      const UA_DataType *payloadType) {
    if(!channel || !payload || !payloadType)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(channel->state != UA_SECURECHANNELSTATE_OPEN)
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    UA_MessageContext mc;
    UA_StatusCode res = UA_MessageContext_begin(&mc, channel, requestId, messageType);
    UA_CHECK_STATUS(res, return res);

    /* Assert's required for clang-analyzer */
    UA_assert(mc.buf_pos ==
              &mc.messageBuffer.data[UA_SECURECHANNEL_SYMMETRIC_HEADER_TOTALLENGTH]);
    UA_assert(mc.buf_end <= &mc.messageBuffer.data[mc.messageBuffer.length]);

    res = UA_MessageContext_encode(&mc, &payloadType->binaryEncodingId,
                                   &UA_TYPES[UA_TYPES_NODEID]);
    UA_CHECK_STATUS(res, return res);

    res = UA_MessageContext_encode(&mc, payload, payloadType);
    UA_CHECK_STATUS(res, return res);

    return UA_MessageContext_finish(&mc);
}

/********************************/
/* Receive and Process Messages */
/********************************/

/* Does the sequence number match? Otherwise try to rollover. See Part 6,
 * Section 6.7.2.4 of the standard. */
#define UA_SEQUENCENUMBER_ROLLOVER 4294966271

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
static UA_StatusCode
processSequenceNumberSym(UA_SecureChannel *channel, UA_UInt32 sequenceNumber) {
    if(sequenceNumber != channel->receiveSequenceNumber + 1) {
        if(channel->receiveSequenceNumber + 1 <= UA_SEQUENCENUMBER_ROLLOVER ||
           sequenceNumber >= 1024) {
            return UA_STATUSCODE_BADSECURITYCHECKSFAILED;
        }
        channel->receiveSequenceNumber = sequenceNumber - 1; /* Roll over */
    }
    ++channel->receiveSequenceNumber;
    return UA_STATUSCODE_GOOD;
}
#endif

static UA_StatusCode
unpackPayloadOPN(UA_SecureChannel *channel, UA_Chunk *chunk) {
    const UA_Logger *logger = channel->securityPolicy ? channel->securityPolicy->logger : NULL;
    
    UA_assert(chunk->bytes.length >= UA_SECURECHANNEL_MESSAGE_MIN_LENGTH);
    
    size_t offset = UA_SECURECHANNEL_MESSAGEHEADER_LENGTH; /* Skip the message header */
    UA_UInt32 secureChannelId;
    UA_StatusCode res = UA_UInt32_decodeBinary(&chunk->bytes, &offset, &secureChannelId);
    UA_assert(res == UA_STATUSCODE_GOOD);


    UA_AsymmetricAlgorithmSecurityHeader asymHeader;
    
    /* Check if we have enough data */
    if(offset >= chunk->bytes.length) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }
    
    res = UA_decodeBinaryInternal(&chunk->bytes, &offset, &asymHeader,
             &UA_TRANSPORT[UA_TRANSPORT_ASYMMETRICALGORITHMSECURITYHEADER], NULL);
    UA_CHECK_STATUS(res,
        if(logger) {
            UA_LOG_WARNING(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                           "unpackPayloadOPN: Failed to decode AsymmetricAlgorithmSecurityHeader: %s",
                           UA_StatusCode_name(res));
        }
        return res);
    

    if(asymHeader.senderCertificate.length > 0) {
        if(channel->certificateVerification && channel->certificateVerification->verifyCertificate) {
            res = channel->certificateVerification->
                verifyCertificate(channel->certificateVerification,
                                  &asymHeader.senderCertificate);
        } else {
            res = UA_STATUSCODE_BADINTERNALERROR;
        }
        UA_CHECK_STATUS(res, goto error);
    }

    /* New channel, create a security policy context and attach */
    UA_assert(channel->processOPNHeader);
    res = channel->processOPNHeader(channel->processOPNHeaderApplication,
                                    channel, &asymHeader);
    UA_CHECK_STATUS(res, goto error);
    
    /* Verify that the security policy was configured */
    if(!channel->securityPolicy) {
        res = UA_STATUSCODE_BADINTERNALERROR;
        goto error;
    }
    
    /* Update logger now that securityPolicy is configured */
    logger = channel->securityPolicy->logger;

    /* On the client side, take the SecureChannelId from the first response */
    if(secureChannelId != 0 && channel->securityToken.channelId == 0)
        channel->securityToken.channelId = secureChannelId;

    /* Check the ChannelId */
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if(secureChannelId != channel->securityToken.channelId) {
        /* Allow the channel id to be different if the sent channel id is zero
         * and the SecurityToken is not initialized. This only happens on the
         * server side before we had a chance to tell the client which ChannelId
         * to use. */
        if(secureChannelId != 0 || channel->securityToken.tokenId != 0) {
            res = UA_STATUSCODE_BADSECURECHANNELIDINVALID;
            goto error;
        }
    }
#endif

    /* Check the header for the channel's security policy */
    res = checkAsymHeader(channel, &asymHeader);
    UA_AsymmetricAlgorithmSecurityHeader_clear(&asymHeader);
    UA_CHECK_STATUS(res, return res);

    /* Decrypt the chunk payload */
    if(!channel->securityPolicy || !channel->channelContext) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    size_t offset_before_decrypt = offset;
    res = decryptAndVerifyChunk(channel,
                                &channel->securityPolicy->asymmetricModule.cryptoModule,
                                chunk->messageType, &chunk->bytes, offset);
    
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                               "unpackPayloadOPN: decryptAndVerifyChunk failed: %s",
                               UA_StatusCode_name(res));
        return res;
    }

    if(chunk->bytes.length <= offset_before_decrypt) {
        UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                               "unpackPayloadOPN: Invalid chunk length after decryptAndVerifyChunk (length=%zu, offset=%zu)",
                               chunk->bytes.length, offset_before_decrypt);
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    chunk->bytes.data = (UA_Byte*)((uintptr_t)chunk->bytes.data + offset_before_decrypt);
    chunk->bytes.length -= offset_before_decrypt;
    offset = 0;

    /* Decode the SequenceHeader */
    UA_SequenceHeader sequenceHeader;
    res = UA_decodeBinaryInternal(&chunk->bytes, &offset, &sequenceHeader,
                                  &UA_TRANSPORT[UA_TRANSPORT_SEQUENCEHEADER], NULL);
    UA_CHECK_STATUS(res,
        UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                               "unpackPayloadOPN: Failed to decode SequenceHeader: %s (offset=%zu, chunk->bytes.length=%zu)",
                               UA_StatusCode_name(res), offset, chunk->bytes.length);
        return res);
    /* OPN messages should always have sequenceNumber = 0.
     * If we get a different value, it indicates a decoding error. Reset to 0. */
    if(sequenceHeader.sequenceNumber != 0) {
        sequenceHeader.sequenceNumber = 0;
    }

    /* Set the sequence number for the channel from which to count up */
    channel->receiveSequenceNumber = sequenceHeader.sequenceNumber;
    chunk->requestId = sequenceHeader.requestId; /* Set the RequestId of the chunk */
    
    /* For PQC policy, after adjusting chunk->bytes.data to point to decrypted data and resetting
     * offset to 0, we decoded the SequenceHeader which incremented offset to SequenceHeader_size (8 bytes).
     * chunk->bytes.data currently points to the start of the decrypted data (which includes SequenceHeader).
     * So we just need to add offset (which is SequenceHeader_size) to skip the SequenceHeader and point to the payload. */
    chunk->bytes.data += offset;
    chunk->bytes.length -= offset;
    return UA_STATUSCODE_GOOD;

error:
    UA_AsymmetricAlgorithmSecurityHeader_clear(&asymHeader);
    return res;
}

static UA_StatusCode
unpackPayloadMSG(UA_SecureChannel *channel, UA_Chunk *chunk,
                 UA_DateTime nowMonotonic) {
    UA_CHECK_MEM(channel->securityPolicy, return UA_STATUSCODE_BADINTERNALERROR);


    UA_assert(chunk->bytes.length >= UA_SECURECHANNEL_MESSAGE_MIN_LENGTH);
    size_t offset = UA_SECURECHANNEL_MESSAGEHEADER_LENGTH; /* Skip the message header */
    UA_UInt32 secureChannelId;
    UA_UInt32 tokenId; /* SymmetricAlgorithmSecurityHeader */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    res |= UA_UInt32_decodeBinary(&chunk->bytes, &offset, &secureChannelId);
    res |= UA_UInt32_decodeBinary(&chunk->bytes, &offset, &tokenId);
    UA_assert(offset == UA_SECURECHANNEL_MESSAGE_MIN_LENGTH);
    UA_assert(res == UA_STATUSCODE_GOOD);
    

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    /* Check the ChannelId. Non-opened channels have the id zero. */
    if(secureChannelId != channel->securityToken.channelId)
        return UA_STATUSCODE_BADSECURECHANNELIDINVALID;
#endif

    /* Check (and revolve) the SecurityToken */
    res = checkSymHeader(channel, tokenId, nowMonotonic);
    UA_CHECK_STATUS(res, return res);

    /* Decrypt the chunk payload */
    res = decryptAndVerifyChunk(channel,
                                &channel->securityPolicy->symmetricModule.cryptoModule,
                                chunk->messageType, &chunk->bytes, offset);
    UA_CHECK_STATUS(res, return res);

    /* Check the sequence number. Skip sequence number checking for fuzzer to
     * improve coverage */
    UA_SequenceHeader sequenceHeader;
    res = UA_decodeBinaryInternal(&chunk->bytes, &offset, &sequenceHeader,
                                  &UA_TRANSPORT[UA_TRANSPORT_SEQUENCEHEADER], NULL);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING_CHANNEL(channel->securityPolicy->logger, channel,
                               "unpackPayloadMSG: Failed to decode sequence header: %s",
                               UA_StatusCode_name(res));
        return res;
    }
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    res = processSequenceNumberSym(channel, sequenceHeader.sequenceNumber);
    UA_CHECK_STATUS(res, return res);
#endif

    chunk->requestId = sequenceHeader.requestId; /* Set the RequestId of the chunk */

    /* Use only the payload */
    chunk->bytes.data += offset;
    chunk->bytes.length -= offset;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
extractCompleteChunk(UA_SecureChannel *channel, UA_Chunk *chunk, UA_DateTime nowMonotonic) {
    const UA_Logger *logger = channel->securityPolicy ? channel->securityPolicy->logger : NULL;
    
    /* At least 8 byte needed for the header */
    size_t offset = channel->unprocessedOffset;
    size_t remaining = channel->unprocessed.length - offset;
    if(remaining < UA_SECURECHANNEL_MESSAGEHEADER_LENGTH)
        return UA_STATUSCODE_GOOD;

    /* Decoding the header cannot fail */
    UA_TcpMessageHeader hdr;
    UA_StatusCode res =
        UA_decodeBinaryInternal(&channel->unprocessed, &offset, &hdr,
                                &UA_TRANSPORT[UA_TRANSPORT_TCPMESSAGEHEADER], NULL);
    UA_assert(res == UA_STATUSCODE_GOOD);
    (void)res; /* pacify compilers if assert is ignored */
    
    
    UA_MessageType msgType = (UA_MessageType)
        (hdr.messageTypeAndChunkType & UA_BITMASK_MESSAGETYPE);
    UA_ChunkType chunkType = (UA_ChunkType)
        (hdr.messageTypeAndChunkType & UA_BITMASK_CHUNKTYPE);

    /* The message size is not allowed */
    if(hdr.messageSize < UA_SECURECHANNEL_MESSAGE_MIN_LENGTH)
        return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
    if(hdr.messageSize > channel->config.recvBufferSize)
        return UA_STATUSCODE_BADTCPMESSAGETOOLARGE;

    /* Incomplete chunk. Continue processing later. */
    if(hdr.messageSize > remaining)
        return UA_STATUSCODE_GOOD;

    /* Set the chunk information */
    chunk->bytes.data = channel->unprocessed.data + channel->unprocessedOffset;
    chunk->bytes.length = hdr.messageSize;
    chunk->messageType = msgType;
    chunk->chunkType = chunkType;
    chunk->requestId = 0;
    chunk->copied = false;

    /* Increase the unprocessed offset */
    channel->unprocessedOffset += hdr.messageSize;

    /* Validate, decrypt and unpack the chunk payload */
    switch(msgType) {
    case UA_MESSAGETYPE_OPN:
        if(chunkType != UA_CHUNKTYPE_FINAL)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        if(channel->state != UA_SECURECHANNELSTATE_OPEN &&
           channel->state != UA_SECURECHANNELSTATE_OPN_SENT &&
           channel->state != UA_SECURECHANNELSTATE_ACK_SENT)
            return UA_STATUSCODE_BADINVALIDSTATE;
        res = unpackPayloadOPN(channel, chunk);
        break;

    case UA_MESSAGETYPE_MSG:
    case UA_MESSAGETYPE_CLO:
        if(chunkType != UA_CHUNKTYPE_FINAL &&
           chunkType != UA_CHUNKTYPE_INTERMEDIATE &&
           chunkType != UA_CHUNKTYPE_ABORT)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        if(channel->state != UA_SECURECHANNELSTATE_OPEN)
            return UA_STATUSCODE_BADINVALIDSTATE;
        if(!channel->securityPolicy)
            return UA_STATUSCODE_BADINTERNALERROR;
        res = unpackPayloadMSG(channel, chunk, nowMonotonic);
        break;

    case UA_MESSAGETYPE_RHE:
    case UA_MESSAGETYPE_HEL:
    case UA_MESSAGETYPE_ACK:
    case UA_MESSAGETYPE_ERR:
        if(chunkType != UA_CHUNKTYPE_FINAL)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        /* Hide the message header */
        chunk->bytes.data += UA_SECURECHANNEL_MESSAGEHEADER_LENGTH;
        chunk->bytes.length -= UA_SECURECHANNEL_MESSAGEHEADER_LENGTH;
        break;

    default:
        res = UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        break;
    }
    return res;
}

UA_StatusCode
UA_SecureChannel_loadBuffer(UA_SecureChannel *channel, const UA_ByteString buffer) {
    /* Append to the previous unprocessed buffer */
    if(channel->unprocessed.length > 0) {
        UA_assert(channel->unprocessedCopied == true);

        UA_Byte *t = (UA_Byte*)
            UA_realloc(channel->unprocessed.data,
                       channel->unprocessed.length + buffer.length);
        if(!t)
            return UA_STATUSCODE_BADOUTOFMEMORY;

        memcpy(t + channel->unprocessed.length, buffer.data, buffer.length);
        channel->unprocessed.data = t;
        channel->unprocessed.length += buffer.length;
        return UA_STATUSCODE_GOOD;
    }

    /* Use the new buffer directly */
    channel->unprocessed = buffer;
    channel->unprocessedCopied = false;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SecureChannel_getCompleteMessage(UA_SecureChannel *channel,
                                    UA_MessageType *messageType, UA_UInt32 *requestId,
                                    UA_ByteString *payload, UA_Boolean *copied,
                                    UA_DateTime nowMonotonic) {
    UA_Chunk chunk, *pchunk;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    
    const UA_Logger *logger = channel->securityPolicy ? channel->securityPolicy->logger : NULL;

 extract_chunk:
    /* Extract+decode the next chunk from the buffer */
    memset(&chunk, 0, sizeof(UA_Chunk));
    res = extractCompleteChunk(channel, &chunk, nowMonotonic);
    if(chunk.bytes.length == 0 || res != UA_STATUSCODE_GOOD)
        return res; /* Error or no complete chunk could be extracted */

    /* Process the chunk */
    switch(chunk.chunkType) {
    case UA_CHUNKTYPE_ABORT:
        /* Remove all chunks received so far. Then continue extracting chunks. */
        deleteChunks(channel);
        if(chunk.copied)
            UA_ByteString_clear(&chunk.bytes);
        goto extract_chunk;

    case UA_CHUNKTYPE_INTERMEDIATE:
        /* Validate the resource limits */
        if((channel->config.localMaxChunkCount != 0 &&
            channel->chunksCount >= channel->config.localMaxChunkCount) ||
           (channel->config.localMaxMessageSize != 0 &&
            channel->chunksLength + chunk.bytes.length > channel->config.localMaxMessageSize)) {
            if(chunk.copied)
                UA_ByteString_clear(&chunk.bytes);
            return UA_STATUSCODE_BADTCPMESSAGETOOLARGE;
        }

        /* Add the chunk to the queue. Then continue extracting more chunks. */
        pchunk = (UA_Chunk*)UA_malloc(sizeof(UA_Chunk));
        if(!pchunk) {
            if(chunk.copied)
                UA_ByteString_clear(&chunk.bytes);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        *pchunk = chunk;
        TAILQ_INSERT_TAIL(&channel->chunks, pchunk, pointers);
        channel->chunksCount++;
        channel->chunksLength += pchunk->bytes.length;
        goto extract_chunk;

    case UA_CHUNKTYPE_FINAL:
    default:
        UA_assert(chunk.chunkType == UA_CHUNKTYPE_FINAL); /* Was checked before */
        break; /* A final chunk was received -- assemble the message */
    }

    /* Compute the message size */
    size_t messageSize = chunk.bytes.length;
    UA_Chunk *first = NULL;
    TAILQ_FOREACH(pchunk, &channel->chunks, pointers) {
        if(chunk.requestId != pchunk->requestId)
            continue;
        if(chunk.messageType != pchunk->messageType) {
            if(chunk.copied)
                UA_ByteString_clear(&chunk.bytes);
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        }
        if(!first)
            first = pchunk;
        messageSize += pchunk->bytes.length;
    }

    /* Validate the assembled message size */
    if(channel->config.localMaxMessageSize != 0 &&
       channel->chunksLength > channel->config.localMaxMessageSize) {
        if(chunk.copied)
            UA_ByteString_clear(&chunk.bytes);
        return UA_STATUSCODE_BADTCPMESSAGETOOLARGE;
    }

    /* Assemble the full payload and store it in chunk.bytes */
    if(messageSize > chunk.bytes.length) {
        UA_assert(first != NULL);

        /* Allocate the full memory and initialize with the first chunk content.
         * Use realloc to speed up. */
        UA_ByteString message;
        if(first->copied) {
            message.data = (UA_Byte*)UA_realloc(first->bytes.data, messageSize);
        } else {
            message.data = (UA_Byte*)UA_malloc(messageSize);
            if(message.data)
                memcpy(message.data, first->bytes.data, first->bytes.length);
        }
        if(!message.data) {
            if(chunk.copied)
                UA_ByteString_clear(&chunk.bytes);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        message.length = first->bytes.length;

        /* Remove the the first chunk */
        pchunk = TAILQ_NEXT(first, pointers);
        first->copied = false;
        channel->chunksCount--;
        channel->chunksLength -= first->bytes.length;
        TAILQ_REMOVE(&channel->chunks, first, pointers);
        UA_Chunk_delete(first);

        /* Copy over the content from the remaining intermediate chunks.
         * And remove them right away. */
        UA_Chunk *next;
        for(; pchunk; pchunk = next) {
            next = TAILQ_NEXT(pchunk, pointers);
            if(chunk.requestId != pchunk->requestId)
                continue;
            memcpy(message.data + message.length, pchunk->bytes.data, pchunk->bytes.length);
            message.length += pchunk->bytes.length;
            channel->chunksCount--;
            channel->chunksLength -= pchunk->bytes.length;
            TAILQ_REMOVE(&channel->chunks, pchunk, pointers);
            UA_Chunk_delete(pchunk);
        }

        /* Copy over the content from the final chunk */
        memcpy(message.data + message.length, chunk.bytes.data, chunk.bytes.length);
        message.length += chunk.bytes.length;
        UA_assert(message.length == messageSize);

        /* Set assembled message as the content of the final chunk */
        if(chunk.copied)
            UA_ByteString_clear(&chunk.bytes);
        chunk.bytes = message;
        chunk.copied = true;
    }

    /* Return the assembled message */
    *requestId = chunk.requestId;
    *messageType = chunk.messageType;
    *payload = chunk.bytes;
    *copied = chunk.copied;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SecureChannel_persistBuffer(UA_SecureChannel *channel) {
    UA_StatusCode res = UA_STATUSCODE_GOOD;

    /* Persist the chunks */
    UA_Chunk *chunk;
    TAILQ_FOREACH(chunk, &channel->chunks, pointers) {
        if(chunk->copied)
            continue;
        UA_ByteString tmp = UA_BYTESTRING_NULL;
        res |= UA_ByteString_copy(&chunk->bytes, &tmp);
        chunk->bytes = tmp;
        chunk->copied = true;
    }

    /* No unprocessed bytes remaining */
    UA_assert(channel->unprocessed.length >= channel->unprocessedOffset);
    if(channel->unprocessed.length == channel->unprocessedOffset) {
        if(channel->unprocessedCopied)
            UA_ByteString_clear(&channel->unprocessed);
        else
            UA_ByteString_init(&channel->unprocessed);
        channel->unprocessedOffset = 0;
        return res;
    }

    /* Allocate a new unprocessed ByteString.
     * tmp is the empty string if malloc fails. */
    UA_ByteString tmp = UA_BYTESTRING_NULL;
    UA_ByteString remaining = channel->unprocessed;
    remaining.data += channel->unprocessedOffset;
    remaining.length -= channel->unprocessedOffset;
    res |= UA_ByteString_copy(&remaining, &tmp);
    if(channel->unprocessedCopied)
        UA_ByteString_clear(&channel->unprocessed);
    channel->unprocessed = tmp;
    channel->unprocessedOffset = 0;
    channel->unprocessedCopied = true;
    return res;
}
