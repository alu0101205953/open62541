/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2022 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2023 (c) Fraunhofer IOSB (Author: Kai Huebl)
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 */

#include <open62541/util.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/plugin/securitypolicy_pqc.h>
#include <open62541/plugin/log_stdout.h>

#include "ua_filestore_common.h"
#include "mp_printf.h"

#include <errno.h>

#ifdef UA_ENABLE_ENCRYPTION

#if defined(__linux__) || defined(UA_ARCHITECTURE_WIN32) || defined(__APPLE__)

#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_LIBRESSL)
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "openssl/securitypolicy_common.h"
#endif

#ifdef __linux__
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * ( EVENT_SIZE + 16 ))
#endif /* __linux__ */

typedef struct {
    /* Memory cert store as a base */
    UA_CertificateGroup *store;

#ifdef __linux__
    int inotifyFd;
#endif /* __linux__ */

    UA_String trustedCertFolder;
    UA_String trustedCrlFolder;
    UA_String issuerCertFolder;
    UA_String issuerCrlFolder;
    UA_String rejectedCertFolder;
    UA_String ownCertFolder;
    UA_String ownKeyFolder;
    UA_String rootFolder;
} FileCertStore;

static int
mkpath(char *dir, UA_MODE mode) {
    struct UA_STAT sb;

    if(dir == NULL)
        return 1;

    if(!UA_stat(dir, &sb))
        return 0;  /* Directory already exist */

    size_t len = strlen(dir) + 1;
    char *tmp_dir = (char*)UA_malloc(len);
    if(!tmp_dir)
        return 1;
    memcpy(tmp_dir, dir, len);

    /* Before the actual target directory is created, the recursive call ensures
     * that all parent directories are created or already exist. */
    mkpath(UA_dirname(tmp_dir), mode);
    UA_free(tmp_dir);

    return UA_mkdir(dir, mode);
}

static UA_StatusCode
removeAllFilesFromDir(const char *const path, bool removeSubDirs) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Check parameter */
    if(path == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* remove all regular files from directory */
    UA_DIR *dir = UA_opendir(path);
    if(!dir)
        return UA_STATUSCODE_BADINTERNALERROR;

    struct UA_DIRENT *dirent;
    while((dirent = UA_readdir(dir)) != NULL) {
        if(dirent->d_type == UA_DT_REG) {
            char file_name[UA_FILENAME_MAX];
            mp_snprintf(file_name, UA_FILENAME_MAX, "%s/%s", path,
                        (char *)dirent->d_name);
            UA_remove(file_name);
        }
        if(dirent->d_type == UA_DT_DIR && removeSubDirs == true) {
            char *directory = (char*)dirent->d_name;

            char dir_name[UA_FILENAME_MAX];
            mp_snprintf(dir_name, UA_FILENAME_MAX, "%s/%s", path, (char *)dirent->d_name);

            if(strlen(directory) == 1 && directory[0] == '.')
                continue;
            if(strlen(directory) == 2 && directory[0] == '.' && directory[1] == '.')
                continue;

            retval = removeAllFilesFromDir(dir_name, removeSubDirs);
        }
    }
    UA_closedir(dir);

    return retval;
}

static UA_StatusCode
getCertFileName(const char *path, const UA_ByteString *certificate,
                char *fileNameBuf, size_t fileNameLen) {
    /* Check parameter */
    if(path == NULL || certificate == NULL || fileNameBuf == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_String thumbprint = UA_STRING_NULL;
    thumbprint.length = 40;
    thumbprint.data = (UA_Byte*)UA_calloc(thumbprint.length, sizeof(UA_Byte));
    if(!thumbprint.data) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_String subjectName = UA_STRING_NULL;

    /* Extract thumbprint and subjectName - both are REQUIRED for filename generation */
    UA_StatusCode thumbprintRet = UA_CertificateUtils_getThumbprint((UA_ByteString*)(uintptr_t)certificate, &thumbprint);
    UA_StatusCode subjectRet = UA_CertificateUtils_getSubjectName((UA_ByteString*)(uintptr_t)certificate, &subjectName);

    /* CRITICAL: If either extraction fails, we cannot generate a valid filename */
    /* This prevents creating files with empty names like "[]" */
    if(thumbprintRet != UA_STATUSCODE_GOOD || thumbprint.length == 0 || !thumbprint.data) {
        UA_String_clear(&thumbprint);
        UA_String_clear(&subjectName);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    if(subjectRet != UA_STATUSCODE_GOOD || subjectName.length == 0 || !subjectName.data) {
        UA_String_clear(&thumbprint);
        UA_String_clear(&subjectName);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if((thumbprint.length + subjectName.length + 2) > fileNameLen) {
        UA_String_clear(&thumbprint);
        UA_String_clear(&subjectName);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    char *thumbprintBuffer = (char*)UA_malloc(thumbprint.length + 1);
    char *subjectNameBuffer = (char*)UA_malloc(subjectName.length + 1);
    
    if(!thumbprintBuffer || !subjectNameBuffer) {
        UA_free(thumbprintBuffer);
        UA_free(subjectNameBuffer);
        UA_String_clear(&thumbprint);
        UA_String_clear(&subjectName);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    memcpy(thumbprintBuffer, thumbprint.data, thumbprint.length);
    thumbprintBuffer[thumbprint.length] = '\0';
    memcpy(subjectNameBuffer, subjectName.data, subjectName.length);
    subjectNameBuffer[subjectName.length] = '\0';

    char *subName = NULL;
    char *substring = "CN=";
    char *ptr = strstr(subjectNameBuffer, substring);

    if(ptr != NULL) {
        subName = ptr + 3;
        /* Find end of CN value (next comma or end of string) */
        char *cnEnd = strchr(subName, ',');
        if(cnEnd) {
            *cnEnd = '\0'; /* Truncate at comma */
        }
    } else {
        subName = subjectNameBuffer;
    }

    /* CRITICAL: Validate that subName and thumbprintBuffer are not empty */
    /* This prevents creating filenames like "[]" or "[thumbprint]" */
    if(!subName || strlen(subName) == 0) {
        UA_String_clear(&thumbprint);
        UA_String_clear(&subjectName);
        UA_free(thumbprintBuffer);
        UA_free(subjectNameBuffer);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    if(!thumbprintBuffer || strlen(thumbprintBuffer) == 0) {
        UA_String_clear(&thumbprint);
        UA_String_clear(&subjectName);
        UA_free(thumbprintBuffer);
        UA_free(subjectNameBuffer);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(mp_snprintf(fileNameBuf, fileNameLen, "%s/%s[%s]", path, subName,
                   thumbprintBuffer) < 0) {
        retval = UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_String_clear(&thumbprint);
    UA_String_clear(&subjectName);
    UA_free(thumbprintBuffer);
    UA_free(subjectNameBuffer);

    return retval;
}

static UA_StatusCode
readCertificates(UA_ByteString **list, size_t *listSize, const UA_String path) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    char listPath[UA_PATH_MAX] = {0};
    mp_snprintf(listPath, UA_PATH_MAX, "%.*s",
                (int)path.length, (char*)path.data);

    /* Determine number of certificates */
    size_t numCerts = 0;
    UA_DIR *dir = UA_opendir(listPath);
    if(!dir) {
        /* If directory doesn't exist (ENOENT), treat as empty trust store */
        /* ENOENT is defined on both POSIX and Windows */
        if(errno == ENOENT) {
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                       "[FILESTORE] Missing PKI directory treated as empty: %s",
                       listPath);
            /* Return empty list */
            if(list) {
                *list = NULL;
            }
            if(listSize) {
                *listSize = 0;
            }
            return UA_STATUSCODE_GOOD;
        }
        
        /* For other errors, log and return error */
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[DIAG-readCertificates] BADINTERNALERROR: UA_opendir failed - "
                    "listPath=%s, errno=%d, list=%p, listSize=%p",
                    listPath, errno, (void*)list, (void*)listSize);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    struct UA_DIRENT *dirent;
    while((dirent = UA_readdir(dir)) != NULL) {
        if(dirent->d_type != UA_DT_REG)
            continue;
        numCerts++;
    }

    retval = UA_Array_resize((void **)list, listSize, numCerts, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_closedir(dir);
        return retval;
    }

    /* Read files from directory */
    size_t numActCerts = 0;
    UA_rewinddir(dir);

    while((dirent = UA_readdir(dir)) != NULL) {
        if(dirent->d_type != UA_DT_REG)
            continue;
        if(numActCerts < numCerts) {
            /* Create filename to load */
            char filename[UA_PATH_MAX] = {0};
            if(mp_snprintf(filename, UA_PATH_MAX, "%s/%s", listPath, dirent->d_name) < 0) {
                UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SECURITYPOLICY,
                            "[DIAG-readCertificates] BADINTERNALERROR: mp_snprintf failed - "
                            "listPath=%s, dirent->d_name=%s, filename buffer size=%d",
                            listPath, dirent->d_name, UA_PATH_MAX);
                UA_closedir(dir);
                return UA_STATUSCODE_BADINTERNALERROR;
            }

            /* Load data from file */
            retval = readFileToByteString(filename, &((*list)[numActCerts]));
            if(retval != UA_STATUSCODE_GOOD) {
                UA_closedir(dir);
                return retval;
            }
        }
        numActCerts++;
    }
    UA_closedir(dir);

    return retval;
}

static UA_StatusCode
readTrustStore(UA_CertificateGroup *certGroup, UA_TrustListDataType *trustList) {
    const UA_Logger *logger = certGroup ? certGroup->logging : NULL;
    
    if(certGroup == NULL) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-readTrustStore] BADINTERNALERROR: certGroup is NULL - trustList=%p",
                        (void*)trustList);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;
    if(context == NULL) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-readTrustStore] BADINTERNALERROR: context is NULL - "
                        "certGroup=%p, certGroup->context=%p, trustList=%p",
                        (void*)certGroup, (void*)certGroup->context, (void*)trustList);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    
    /* Log directory paths */
    if(logger) {
        char trustedPath[UA_PATH_MAX] = {0};
        char issuerPath[UA_PATH_MAX] = {0};
        mp_snprintf(trustedPath, UA_PATH_MAX, "%.*s", 
                   (int)context->trustedCertFolder.length, (char*)context->trustedCertFolder.data);
        mp_snprintf(issuerPath, UA_PATH_MAX, "%.*s", 
                   (int)context->issuerCertFolder.length, (char*)context->issuerCertFolder.data);
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                   "[FILESTORE-DIAG] readTrustStore: Loading certificates from: trusted=%s, issuer=%s",
                   trustedPath, issuerPath);
    }
    
    retval |= readCertificates(&trustList->trustedCertificates, &trustList->trustedCertificatesSize,
                               context->trustedCertFolder);
    retval |= readCertificates(&trustList->trustedCrls, &trustList->trustedCrlsSize,
                               context->trustedCrlFolder);
    retval |= readCertificates(&trustList->issuerCertificates, &trustList->issuerCertificatesSize,
                               context->issuerCertFolder);
    retval |= readCertificates(&trustList->issuerCrls, &trustList->issuerCrlsSize,
                               context->issuerCrlFolder);

    /* Log loaded certificate counts */
    if(logger) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                   "[FILESTORE-DIAG] readTrustStore: Loaded certificates - "
                   "trustedCertificates=%zu, issuerCertificates=%zu, trustedCrls=%zu, issuerCrls=%zu",
                   trustList->trustedCertificatesSize, trustList->issuerCertificatesSize,
                   trustList->trustedCrlsSize, trustList->issuerCrlsSize);
    }

    return retval;
}

static UA_StatusCode
reloadAndWriteTrustStore(UA_CertificateGroup *certGroup) {
    const UA_Logger *logger = certGroup ? certGroup->logging : NULL;
    
    if(certGroup == NULL) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-reloadAndWriteTrustStore] BADINTERNALERROR: certGroup is NULL");
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    FileCertStore *context = (FileCertStore *)certGroup->context;
    if(context == NULL) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-reloadAndWriteTrustStore] BADINTERNALERROR: context is NULL - "
                        "certGroup=%p, certGroup->context=%p",
                        (void*)certGroup, (void*)certGroup->context);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    if(context->store == NULL) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-reloadAndWriteTrustStore] BADINTERNALERROR: context->store is NULL - "
                        "certGroup=%p, context=%p, context->store=%p",
                        (void*)certGroup, (void*)context, (void*)context->store);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;

    UA_StatusCode retval = readTrustStore(certGroup, &trustList);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-reloadAndWriteTrustStore] readTrustStore failed: %s - "
                        "certGroup=%p, context=%p, context->store=%p",
                        UA_StatusCode_name(retval),
                        (void*)certGroup, (void*)context, (void*)context->store);
        }
        UA_TrustListDataType_clear(&trustList);
        return retval;
    }

    /* Log before setTrustList */
    if(logger) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                   "[FILESTORE-DIAG] reloadAndWriteTrustStore: About to setTrustList with - "
                   "trustedCertificates=%zu, issuerCertificates=%zu",
                   trustList.trustedCertificatesSize, trustList.issuerCertificatesSize);
    }
    
    retval = context->store->setTrustList(context->store, &trustList);
    if(retval != UA_STATUSCODE_GOOD && logger) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[DIAG-reloadAndWriteTrustStore] setTrustList failed: %s - "
                    "certGroup=%p, context=%p, context->store=%p",
                    UA_StatusCode_name(retval),
                    (void*)certGroup, (void*)context, (void*)context->store);
        UA_TrustListDataType_clear(&trustList);
        return retval;
    }
    
    /* CRITICAL: After setTrustList, reloadCertificates must be called to populate X509 stacks */
    /* setTrustList only sets reloadRequired=true. reloadCertificates is normally called in verifyCertificate, */
    /* but for PQC we need the issuer BEFORE verifyCertificate. Force reload by calling verifyCertificate */
    /* with an invalid certificate that will trigger reloadCertificates (due to reloadRequired=true) */
    /* and then fail early on parsing. This populates the X509 stacks without side effects. */
    typedef struct {
        UA_TrustListDataType trustList;
        size_t rejectedCertificatesSize;
        UA_ByteString *rejectedCertificates;
        UA_UInt32 maxTrustListSize;
        UA_UInt32 maxRejectedListSize;
        UA_Boolean reloadRequired;
        STACK_OF(X509) *trustedCertificates;
        STACK_OF(X509) *issuerCertificates;
        STACK_OF(X509_CRL) *crls;
    } MemoryCertStore;
    
    MemoryCertStore *memStore = (MemoryCertStore *)context->store->context;
    if(memStore && memStore->reloadRequired) {
        /* Force reloadCertificates by calling verifyCertificate with invalid certificate */
        /* This triggers reloadCertificates (because reloadRequired=true) and populates X509 stacks */
        UA_ByteString dummyCert = UA_BYTESTRING_NULL;
        dummyCert.length = 1;
        dummyCert.data = (UA_Byte*)UA_malloc(1);
        if(dummyCert.data) {
            dummyCert.data[0] = 0x00; /* Invalid certificate - will fail parsing but trigger reload */
            /* This call will: 1) Check reloadRequired=true, 2) Call reloadCertificates, 3) Fail on parsing */
            /* The failure is expected and harmless - we just need reloadCertificates to run */
            (void)context->store->verifyCertificate(context->store, &dummyCert);
            UA_free(dummyCert.data);
            if(logger) {
                UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                           "[FILESTORE-DIAG] reloadAndWriteTrustStore: Forced reloadCertificates via dummy verifyCertificate");
            }
        }
    }
    
    if(logger) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                   "[FILESTORE-DIAG] reloadAndWriteTrustStore: setTrustList succeeded, "
                   "X509 stacks should now be populated in MemoryCertStore");
    }
    UA_TrustListDataType_clear(&trustList);

    return retval;
}

static UA_StatusCode
reloadTrustStore(UA_CertificateGroup *certGroup) {
    if(certGroup == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

 #ifdef __linux__
    FileCertStore *context = (FileCertStore *)certGroup->context;

    char buffer[BUF_LEN];
    const int length = read(context->inotifyFd, buffer, BUF_LEN );
    if(length == -1 && errno != EAGAIN)
        return UA_STATUSCODE_BADINTERNALERROR;
#else
    /* TODO: Implement a way to check for changes in the pki folder */
    const int length = 0;
#endif /* __linux__ */

    /* No events, which means no changes to the pki folder */
    /* If the nonblocking read() found no events to read, then
     * it returns -1 with errno set to EAGAIN. In that case,
     * we exit the loop. */
    if(length <= 0)
        return UA_STATUSCODE_GOOD;

    return reloadAndWriteTrustStore(certGroup);
}

static UA_StatusCode
writeCertificates(UA_CertificateGroup *certGroup, const UA_ByteString *list,
                  size_t listSize, const char *listPath) {
    /* Check parameter */
    if(listPath == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(listSize > 0 && list == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < listSize; i++) {
        /* Create filename to load */
        char filename[UA_PATH_MAX] = {0};
        retval = getCertFileName(listPath, &list[i], filename, UA_PATH_MAX);
        if(retval != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADINTERNALERROR;

        /* Check if certificate already exists - skip if it does to avoid duplication */
        struct UA_STAT sb;
        if(UA_stat(filename, &sb) == 0) {
            /* File already exists - skip writing to avoid duplication */
            continue;
        }

        /* Store data in file */
        retval = writeByteStringToFile(filename, &list[i]);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }

    return retval;
}

static UA_StatusCode
writeTrustList(UA_CertificateGroup *certGroup, const UA_ByteString *list,
               size_t listSize, const UA_String path) {
    /* Check parameter */
    if(path.length == 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    if(listSize > 0 && list == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    char listPath[UA_PATH_MAX] = {0};
    mp_snprintf(listPath, UA_PATH_MAX, "%.*s", (int)path.length, (char *)path.data);
    /* remove existing files in directory */
    UA_StatusCode retval = removeAllFilesFromDir(listPath, false);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    return writeCertificates(certGroup, list, listSize, listPath);
}

static UA_StatusCode
writeTrustStore(UA_CertificateGroup *certGroup, const UA_UInt32 trustListMask) {
    /* Check parameter */
    if(certGroup == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    FileCertStore *context = (FileCertStore *)certGroup->context;

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = trustListMask;

    context->store->getTrustList(context->store, &trustList);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(trustList.specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES) {
        retval = writeTrustList(certGroup, trustList.trustedCertificates,
                                trustList.trustedCertificatesSize, context->trustedCertFolder);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }
    if(trustList.specifiedLists & UA_TRUSTLISTMASKS_TRUSTEDCRLS) {
        retval = writeTrustList(certGroup, trustList.trustedCrls,
                                trustList.trustedCrlsSize, context->trustedCrlFolder);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }
    if(trustList.specifiedLists & UA_TRUSTLISTMASKS_ISSUERCERTIFICATES) {
        retval = writeTrustList(certGroup, trustList.issuerCertificates,
                                trustList.issuerCertificatesSize, context->issuerCertFolder);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }
    if(trustList.specifiedLists & UA_TRUSTLISTMASKS_ISSUERCRLS) {
        retval = writeTrustList(certGroup, trustList.issuerCrls,
                                trustList.issuerCrlsSize, context->issuerCrlFolder);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }
    UA_TrustListDataType_clear(&trustList);

    return retval;
}

static UA_StatusCode
FileCertStore_setupStorePath(UA_CertificateGroup *certGroup, char *directory, char *rootDirectory,
                             size_t rootDirectorySize, UA_String *out) {
    char path[UA_PATH_MAX] = {0};
    size_t pathSize = 0;

    strncpy(path, rootDirectory, UA_PATH_MAX);
    pathSize = strnlen(path, UA_PATH_MAX);

    strncpy(&path[pathSize], directory, UA_PATH_MAX - pathSize);

    *out = UA_STRING_ALLOC(path);

    const UA_Logger *logger = certGroup ? certGroup->logging : NULL;
    
    /* Create directory recursively. mkpath() returns 0 on success, != 0 on failure */
    int mkpathResult = mkpath(path, 0777);
    if(mkpathResult != 0) {
        /* Check if directory was created by another thread/process (race condition) */
        struct UA_STAT sb;
        if(UA_stat(path, &sb) == 0) {
            /* Directory exists now - treat as success (idempotent behavior) */
            return UA_STATUSCODE_GOOD;
        }
        
        /* Real failure - log error and return error code */
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create PKI directory: %s (errno=%d, mkpath_result=%d)",
                        path, errno, mkpathResult);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
FileCertStore_createPkiDirectory(UA_CertificateGroup *certGroup, const UA_String directory) {
    const UA_Logger *logger = certGroup ? certGroup->logging : NULL;
    
    if(certGroup == NULL) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-FileCertStore_createPkiDirectory] BADINTERNALERROR: certGroup is NULL - "
                        "directory.length=%zu, directory.data=%p",
                        directory.length, (void*)directory.data);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    FileCertStore *context = (FileCertStore *)certGroup->context;
    if(!context) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-FileCertStore_createPkiDirectory] BADINTERNALERROR: context is NULL - "
                        "certGroup=%p, certGroup->context=%p, directory.length=%zu, directory.data=%.*s",
                        (void*)certGroup, (void*)certGroup->context,
                        directory.length, (int)directory.length, directory.data);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    char rootDirectory[UA_PATH_MAX] = {0};
    size_t rootDirectorySize = 0;

    if(directory.length <= 0 || directory.length >= UA_PATH_MAX) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-FileCertStore_createPkiDirectory] BADINTERNALERROR: invalid directory length - "
                        "certGroup=%p, context=%p, directory.length=%zu (must be >0 and <%d), directory.data=%.*s",
                        (void*)certGroup, (void*)context,
                        directory.length, UA_PATH_MAX,
                        (int)(directory.length < 100 ? directory.length : 100), directory.data);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    memcpy(rootDirectory, directory.data, directory.length);
    rootDirectorySize = strnlen(rootDirectory, UA_PATH_MAX);

    /* Add Certificate Group Id */
    UA_NodeId applCertGroup =
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId httpCertGroup =
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTHTTPSGROUP);
    UA_NodeId userTokenCertGroup =
        UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTUSERTOKENGROUP);

    if(UA_NodeId_equal(&certGroup->certificateGroupId, &applCertGroup)) {
        strncpy(&rootDirectory[rootDirectorySize], "/ApplCerts", UA_PATH_MAX - rootDirectorySize);
    } else if(UA_NodeId_equal(&certGroup->certificateGroupId, &httpCertGroup)) {
        strncpy(&rootDirectory[rootDirectorySize], "/HttpCerts", UA_PATH_MAX - rootDirectorySize);
    } else if(UA_NodeId_equal(&certGroup->certificateGroupId, &userTokenCertGroup)) {
        strncpy(&rootDirectory[rootDirectorySize], "/UserTokenCerts", UA_PATH_MAX - rootDirectorySize);
    } else {
        UA_String nodeIdStr;
        UA_String_init(&nodeIdStr);
        UA_NodeId_print(&certGroup->certificateGroupId, &nodeIdStr);
        strncpy(&rootDirectory[rootDirectorySize], (char *)nodeIdStr.data, UA_PATH_MAX - rootDirectorySize);
        UA_String_clear(&nodeIdStr);
    }
    rootDirectorySize = strnlen(rootDirectory, UA_PATH_MAX);

    context->rootFolder = UA_STRING_ALLOC(rootDirectory);

    /* Create parent directories explicitly before creating subdirectories */
    /* This ensures that paths like ./server_pki/ApplCerts/rejected exist before creating rejected/certs */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    
    /* Step 1: Create the root certificate group directory (e.g., ./server_pki/ApplCerts) */
    int mkpathResult = mkpath(rootDirectory, 0777);
    if(mkpathResult != 0) {
        /* Check for race condition: directory might have been created by another thread/process */
        struct UA_STAT sb;
        if(UA_stat(rootDirectory, &sb) != 0) {
            /* Real failure - log error */
            if(logger) {
                UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                            "[FILESTORE] Failed to create root certificate group directory: %s (errno=%d, mkpath_result=%d)",
                            rootDirectory, errno, mkpathResult);
            }
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }
    
    /* Step 2: Create parent directories for each subdirectory category */
    char parentDir[UA_PATH_MAX] = {0};
    const char *parentDirs[] = {"/rejected", "/own", "/trusted", "/issuer"};
    size_t numParentDirs = sizeof(parentDirs) / sizeof(parentDirs[0]);
    
    for(size_t i = 0; i < numParentDirs; i++) {
        mp_snprintf(parentDir, UA_PATH_MAX, "%s%s", rootDirectory, parentDirs[i]);
        mkpathResult = mkpath(parentDir, 0777);
        if(mkpathResult != 0) {
            /* Check for race condition */
            struct UA_STAT sb;
            if(UA_stat(parentDir, &sb) != 0) {
                /* Real failure - log error */
                if(logger) {
                    UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                                "[FILESTORE] Failed to create parent directory: %s (errno=%d, mkpath_result=%d)",
                                parentDir, errno, mkpathResult);
                }
                return UA_STATUSCODE_BADINTERNALERROR;
            }
        }
    }
    
    /* Step 3: Now create subdirectories (certs, crl, private) */
    retval |= FileCertStore_setupStorePath(certGroup, "/trusted/certs", rootDirectory,
                                           rootDirectorySize, &context->trustedCertFolder);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create trusted/certs directory");
        }
        return retval;
    }
    
    retval |= FileCertStore_setupStorePath(certGroup, "/trusted/crl", rootDirectory,
                                           rootDirectorySize, &context->trustedCrlFolder);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create trusted/crl directory");
        }
        return retval;
    }
    
    retval |= FileCertStore_setupStorePath(certGroup, "/issuer/certs", rootDirectory,
                                           rootDirectorySize, &context->issuerCertFolder);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create issuer/certs directory");
        }
        return retval;
    }
    
    retval |= FileCertStore_setupStorePath(certGroup, "/issuer/crl", rootDirectory,
                                           rootDirectorySize, &context->issuerCrlFolder);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create issuer/crl directory");
        }
        return retval;
    }
    
    retval |= FileCertStore_setupStorePath(certGroup, "/rejected/certs", rootDirectory,
                                           rootDirectorySize, &context->rejectedCertFolder);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create rejected/certs directory");
        }
        return retval;
    }
    
    retval |= FileCertStore_setupStorePath(certGroup, "/own/certs", rootDirectory,
                                           rootDirectorySize, &context->ownCertFolder);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create own/certs directory");
        }
        return retval;
    }
    
    retval |= FileCertStore_setupStorePath(certGroup, "/own/private", rootDirectory,
                                           rootDirectorySize, &context->ownKeyFolder);
    if(retval != UA_STATUSCODE_GOOD) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE] Failed to create own/private directory");
        }
        return retval;
    }

    return retval;
}

#ifdef __linux__

static UA_StatusCode
FileCertStore_createInotifyEvent(UA_CertificateGroup *certGroup) {
    if(certGroup == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    FileCertStore *context = (FileCertStore *)certGroup->context;

    context->inotifyFd = inotify_init1(IN_NONBLOCK);
    if(context->inotifyFd == -1)
        return UA_STATUSCODE_BADINTERNALERROR;

    char folder[UA_PATH_MAX] = {0};
    mp_snprintf(folder, UA_PATH_MAX, "%.*s",
                (int)context->rootFolder.length, (char*)context->rootFolder.data);
    int wd = inotify_add_watch(context->inotifyFd, folder, IN_ALL_EVENTS);
    if(wd == -1) {
        close(context->inotifyFd);
        context->inotifyFd = -1;
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    mp_snprintf(folder, UA_PATH_MAX, "%.*s",
                (int)context->trustedCertFolder.length, (char*)context->trustedCertFolder.data);
    wd = inotify_add_watch(context->inotifyFd, folder, IN_ALL_EVENTS);
    if(wd == -1) {
        close(context->inotifyFd);
        context->inotifyFd = -1;
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    return UA_STATUSCODE_GOOD;
}

#endif /* __linux__ */

/* Ensure that the rejected certificates directory exists before writing */
static UA_StatusCode
ensureRejectedDirectoryExists(UA_CertificateGroup *certGroup, const UA_String *rejectedCertFolder) {
    if(certGroup == NULL || rejectedCertFolder == NULL || rejectedCertFolder->length == 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    
    const UA_Logger *logger = certGroup->logging;
    char dirPath[UA_PATH_MAX] = {0};
    mp_snprintf(dirPath, UA_PATH_MAX, "%.*s", (int)rejectedCertFolder->length, (char *)rejectedCertFolder->data);
    
    /* Check if directory already exists */
    struct UA_STAT sb;
    if(UA_stat(dirPath, &sb) == 0) {
        /* Directory exists - success */
        return UA_STATUSCODE_GOOD;
    }
    
    /* Directory doesn't exist - create it recursively */
    int mkpathResult = mkpath(dirPath, 0777);
    if(mkpathResult != 0) {
        /* Check for race condition: directory might have been created by another thread/process */
        if(UA_stat(dirPath, &sb) == 0) {
            /* Directory exists now - treat as success (idempotent behavior) */
            return UA_STATUSCODE_GOOD;
        }
        
        /* Real failure - log error */
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE-REJECTED] Failed to create rejected/certs directory: %s (errno=%d, mkpath_result=%d)",
                        dirPath, errno, mkpathResult);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Directory created successfully */
    if(logger) {
        UA_LOG_DEBUG(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[FILESTORE-REJECTED] Created rejected/certs directory: %s", dirPath);
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
FileCertStore_getTrustList(UA_CertificateGroup *certGroup, UA_TrustListDataType *trustList) {
    /* Check parameter */
    if(certGroup == NULL || trustList == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    FileCertStore *context = (FileCertStore *)certGroup->context;
    /* It will only re-read the Cert store on the file system if there have been changes to files. */
    UA_StatusCode retval = reloadTrustStore(certGroup);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    return context->store->getTrustList(context->store, trustList);
}

static UA_StatusCode
FileCertStore_setTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList) {
    /* Check parameter */
    if(certGroup == NULL || trustList == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    FileCertStore *context = (FileCertStore *)certGroup->context;
    /* It will only re-read the Cert store on the file system if there have been changes to files. */
    UA_StatusCode retval = reloadTrustStore(certGroup);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = context->store->setTrustList(context->store, trustList);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    return writeTrustStore(certGroup, trustList->specifiedLists);
}

static UA_StatusCode
FileCertStore_addToTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList) {
    /* Check parameter */
    if(certGroup == NULL || trustList == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    FileCertStore *context = (FileCertStore *)certGroup->context;
    /* It will only re-read the Cert store on the file system if there have been changes to files. */
    UA_StatusCode retval = reloadTrustStore(certGroup);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = context->store->addToTrustList(context->store, trustList);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    return writeTrustStore(certGroup, trustList->specifiedLists);
}

static UA_StatusCode
FileCertStore_removeFromTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList) {
    /* Check parameter */
    if(certGroup == NULL || trustList == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    FileCertStore *context = (FileCertStore *)certGroup->context;
    /* It will only re-read the Cert store on the file system if there have been changes to files. */
    UA_StatusCode retval = reloadTrustStore(certGroup);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = context->store->removeFromTrustList(context->store, trustList);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    return writeTrustStore(certGroup, trustList->specifiedLists);
}

static UA_StatusCode
FileCertStore_getRejectedList(UA_CertificateGroup *certGroup, UA_ByteString **rejectedList, size_t *rejectedListSize) {
    /* Check parameter */
    if(certGroup == NULL || rejectedList == NULL || rejectedListSize == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    FileCertStore *context = (FileCertStore *)certGroup->context;
    return context->store->getRejectedList(context->store, rejectedList, rejectedListSize);
}

static UA_StatusCode
FileCertStore_getCertificateCrls(UA_CertificateGroup *certGroup, const UA_ByteString *certificate,
                                 const UA_Boolean isTrusted, UA_ByteString **crls,
                                 size_t *crlsSize) {
    /* Check parameter */
    if(certGroup == NULL || certificate == NULL || crls == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    FileCertStore *context = (FileCertStore *)certGroup->context;
    /* It will only re-read the Cert store on the file system if there have been changes to files. */
    UA_StatusCode retval = reloadTrustStore(certGroup);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    return context->store->getCertificateCrls(context->store, certificate, isTrusted, crls, crlsSize);
}

static UA_StatusCode
FileCertStore_verifyCertificate(UA_CertificateGroup *certGroup, const UA_ByteString *certificate) {
    /* Check parameter */
    if(certGroup == NULL || certificate == NULL)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    FileCertStore *context = (FileCertStore *)certGroup->context;
    
    /* Log for tracing */
    if(certGroup->logging) {
        UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[FILESTORE-VERIFY] FileCertStore_verifyCertificate called: cert.length=%zu, trustedFolder=%.*s",
                    certificate->length,
                    (int)context->trustedCertFolder.length, context->trustedCertFolder.data);
    }
    
    /* CRITICAL: Reload trust store BEFORE PQC verification to ensure certificates are loaded */
    /* This ensures that issuerCertificates and trustedCertificates are populated from disk */
    UA_StatusCode reloadRetval = reloadAndWriteTrustStore(certGroup);
    if(reloadRetval != UA_STATUSCODE_GOOD && certGroup->logging) {
        UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                      "[FILESTORE-PQC] Failed to reload trust store before PQC verification: %s",
                      UA_StatusCode_name(reloadRetval));
    }
    
    /* PQC signature verification: If certificate is PQC-signed, verify signature first */
    UA_Boolean isPQCSigned = UA_PQC_IsCertificatePQCSigned(certificate, certGroup->logging);
    if(isPQCSigned) {
        if(certGroup->logging) {
            UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[FILESTORE-PQC] Certificate is PQC-signed, verifying signature...");
        }
        
        /* Find issuer CA explicitly before calling PQC verification */
        X509 *issuerCA = NULL;
        X509 *certX509 = UA_OpenSSL_LoadCertificate(certificate);
        if(certX509) {
            X509_NAME *issuerName = X509_get_issuer_name(certX509);
            char issuerNameBuf[256] = {0};
            if(issuerName) {
                X509_NAME_oneline(issuerName, issuerNameBuf, sizeof(issuerNameBuf));
            }
            
            if(certGroup->logging) {
                UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                           "[FILESTORE-PQC-DIAG] Certificate issuer: %s", issuerNameBuf);
            }
            
            if(issuerName && context->store && context->store->context) {
                /* Access MemoryCertStore to get issuerCertificates */
                typedef struct {
                    UA_TrustListDataType trustList;
                    size_t rejectedCertificatesSize;
                    UA_ByteString *rejectedCertificates;
                    UA_UInt32 maxTrustListSize;
                    UA_UInt32 maxRejectedListSize;
                    UA_Boolean reloadRequired;
                    STACK_OF(X509) *trustedCertificates;
                    STACK_OF(X509) *issuerCertificates;
                    STACK_OF(X509_CRL) *crls;
                } MemoryCertStore;
                
                MemoryCertStore *memStore = (MemoryCertStore *)context->store->context;
                
                if(certGroup->logging) {
                    int issuerCount = (memStore && memStore->issuerCertificates) ? 
                                      sk_X509_num(memStore->issuerCertificates) : 0;
                    int trustedCount = (memStore && memStore->trustedCertificates) ? 
                                       sk_X509_num(memStore->trustedCertificates) : 0;
                    UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                               "[FILESTORE-PQC-DIAG] MemoryCertStore state: issuerCertificates=%d, trustedCertificates=%d",
                               issuerCount, trustedCount);
                    
                    /* Log all issuer certificates */
                    if(memStore && memStore->issuerCertificates) {
                        for(int i = 0; i < issuerCount; i++) {
                            X509 *candidate = sk_X509_value(memStore->issuerCertificates, i);
                            if(candidate) {
                                X509_NAME *candidateSubject = X509_get_subject_name(candidate);
                                char candidateSubjectBuf[256] = {0};
                                if(candidateSubject) {
                                    X509_NAME_oneline(candidateSubject, candidateSubjectBuf, sizeof(candidateSubjectBuf));
                                }
                                UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                           "[FILESTORE-PQC-DIAG] issuerCertificates[%d] subject: %s", 
                                           i, candidateSubjectBuf);
                            }
                        }
                    }
                    
                    /* Log all trusted certificates */
                    if(memStore && memStore->trustedCertificates) {
                        for(int i = 0; i < trustedCount; i++) {
                            X509 *candidate = sk_X509_value(memStore->trustedCertificates, i);
                            if(candidate) {
                                X509_NAME *candidateSubject = X509_get_subject_name(candidate);
                                char candidateSubjectBuf[256] = {0};
                                if(candidateSubject) {
                                    X509_NAME_oneline(candidateSubject, candidateSubjectBuf, sizeof(candidateSubjectBuf));
                                }
                                UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                           "[FILESTORE-PQC-DIAG] trustedCertificates[%d] subject: %s", 
                                           i, candidateSubjectBuf);
                            }
                        }
                    }
                }
                
                if(memStore && memStore->issuerCertificates) {
                    /* Search for issuer CA in issuerCertificates stack */
                    int issuerCount = sk_X509_num(memStore->issuerCertificates);
                    for(int i = 0; i < issuerCount; i++) {
                        X509 *candidate = sk_X509_value(memStore->issuerCertificates, i);
                        if(candidate) {
                            X509_NAME *candidateSubject = X509_get_subject_name(candidate);
                            int cmp = X509_NAME_cmp(issuerName, candidateSubject);
                            if(certGroup->logging) {
                                char candidateSubjectBuf[256] = {0};
                                if(candidateSubject) {
                                    X509_NAME_oneline(candidateSubject, candidateSubjectBuf, sizeof(candidateSubjectBuf));
                                }
                                UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                           "[FILESTORE-PQC-DIAG] Comparing issuer '%s' with issuerCertificates[%d] subject '%s': cmp=%d",
                                           issuerNameBuf, i, candidateSubjectBuf, cmp);
                            }
                            if(cmp == 0) {
                                issuerCA = candidate;
                                if(certGroup->logging) {
                                    UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                               "[FILESTORE-PQC-DIAG] ✓ Issuer CA found in issuerCertificates[%d]", i);
                                }
                                break;
                            }
                        }
                    }
                }
                
                /* If not found in issuerCertificates, check trustedCertificates */
                if(!issuerCA && memStore && memStore->trustedCertificates) {
                    int trustedCount = sk_X509_num(memStore->trustedCertificates);
                    for(int i = 0; i < trustedCount; i++) {
                        X509 *candidate = sk_X509_value(memStore->trustedCertificates, i);
                        if(candidate) {
                            X509_NAME *candidateSubject = X509_get_subject_name(candidate);
                            int cmp = X509_NAME_cmp(issuerName, candidateSubject);
                            if(certGroup->logging) {
                                char candidateSubjectBuf[256] = {0};
                                if(candidateSubject) {
                                    X509_NAME_oneline(candidateSubject, candidateSubjectBuf, sizeof(candidateSubjectBuf));
                                }
                                UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                           "[FILESTORE-PQC-DIAG] Comparing issuer '%s' with trustedCertificates[%d] subject '%s': cmp=%d",
                                           issuerNameBuf, i, candidateSubjectBuf, cmp);
                            }
                            if(cmp == 0) {
                                issuerCA = candidate;
                                if(certGroup->logging) {
                                    UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                               "[FILESTORE-PQC-DIAG] ✓ Issuer CA found in trustedCertificates[%d]", i);
                                }
                                break;
                            }
                        }
                    }
                }
            } else {
                if(certGroup->logging) {
                    UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                  "[FILESTORE-PQC-DIAG] MemoryCertStore not accessible: context->store=%p, context->store->context=%p",
                                  (void*)context->store, 
                                  (void*)(context->store ? context->store->context : NULL));
                }
            }
            
            /* If no issuer found, check if certificate is self-signed */
            if(!issuerCA) {
                X509_NAME *subject = X509_get_subject_name(certX509);
                X509_NAME *issuer = X509_get_issuer_name(certX509);
                char subjectBuf[256] = {0};
                if(subject) {
                    X509_NAME_oneline(subject, subjectBuf, sizeof(subjectBuf));
                }
                if(subject && issuer) {
                    int selfSignedCmp = X509_NAME_cmp(subject, issuer);
                    if(certGroup->logging) {
                        UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                   "[FILESTORE-PQC-DIAG] Certificate subject: %s, issuer: %s, self-signed cmp=%d",
                                   subjectBuf, issuerNameBuf, selfSignedCmp);
                    }
                    if(selfSignedCmp == 0) {
                        /* Self-signed: issuerCA remains NULL, will be handled by PQC verification */
                        if(certGroup->logging) {
                            UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                       "[FILESTORE-PQC] Certificate is self-signed (subject == issuer)");
                        }
                    } else {
                        if(certGroup->logging) {
                            UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                          "[FILESTORE-PQC] Issuer CA not found in issuerCertificates or trustedCertificates. "
                                          "Issuer: %s, Subject: %s", issuerNameBuf, subjectBuf);
                        }
                    }
                }
            }
        }
        
        /* Verify PQC signature with issuer (or NULL for self-signed) */
        UA_StatusCode pqcVerifyResult = UA_PQC_VerifyCertificateSignature(certificate, issuerCA, certGroup->logging);
        
        /* Clean up parsed certificate */
        if(certX509) {
            X509_free(certX509);
        }
        
        if(pqcVerifyResult != UA_STATUSCODE_GOOD) {
            if(certGroup->logging) {
                UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                              "[FILESTORE-PQC] PQC signature verification FAILED: %s",
                              UA_StatusCode_name(pqcVerifyResult));
            }
            
            /* Abort verification - PQC signature is invalid */
            /* Note: Certificate will be added to rejectedList by MemoryCertStore_verifyCertificate below */
            /* and written to disk in the unified rejectedList write at the end */
            return UA_STATUSCODE_BADCERTIFICATEINVALID;
        } else {
            if(certGroup->logging) {
                UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                           "[FILESTORE-PQC] PQC signature verification SUCCEEDED");
            }
        }
    }
    
    /* It will only re-read the Cert store on the file system if there have been changes to files. */
    /* Note: For PQC certificates, we already called reloadAndWriteTrustStore above */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(!isPQCSigned) {
        retval = reloadTrustStore(certGroup);
        if(retval != UA_STATUSCODE_GOOD) {
            return retval;
        }
    }

    /* First, check if certificate is already in trusted directory */
    UA_Boolean isInTrusted = UA_FALSE;
    UA_ByteString *trustedCerts = NULL;
    size_t trustedCertsSize = 0;
    retval = readCertificates(&trustedCerts, &trustedCertsSize, context->trustedCertFolder);
    if(retval == UA_STATUSCODE_GOOD) {
        for(size_t i = 0; i < trustedCertsSize; i++) {
            if(UA_ByteString_equal(certificate, &trustedCerts[i])) {
                isInTrusted = UA_TRUE;
                break;
            }
        }
        /* Clean up trusted certificates array */
        if(trustedCerts) {
            for(size_t i = 0; i < trustedCertsSize; i++) {
                UA_ByteString_clear(&trustedCerts[i]);
            }
            UA_Array_delete(trustedCerts, trustedCertsSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        }
    }

    /* If certificate is not in trusted, save it to rejected directory */
    /* This allows the administrator to manually move it to trusted/ if needed */
    if(!isInTrusted) {
        /* Ensure rejected directory exists before writing */
        UA_StatusCode dirResult = ensureRejectedDirectoryExists(certGroup, &context->rejectedCertFolder);
        if(dirResult == UA_STATUSCODE_GOOD) {
            char filename[UA_PATH_MAX] = {0};
            UA_StatusCode filenameResult = getCertFileName((char*)context->rejectedCertFolder.data, certificate, filename, UA_PATH_MAX);
            if(filenameResult == UA_STATUSCODE_GOOD) {
                /* Check if certificate already exists in rejected */
                struct UA_STAT sb;
                if(UA_stat(filename, &sb) != 0) {
                    /* Save certificate to rejected directory */
                    UA_StatusCode writeResult = writeByteStringToFile(filename, certificate);
                    if(writeResult == UA_STATUSCODE_GOOD) {
                        if(certGroup->logging) {
                            UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                       "[FILESTORE-REJECTED] Certificate written to rejected/: %s "
                                       "(Administrator must manually move to trusted directory to trust it)",
                                       filename);
                        }
                    } else {
                        /* Log error but don't change verification result */
                        if(certGroup->logging) {
                            UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                          "[FILESTORE-REJECTED] Failed to write rejected certificate to %s: %s",
                                          filename, UA_StatusCode_name(writeResult));
                        }
                    }
                }
            }
        } else {
            /* Log error but don't change verification result */
            if(certGroup->logging) {
                UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                              "[FILESTORE-REJECTED] Failed to ensure rejected/certs directory exists: %s",
                              UA_StatusCode_name(dirResult));
            }
        }
    }

    /* Verify certificate using the trust store (only trusts certificates in trusted directory) */
    /* Note: MemoryCertStore_verifyCertificate will add failed certificates to rejectedList internally */
    retval = context->store->verifyCertificate(context->store, certificate);
    
    /* Write rejectedList to filestore if verification failed (certificate was added to rejectedList by MemoryCertStore) */
    /* Note: writeCertificates now checks if files already exist before writing, preventing duplication */
    if(retval != UA_STATUSCODE_GOOD) {
        /* Ensure rejected directory exists before writing rejectedList */
        UA_StatusCode dirResult = ensureRejectedDirectoryExists(certGroup, &context->rejectedCertFolder);
        if(dirResult == UA_STATUSCODE_GOOD) {
            /* write rejectedList to filestore */
            UA_ByteString *rejectedList = NULL;
            size_t rejectedListSize = 0;
            context->store->getRejectedList(context->store, &rejectedList, &rejectedListSize);
            
            if(rejectedListSize > 0) {
                /* Use writeCertificates directly (not writeTrustList) to avoid removing existing files */
                /* writeCertificates will skip files that already exist */
                char listPath[UA_PATH_MAX] = {0};
                mp_snprintf(listPath, UA_PATH_MAX, "%.*s", 
                           (int)context->rejectedCertFolder.length, (char *)context->rejectedCertFolder.data);
                UA_StatusCode writeResult = writeCertificates(certGroup, rejectedList, rejectedListSize, listPath);
                if(writeResult != UA_STATUSCODE_GOOD) {
                    /* Log error but don't change verification result */
                    if(certGroup->logging) {
                        UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                                      "[FILESTORE-REJECTED] Failed to write rejected list to filestore: %s",
                                      UA_StatusCode_name(writeResult));
                    }
                } else if(certGroup->logging) {
                    UA_LOG_INFO(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                               "[FILESTORE-REJECTED] Wrote rejected certificate(s) to rejected/ directory "
                               "(existing files were skipped to avoid duplication)");
                }
            }
            UA_Array_delete(rejectedList, rejectedListSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        } else {
            /* Log error but don't change verification result */
            if(certGroup->logging) {
                UA_LOG_WARNING(certGroup->logging, UA_LOGCATEGORY_SECURITYPOLICY,
                              "[FILESTORE-REJECTED] Failed to ensure rejected/certs directory exists before writing rejected list: %s",
                              UA_StatusCode_name(dirResult));
            }
        }
    }

    return retval;
}

static void
FileCertStore_clear(UA_CertificateGroup *certGroup) {
    /* check parameter */
    if(!certGroup || !certGroup->context)
        return;

    UA_NodeId_clear(&certGroup->certificateGroupId);

    FileCertStore *context = (FileCertStore *)certGroup->context;

    if(context->store) {
        context->store->clear(context->store);
        UA_free(context->store);
    }
    UA_String_clear(&context->trustedCertFolder);
    UA_String_clear(&context->trustedCrlFolder);
    UA_String_clear(&context->issuerCertFolder);
    UA_String_clear(&context->issuerCrlFolder);
    UA_String_clear(&context->rejectedCertFolder);
    UA_String_clear(&context->ownCertFolder);
    UA_String_clear(&context->ownKeyFolder);
    UA_String_clear(&context->rootFolder);

#ifdef __linux__
    if(context->inotifyFd > 0)
        close(context->inotifyFd);
#endif /* __linux__ */

    UA_free(context);
    certGroup->context = NULL;
}

UA_StatusCode
UA_CertificateGroup_Filestore(UA_CertificateGroup *certGroup,
                              UA_NodeId *certificateGroupId,
                              const UA_String storePath,
                              const UA_Logger *logger,
                              const UA_KeyValueMap *params) {
    if(certGroup == NULL || certificateGroupId == NULL) {
        if(logger) {
            UA_LOG_ERROR(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                        "[DIAG-UA_CertificateGroup_Filestore] BADINTERNALERROR: NULL parameter - "
                        "certGroup=%p, certificateGroupId=%p, storePath.length=%zu, storePath.data=%p",
                        (void*)certGroup, (void*)certificateGroupId,
                        storePath.length, (void*)storePath.data);
        }
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Clear if the plugin is already initialized */
    if(certGroup->clear)
        certGroup->clear(certGroup);

    UA_NodeId_copy(certificateGroupId, &certGroup->certificateGroupId);
    certGroup->logging = logger;

    certGroup->getTrustList = FileCertStore_getTrustList;
    certGroup->setTrustList = FileCertStore_setTrustList;
    certGroup->addToTrustList = FileCertStore_addToTrustList;
    certGroup->removeFromTrustList = FileCertStore_removeFromTrustList;
    certGroup->getRejectedList = FileCertStore_getRejectedList;
    certGroup->getCertificateCrls = FileCertStore_getCertificateCrls;
    certGroup->verifyCertificate = FileCertStore_verifyCertificate;
    certGroup->clear = FileCertStore_clear;

    /* Log initialization for tracing */
    if(logger) {
        UA_LOG_INFO(logger, UA_LOGCATEGORY_SECURITYPOLICY,
                    "[FILESTORE-INIT] CertificateGroup_Filestore initialized: verifyCertificate=%p, storePath=%.*s",
                    (void*)certGroup->verifyCertificate,
                    (int)storePath.length, storePath.data);
    }

    /* Set PKI Store context data */
    FileCertStore *context = (FileCertStore *)UA_calloc(1, sizeof(FileCertStore));
    if(!context) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto cleanup;
    }
    certGroup->context = context;

    retval = FileCertStore_createPkiDirectory(certGroup, storePath);
    if(retval != UA_STATUSCODE_GOOD) {
        goto cleanup;
    }

    context->store = (UA_CertificateGroup*)UA_calloc(1, sizeof(UA_CertificateGroup));
    retval = UA_CertificateGroup_Memorystore(context->store, certificateGroupId, NULL, logger, params);
    if(retval != UA_STATUSCODE_GOOD) {
        goto cleanup;
    }

#ifdef __linux__
    retval = FileCertStore_createInotifyEvent(certGroup);
    if(retval != UA_STATUSCODE_GOOD) {
        goto cleanup;
    }
#endif /* __linux__ */

    retval = reloadAndWriteTrustStore(certGroup);
    if(retval != UA_STATUSCODE_GOOD) {
        goto cleanup;
    }

    return UA_STATUSCODE_GOOD;

    cleanup:
        certGroup->clear(certGroup);
    return retval;
}

#endif /* defined(__linux__) || defined(UA_ARCHITECTURE_WIN32) */

#endif /* UA_ENABLE_ENCRYPTION */
