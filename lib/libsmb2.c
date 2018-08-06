/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

   Portions of this code are copyright 2017 to Primary Data Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef STDC_HEADERS
#include <stddef.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>

#ifdef _WIN32
#include "asprintf.h"
#endif

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"
#include "portable-endian.h"

#ifdef HAVE_OPENSSL_LIBS

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/opensslv.h>

#define OPENSSL_VER_101	0x1000109fL
#define OPENSSL_VER_102	0x10002100L

#endif

#include "ntlmssp.h"
#include "krb5-wrapper.h"

/* strings used to derive SMB signing and encryption keys */
static const char SMB2AESCMAC[] = "SMB2AESCMAC";
static const char SmbSign[] = "SmbSign";
/* The following strings will be used for deriving other keys
static const char SMB2APP[] = "SMB2APP";
static const char SmbRpc[] = "SmbRpc";
static const char SMB2AESCCM[] = "SMB2AESCCM";
static const char ServerOut[] = "ServerOut";
static const char ServerIn[] = "ServerIn ";
static const char SMBSigningKey[] = "SMBSigningKey";
static const char SMBAppKey[] = "SMBAppKey";
static const char SMBS2CCipherKey[] = "SMBS2CCipherKey";
static const char SMBC2SCipherKey[] = "SMBC2SCipherKey";
*/

#ifdef HAVE_OPENSSL_LIBS
void smb2_derive_key(
    uint8_t     *derivation_key,
    uint32_t    derivation_key_len,
    const char  *label,
    uint32_t    label_len,
    const char  *context,
    uint32_t    context_len,
    uint8_t     derived_key[SMB2_KEY_SIZE]
    )
{
        const uint32_t counter = htobe32(1);
        const uint32_t keylen = htobe32(SMB2_KEY_SIZE * 8);
        static uint8_t nul = 0;
        uint8_t final_hash[256/8] = {0};
        uint8_t input_key[SMB2_KEY_SIZE] = {0};
        unsigned int finalHashSize = sizeof(final_hash);

#if (OPENSSL_VERSION_NUMBER <= OPENSSL_VER_102)
        HMAC_CTX hmac = {0};

        memcpy(input_key, derivation_key, MIN(sizeof(input_key), derivation_key_len));
        HMAC_CTX_init(&hmac);
        HMAC_Init_ex(&hmac, input_key, sizeof(input_key), EVP_sha256(), NULL);

        /* i */
        HMAC_Update(&hmac, (unsigned char*) &counter, sizeof(counter));
        /* label */
        HMAC_Update(&hmac, (unsigned char*) label, label_len);
        /* 0x00 */
        HMAC_Update(&hmac, &nul, sizeof(nul));
        /* context */
        HMAC_Update(&hmac, (unsigned char*) context, context_len);
        /* L */
        HMAC_Update(&hmac, (unsigned char*) &keylen, sizeof(keylen));

        HMAC_Final(&hmac, final_hash, &finalHashSize);
        HMAC_CTX_cleanup(&hmac);
#else
        HMAC_CTX *hmac = HMAC_CTX_new();

        HMAC_CTX_reset(hmac);
        memcpy(input_key, derivation_key, MIN(sizeof(input_key), derivation_key_len));
        HMAC_Init_ex(hmac, input_key, sizeof(input_key), EVP_sha256(), NULL);

        /* i */
        HMAC_Update(hmac, (unsigned char*) &counter, sizeof(counter));
        /* label */
        HMAC_Update(hmac, (unsigned char*) label, label_len);
        /* 0x00 */
        HMAC_Update(hmac, &nul, sizeof(nul));
        /* context */
        HMAC_Update(hmac, (unsigned char*) context, context_len);
        /* L */
        HMAC_Update(hmac, (unsigned char*) &keylen, sizeof(keylen));

        HMAC_Final(hmac, final_hash, &finalHashSize);
        HMAC_CTX_free(hmac); hmac= NULL;
#endif
        memcpy(derived_key, final_hash, MIN(finalHashSize, SMB2_KEY_SIZE));
}
#endif

#ifndef O_SYNC
#ifndef O_DSYNC
#define O_DSYNC		040000
#endif // !O_DSYNC
#define __O_SYNC	020000000
#define O_SYNC		(__O_SYNC|O_DSYNC)
#endif // !O_SYNC

const smb2_file_id compound_file_id = {
        0xffffffffffffffff,
        0xffffffffffffffff
};

typedef struct _query_set_info_data {
        void *info;
} query_set_data;

typedef struct _ioctl_data {
        uint8_t  *output_buffer;
        uint32_t *output_count;
} ioctl_data;

typedef struct _rw_data {
        struct smb2fh *fh;
} rw_data;

typedef struct _create_cb_data {
        uint8_t needToClose:1;
        struct smb2fh *fh;
} create_cb_data;

typedef struct _async_cb_data {
        smb2_command_cb cb;
        void            *cb_data;
        uint16_t        cmd;
        uint32_t        status;
        union {
                query_set_data qs_info;
                ioctl_data     ioctl;
                rw_data        rwData;
                create_cb_data cr_data;
        } acb_data_U;
} async_cb_data;

struct smb2_dirent_internal {
        struct smb2_dirent_internal *next;
        struct smb2dirent dirent;
};

struct smb2dir {
        smb2_command_cb cb;
        void *cb_data;
        smb2_file_id file_id;

        struct smb2_dirent_internal *entries;
        struct smb2_dirent_internal *current_entry;
        int index;
};

static void
smb2_close_context(struct smb2_context *smb2)
{
        if (smb2->fd != -1) {
                close(smb2->fd);
                smb2->fd = -1;
        }
        smb2->is_connected = 0;
        smb2->message_id = 0;
        smb2->session_id = 0;
        smb2->tree_id = 0;
        memset(smb2->signing_key, 0, SMB2_KEY_SIZE);
        if (smb2->session_key) {
                free(smb2->session_key);
                smb2->session_key = NULL;
        }
        smb2->session_key_size = 0;
}

static int
send_session_setup_request(struct smb2_context *smb2,
                           async_cb_data *data,
                           unsigned char *buf, int len);

static void
free_smb2dir(struct smb2dir *dir)
{

        while (dir->entries) {
                struct smb2_dirent_internal *e = dir->entries->next;

                free(discard_const(dir->entries->dirent.name));
                free(dir->entries);
                dir->entries = e;
        }
        free(dir);
}

void
smb2_seekdir(struct smb2_context *smb2, struct smb2dir *dir,
                  long loc)
{
        dir->current_entry = dir->entries;
        dir->index = 0;

        while (dir->current_entry && loc--) {
                dir->current_entry = dir->current_entry->next;
                dir->index++;
        }
}

long
smb2_telldir(struct smb2_context *smb2, struct smb2dir *dir)
{
        return dir->index;
}

void
smb2_rewinddir(struct smb2_context *smb2,
                    struct smb2dir *dir)
{
        dir->current_entry = dir->entries;
        dir->index = 0;
}

struct smb2dirent *
smb2_readdir(struct smb2_context *smb2,
             struct smb2dir *dir)
{
        struct smb2dirent *ent;

        if (dir->current_entry == NULL) {
                return NULL;
        }

        ent = &dir->current_entry->dirent;
        dir->current_entry = dir->current_entry->next;
        dir->index++;

        return ent;
}

void
smb2_closedir(struct smb2_context *smb2, struct smb2dir *dir)
{
        free_smb2dir(dir);
}

static int
decode_dirents(struct smb2_context *smb2, struct smb2dir *dir,
               struct smb2_iovec *vec)
{
        struct smb2_dirent_internal *ent;
        struct smb2_fileidfulldirectoryinformation fs;
        uint32_t offset = 0;

        do {
                struct smb2_iovec tmp_vec;

                /* Make sure we do not go beyond end of vector */
                if (offset >= vec->len) {
                        smb2_set_error(smb2, "Malformed query reply.");
                        return -1;
                }
                
                ent = malloc(sizeof(struct smb2_dirent_internal));
                if (ent == NULL) {
                        smb2_set_error(smb2, "Failed to allocate "
                                       "dirent_internal");
                        return -1;
                }
                memset(ent, 0, sizeof(struct smb2_dirent_internal));
                SMB2_LIST_ADD(&dir->entries, ent);


                tmp_vec.buf = &vec->buf[offset];
                tmp_vec.len = vec->len - offset;

                smb2_decode_fileidfulldirectoryinformation(smb2, &fs,
                                                           &tmp_vec);
                /* steal the name */
                ent->dirent.name = fs.name;
                ent->dirent.st.smb2_type = SMB2_TYPE_FILE;
                if (fs.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
                        ent->dirent.st.smb2_type = SMB2_TYPE_DIRECTORY;
                }
                ent->dirent.st.smb2_nlink = 0;
                ent->dirent.st.smb2_ino = fs.file_id;
                ent->dirent.st.smb2_size = fs.end_of_file;
                ent->dirent.st.smb2_atime = fs.last_access_time.tv_sec;
                ent->dirent.st.smb2_atime_nsec = fs.last_access_time.tv_usec * 1000;
                ent->dirent.st.smb2_mtime = fs.last_write_time.tv_sec;
                ent->dirent.st.smb2_mtime_nsec = fs.last_write_time.tv_usec * 1000;
                ent->dirent.st.smb2_ctime = fs.change_time.tv_sec;
                ent->dirent.st.smb2_ctime_nsec = fs.change_time.tv_usec * 1000;
                ent->dirent.st.smb2_crtime = fs.creation_time.tv_sec;
                ent->dirent.st.smb2_crtime_nsec = fs.creation_time.tv_usec * 1000;
                ent->dirent.allocation_size = fs.allocation_size;
                ent->dirent.attributes = fs.file_attributes;
                ent->dirent.ea_size = fs.ea_size;


                offset += fs.next_entry_offset;
        } while (fs.next_entry_offset);
        
        return 0;
}

static void
od_close_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct smb2dir *dir = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                free_smb2dir(dir);
                return;
        }

        dir->current_entry = dir->entries;
        dir->index = 0;

        /* dir will be freed in smb2_closedir() */
        dir->cb(smb2, 0, dir, dir->cb_data);
}

static void
query_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct smb2dir *dir = private_data;
        struct smb2_query_directory_reply *rep = command_data;

        if (status == SMB2_STATUS_SUCCESS) {
                struct smb2_iovec vec;
                struct smb2_query_directory_request req;
                struct smb2_pdu *pdu;

                vec.buf = rep->output_buffer;
                vec.len = rep->output_buffer_length;

                if (decode_dirents(smb2, dir, &vec) < 0) {
                        dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                        free_smb2dir(dir);
                        return;
                }

                /* We need to get more data */
                memset(&req, 0, sizeof(struct smb2_query_directory_request));
                req.file_information_class = SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION;
                req.flags = 0;
                req.file_id.persistent_id = dir->file_id.persistent_id;
                req.file_id.volatile_id= dir->file_id.volatile_id;
                req.output_buffer_length = 0xffff;
                req.name = "*";

                pdu = smb2_cmd_query_directory_async(smb2, &req, query_cb, dir);
                if (pdu == NULL) {
                        dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                        free_smb2dir(dir);
                        return;
                }
                smb2_queue_pdu(smb2, pdu);

                return;
        }

        if (status == SMB2_STATUS_NO_MORE_FILES) {
                struct smb2_close_request req;
                struct smb2_pdu *pdu;

                /* We have all the data */
                memset(&req, 0, sizeof(struct smb2_close_request));
                req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
                req.file_id.persistent_id = dir->file_id.persistent_id;
                req.file_id.volatile_id = dir->file_id.volatile_id;

                pdu = smb2_cmd_close_async(smb2, &req, od_close_cb, dir);
                if (pdu == NULL) {
                        dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                        free_smb2dir(dir);
                        return;
                }
                smb2_queue_pdu(smb2, pdu);

                return;
        }

        smb2_set_error(smb2, "Query directory failed with (0x%08x) %s. %s",
                       status, nterror_to_str(status),
                       smb2_get_error(smb2));
        dir->cb(smb2, -nterror_to_errno(status), NULL, dir->cb_data);
        free_smb2dir(dir);
}

static void
opendir_cb(struct smb2_context *smb2, int status,
           void *command_data, void *private_data)
{
        struct smb2dir *dir = private_data;
        struct smb2_create_reply *rep = command_data;
        struct smb2_query_directory_request req;
        struct smb2_pdu *pdu;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Opendir failed with (0x%08x) %s.",
                               status, nterror_to_str(status));
                dir->cb(smb2, -nterror_to_errno(status), NULL, dir->cb_data);
                free_smb2dir(dir);
                return;
        }

        dir->file_id.persistent_id = rep->file_id.persistent_id;
        dir->file_id.volatile_id = rep->file_id.volatile_id;

        memset(&req, 0, sizeof(struct smb2_query_directory_request));
        req.file_information_class = SMB2_FILE_ID_FULL_DIRECTORY_INFORMATION;
        req.flags = 0;
        req.file_id.persistent_id = dir->file_id.persistent_id;
        req.file_id.volatile_id = dir->file_id.volatile_id;
        req.output_buffer_length = 0xffff;
        req.name = "*";

        pdu = smb2_cmd_query_directory_async(smb2, &req, query_cb, dir);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create query command.");
                dir->cb(smb2, -ENOMEM, NULL, dir->cb_data);
                free_smb2dir(dir);
                return;
        }
        smb2_queue_pdu(smb2, pdu);
}

int
smb2_opendir_async(struct smb2_context *smb2, const char *path,
                   smb2_command_cb cb, void *cb_data)
{
        struct smb2_create_request req;
        struct smb2dir *dir;
        struct smb2_pdu *pdu;

        if (path == NULL) {
                path = "";
        }

        dir = malloc(sizeof(struct smb2dir));
        if (dir == NULL) {
                smb2_set_error(smb2, "Failed to allocate smb2dir.");
                return -1;
        }
        memset(dir, 0, sizeof(struct smb2dir));
        dir->cb = cb;
        dir->cb_data = cb_data;

        memset(&req, 0, sizeof(struct smb2_create_request));
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        req.desired_access = SMB2_FILE_LIST_DIRECTORY | SMB2_FILE_READ_ATTRIBUTES;
        req.file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
        req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        req.create_disposition = SMB2_FILE_OPEN;
        req.create_options = SMB2_FILE_DIRECTORY_FILE;
        req.name = path;

        pdu = smb2_cmd_create_async(smb2, &req, opendir_cb, dir);
        if (pdu == NULL) {
                free_smb2dir(dir);
                smb2_set_error(smb2, "Failed to create opendir command.");
                return -1;
        }
        smb2_queue_pdu(smb2, pdu);
        
        return 0;
}

static void
smb2_free_auth_data(struct smb2_context *smb2)
{
        if (smb2->auth_data) {
                if (smb2->sec == SMB2_SEC_KRB5) {
                        krb5_free_auth_data(smb2->auth_data);
                } else {
                        ntlmssp_destroy_context(smb2->auth_data);
                }
        }
}


static void
tree_connect_cb(struct smb2_context *smb2, int status,
                void *command_data, void *private_data)
{
        async_cb_data *tcon_data = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_close_context(smb2);
                smb2_set_error(smb2, "Session setup failed with (0x%08x) %s. %s",
                               status, nterror_to_str(status),
                               smb2_get_error(smb2));
                tcon_data->cb(smb2, -nterror_to_errno(status), NULL, tcon_data->cb_data);
                smb2_free_auth_data(smb2);
                free(tcon_data);
                return;
        }

        tcon_data->cb(smb2, 0, NULL, tcon_data->cb_data);
        smb2_free_auth_data(smb2);
        free(tcon_data);
}

static void
session_setup_cb(struct smb2_context *smb2, int status,
                 void *command_data, void *private_data)
{
        async_cb_data *session_data = private_data;
        struct smb2_session_setup_reply *rep = command_data;
        struct smb2_tree_connect_request req;
        struct smb2_pdu *pdu;
        int ret;

        if (status == SMB2_STATUS_MORE_PROCESSING_REQUIRED) {
                if ((ret = send_session_setup_request(
                                smb2, session_data, rep->security_buffer,
                                rep->security_buffer_length)) < 0) {
                        smb2_close_context(smb2);
                        session_data->cb(smb2, ret, NULL, session_data->cb_data);
                        smb2_free_auth_data(smb2);
                        return;
                }
                return;
        } else if (smb2->sec == SMB2_SEC_KRB5) {
                /* For NTLM the status will be
                 * SMB2_STATUS_MORE_PROCESSING_REQUIRED and a second call to
                 * gss_init_sec_context will complete the gss session.
                 * But for krb5 a second call to gss_init_sec_context is
                 * required if GSS_C_MUTUAL_FLAG is set
                 */
                if (krb5_session_request(smb2, smb2->auth_data,
                                         rep->security_buffer,
                                         rep->security_buffer_length) < 0) {
                        session_data->cb(smb2, -1, NULL, session_data->cb_data);
                        smb2_free_auth_data(smb2);
                        return;
                }
        }

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_close_context(smb2);
                smb2_set_error(smb2, "Session setup failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                session_data->cb(smb2, -nterror_to_errno(status), NULL,
                                 session_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
        }

        if (smb2->signing_required) {
                uint8_t zero_key[SMB2_KEY_SIZE] = {0};
                int have_valid_session_key = 1;

                if (smb2->sec == SMB2_SEC_KRB5) {
                        if (krb5_session_get_session_key(smb2, smb2->auth_data) < 0) {
                                have_valid_session_key = 0;
                        }
                } else if (smb2->sec == SMB2_SEC_NTLMSSP) {
                        if (ntlmssp_get_session_key(smb2->auth_data,
                                            &smb2->session_key,
                                            &smb2->session_key_size) < 0) {
                                have_valid_session_key = 0;
                        }
                }
                /* check if the session key is proper */
                if (smb2->session_key == NULL || memcmp(smb2->session_key, zero_key, SMB2_KEY_SIZE) == 0) {
                        have_valid_session_key = 0;
                }
                if (have_valid_session_key == 0)
                {
                        smb2_close_context(smb2);
                        smb2_set_error(smb2, "Signing required by server. Session "
                                       "Key is not available %s",
                                       smb2_get_error(smb2));
                        session_data->cb(smb2, -1, NULL, session_data->cb_data);
                        smb2_free_auth_data(smb2);
                        return;
                }

                /* Derive the signing key from session key
                 * This is based on negotiated protocol
                 */
                if (smb2->dialect == SMB2_VERSION_0202 ||
                    smb2->dialect == SMB2_VERSION_0210) {
                        /* For SMB2 session key is the signing key */
                        memcpy(smb2->signing_key,
                               smb2->session_key,
                               MIN(smb2->session_key_size, SMB2_KEY_SIZE));
                } else if (smb2->dialect <= SMB2_VERSION_0302) {
#ifdef HAVE_OPENSSL_LIBS
                        smb2_derive_key(smb2->session_key,
                                        smb2->session_key_size,
                                        SMB2AESCMAC,
                                        sizeof(SMB2AESCMAC),
                                        SmbSign,
                                        sizeof(SmbSign),
                                        smb2->signing_key);
#else
                        smb2_close_context(smb2);
                        smb2_set_error(smb2, "Signing Requires OpenSSL support");
                        session_data->cb(smb2, -EINVAL, NULL, session_data->cb_data);
                        smb2_free_auth_data(smb2);
                        return;
#endif
                } else if (smb2->dialect > SMB2_VERSION_0302) {
                        smb2_close_context(smb2);
                        smb2_set_error(smb2, "Signing Required by server. "
                                             "Not yet implemented for SMB3.1");
                        session_data->cb(smb2, -EINVAL, NULL, session_data->cb_data);
                        smb2_free_auth_data(smb2);
                        return;
                }
        }

        memset(&req, 0, sizeof(struct smb2_tree_connect_request));
        req.flags       = 0;
        req.path_length = 2 * smb2->ucs2_unc->len;
        req.path        = smb2->ucs2_unc->val;

        pdu = smb2_cmd_tree_connect_async(smb2, &req, tree_connect_cb, session_data);
        if (pdu == NULL) {
                smb2_close_context(smb2);
                session_data->cb(smb2, -ENOMEM, NULL, session_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
        }
        smb2_queue_pdu(smb2, pdu);
}

/* Returns 0 for success and -errno for failure */
static int
send_session_setup_request(struct smb2_context *smb2,
                           async_cb_data *session_data,
                           unsigned char *buf, int len)
{
        struct smb2_pdu *pdu;
        struct smb2_session_setup_request req;

        /* Session setup request. */
        memset(&req, 0, sizeof(struct smb2_session_setup_request));
        req.security_mode = smb2->security_mode;

        if (smb2->sec == SMB2_SEC_KRB5) {
                if (krb5_session_request(smb2, smb2->auth_data, buf, len) < 0) {
                        smb2_close_context(smb2);
                        return -1;
                }
                req.security_buffer_length = krb5_get_output_token_length(smb2->auth_data);
                req.security_buffer = krb5_get_output_token_buffer(smb2->auth_data);
        } else {
                if (ntlmssp_generate_blob(smb2, smb2->auth_data, buf, len,
                                          &req.security_buffer,
                                          &req.security_buffer_length) < 0) {
                        smb2_close_context(smb2);
                        return -1;
                }
        }

        pdu = smb2_cmd_session_setup_async(smb2, &req,
                                           session_setup_cb,
                                           session_data);
        if (pdu == NULL) {
                smb2_close_context(smb2);
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
negotiate_cb(struct smb2_context *smb2, int status,
             void *command_data, void *private_data)
{
        async_cb_data *negotiate_data = private_data;
        struct smb2_negotiate_reply *rep = command_data;
        int ret;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_close_context(smb2);
                smb2_set_error(smb2, "Negotiate failed with (0x%08x) %s. %s",
                               status, nterror_to_str(status),
                               smb2_get_error(smb2));
                negotiate_data->cb(smb2, -nterror_to_errno(status), NULL,
                                   negotiate_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
        }

        /* update the context with the server capabilities */
        if (rep->dialect_revision > SMB2_VERSION_0202) {
                if (rep->capabilities & SMB2_GLOBAL_CAP_LARGE_MTU) {
                        smb2->supports_multi_credit = 1;
                }
        }

        smb2->max_transact_size = rep->max_transact_size;
        smb2->max_read_size     = rep->max_read_size;
        smb2->max_write_size    = rep->max_write_size;
        smb2->dialect           = rep->dialect_revision;

        if (rep->security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
#if !defined(HAVE_OPENSSL_LIBS)
                smb2_set_error(smb2, "Signing Required by server. Not yet implemented");
                negotiate_data->cb(smb2, -EINVAL, NULL, negotiate_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
#endif
                smb2->signing_required = 1;
        }

        if (smb2->sec == SMB2_SEC_KRB5) {
                smb2->auth_data = krb5_negotiate_reply(smb2,
                                                         smb2->server,
                                                         smb2->domain,
                                                         smb2->user,
                                                         smb2->password);
        } else {
                smb2->auth_data = ntlmssp_init_context(smb2->user,
                                                         smb2->password,
                                                         smb2->domain,
                                                         smb2->workstation,
                                                         smb2->client_challenge);
        }
        if (smb2->auth_data == NULL) {
                smb2_close_context(smb2);
                negotiate_data->cb(smb2, -ENOMEM, NULL, negotiate_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
        }

        if ((ret = send_session_setup_request(smb2, negotiate_data, NULL, 0)) < 0) {
                smb2_close_context(smb2);
                negotiate_data->cb(smb2, ret, NULL, negotiate_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
        }
}

static void
connect_cb(struct smb2_context *smb2, int status,
           void *command_data _U_, void *private_data)
{
        async_cb_data *conn_data = private_data;
        struct smb2_negotiate_request req;
        struct smb2_pdu *pdu;

        if (status != 0) {
                smb2_set_error(smb2, "Socket connect failed with %d", status);
                conn_data->cb(smb2, -status, NULL, conn_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
        }

        memset(&req, 0, sizeof(struct smb2_negotiate_request));
        req.capabilities = SMB2_GLOBAL_CAP_LARGE_MTU;
        req.security_mode = smb2->security_mode;

        /* use these by default */
        if (smb2->sec == SMB2_SEC_KRB5) {
                smb2->use_cached_creds = 1;
        }
        smb2->version = SMB2_VERSION_ANY;

        switch (smb2->version) {
        case SMB2_VERSION_ANY:
                req.dialect_count = 4;
                req.dialects[0] = SMB2_VERSION_0202;
                req.dialects[1] = SMB2_VERSION_0210;
                req.dialects[2] = SMB2_VERSION_0300;
                req.dialects[3] = SMB2_VERSION_0302;
                break;
        case SMB2_VERSION_ANY2:
                req.dialect_count = 2;
                req.dialects[0] = SMB2_VERSION_0202;
                req.dialects[1] = SMB2_VERSION_0210;
                break;
        case SMB2_VERSION_ANY3:
                req.dialect_count = 2;
                req.dialects[0] = SMB2_VERSION_0300;
                req.dialects[1] = SMB2_VERSION_0302;
                break;
        case SMB2_VERSION_0202:
        case SMB2_VERSION_0210:
        case SMB2_VERSION_0300:
        case SMB2_VERSION_0302:
                req.dialect_count = 1;
                req.dialects[0] = smb2->version;
                break;
        }

        memcpy(req.client_guid, smb2_get_client_guid(smb2), SMB2_GUID_SIZE);

        pdu = smb2_cmd_negotiate_async(smb2, &req, negotiate_cb, conn_data);
        if (pdu == NULL) {
                conn_data->cb(smb2, -ENOMEM, NULL, conn_data->cb_data);
                smb2_free_auth_data(smb2);
                return;
        }
        smb2_queue_pdu(smb2, pdu);
}

int
smb2_connect_share_async(struct smb2_context *smb2,
                         const char *server,
                         const char *share, const char *user,
                         smb2_command_cb cb, void *cb_data)
{
        async_cb_data *conn_data;

        if (smb2->server) {
                free(discard_const(smb2->server));
        }
        smb2->server = strdup(server);

        if (smb2->share) {
                free(discard_const(smb2->share));
        }
        smb2->share = strdup(share);

        if (user) {
                smb2_set_user(smb2, user);
        }

        conn_data = malloc(sizeof(async_cb_data));
        if (conn_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate async_cb_data");
                return -ENOMEM;
        }
        memset(conn_data, 0, sizeof(async_cb_data));

        if (smb2->utf8_unc) {
                free(smb2->utf8_unc);
        }
        if (asprintf(&smb2->utf8_unc, "\\\\%s\\%s", smb2->server, smb2->share) < 0) {
                smb2_free_auth_data(smb2);
                smb2_set_error(smb2, "Failed to allocate unc string.");
                return -ENOMEM;
        }

        if (smb2->ucs2_unc) {
                free(smb2->ucs2_unc);
        }
        smb2->ucs2_unc = utf8_to_ucs2(smb2->utf8_unc);
        if (smb2->ucs2_unc == NULL) {
                smb2_free_auth_data(smb2);
                smb2_set_error(smb2, "Count not convert UNC:[%s] into UCS2",
                               smb2->utf8_unc);
                return -ENOMEM;
        }

        conn_data->cb = cb;
        conn_data->cb_data = cb_data;

        if (smb2_connect_async(smb2, server, connect_cb, conn_data) != 0) {
                smb2_free_auth_data(smb2);
                return -ENOMEM;
        }

        return 0;
}

static void
free_smb2fh(struct smb2fh *fh)
{
        free(fh);
}

static void
close_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct smb2fh *fh = private_data;

        if (status != SMB2_STATUS_SUCCESS && status != SMB2_STATUS_FILE_CLOSED) {
                smb2_set_error(smb2, "Close failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                fh->cb(smb2, -nterror_to_errno(status), NULL, fh->cb_data);
                return;
        }

        fh->cb(smb2, 0, NULL, fh->cb_data);
        free_smb2fh(fh);
}

int
smb2_close_async(struct smb2_context *smb2, struct smb2fh *fh,
                 smb2_command_cb cb, void *cb_data)
{
        struct smb2_close_request req;
        struct smb2_pdu *pdu;

        fh->cb = cb;
        fh->cb_data = cb_data;

        memset(&req, 0, sizeof(struct smb2_close_request));
        req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
        req.file_id.persistent_id = fh->file_id.persistent_id;
        req.file_id.volatile_id = fh->file_id.volatile_id;

        pdu = smb2_cmd_close_async(smb2, &req, close_cb, fh);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create close command");
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
open_cb(struct smb2_context *smb2, int status,
        void *command_data, void *private_data)
{
        async_cb_data *create_data = private_data;
        struct smb2fh *fh = create_data->acb_data_U.cr_data.fh;
        struct smb2_create_reply *rep = command_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "SMB2_CREATE failed - %s", smb2_get_error(smb2));
                create_data->cb(smb2, -nterror_to_errno(status), NULL, create_data->cb_data);
                free_smb2fh(fh);
                free(create_data);
                return;
        }
        create_data->status = status;

        if (create_data->acb_data_U.cr_data.needToClose) {
                if (smb2_close_async(smb2, fh, create_data->cb, create_data->cb_data) != 0) {
                        smb2_set_error(smb2, "SMB2_CLOSE failed - %s", smb2_get_error(smb2));
                }
                create_data->acb_data_U.cr_data.fh = NULL;
                free(create_data);
                return;
        } else {
                fh->file_id.persistent_id = rep->file_id.persistent_id;
                fh->file_id.volatile_id = rep->file_id.volatile_id;
                create_data->cb(smb2, 0, fh, create_data->cb_data);

                create_data->acb_data_U.cr_data.fh = NULL;
                free(create_data);
        }

        return;
}

int
smb2_open_file_async(struct smb2_context *smb2,
                     const char *path,
                     uint8_t  security_flags,
                     uint32_t impersonation_level,
                     uint64_t smb_create_flags,
                     uint32_t desired_access,
                     uint32_t file_attributes,
                     uint32_t share_access,
                     uint32_t create_disposition,
                     uint32_t create_options,
                     smb2_command_cb cb, void *cb_data)
{
        async_cb_data *create_data = NULL;
        struct smb2_create_request req;
        struct smb2_pdu *pdu;

        create_data = malloc(sizeof(async_cb_data));
        if (create_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate create_data");
                return -ENOMEM;
        }
        memset(create_data, 0, sizeof(async_cb_data));

        create_data->acb_data_U.cr_data.fh = malloc(sizeof(struct smb2fh));
        if (create_data->acb_data_U.cr_data.fh == NULL) {
                smb2_set_error(smb2, "Failed to allocate smbfh");
                return -ENOMEM;
        }
        memset(create_data->acb_data_U.cr_data.fh, 0, sizeof(struct smb2fh));

        create_data->cb = cb;
        create_data->cb_data = cb_data;
        create_data->acb_data_U.cr_data.needToClose = 0;

        if (create_options & SMB2_FILE_DELETE_ON_CLOSE) {
                create_data->acb_data_U.cr_data.needToClose = 1;
        }
        if ((create_options & SMB2_FILE_DIRECTORY_FILE)
            && (create_disposition == SMB2_FILE_CREATE)) {
                create_data->acb_data_U.cr_data.needToClose = 1;
        }

        // TODO - is this needed?
        //create_options |= SMB2_FILE_NON_DIRECTORY_FILE;

        memset(&req, 0, sizeof(struct smb2_create_request));
        req.security_flags         = security_flags;
        req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        req.impersonation_level    = impersonation_level;
        req.smb_create_flags       = smb_create_flags;
        req.desired_access         = desired_access;
        req.file_attributes        = file_attributes;
        req.share_access           = share_access;
        req.create_disposition     = create_disposition;
        req.create_options         = create_options;
        req.name = path;

        pdu = smb2_cmd_create_async(smb2, &req, open_cb, create_data);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create create command");
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

int
smb2_open_async(struct smb2_context *smb2, const char *path, int flags,
                smb2_command_cb cb, void *cb_data)
{
        uint8_t  security_flags = 0;
        uint64_t smb_create_flags = 0;
        uint32_t desired_access = 0;
        uint32_t file_attributes = 0;
        uint32_t share_access = 0;
        uint32_t create_disposition = 0;
        uint32_t create_options = 0;

        /* Create disposition */
        if (flags & O_CREAT) {
                if (flags & O_EXCL) {
                        create_disposition = SMB2_FILE_CREATE;
                } else {
                        create_disposition = SMB2_FILE_OVERWRITE_IF;
                }
        } else {
                if (flags & (O_WRONLY | O_RDWR)) {
                        create_disposition = SMB2_FILE_OPEN_IF;
                } else {
                        create_disposition = SMB2_FILE_OPEN;
                }
        }

        /* desired access */
        if (flags & (O_RDWR | O_WRONLY)) {
                desired_access |= SMB2_FILE_WRITE_DATA |
                        SMB2_FILE_WRITE_EA |
                        SMB2_FILE_WRITE_ATTRIBUTES;
        }
        if (flags & O_RDWR || !(flags & O_WRONLY)) {
                desired_access |= SMB2_FILE_READ_DATA |
                        SMB2_FILE_READ_EA |
                        SMB2_FILE_READ_ATTRIBUTES;
        }

        /* create options */
        create_options |= SMB2_FILE_NON_DIRECTORY_FILE;

        if (flags & O_SYNC) {
                desired_access |= SMB2_SYNCHRONIZE;
                create_options |= SMB2_FILE_NO_INTERMEDIATE_BUFFERING;
        }

        share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;

        return smb2_open_file_async(smb2, path,
                                    security_flags,
                                    SMB2_IMPERSONATION_IMPERSONATION,
                                    smb_create_flags,
                                    desired_access,
                                    file_attributes,
                                    share_access,
                                    create_disposition,
                                    create_options,
                                    cb, cb_data);
}

int
smb2_open_pipe_async(struct smb2_context *smb2,
                     const char *pipe,
                     smb2_command_cb cb, void *cb_data)
{
        uint8_t  security_flags = 0;
        uint64_t smb_create_flags = 0;
        uint32_t desired_access = 0;
        uint32_t file_attributes = 0;
        uint32_t share_access = 0;
        uint32_t create_disposition = 0;
        uint32_t create_options = 0;
        uint32_t impersonation_level = 0;

        create_disposition = SMB2_FILE_OPEN;
        create_options = SMB2_FILE_OPEN_NO_RECALL | SMB2_FILE_NON_DIRECTORY_FILE;
        desired_access |= SMB2_FILE_WRITE_DATA | SMB2_FILE_WRITE_EA |
                          SMB2_FILE_WRITE_ATTRIBUTES;

        if (strcasecmp(pipe, "srvsvc") == 0) {
                impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
                desired_access = 0x0012019f;
                share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
        } else if (strcasecmp(pipe, "wkssvc") == 0) {
                impersonation_level = SMB2_IMPERSONATION_IDENTIFICATION;
                desired_access = 0x0012019f;
                share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
        } else if (strcasecmp(pipe, "lsarpc") == 0) {
                impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
                desired_access = 0x0002019f;
                share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
                create_options = 0x00000000;
        }

        return smb2_open_file_async(smb2, pipe,
                                    security_flags,
                                    impersonation_level,
                                    smb_create_flags,
                                    desired_access,
                                    file_attributes,
                                    share_access,
                                    create_disposition,
                                    create_options,
                                    cb, cb_data);
}

int
smb2_mkdir_async(struct smb2_context *smb2, const char *path,
                 smb2_command_cb cb, void *cb_data)
{
        uint32_t file_attributes = 0;
        uint32_t desired_access = 0;
        uint32_t share_access = 0;
        uint32_t create_disposition = 0;
        uint32_t create_options = 0;
        uint64_t smb_create_flags = 0;

        desired_access = SMB2_FILE_READ_ATTRIBUTES;
        file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
        share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        create_disposition = SMB2_FILE_CREATE;
        create_options = SMB2_FILE_DIRECTORY_FILE;

        return smb2_open_file_async(smb2, path,
                                    0, SMB2_IMPERSONATION_IMPERSONATION,
                                    smb_create_flags,
                                    desired_access,
                                    file_attributes,
                                    share_access,
                                    create_disposition,
                                    create_options,
                                    cb, cb_data);
}

static int
smb2_unlink_internal(struct smb2_context *smb2, const char *path,
                     int is_dir,
                     smb2_command_cb cb, void *cb_data)
{
        uint32_t file_attributes = 0;
        uint32_t desired_access = 0;
        uint32_t share_access = 0;
        uint32_t create_disposition = 0;
        uint32_t create_options = 0;
        uint64_t smb_create_flags = 0;

        desired_access = SMB2_DELETE;
        if (is_dir) {
                file_attributes = SMB2_FILE_ATTRIBUTE_DIRECTORY;
        } else {
                file_attributes = SMB2_FILE_ATTRIBUTE_NORMAL;
        }
        share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;
        create_disposition = SMB2_FILE_OPEN;
        create_options = SMB2_FILE_DELETE_ON_CLOSE;

        return smb2_open_file_async(smb2, path,
                                    0, SMB2_IMPERSONATION_IMPERSONATION,
                                    smb_create_flags,
                                    desired_access,
                                    file_attributes,
                                    share_access,
                                    create_disposition,
                                    create_options,
                                    cb, cb_data);
}

int
smb2_unlink_async(struct smb2_context *smb2, const char *path,
                  smb2_command_cb cb, void *cb_data)
{
        return smb2_unlink_internal(smb2, path, 0, cb, cb_data);
}

int
smb2_rmdir_async(struct smb2_context *smb2, const char *path,
                 smb2_command_cb cb, void *cb_data)
{
        return smb2_unlink_internal(smb2, path, 1, cb, cb_data);
}

static void
fsync_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        struct smb2fh *fh = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Flush failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                fh->cb(smb2, -nterror_to_errno(status), NULL, fh->cb_data);
                return;
        }

        fh->cb(smb2, 0, NULL, fh->cb_data);
}

int
smb2_fsync_async(struct smb2_context *smb2, struct smb2fh *fh,
                 smb2_command_cb cb, void *cb_data)
{
        struct smb2_flush_request req;
        struct smb2_pdu *pdu;

        fh->cb = cb;
        fh->cb_data = cb_data;

        memset(&req, 0, sizeof(struct smb2_flush_request));
        req.file_id.persistent_id = fh->file_id.persistent_id;
        req.file_id.volatile_id = fh->file_id.volatile_id;

        pdu = smb2_cmd_flush_async(smb2, &req, fsync_cb, fh);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create flush command");
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
read_cb(struct smb2_context *smb2, int status,
      void *command_data, void *private_data)
{
        async_cb_data *read_data = private_data;
        struct smb2fh *fh = read_data->acb_data_U.rwData.fh;
        struct smb2_read_reply *rep = command_data;

        if (status && status != SMB2_STATUS_END_OF_FILE) {
                smb2_set_error(smb2, "Read/Write failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                read_data->cb(smb2, -nterror_to_errno(status), NULL, read_data->cb_data);
                free(read_data);
                return;
        }

        if (status == SMB2_STATUS_SUCCESS) {
                fh->offset += rep->data_length;
        }

        read_data->cb(smb2, rep->data_length, NULL, read_data->cb_data);
        free(read_data);
}

int
smb2_pread_async(struct smb2_context *smb2, struct smb2fh *fh,
                 uint8_t *buf, uint32_t count, uint64_t offset,
                 smb2_command_cb cb, void *cb_data)
{
        struct smb2_read_request req;
        async_cb_data *read_data;
        struct smb2_pdu *pdu;
        int needed_credits = (count - 1) / 65536 + 1;

        if (count > smb2->max_read_size) {
                count = smb2->max_read_size;
        }
        if (smb2->dialect > SMB2_VERSION_0202) {
                if (needed_credits > MAX_CREDITS - 16) {
                        count =  (MAX_CREDITS - 16) * 65536;
                }
                needed_credits = (count - 1) / 65536 + 1;
                if (needed_credits > smb2->credits) {
                        count = smb2->credits * 65536;
                }
        } else {
                if (count > 65536) {
                        count = 65536;
                }
        }

        read_data = malloc(sizeof(async_cb_data));
        if (read_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate async_cb_data");
                return -ENOMEM;
        }
        memset(read_data, 0, sizeof(async_cb_data));

        fh->offset = offset;

        read_data->cb = cb;
        read_data->cb_data = cb_data;
        read_data->acb_data_U.rwData.fh = fh;

        memset(&req, 0, sizeof(struct smb2_read_request));
        req.flags = 0;
        req.length = count;
        req.offset = offset;
        req.buf = buf;
        req.file_id.persistent_id = fh->file_id.persistent_id;
        req.file_id.volatile_id = fh->file_id.volatile_id;
        req.minimum_count = 0;
        req.channel = SMB2_CHANNEL_NONE;
        req.remaining_bytes = 0;

        pdu = smb2_cmd_read_async(smb2, &req, read_cb, read_data);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create read command");
                return -1;
        }

        smb2_queue_pdu(smb2, pdu);

        return 0;
}        

int
smb2_read_async(struct smb2_context *smb2, struct smb2fh *fh,
                uint8_t *buf, uint32_t count,
                smb2_command_cb cb, void *cb_data)
{
        return smb2_pread_async(smb2, fh, buf, count, fh->offset,
                                cb, cb_data);
}

static void
write_cb(struct smb2_context *smb2, int status,
      void *command_data, void *private_data)
{
        async_cb_data *write_data = private_data;
        struct smb2fh *fh = write_data->acb_data_U.rwData.fh;
        struct smb2_write_reply *rep = command_data;

        if (status && status != SMB2_STATUS_END_OF_FILE) {
                smb2_set_error(smb2, "Read/Write failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                write_data->cb(smb2, -nterror_to_errno(status), NULL, write_data->cb_data);
                free(write_data);
                return;
        }

        if (status == SMB2_STATUS_SUCCESS) {
                fh->offset += rep->count;
        }

        write_data->cb(smb2, rep->count, NULL, write_data->cb_data);
        free(write_data);
}

int
smb2_pwrite_async(struct smb2_context *smb2, struct smb2fh *fh,
                  uint8_t *buf, uint32_t count, uint64_t offset,
                  smb2_command_cb cb, void *cb_data)
{
        struct smb2_write_request req;
        async_cb_data *write_data;
        struct smb2_pdu *pdu;
        int needed_credits = (count - 1) / 65536 + 1;

        if (count > smb2->max_write_size) {
                count = smb2->max_write_size;
        }
        if (smb2->dialect > SMB2_VERSION_0202) {
                if (needed_credits > MAX_CREDITS - 16) {
                        count =  (MAX_CREDITS - 16) * 65536;
                }
                needed_credits = (count - 1) / 65536 + 1;
                if (needed_credits > smb2->credits) {
                        count = smb2->credits * 65536;
                }
        } else {
                if (count > 65536) {
                        count = 65536;
                }
        }

        write_data = malloc(sizeof(async_cb_data));
        if (write_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate rw_data");
                return -ENOMEM;
        }
        memset(write_data, 0, sizeof(async_cb_data));

        fh->offset = offset;

        write_data->cb = cb;
        write_data->cb_data = cb_data;
        write_data->acb_data_U.rwData.fh = fh;

        memset(&req, 0, sizeof(struct smb2_write_request));
        req.length = count;
        req.offset = offset;
        req.buf = buf;
        req.file_id.persistent_id = fh->file_id.persistent_id;
        req.file_id.volatile_id = fh->file_id.volatile_id;
        req.channel = SMB2_CHANNEL_NONE;
        req.remaining_bytes = 0;
        req.flags = 0;

        pdu = smb2_cmd_write_async(smb2, &req, write_cb, write_data);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create write command");
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}        

int
smb2_write_async(struct smb2_context *smb2, struct smb2fh *fh,
                 uint8_t *buf, uint32_t count,
                 smb2_command_cb cb, void *cb_data)
{
        return smb2_pwrite_async(smb2, fh, buf, count, fh->offset,
                                 cb, cb_data);
}

int64_t
smb2_lseek(struct smb2_context *smb2, struct smb2fh *fh,
           int64_t offset, int whence, uint64_t *current_offset)
{
        switch(whence) {
        case SEEK_SET:
                if (offset < 0) {
                        smb2_set_error(smb2, "Lseek() offset would become"
                                       "negative");
                        return -EINVAL;
                }
                fh->offset = offset;
                if (current_offset) {
                        *current_offset = fh->offset;
                }
                return fh->offset;
        case SEEK_CUR:
                if (fh->offset + offset < 0) {
                        smb2_set_error(smb2, "Lseek() offset would become"
                                       "negative");
                        return -EINVAL;
                }
                fh->offset += offset;
                if (current_offset) {
                        *current_offset = fh->offset;
                }
                return fh->offset;
        case SEEK_END:
                smb2_set_error(smb2, "SEEK_END not implemented");
                return -EINVAL;
        default:
                smb2_set_error(smb2, "Invalid whence(%d) for lseek",
                               whence);
                return -EINVAL;
        }
}

static void
fstat_cb_1(struct smb2_context *smb2, int status,
           void *command_data, void *private_data)
{
        async_cb_data *stat_data = private_data;
        struct smb2_query_info_reply *rep = command_data;
        struct smb2_file_all_info *fs = rep->output_buffer;
        struct smb2_stat_64 *st = stat_data->acb_data_U.qs_info.info;

        if (status != SMB2_STATUS_SUCCESS) {
                stat_data->cb(smb2, -nterror_to_errno(status),
                       NULL, stat_data->cb_data);
                free(stat_data);
                return;
        }

        st->smb2_type = SMB2_TYPE_FILE;
        if (fs->basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
                st->smb2_type = SMB2_TYPE_DIRECTORY;
        }
        st->smb2_nlink      = fs->standard.number_of_links;
        st->smb2_ino        = fs->index_number;
        st->smb2_size       = fs->standard.end_of_file;
        st->smb2_atime      = fs->basic.last_access_time.tv_sec;
        st->smb2_atime_nsec = fs->basic.last_access_time.tv_usec *
                1000;
        st->smb2_mtime      = fs->basic.last_write_time.tv_sec;
        st->smb2_mtime_nsec = fs->basic.last_write_time.tv_usec *
                1000;
        st->smb2_ctime      = fs->basic.change_time.tv_sec;
        st->smb2_ctime_nsec = fs->basic.change_time.tv_usec *
                1000;
        st->smb2_crtime      = fs->basic.creation_time.tv_sec;
        st->smb2_crtime_nsec = fs->basic.creation_time.tv_usec *
                1000;

        smb2_free_data(smb2, fs);

        stat_data->cb(smb2, 0, st, stat_data->cb_data);
        free(stat_data);
}

int
smb2_fstat_async(struct smb2_context *smb2, struct smb2fh *fh,
                 struct smb2_stat_64 *st,
                 smb2_command_cb cb, void *cb_data)
{
        async_cb_data *stat_data;
        struct smb2_query_info_request req;
        struct smb2_pdu *pdu;

        stat_data = malloc(sizeof(async_cb_data));
        if (stat_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate stat_data");
                return -ENOMEM;
        }
        memset(stat_data, 0, sizeof(async_cb_data));

        stat_data->cb = cb;
        stat_data->cb_data = cb_data;
        stat_data->acb_data_U.qs_info.info = st;

        memset(&req, 0, sizeof(struct smb2_query_info_request));
        req.info_type = SMB2_0_INFO_FILE;
        req.file_info_class = SMB2_FILE_ALL_INFORMATION;
        req.output_buffer_length = 65535;
        req.additional_information = 0;
        req.flags = 0;
        req.file_id.persistent_id = fh->file_id.persistent_id;
        req.file_id.volatile_id = fh->file_id.volatile_id;

        pdu = smb2_cmd_query_info_async(smb2, &req, fstat_cb_1, stat_data);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create query command");
                free(stat_data);
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
getinfo_create_cb(struct smb2_context *smb2, int status,
                  void *command_data _U_, void *private_data)
{
        async_cb_data *getinfo_data = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Open failed with (0x%08x) %s.",
                               status, nterror_to_str(status));
                getinfo_data->cb(smb2, -nterror_to_errno(status), NULL, getinfo_data->cb_data);
                getinfo_data->status = status;
                return;
        }
        getinfo_data->status = status;
}

static void
getinfo_close_cb(struct smb2_context *smb2, int status,
                 void *command_data _U_, void *private_data)
{
        async_cb_data *getinfo_data = private_data;

        if (getinfo_data->status != SMB2_STATUS_SUCCESS) {
                return;
        }
        getinfo_data->status = status;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "CloseFile failed with (0x%08x) %s.",
                               status, nterror_to_str(status));
                getinfo_data->cb(smb2, -nterror_to_errno(status), NULL, getinfo_data->cb_data);
                return;
        }

        getinfo_data->cb(smb2, -nterror_to_errno(getinfo_data->status),
                         getinfo_data->acb_data_U.qs_info.info,
                         getinfo_data->cb_data);
        getinfo_data->acb_data_U.qs_info.info = NULL;
        free(getinfo_data);
}

static void
getinfo_query_cb(struct smb2_context *smb2, int status,
                 void *command_data, void *private_data)
{
        async_cb_data *getinfo_data = private_data;
        struct smb2_query_info_reply *rep = command_data;
        smb2_file_info *info = (smb2_file_info *)(getinfo_data->acb_data_U.qs_info.info);

        if (getinfo_data->status != SMB2_STATUS_SUCCESS) {
                return;
        }
        getinfo_data->status = status;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "QueryFileInfo failed with (0x%08x) %s.",
                               status, nterror_to_str(status));
                getinfo_data->cb(smb2, -nterror_to_errno(status),
                                 NULL, getinfo_data->cb_data);
                return;
        }

        if (info->info_type == SMB2_0_INFO_FILE)
        {
                if (info->file_info_class == SMB2_FILE_BASIC_INFORMATION)
                {
                        struct smb2_file_basic_info *basic = rep->output_buffer;
                        (info->u_info).basic_info = *basic;
                }
                else if (info->file_info_class == SMB2_FILE_STANDARD_INFORMATION)
                {
                        struct smb2_file_standard_info *standard = rep->output_buffer;
                        (info->u_info).standard_info = *standard;
                }
                else if (info->file_info_class == SMB2_FILE_ALL_INFORMATION)
                {
                        struct smb2_file_all_info *all_info = rep->output_buffer;
                        (info->u_info).all_info = *all_info;
                }
                else if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION)
                {
                }
                else if (info->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION)
                {
                }
        }
        else if (info->info_type == SMB2_0_INFO_FILESYSTEM)
        {
                if (info->file_info_class == SMB2_FILE_FS_SIZE_INFORMATION)
                {
                        struct smb2_file_fs_size_info *fsize = rep->output_buffer;
                        (info->u_info).fs_size_info = *fsize;
                }
                else if (info->file_info_class == SMB2_FILE_FS_DEVICE_INFORMATION)
                {
                        struct smb2_file_fs_device_info *fs_device = rep->output_buffer;
                        (info->u_info).fs_device_info = *fs_device;
                }
                else if (info->file_info_class == SMB2_FILE_FS_CONTROL_INFORMATION)
                {
                        struct smb2_file_fs_control_info *fs_control = rep->output_buffer;
                        (info->u_info).fs_control_info = *fs_control;
                }
                else if (info->file_info_class == SMB2_FILE_FS_SECTOR_SIZE_INFORMATION)
                {
                        struct smb2_file_fs_sector_size_info *fs_sector = rep->output_buffer;
                        (info->u_info).fs_sector_size_info = *fs_sector;
                }
                else if (info->file_info_class == SMB2_FILE_FS_FULL_SIZE_INFORMATION)
                {
                        struct smb2_file_fs_full_size_info *vfs = rep->output_buffer;
                        (info->u_info).fs_full_size_info = *vfs;
                }
        }
        else if (info->info_type == SMB2_0_INFO_SECURITY)
        {
                struct smb2_security_descriptor *sd = rep->output_buffer;
                (info->u_info).security_info = sd;
                rep->output_buffer = NULL; // DONOT free here, it will be used and freed by caller.
        }
        else if (info->info_type == SMB2_0_INFO_QUOTA)
        {
        }
        else
        {
                smb2_set_error(smb2, "Invalid INFO TYPE");
        }

        getinfo_data->cb(smb2, 0, NULL, getinfo_data->cb_data);
        if (rep->output_buffer != NULL) {
                smb2_free_data(smb2, rep->output_buffer); rep->output_buffer = NULL;
        }
        return;
}

int
smb2_getinfo_async(struct smb2_context *smb2,
                   const char *path,
                   smb2_file_info *info,
                   smb2_command_cb cb, void *cb_data)
{
        async_cb_data *getinfo_data;
        struct smb2_create_request cr_req;
        struct smb2_query_info_request qi_req;
        struct smb2_close_request cl_req;
        struct smb2_pdu *pdu, *next_pdu;

        if (info == NULL) {
                smb2_set_error(smb2, "No info type provided for query");
                return -1;
        }

        getinfo_data = malloc(sizeof(async_cb_data));
        if (getinfo_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate getinfo_data");
                return -1;
        }
        memset(getinfo_data, 0, sizeof(async_cb_data));

        getinfo_data->cb      = cb;
        getinfo_data->cb_data = cb_data;
        getinfo_data->acb_data_U.qs_info.info    = info;

        /* CREATE command */
        memset(&cr_req, 0, sizeof(struct smb2_create_request));
        cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
        cr_req.desired_access = SMB2_FILE_READ_ATTRIBUTES | SMB2_FILE_READ_EA;
        if (info->info_type == SMB2_0_INFO_SECURITY) {
                cr_req.desired_access = SMB2_READ_CONTROL;
        }
        cr_req.file_attributes = 0;
        cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        cr_req.create_disposition = SMB2_FILE_OPEN;
        cr_req.create_options = 0;
        cr_req.name = path;

        pdu = smb2_cmd_create_async(smb2, &cr_req, getinfo_create_cb, getinfo_data);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create create command");
                free(getinfo_data);
                return -1;
        }

        /* QUERY INFO command */
        memset(&qi_req, 0, sizeof(struct smb2_query_info_request));
        qi_req.info_type = info->info_type;
        qi_req.file_info_class = info->file_info_class;
        qi_req.output_buffer_length = 65535;
        qi_req.additional_information = 0;
        if (info->info_type == SMB2_0_INFO_SECURITY) {
                qi_req.file_info_class = 0;
                qi_req.additional_information =
                               SMB2_OWNER_SECURITY_INFORMATION |
                               SMB2_GROUP_SECURITY_INFORMATION |
                               SMB2_DACL_SECURITY_INFORMATION;
        }
        qi_req.flags = 0;
        qi_req.file_id.persistent_id = compound_file_id.persistent_id;
        qi_req.file_id.volatile_id= compound_file_id.volatile_id;

        next_pdu = smb2_cmd_query_info_async(smb2, &qi_req,
                                             getinfo_query_cb, getinfo_data);
        if (next_pdu == NULL) {
                smb2_set_error(smb2, "Failed to create query command");
                free(getinfo_data);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        /* CLOSE command */
        memset(&cl_req, 0, sizeof(struct smb2_close_request));
        cl_req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
        cl_req.file_id.persistent_id = compound_file_id.persistent_id;
        cl_req.file_id.volatile_id= compound_file_id.volatile_id;

        next_pdu = smb2_cmd_close_async(smb2, &cl_req, getinfo_close_cb, getinfo_data);
        if (next_pdu == NULL) {
                getinfo_data->cb(smb2, -ENOMEM, NULL, getinfo_data->cb_data);
                free(getinfo_data);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
ftrunc_cb_1(struct smb2_context *smb2, int status,
            void *command_data _U_, void *private_data)
{
        async_cb_data *cb_data = private_data;

        cb_data->cb(smb2, -nterror_to_errno(status),
                    NULL, cb_data->cb_data);
        free(cb_data);
}

int
smb2_ftruncate_async(struct smb2_context *smb2, struct smb2fh *fh,
                     uint64_t length, smb2_command_cb cb, void *cb_data)
{
        async_cb_data *trunc_data;
        struct smb2_set_info_request req;
        struct smb2_file_end_of_file_info eofi;
        struct smb2_pdu *pdu;

        trunc_data = malloc(sizeof(async_cb_data));
        if (trunc_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate trunc_data");
                return -ENOMEM;
        }
        memset(trunc_data, 0, sizeof(async_cb_data));

        trunc_data->cb = cb;
        trunc_data->cb_data = cb_data;

        eofi.end_of_file = length;

        memset(&req, 0, sizeof(struct smb2_set_info_request));
        req.info_type = SMB2_0_INFO_FILE;
        req.file_info_class = SMB2_FILE_END_OF_FILE_INFORMATION;
        req.additional_information = 0;
        req.file_id.persistent_id = fh->file_id.persistent_id;
        req.file_id.volatile_id= fh->file_id.volatile_id;
        req.input_data = &eofi;

        pdu = smb2_cmd_set_info_async(smb2, &req, ftrunc_cb_1, trunc_data);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create set info command");
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
disconnect_cb_2(struct smb2_context *smb2, int status,
           void *command_data _U_, void *private_data)
{
        async_cb_data *dc_data = private_data;

        dc_data->cb(smb2, 0, NULL, dc_data->cb_data);
        free(dc_data);
        close(smb2->fd);
        smb2->fd = -1;
}

static void
disconnect_cb_1(struct smb2_context *smb2, int status,
           void *command_data _U_, void *private_data)
{
        async_cb_data *dc_data = private_data;
        struct smb2_pdu *pdu;

        pdu = smb2_cmd_logoff_async(smb2, disconnect_cb_2, dc_data);
        if (pdu == NULL) {
                dc_data->cb(smb2, -ENOMEM, NULL, dc_data->cb_data);
                free(dc_data);
                return;
        }
        smb2_queue_pdu(smb2, pdu);
}

int
smb2_disconnect_share_async(struct smb2_context *smb2,
                            smb2_command_cb cb, void *cb_data)
{
        async_cb_data *dc_data;
        struct smb2_pdu *pdu;

        dc_data = malloc(sizeof(async_cb_data));
        if (dc_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate async_cb_data");
                return -ENOMEM;
        }
        memset(dc_data, 0, sizeof(async_cb_data));

        dc_data->cb = cb;
        dc_data->cb_data = cb_data;

        pdu = smb2_cmd_tree_disconnect_async(smb2, disconnect_cb_1, dc_data);
        if (pdu == NULL) {
                free(dc_data);
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
echo_cb(struct smb2_context *smb2, int status,
           void *command_data _U_, void *private_data)
{
        async_cb_data *cb_data = private_data;

        cb_data->cb(smb2, -nterror_to_errno(status),
                    NULL, cb_data->cb_data);
        free(cb_data);
}

int
smb2_echo_async(struct smb2_context *smb2,
                smb2_command_cb cb, void *cb_data)
{
        async_cb_data *echo_data;
        struct smb2_pdu *pdu;

        echo_data = malloc(sizeof(async_cb_data));
        if (echo_data == NULL) {
                smb2_set_error(smb2, "Failed to allocate echo_data");
                return -ENOMEM;
        }
        memset(echo_data, 0, sizeof(async_cb_data));

        echo_data->cb = cb;
        echo_data->cb_data = cb_data;

        pdu = smb2_cmd_echo_async(smb2, echo_cb, echo_data);
        if (pdu == NULL) {
                free(echo_data);
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

uint32_t
smb2_get_max_read_size(struct smb2_context *smb2)
{
        return smb2->max_read_size;
}

uint32_t
smb2_get_max_write_size(struct smb2_context *smb2)
{
        return smb2->max_write_size;
}

static void
ioctl_cb(struct smb2_context *smb2, int status,
         void *command_data, void *private_data)
{
        async_cb_data *ioctl_d = private_data;

        struct smb2_ioctl_reply *rep = command_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "IOCTL failed with (0x%08x) %s",
                               status, nterror_to_str(status));
                ioctl_d->cb(smb2, -nterror_to_errno(status), NULL, ioctl_d->cb_data);
                free(ioctl_d);
                return;
        }

        memcpy(ioctl_d->acb_data_U.ioctl.output_buffer,
               rep->output_buffer,
               rep->output_count);
        *(ioctl_d->acb_data_U.ioctl.output_count) = rep->output_count;

        ioctl_d->cb(smb2, status, NULL, ioctl_d->cb_data);
        free(ioctl_d);
}

int
smb2_ioctl_async(struct smb2_context *smb2, struct smb2fh *fh,
                 uint32_t ioctl_ctl, uint32_t ioctl_flags,
                 uint8_t *input_buffer, uint32_t input_count,
                 uint8_t *output_buffer, uint32_t *output_count,
                 smb2_command_cb cb, void *cb_data)
{
        struct smb2_ioctl_request req;
        async_cb_data *ioctl_d;
        struct smb2_pdu *pdu;

        if (input_count > smb2->max_transact_size) {
                smb2_set_error(smb2, "Ioctl count %d larger than "
                               "max_transact_size %d", input_count,
                               smb2->max_transact_size);
                return -EIO;
        }

        ioctl_d = malloc(sizeof(async_cb_data));
        if (ioctl_d == NULL) {
                smb2_set_error(smb2, "Failed to allocate async_cb_data");
                return -ENOMEM;
        }
        memset(ioctl_d, 0, sizeof(async_cb_data));

        ioctl_d->cb = cb;
        ioctl_d->cb_data = cb_data;
        ioctl_d->acb_data_U.ioctl.output_buffer = output_buffer;
        ioctl_d->acb_data_U.ioctl.output_count  = output_count;

        memset(&req, 0, sizeof(struct smb2_ioctl_request));
        req.ctl_code = ioctl_ctl;
        req.input_count = input_count;
        req.input_buffer = input_buffer;
        req.file_id.persistent_id = fh->file_id.persistent_id;
        req.file_id.volatile_id= fh->file_id.volatile_id;
        req.flags = ioctl_flags;
        req.max_input_response = 0;
        req.max_output_response = 64 * 1024;

        pdu = smb2_cmd_ioctl_async(smb2, &req, ioctl_cb, ioctl_d);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create ioctl command : %s",
                               smb2_get_error(smb2));
                return -ENOMEM;
        }
        smb2_queue_pdu(smb2, pdu);

        return 0;
}

static void
setinfo_create_cb(struct smb2_context *smb2, int status,
                  void *command_data _U_, void *private_data)
{
        async_cb_data *setinfoData = private_data;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "Open failed with (0x%08x) %s.",
                               status, nterror_to_str(status));
                setinfoData->cb(smb2, -nterror_to_errno(status),
                                NULL, setinfoData->cb_data);
                setinfoData->status = status;
                return;
        }
        setinfoData->status = status;
}

static void
setinfo_set_cb(struct smb2_context *smb2, int status,
                     void *command_data, void *private_data)
{
        async_cb_data *setinfoData = private_data;

        if (setinfoData->status != SMB2_STATUS_SUCCESS) {
                return;
        }
        setinfoData->status = status;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "SetInfo failed with (0x%08x) %s.",
                               status, nterror_to_str(status));
                setinfoData->cb(smb2, -nterror_to_errno(status),
                                NULL, setinfoData->cb_data);
                return;
        }

        setinfoData->cb(smb2, -nterror_to_errno(status),
                        NULL, setinfoData->cb_data);
}

static void
setinfo_close_cb(struct smb2_context *smb2, int status,
                       void *command_data _U_, void *private_data)
{
        async_cb_data *setinfoData = private_data;

        if (setinfoData->status != SMB2_STATUS_SUCCESS) {
                return;
        }
        setinfoData->status = status;

        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "CloseFile failed with (0x%08x) %s.",
                               status, nterror_to_str(status));
                setinfoData->cb(smb2, -nterror_to_errno(status),
                                NULL, setinfoData->cb_data);
                return;
        }

        setinfoData->cb(smb2, -nterror_to_errno(status),
                        NULL, setinfoData->cb_data);
        free(setinfoData);
}

int
smb2_setinfo_async(struct smb2_context *smb2,
                   const char *path,
                   smb2_file_info *info,
                   smb2_command_cb cb, void *cb_data)
{
        struct smb2_create_request cr_req;
        struct smb2_set_info_request si_req;
        struct smb2_close_request cl_req;
        struct smb2_pdu *pdu, *next_pdu;
        async_cb_data *setinfoData = NULL;

        if (info == NULL) {
                smb2_set_error(smb2, "%s : no info provided", __func__);
                return -1;
        }

        if (info->info_type != SMB2_0_INFO_FILE && info->info_type != SMB2_0_INFO_SECURITY) {
                smb2_set_error(smb2, "%s: Invalid INFOTYPE to set", __func__);
                return -1;
        }

        if (info->info_type == SMB2_0_INFO_SECURITY)
                info->file_info_class = 0;

        setinfoData = (async_cb_data *) malloc(sizeof(async_cb_data));
        if (setinfoData == NULL) {
                smb2_set_error(smb2, "%s : failed to allocate setinfoData", __func__);
                return -1;
        }
        memset(setinfoData, 0, sizeof(async_cb_data));
        setinfoData->cb = cb;
        setinfoData->cb_data = cb_data;

        /* CREATE command */
        memset(&cr_req, 0, sizeof(struct smb2_create_request));
        cr_req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        cr_req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;

        /* set the proper desired access */
        if (info->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION) {
                cr_req.desired_access = SMB2_GENERIC_WRITE;
        } else if (info->file_info_class == SMB2_FILE_BASIC_INFORMATION) {
                cr_req.desired_access = SMB2_FILE_WRITE_ATTRIBUTES |
                                        SMB2_FILE_WRITE_EA;
        } else if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION) {
                cr_req.desired_access = SMB2_GENERIC_READ |
                                        SMB2_FILE_READ_ATTRIBUTES |
                                        SMB2_DELETE;
        }
        if (info->info_type == SMB2_0_INFO_SECURITY) {
                cr_req.desired_access= SMB2_WRITE_DACL | SMB2_WRITE_OWNER;
        }

        cr_req.file_attributes = 0;
        cr_req.share_access = SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE;
        if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION) {
                cr_req.share_access = SMB2_FILE_SHARE_READ |
                                      SMB2_FILE_SHARE_WRITE |
                                      SMB2_FILE_SHARE_DELETE;
        }
        cr_req.create_disposition = SMB2_FILE_OPEN;
        cr_req.create_options = 0;
        cr_req.name = path;

        pdu = smb2_cmd_create_async(smb2, &cr_req, setinfo_create_cb, setinfoData);
        if (pdu == NULL) {
                smb2_set_error(smb2, "Failed to create create command");
                free(setinfoData);
                return -1;
        }

        /* SET INFO command */
        memset(&si_req, 0, sizeof(struct smb2_set_info_request));
        si_req.info_type = info->info_type;
        si_req.file_info_class = info->file_info_class;
        si_req.file_id.persistent_id = compound_file_id.persistent_id;
        si_req.file_id.volatile_id= compound_file_id.volatile_id;

        if (info->file_info_class == SMB2_FILE_RENAME_INFORMATION) {
                si_req.input_data = &((info->u_info).rename_info);
        } else if(info->file_info_class == SMB2_FILE_END_OF_FILE_INFORMATION) {
                si_req.input_data = &((info->u_info).eof_info);
        } else if (info->file_info_class == SMB2_FILE_BASIC_INFORMATION) {
                si_req.input_data = &((info->u_info).basic_info);
        }

        if (info->info_type == SMB2_0_INFO_SECURITY) {
                si_req.additional_information =
                                 SMB2_OWNER_SECURITY_INFORMATION |
                                 SMB2_GROUP_SECURITY_INFORMATION |
                                 SMB2_DACL_SECURITY_INFORMATION;
                si_req.input_data = &((info->u_info).sec_info);
        }

        next_pdu = smb2_cmd_set_info_async(smb2, &si_req,
                                           setinfo_set_cb,
                                           setinfoData);
        if (next_pdu == NULL) {
                smb2_set_error(smb2, "Failed to create set-info command. %s",
                               smb2_get_error(smb2));
                free(setinfoData);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        /* CLOSE command */
        memset(&cl_req, 0, sizeof(struct smb2_close_request));
        cl_req.flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
        cl_req.file_id.persistent_id = compound_file_id.persistent_id;
        cl_req.file_id.volatile_id= compound_file_id.volatile_id;

        next_pdu = smb2_cmd_close_async(smb2, &cl_req,
                                        setinfo_close_cb,
                                        setinfoData);
        if (next_pdu == NULL) {
                smb2_set_error(smb2, "Failed to create close command. %s",
                               smb2_get_error(smb2));
                setinfoData->cb(smb2, -ENOMEM, NULL, setinfoData->cb_data);
                free(setinfoData);
                smb2_free_pdu(smb2, pdu);
                return -1;
        }
        smb2_add_compound_pdu(smb2, pdu, next_pdu);

        smb2_queue_pdu(smb2, pdu);

        return 0;
}
