/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2018 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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

#ifndef HAVE_LIBKRB5

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

#include <ctype.h>
#include "portable-endian.h"
#include <stdio.h>
#include <time.h>

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"

#include "md4.h"
#include "md5.h"
#include "hmac-md5.h"
#include "ntlmssp.h"

struct auth_data {
        unsigned char *buf;
        int len;
        int allocated;

        int neg_result;
        unsigned char *ntlm_buf;
        int ntlm_len;

        const char *user;
        const char *password;
        const char *domain;
        const char *workstation;
        const char *client_challenge;

        uint8_t exported_session_key[SMB2_KEY_SIZE];
};

#define NEGOTIATE_MESSAGE      0x00000001
#define CHALLENGE_MESSAGE      0x00000002
#define AUTHENTICATION_MESSAGE 0x00000003

#define NTLMSSP_NEGOTIATE_56                               0x80000000
#define NTLMSSP_NEGOTIATE_128                              0x20000000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY         0x00080000
#define NTLMSSP_TARGET_TYPE_SERVER                         0x00020000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN                      0x00008000
#define NTLMSSP_NEGOTIATE_NTLM                             0x00000200
#define NTLMSSP_NEGOTIATE_SIGN                             0x00000010
#define NTLMSSP_REQUEST_TARGET                             0x00000004
#define NTLMSSP_NEGOTIATE_OEM                              0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE                          0x00000001
#define NTLMSSP_NEGOTIATE_KEY_EXCH                         0x40000000

void
ntlmssp_destroy_context(struct auth_data *auth)
{
        free(auth->ntlm_buf);
        free(auth->buf);
        free(auth);
        memset(auth->exported_session_key, 0, SMB2_KEY_SIZE);
}

struct auth_data *
ntlmssp_init_context(const char *user,
                     const char *password,
                     const char *domain,
                     const char *workstation,
                     const char *client_challenge)
{
        struct auth_data *auth_data = NULL;

        auth_data = malloc(sizeof(struct auth_data));
        if (auth_data == NULL) {
                return NULL;
        }
        memset(auth_data, 0, sizeof(struct auth_data));

        auth_data->user        = user;
        auth_data->password    = password;
        auth_data->domain      = domain;
        auth_data->workstation = workstation;
        auth_data->client_challenge = client_challenge;

        memset(auth_data->exported_session_key, 0, SMB2_KEY_SIZE);

        return auth_data;
}

static int
encoder(const void *buffer, size_t size, void *ptr)
{
        struct auth_data *auth_data = ptr;

        if (size + auth_data->len > auth_data->allocated) {
                unsigned char *tmp = auth_data->buf;

                auth_data->allocated = 2 * ((size + auth_data->allocated + 256) & ~0xff);
                auth_data->buf = malloc(auth_data->allocated);
                if (auth_data->buf == NULL) {
                        free(tmp);
                        return -1;
                }
                memcpy(auth_data->buf, tmp, auth_data->len);
                free(tmp);
        }

        memcpy(auth_data->buf + auth_data->len, buffer, size);
        auth_data->len += size;

        return 0;
}

static int
ntlm_negotiate_message(struct auth_data *auth_data)
{
        unsigned char ntlm[32];
        uint32_t u32;

        memset(ntlm, 0, 32);
        memcpy(ntlm, "NTLMSSP", 8);

        u32 = htole32(NEGOTIATE_MESSAGE);
        memcpy(&ntlm[8], &u32, 4);

        u32 = htole32(NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
                      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
                      //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
                      NTLMSSP_NEGOTIATE_NTLM|
                      //NTLMSSP_NEGOTIATE_SIGN|
                      NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
                      NTLMSSP_NEGOTIATE_UNICODE);
        memcpy(&ntlm[12], &u32, 4);

        if (encoder(&ntlm[0], 32, auth_data) < 0) {
                return -1;
        }

        return 0;
}

static int
ntlm_challenge_message(struct auth_data *auth_data, unsigned char *buf,
                       int len)
{
        free(auth_data->ntlm_buf);
        auth_data->ntlm_len = len;
        auth_data->ntlm_buf = malloc(auth_data->ntlm_len);
        if (auth_data->ntlm_buf == NULL) {
                return -1;
        }
        memcpy(auth_data->ntlm_buf, buf, auth_data->ntlm_len);

        return 0;
}

static int
NTOWFv1(const char *password, unsigned char password_hash[16])
{
        MD4_CTX ctx;
        struct ucs2 *ucs2_password = NULL;

        ucs2_password = utf8_to_ucs2(password);
        if (ucs2_password == NULL) {
                return -1;
        }
        MD4Init(&ctx);
        MD4Update(&ctx, (unsigned char *)ucs2_password->val, ucs2_password->len * 2);
        MD4Final(password_hash, &ctx);
        free(ucs2_password);

        return 0;
}

static int
NTOWFv2(const char *user, const char *password, const char *domain,
        unsigned char ntlmv2_hash[16])
{
        int i, len;
        char *userdomain;
        struct ucs2 *ucs2_userdomain = NULL;
        unsigned char ntlm_hash[16];

        if (NTOWFv1(password, ntlm_hash) < 0) {
                return -1;
        }

        len = strlen(user) + 1;
        if (domain) {
                len += strlen(domain);
        }
        userdomain = malloc(len);
        if (userdomain == NULL) {
                return -1;
        }

        strcpy(userdomain, user);
        for (i = strlen(userdomain) - 1; i >=0; i--) {
                if (islower(userdomain[i])) {
                        userdomain[i] = toupper(userdomain[i]);
                }
        }
        if (domain) {
                strcat(userdomain, domain);
        }

        ucs2_userdomain = utf8_to_ucs2(userdomain);
        if (ucs2_userdomain == NULL) {
                return -1;
        }

        hmac_md5((unsigned char *)ucs2_userdomain->val,
                 ucs2_userdomain->len * 2,
                 ntlm_hash, 16, ntlmv2_hash);
        free(userdomain);
        free(ucs2_userdomain);

        return 0;
}

/* This is not the same temp as in MS-NLMP. This temp has an additional
 * 16 bytes at the start of the buffer.
 * Use &auth_data->val[16] if you want the temp from MS-NLMP
 */
static int
encode_temp(struct auth_data *auth_data, uint64_t t, char *client_challenge,
            char *server_challenge, char *server_name, int server_name_len)
{
        unsigned char sign[8] = {0x01, 0x01, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00};
        unsigned char zero[8] = {0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00};

        if (encoder(&zero, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(server_challenge, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(sign, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(&t, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(client_challenge, 8, auth_data) < 0) {
                return -1;
        }
        if (encoder(&zero, 4, auth_data) < 0) {
                return -1;
        }
        if (encoder(server_name, server_name_len, auth_data) < 0) {
                return -1;
        }
        if (encoder(&zero, 4, auth_data) < 0) {
                return -1;
        }

        return 0;
}

static int
encode_ntlm_auth(struct smb2_context *smb2, struct auth_data *auth_data,
                 char *server_challenge)
{
        int ret = -1;
        unsigned char lm_buf[16];
        unsigned char *NTChallengeResponse_buf = NULL;
        unsigned char ResponseKeyNT[16];
        struct ucs2 *ucs2_domain = NULL;
        struct ucs2 *ucs2_user = NULL;
        struct ucs2 *ucs2_workstation = NULL;
        int NTChallengeResponse_len;
        unsigned char NTProofStr[16];
        unsigned char LMStr[16];
        uint64_t t;
        struct smb2_timeval tv;
        char *server_name_buf;
        int server_name_len;
        uint32_t u32;
        uint32_t server_neg_flags;
        unsigned char key_exch[SMB2_KEY_SIZE];

        tv.tv_sec = time(NULL);
        tv.tv_usec = 0;
        t = timeval_to_win(&tv);

        if (auth_data->password == NULL) {
                smb2_set_error(smb2, "No password set, can not use NTLM\n");
                goto finished;
        }

        /*
         * Generate Concatenation of(NTProofStr, temp)
         */
        if (NTOWFv2(auth_data->user, auth_data->password,
                    auth_data->domain, ResponseKeyNT)
            < 0) {
                goto finished;
        }

        /* get the server neg flags */
        memcpy(&server_neg_flags, &auth_data->ntlm_buf[20], 4);
        server_neg_flags = le32toh(server_neg_flags);

        memcpy(&u32, &auth_data->ntlm_buf[40], 4);
        u32 = le32toh(u32);
        server_name_len = u32 >> 16;

        memcpy(&u32, &auth_data->ntlm_buf[44], 4);
        u32 = le32toh(u32);
        server_name_buf = (char *)&auth_data->ntlm_buf[u32];

        if (encode_temp(auth_data, t, (char *)auth_data->client_challenge,
                        server_challenge, server_name_buf,
                        server_name_len) < 0) {
                return -1;
        }

        hmac_md5(&auth_data->buf[8], auth_data->len-8,
                 ResponseKeyNT, 16, NTProofStr);
        memcpy(auth_data->buf, NTProofStr, 16);

        NTChallengeResponse_buf = auth_data->buf;
        NTChallengeResponse_len = auth_data->len;
        auth_data->buf = NULL;
        auth_data->len = 0;
        auth_data->allocated = 0;

        /* get the NTLMv2 Key-Exchange Key
           For NTLMv2 - Key Exchange Key is the Session Base Key
         */
        hmac_md5(NTProofStr, 16, ResponseKeyNT, 16, key_exch);
        memcpy(auth_data->exported_session_key, key_exch, 16);

        /*
         * Generate AUTHENTICATE_MESSAGE
         */
        encoder("NTLMSSP", 8, auth_data);

        /* message type */
        u32 = htole32(AUTHENTICATION_MESSAGE);
        encoder(&u32, 4, auth_data);

        /* lm challenge response fields */
        memcpy(&lm_buf[0], server_challenge, 8);
        memcpy(&lm_buf[8], auth_data->client_challenge, 8);
        hmac_md5(&lm_buf[0], 16,
                 ResponseKeyNT, 16, LMStr);
        u32 = htole32(0x00180018);
        encoder(&u32, 4, auth_data);
        u32 = 0;
        encoder(&u32, 4, auth_data);

        /* nt challenge response fields */
        u32 = htole32((NTChallengeResponse_len<<16)|
                      NTChallengeResponse_len);
        encoder(&u32, 4, auth_data);
        u32 = 0;
        encoder(&u32, 4, auth_data);

        /* domain name fields */
        if (auth_data->domain) {
                ucs2_domain = utf8_to_ucs2(auth_data->domain);
                if (ucs2_domain == NULL) {
                        goto finished;
                }
                u32 = ucs2_domain->len * 2;
                u32 = htole32((u32 << 16) | u32);
                encoder(&u32, 4, auth_data);
                u32 = 0;
                encoder(&u32, 4, auth_data);
        } else {
                u32 = 0;
                encoder(&u32, 4, auth_data);
                encoder(&u32, 4, auth_data);
        }

        /* user name fields */
        ucs2_user = utf8_to_ucs2(auth_data->user);
        if (ucs2_user == NULL) {
                goto finished;
        }
        u32 = ucs2_user->len * 2;
        u32 = htole32((u32 << 16) | u32);
        encoder(&u32, 4, auth_data);
        u32 = 0;
        encoder(&u32, 4, auth_data);

        /* workstation name fields */
        if (auth_data->workstation) {
                ucs2_workstation = utf8_to_ucs2(auth_data->workstation);
                if (ucs2_workstation == NULL) {
                        goto finished;
                }
                u32 = ucs2_workstation->len * 2;
                u32 = htole32((u32 << 16) | u32);
                encoder(&u32, 4, auth_data);
                u32 = 0;
                encoder(&u32, 4, auth_data);
        } else {
                u32 = 0;
                encoder(&u32, 4, auth_data);
                encoder(&u32, 4, auth_data);
        }

        /* encrypted random session key */
        u32 = 0;
        encoder(&u32, 4, auth_data);
        encoder(&u32, 4, auth_data);

        /* negotiate flags */
        u32 = htole32(NTLMSSP_NEGOTIATE_56|NTLMSSP_NEGOTIATE_128|
                      NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY|
                      //NTLMSSP_NEGOTIATE_ALWAYS_SIGN|
                      NTLMSSP_NEGOTIATE_NTLM|
                      //NTLMSSP_NEGOTIATE_SIGN|
                      NTLMSSP_REQUEST_TARGET|NTLMSSP_NEGOTIATE_OEM|
                      NTLMSSP_NEGOTIATE_UNICODE);
        encoder(&u32, 4, auth_data);

        /* append domain */
        u32 = htole32(auth_data->len);
        memcpy(&auth_data->buf[32], &u32, 4);
        if (ucs2_domain) {
                encoder(ucs2_domain->val, ucs2_domain->len * 2, auth_data);
        }

        /* append user */
        u32 = htole32(auth_data->len);
        memcpy(&auth_data->buf[40], &u32, 4);
        encoder(ucs2_user->val, ucs2_user->len * 2, auth_data);

        /* append workstation */
        u32 = htole32(auth_data->len);
        memcpy(&auth_data->buf[48], &u32, 4);
        if (ucs2_workstation) {
                encoder(ucs2_workstation->val, ucs2_workstation->len * 2, auth_data);
        }

        /* append LMChallengeResponse */
        u32 = htole32(auth_data->len);
        memcpy(&auth_data->buf[16], &u32, 4);
        encoder(LMStr, 16, auth_data);
        encoder(auth_data->client_challenge, 8, auth_data);

        /* append NTChallengeResponse */
        u32 = htole32(auth_data->len);
        memcpy(&auth_data->buf[24], &u32, 4);
        encoder(NTChallengeResponse_buf, NTChallengeResponse_len, auth_data);

        ret = 0;
finished:
        free(ucs2_domain);
        free(ucs2_user);
        free(ucs2_workstation);
        free(NTChallengeResponse_buf);

        return ret;
}

int
ntlmssp_generate_blob(struct smb2_context *smb2, struct auth_data *auth_data,
                      unsigned char *input_buf, int input_len,
                      unsigned char **output_buf, uint16_t *output_len)
{
        free(auth_data->buf);
        auth_data->buf = NULL;
        auth_data->len = 0;
        auth_data->allocated = 0;

        if (input_buf == NULL) {
                ntlm_negotiate_message(auth_data);
        } else {
                if (ntlm_challenge_message(auth_data, input_buf,
                                           input_len) < 0) {
                        return -1;
                }
                if (encode_ntlm_auth(smb2, auth_data,
                                     (char *)&auth_data->ntlm_buf[24]) < 0) {
                        return -1;
                }
        }

        *output_buf = auth_data->buf;
        *output_len = auth_data->len;

        return 0;
}

int
ntlmssp_get_session_key(struct auth_data *auth,
                        uint8_t **key,
                        uint8_t *key_size)
{
        uint8_t *mkey = NULL;

        if (auth == NULL || key == NULL || key_size == NULL) {
                return -1;
        }

        mkey = (uint8_t *) malloc(SMB2_KEY_SIZE);
        if (mkey == NULL) {
                return -1;
        }
        memcpy(mkey, auth->exported_session_key, SMB2_KEY_SIZE);

        *key = mkey;
        *key_size = SMB2_KEY_SIZE;

        return 0;
}
#endif /* HAVE_LIBKRB5 */
