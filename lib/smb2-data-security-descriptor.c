/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2017 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#include <stdint.h>
#include <stdio.h>
#endif

#include <inttypes.h>

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"

typedef struct _SID {
        uint8_t Revision;
        uint8_t SubAuthorityCount;
        uint8_t IdentifierAuthority[6];
        uint32_t SubAuthority[];
} SID, *PSID;

typedef struct _ACE_HEADER {
        uint8_t  AceType;
        uint8_t  AceFlags;
        uint16_t AceSize;
} ACE_HEADER, *PACE_HEADER;

typedef struct _ACCESS_ALLOWED_ACE_HEADER {
        ACE_HEADER ace_hdr;
        uint32_t   Mask;
        uint8_t    Sid[];
} ACCESS_ALLOWED_ACE_HDR, *PACCESS_ALLOWED_ACE_HDR;

typedef struct _ACCESS_ALLOWED_OBJECT_ACE_HEADER {
        ACE_HEADER ace_hdr;
        uint32_t   Mask;
        uint32_t   Flags;
        uint8_t    ObjectType[SMB2_OBJECT_TYPE_SIZE];
        uint8_t    InheritedObjectType[SMB2_OBJECT_TYPE_SIZE];
        uint8_t    Sid[];
} ACCESS_ALLOWED_OBJ_ACE_HDR, *PACCESS_ALLOWED_OBJ_ACE_HDR;

typedef struct _ACCESS_ALLOWED_CALLBACK_ACE_HEADER {
        ACE_HEADER ace_hdr;
        uint32_t   Mask;
        uint8_t    Sid[];
        /*uint8_t    ApplicationData[];*/
} ACCESS_ALLOWED_CALLBACK_ACE_HDR, *PACCESS_ALLOWED_CALLBACK_ACE_HDR;

typedef struct _ACL_HEADER {
        uint8_t  AclRevision;
        uint8_t  Sbz1; /* Padding (should be 0) */
        uint16_t AclSize;
        uint16_t AceCount;
        uint16_t Sbz2; /* Padding (should be 0) */
} ACL_HDR, *PACL_HDR;

typedef struct _SECURITY_DESCRIPTOR_RELATIVE_HEADER {
        uint8_t   Revision;
        uint8_t   Sbz1;     /* Padding (should be 0 unless SE_RM_CONTROL_VALID) */
        uint16_t  Control;
        uint32_t  OffsetOwner;    /* offset to Owner SID */
        uint32_t  OffsetGroup;    /* offset to Group SID */
        uint32_t  OffsetSacl;     /* offset to system ACL */
        uint32_t  OffsetDacl;     /* offset to discretional ACL */
        /* Owner, Group, Sacl, and Dacl data follows */
} SECURITY_DESCRIPTOR_RELATIVE_HDR, *PSECURITY_DESCRIPTOR_RELATIVE_HDR;

uint32_t
smb2_get_sid_size(struct smb2_sid *sid)
{
        uint32_t sid_size = 0;
        sid_size = sizeof(uint8_t) + sizeof(uint8_t) +
                         (SID_ID_AUTH_LEN * sizeof(uint8_t)) +
                         (sid->sub_auth_count * sizeof(uint32_t));
        return sid_size;
}

uint32_t
smb2_get_ace_size(struct smb2_ace *ace)
{
        return ace->ace_size;
}

uint32_t
smb2_get_acl_size(struct smb2_acl *acl)
{
        uint32_t acl_size = 0;
        struct   smb2_ace *ace = NULL;

        acl_size = sizeof(ACL_HDR);
        ace = acl->aces;
        while (ace) {
                acl_size += ace->ace_size;
                ace = ace->next;
        }
        return acl_size;
}

uint32_t
smb2_get_security_descriptor_size(const struct smb2_security_descriptor *sd)
{
        uint32_t sec_size = 0;

        sec_size += (5 * sizeof(uint32_t));
        if (sd->owner) {
                sec_size += smb2_get_sid_size(sd->owner);
        }
        if (sd->group) {
                sec_size += smb2_get_sid_size(sd->group);
        }
        if (sd->dacl) {
                sec_size += smb2_get_acl_size(sd->dacl);
        }
        return sec_size;
}

static struct smb2_sid *
decode_sid(struct smb2_context *smb2, struct smb2_iovec *v)
{
        struct smb2_sid *sid;
        uint8_t revision, sub_auth_count;
        int i;

        if (v->len < 8) {
                smb2_set_error(smb2, "SID must be at least 8 bytes");
                return NULL;
        }

        smb2_get_uint8(v, 0, &revision);
        if (revision != 1) {
                smb2_set_error(smb2, "can not decode sid with "
                               "revision %d", revision);
                return NULL;
        }
        smb2_get_uint8(v, 1, &sub_auth_count);

        if (v->len < 8 + sub_auth_count * sizeof(uint32_t)) {
                smb2_set_error(smb2, "SID is bigger than the buffer");
                return NULL;
        }

        sid = (struct smb2_sid *)malloc(8+(sub_auth_count * sizeof(uint32_t)));
        if (sid == NULL) {
                smb2_set_error(smb2, "failed to allocate sid.");
                return NULL;
        }

        sid->revision = revision;
        sid->sub_auth_count = sub_auth_count;
        memcpy(&sid->id_auth[0], &v->buf[2], SID_ID_AUTH_LEN);
        for (i = 0; i < sub_auth_count; i++) {
                smb2_get_uint32(v, 8 + i * sizeof(uint32_t),
                                &sid->sub_auth[i]);
        }

        v->len -= 8 + sub_auth_count * sizeof(uint32_t);
        v->buf += 8 + sub_auth_count * sizeof(uint32_t);

        return sid;
}

static struct smb2_ace *
decode_ace(struct smb2_context *smb2, struct smb2_iovec *vec)
{
        struct smb2_iovec v = *vec;
        uint8_t ace_type, ace_flags;
        uint16_t ace_size;
        struct smb2_ace *ace;

        if (v.len < 4) {
                smb2_set_error(smb2, "not enough data for ace header.");
                return NULL;
        }

        smb2_get_uint8(&v, 0, &ace_type);
        smb2_get_uint8(&v, 1, &ace_flags);
        smb2_get_uint16(&v, 2, &ace_size);

        ace = (struct smb2_ace *)malloc(sizeof(struct smb2_ace));
        if (ace == NULL) {
                smb2_set_error(smb2, "failed to allocate ace.");
                return NULL;
        }

        ace->ace_type  = ace_type;
        ace->ace_flags = ace_flags;
        ace->ace_size  = ace_size;

        /* set the fields to NULL */
        ace->ad_len = 0;
        ace->raw_len = 0;
        ace->sid = NULL;
        ace->ad_data = NULL;
        ace->raw_data = NULL;

        /* Skip past the header */
        if (ace_size < 4) {
                smb2_set_error(smb2, "not enough data for ace data.");
                return NULL;
        }
        if (v.len < ace_size) {
                smb2_set_error(smb2, "not enough data for ace data.");
                return NULL;
        }
        v.len -= 4;
        v.buf = &v.buf[4];

        /* decode the content of the ace */
        /* TODO: have a default case where we just keep the raw blob */
        switch (ace_type) {
        case SMB2_ACCESS_ALLOWED_ACE_TYPE:
        case SMB2_ACCESS_DENIED_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_ACE_TYPE:
        case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                smb2_get_uint32(&v, 0, &ace->mask);

                if (v.len < 4) {
                        smb2_set_error(smb2, "not enough data for ace data.");
                        return NULL;
                }
                v.len -= 4;
                v.buf = &v.buf[4];
                ace->sid = decode_sid(smb2, &v);
                break;
        case SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                if (v.len < 40) {
                        smb2_set_error(smb2, "not enough data for ace data.");
                        return NULL;
                }
                smb2_get_uint32(&v, 0, &ace->mask);

                v.len -= 4;
                v.buf = &v.buf[4];
                smb2_get_uint32(&v, 0, &ace->flags);

                v.len -= 4;
                v.buf = &v.buf[4];
                memcpy(ace->object_type, v.buf, SMB2_OBJECT_TYPE_SIZE);

                v.len -= SMB2_OBJECT_TYPE_SIZE;
                v.buf = &v.buf[SMB2_OBJECT_TYPE_SIZE];
                memcpy(ace->inherited_object_type, v.buf,
                       SMB2_OBJECT_TYPE_SIZE);

                v.len -= SMB2_OBJECT_TYPE_SIZE;
                v.buf = &v.buf[SMB2_OBJECT_TYPE_SIZE];
                ace->sid = decode_sid(smb2, &v);
                break;
        case SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                smb2_get_uint32(&v, 0, &ace->mask);

                if (v.len < 4) {
                        smb2_set_error(smb2, "not enough data for ace data.");
                        return NULL;
                }
                v.len -= 4;
                v.buf = &v.buf[4];
                ace->sid = decode_sid(smb2, &v);

                ace->ad_len = v.len;
                ace->ad_data = malloc(ace->ad_len);
                if (ace->ad_data == NULL) {
                        return NULL;
                }
                memcpy(ace->ad_data, v.buf, v.len);
                break;
        default:
                ace->raw_len = v.len;
                ace->raw_data = malloc(ace->raw_len);
                if (ace->raw_data == NULL) {
                        return NULL;
                }
                memcpy(ace->raw_data, v.buf, v.len);
        }

        return ace;
}

static struct smb2_acl *
decode_acl(struct smb2_context *smb2, struct smb2_iovec *vec)
{
        struct smb2_iovec v = *vec;
        struct smb2_acl *acl;
        uint8_t revision;
        uint16_t acl_size, ace_count;
        int i;

        if (v.len < 8) {
                smb2_set_error(smb2, "not enough data for acl header.");
                return NULL;
        }

        smb2_get_uint8(&v, 0, &revision);
        smb2_get_uint16(&v, 2, &acl_size);
        smb2_get_uint16(&v, 4, &ace_count);

        switch (revision) {
        case SMB2_ACL_REVISION:
        case SMB2_ACL_REVISION_DS:
                break;
        default:
                smb2_set_error(smb2, "can not decode acl with "
                               "revision %d", revision);
                return NULL;
        }
        smb2_get_uint16(&v, 2, &acl_size);
        if (v.len > acl_size) {
                v.len = acl_size;
        }
        if (v.len < acl_size) {
                smb2_set_error(smb2, "not enough data for acl");
                return NULL;
        }

        acl = (struct smb2_acl*)malloc(sizeof(struct smb2_acl));
        if (acl == NULL) {
                smb2_set_error(smb2, "failed to allocate acl.");
                return NULL;
        }

        acl->revision  = revision;
        acl->acl_size  = acl_size;
        acl->ace_count = ace_count;

        /* Skip past the ACL header to the first ace. */
        v.len -= 8;
        v.buf = &v.buf[8];

        acl->aces = NULL;
        for (i = 0; i < ace_count; i++) {
                struct smb2_ace *ace = decode_ace(smb2, &v);

                if (ace == NULL) {
                        smb2_set_error(smb2, "failed to decode ace # %d: %s",
                                       i, smb2_get_error(smb2));
                        return NULL;
                }
                /* skip to the next ace */
                if (ace->ace_size > v.len) {
                        smb2_set_error(smb2, "not enough data for ace %s",
                                       smb2_get_error(smb2));
                        return NULL;
                }
                v.len -= ace->ace_size;
                v.buf = &v.buf[ace->ace_size];

                SMB2_LIST_ADD_END(&acl->aces, ace);
        }

        return acl;
}

int
smb2_decode_security_descriptor(struct smb2_context *smb2,
                                struct smb2_security_descriptor *sd,
                                struct smb2_iovec *vec)
{
        struct smb2_iovec v;
        uint32_t offset_owner, offset_group, offset_sacl, offset_dacl;

        if (vec->len < 20) {
                return -1;
        }

        v.buf = &vec->buf[0];
        v.len = 20;

        smb2_get_uint8(&v, 0, &sd->revision);
        if (sd->revision != 1) {
                smb2_set_error(smb2, "can not decode security descriptor with "
                               "revision %d", sd->revision);
                return -1;
        }
        smb2_get_uint16(&v, 2, &sd->control);

        smb2_get_uint32(&v, 4, &offset_owner);
        smb2_get_uint32(&v, 8, &offset_group);
        smb2_get_uint32(&v, 12, &offset_sacl);
        smb2_get_uint32(&v, 16, &offset_dacl);

        /* Owner */
        if (offset_owner > 0 && offset_owner + 2 + SID_ID_AUTH_LEN < vec->len) {
                v.buf = &vec->buf[offset_owner];
                v.len = vec->len - offset_owner;

                sd->owner = decode_sid(smb2, &v);
                if (sd->owner == NULL) {
                        smb2_set_error(smb2, "failed to decode owner sid: %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
        }

        /* Group */
        if (offset_group > 0 && offset_group + 2 + SID_ID_AUTH_LEN < vec->len) {
                v.buf = &vec->buf[offset_group];
                v.len = vec->len - offset_group;

                sd->group = decode_sid(smb2, &v);
                if (sd->group == NULL) {
                        smb2_set_error(smb2, "failed to decode group sid: %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
        }

        /* DACL */
        if (offset_dacl > 0 && offset_dacl + 8 < vec->len) {
                v.buf = &vec->buf[offset_dacl];
                v.len = vec->len - offset_dacl;

                sd->dacl = decode_acl(smb2, &v);
                if (sd->dacl == NULL) {
                        smb2_set_error(smb2, "failed to decode dacl: %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
        }

        return 0;
}

int
smb2_decode_security_descriptor_buf(struct smb2_context *smb2,
                                    struct smb2_security_descriptor **sd,
                                    uint8_t *buf,
                                    uint32_t *buf_len)
{
        struct smb2_iovec vec;
        struct smb2_security_descriptor* ptr = NULL;
        vec.buf = buf;
        vec.len = *buf_len;

        ptr = (struct smb2_security_descriptor*)
                malloc(sizeof(struct smb2_security_descriptor));

        if (smb2_decode_security_descriptor(smb2, ptr, &vec)) {
                smb2_set_error(smb2, "could not decode security descriptor. %s",
                               smb2_get_error(smb2));
                return -1;
        }

        *sd = ptr;

        return 0;
}

static int
encode_sid(struct smb2_context   *smb2,
           const struct smb2_sid *sid,
           uint8_t               *buffer,
           uint32_t              buffer_len,
           uint32_t              *size_used)
{
        PSID le_sid = NULL;
        uint32_t size_required = 0;
        int i = 0;

        le_sid = (PSID) buffer;

        size_required = sizeof(uint8_t) + sizeof(uint8_t) +
                        (SID_ID_AUTH_LEN * sizeof(uint8_t)) +
                        (sid->sub_auth_count * sizeof(uint32_t));

        if (buffer_len < size_required) {
                smb2_set_error(smb2, "not enough memory to encode SID");
                return -1;
        }

        le_sid->Revision = sid->revision;
        le_sid->SubAuthorityCount = sid->sub_auth_count;
        for (i=0; i < SID_ID_AUTH_LEN; i++) {
                le_sid->IdentifierAuthority[i] = sid->id_auth[i];
        }

        for (i=0; i < sid->sub_auth_count; i++) {
                le_sid->SubAuthority[i] = htole32(sid->sub_auth[i]);
        }

        *size_used = size_required;

        return 0;
}

#define SMB2_ACE_HDR_SIZE	4
static int
encode_ace(struct smb2_context   *smb2,
           const struct smb2_ace *ace,
           uint8_t               *buffer,
           uint32_t              buffer_len,
           uint32_t              *size_used)
{
        uint32_t offset = 0;
        PACE_HEADER le_ace_hdr = NULL;

        if (buffer_len < ace->ace_size) {
                smb2_set_error(smb2, "Not enough buffer to encode ACE");
                return -1;
        }

        le_ace_hdr = (PACE_HEADER) buffer;

        le_ace_hdr->AceType = ace->ace_type;
        le_ace_hdr->AceFlags = ace->ace_flags;
        le_ace_hdr->AceSize = htole16(ace->ace_size);

        switch (ace->ace_type) {
        case SMB2_ACCESS_ALLOWED_ACE_TYPE:
        case SMB2_ACCESS_DENIED_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_ACE_TYPE:
        case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SMB2_SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                {
                        uint32_t sid_size = 0;
                        PACCESS_ALLOWED_ACE_HDR le_access_hdr = (PACCESS_ALLOWED_ACE_HDR) buffer;
                        le_access_hdr->Mask = htole32(ace->mask);
                        offset += sizeof(ACCESS_ALLOWED_ACE_HDR);

                        if (encode_sid(smb2, ace->sid,
                                       le_access_hdr->Sid,
                                       buffer_len - offset, /*buffer+offset is same*/
                                       &sid_size) < 0) {
                                smb2_set_error(smb2, "Failed to encode SID/ACE : %s",
                                               smb2_get_error(smb2));
                                return -1;
                        }
                        offset += sid_size;
                        sid_size = 0;
                }
                break;
        case SMB2_ACCESS_ALLOWED_OBJECT_ACE_TYPE:
        case SMB2_ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                {
                        uint32_t sid_size = 0;
                        int i =0;
                        PACCESS_ALLOWED_OBJ_ACE_HDR le_access_obj_hdr =
                                             (PACCESS_ALLOWED_OBJ_ACE_HDR) buffer;

                        le_access_obj_hdr->Mask = htole32(ace->mask);
                        le_access_obj_hdr->Flags = htole32(ace->flags);
                        for (i=0; i< SMB2_OBJECT_TYPE_SIZE; i++) {
                                le_access_obj_hdr->ObjectType[i] = ace->object_type[i];
                        }
                        for (i=0; i< SMB2_OBJECT_TYPE_SIZE; i++) {
                                le_access_obj_hdr->InheritedObjectType[i] =
                                                      ace->inherited_object_type[i];
                        }

                        offset += sizeof(ACCESS_ALLOWED_OBJ_ACE_HDR);

                        if (encode_sid(smb2, ace->sid,
                                       le_access_obj_hdr->Sid,
                                       buffer_len - offset,
                                       &sid_size) < 0) {
                                smb2_set_error(smb2, "Failed to encode SID/ACE 2 : %s",
                                               smb2_get_error(smb2));
                                return -1;
                        }
                        offset += sid_size;
                        sid_size = 0;
                }
                break;
        case SMB2_ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
        case SMB2_ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case SMB2_SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                {
                        uint32_t sid_size = 0;
                        int i =0;
                        PACCESS_ALLOWED_CALLBACK_ACE_HDR le_acess_callback_hdr =
                                       (PACCESS_ALLOWED_CALLBACK_ACE_HDR) buffer;

                        le_acess_callback_hdr->Mask = htole32(ace->mask);

                        offset += sizeof(ACCESS_ALLOWED_CALLBACK_ACE_HDR);

                        if (encode_sid(smb2, ace->sid,
                                       le_acess_callback_hdr->Sid,
                                       buffer_len - offset,
                                       &sid_size) < 0) {
                                smb2_set_error(smb2, "Failed to encode SID/ACE 3 : %s",
                                               smb2_get_error(smb2));
                                return -1;
                        }
                        offset += sid_size;
                        sid_size = 0;

                        for (i=0; i < ace->ad_len; i++) {
                                *(buffer + offset + i) = ace->ad_data[i];
                        }
                        offset += ace->ad_len;
                }
                break;
        default:
                {
                        int i = 0;
                        offset += sizeof(ACE_HEADER);

                        for (i=0; i < ace->raw_len; i++) {
                                *(buffer + offset + i) = ace->raw_data[i];
                        }
                        offset += ace->raw_len;
                }
                break;
        }

        *size_used = offset;

        return 0;
}

#define SMB2_ACL_HDR_SIZE	8
static int
encode_acl(struct smb2_context   *smb2,
           const struct smb2_acl *acl,
           uint8_t               *buffer,
           uint32_t              buffer_len,
           uint32_t              *size_used)
{
        PACL_HDR le_acl_hdr = NULL;
        uint32_t acl_size = 0;
        uint32_t offset = 0;
        struct   smb2_ace *ace = NULL;

        acl_size = sizeof(ACL_HDR);
        ace = acl->aces;
        while (ace) {
                acl_size += ace->ace_size;
                if (acl_size < ace->ace_size) {
                        smb2_set_error(smb2, "ACL overflow detected");
                        return -1;
                }
                if (acl_size > acl->acl_size) {
                        smb2_set_error(smb2, "Invalid ACL");
                        return -1;
                }
                ace = ace->next;
        }

        if (buffer_len < acl_size) {
                smb2_set_error(smb2, "Not enough memory to encode ACL");
                return -1;
        }

        le_acl_hdr = (PACL_HDR) buffer;

        le_acl_hdr->AclRevision = acl->revision;
        le_acl_hdr->Sbz1 = 0;
        le_acl_hdr->AclSize = htole16(acl->acl_size);
        le_acl_hdr->AceCount = htole16(acl->ace_count);
        le_acl_hdr->Sbz2 = 0;

        offset = sizeof(ACL_HDR);

        ace = acl->aces;
        while (ace) {
                uint32_t ace_size_used = 0;
                if (encode_ace(smb2, ace,
                               buffer+offset,
                               buffer_len - offset,
                               &ace_size_used) < 0) {
                        smb2_set_error(smb2, "Failed to encode ACE : %s", smb2_get_error(smb2));
                        return -1;
                }

                offset += ace_size_used; /* should this be ace->ace_size ?? */
                ace_size_used= 0;

                ace = ace->next;
        }

        *size_used = offset;

        return 0;
}

#define SMB2_SEC_DESC_HDR_SIZE	20
int
smb2_encode_security_descriptor(struct smb2_context *smb2,
                                const struct smb2_security_descriptor *sd,
                                uint8_t  *buffer,
                                uint32_t *buffer_len)
{
        uint32_t size = 0;
        uint32_t offset = 0;
        PSECURITY_DESCRIPTOR_RELATIVE_HDR le_sec_desc = NULL;

        if (buffer == NULL || buffer_len == NULL) {
                smb2_set_error(smb2, "Buffer not allocated for security descriptor");
                return -1;
        }

        size = *buffer_len;
        if (size < smb2_get_security_descriptor_size(sd)) {
                smb2_set_error(smb2, "Buffer too small to encode security descriptor");
                return -9; /* it represents buffer is insufficient */
        }

        le_sec_desc = (PSECURITY_DESCRIPTOR_RELATIVE_HDR) buffer;
        le_sec_desc->Revision = sd->revision;
        le_sec_desc->Sbz1     = 0;
        le_sec_desc->Control  = htole16(sd->control);

        offset += (5 * sizeof(uint32_t));

        if (sd->owner) {
                uint32_t size_used = 0;
                if (encode_sid(smb2, sd->owner,
                               buffer+offset,
                               size - offset,
                               &size_used) < 0) {
                        smb2_set_error(smb2, "Failed to encode owner SID : %s", smb2_get_error(smb2));
                        return -1;
                }
                le_sec_desc->OffsetOwner = htole32(offset);
                offset += size_used;
        }
        if (sd->group) {
                uint32_t size_used = 0;
                if (encode_sid(smb2, sd->group,
                               buffer+offset,
                               size - offset,
                               &size_used) < 0) {
                        smb2_set_error(smb2, "Failed to encode group SID : %s", smb2_get_error(smb2));
                        return -1;
                }
                le_sec_desc->OffsetGroup = htole32(offset);
                offset += size_used;
        }
        if (sd->dacl) {
                uint32_t size_used = 0;
                if (encode_acl(smb2, sd->dacl,
                               buffer+offset,
                               size - offset,
                               &size_used) < 0) {
                        smb2_set_error(smb2, "Failed to encode DACL : %s", smb2_get_error(smb2));
                        return -1;
                }
                le_sec_desc->OffsetDacl = htole32(offset);
                offset += size_used;
        }

        *buffer_len = offset;

        return 0;
}

static void
free_sid(struct smb2_context *smb2, struct smb2_sid *sid)
{
        if (!sid)
            return;
        free(sid);
}

static void
free_ace(struct smb2_context *smb2, struct smb2_ace *ace)
{
        if (!ace)
            return;

        if (ace->sid) {
            free_sid(smb2, ace->sid);
            ace->sid = NULL;
        }
        if (ace->ad_data) {
            free(ace->ad_data);
            ace->ad_data = NULL;
        }
        if (ace->raw_data) {
            free(ace->raw_data);
            ace->raw_data = NULL;
        }

        free(ace);
}

static void
free_acl(struct smb2_context *smb2, struct smb2_acl *acl)
{
        struct smb2_ace *ace = NULL;
        if (!acl)
            return;

        ace = acl->aces;
        for (; ace; ace = ace->next) {
            free_ace(smb2, ace);
        }
        free(acl);
}

void
smb2_free_security_descriptor(struct smb2_context *smb2,
                              struct smb2_security_descriptor *sd)
{
        if (!sd)
            return;

        if (sd->owner) {
                free_sid(smb2, sd->owner);
                sd->owner = NULL;
        }
        if (sd->group) {
                free_sid(smb2, sd->group);
                sd->group = NULL;
        }
        if (sd->dacl) {
                free_acl(smb2, sd->dacl);
                sd->dacl = NULL;
        }

        free(sd);
}

static void
print_sid(struct smb2_sid *sid)
{
        int i;
        uint64_t ia = 0;

        if (sid == NULL) {
                printf("No SID");
                return;
        }

        printf("S-1");
        for(i = 0; i < SID_ID_AUTH_LEN; i++) {
                ia <<= 8;
                ia |= sid->id_auth[i];
        }
        if (ia <= 0xffffffff) {
                printf("-%" PRIu64, ia);
        } else {
                printf("-0x%012" PRIx64, ia);
        }
        for (i = 0; i < sid->sub_auth_count; i++) {
                printf("-%u", sid->sub_auth[i]);
        }
}

static void
print_ace(struct smb2_ace *ace)
{
        printf("ACE: ");
        printf("Type:%d ", ace->ace_type);
        printf("Flags:0x%02x ", ace->ace_flags);
        switch (ace->ace_type) {
        case SMB2_ACCESS_ALLOWED_ACE_TYPE:
        case SMB2_ACCESS_DENIED_ACE_TYPE:
        case SMB2_SYSTEM_AUDIT_ACE_TYPE:
        case SMB2_SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                printf("Mask:0x%08x ", ace->mask);
                print_sid(ace->sid);
                break;
        default:
                printf("can't print this type");
        }
        printf("\n");
}

static void
print_acl(struct smb2_acl *acl)
{
        struct smb2_ace *ace;

        printf("Revision: %d\n", acl->revision);
        printf("Ace count: %d\n", acl->ace_count);
        for (ace = acl->aces; ace; ace = ace->next) {
                print_ace(ace);
        }
};

void
print_security_descriptor(struct smb2_security_descriptor *sd)
{
        printf("=============================================\n");
        printf("Revision: %d\n", sd->revision);
        printf("Control: (0x%08x) ", sd->control);
        if (sd->control & SMB2_SD_CONTROL_SR) {
                printf("SR ");
        }
        if (sd->control & SMB2_SD_CONTROL_RM) {
                printf("RM ");
        }
        if (sd->control & SMB2_SD_CONTROL_PS) {
                printf("PS ");
        }
        if (sd->control & SMB2_SD_CONTROL_PD) {
                printf("PD ");
        }
        if (sd->control & SMB2_SD_CONTROL_SI) {
                printf("SI ");
        }
        if (sd->control & SMB2_SD_CONTROL_DI) {
                printf("DI ");
        }
        if (sd->control & SMB2_SD_CONTROL_SC) {
                printf("SC ");
        }
        if (sd->control & SMB2_SD_CONTROL_DC) {
                printf("DC ");
        }
        if (sd->control & SMB2_SD_CONTROL_DT) {
                printf("DT ");
        }
        if (sd->control & SMB2_SD_CONTROL_SS) {
                printf("SS ");
        }
        if (sd->control & SMB2_SD_CONTROL_SD) {
                printf("SD ");
        }
        if (sd->control & SMB2_SD_CONTROL_SP) {
                printf("SP ");
        }
        if (sd->control & SMB2_SD_CONTROL_DD) {
                printf("DD ");
        }
        if (sd->control & SMB2_SD_CONTROL_DP) {
                printf("DP ");
        }
        if (sd->control & SMB2_SD_CONTROL_GD) {
                printf("GD ");
        }
        if (sd->control & SMB2_SD_CONTROL_OD) {
                printf("OD ");
        }
        printf("\n");

        if (sd->owner) {
                printf("Owner SID: ");
                print_sid(sd->owner);
                printf("\n");
        }
        if (sd->group) {
                printf("Group SID: ");
                print_sid(sd->group);
                printf("\n");
        }
        if (sd->dacl) {
                printf("DACL:\n");
                print_acl(sd->dacl);
        }
        printf("=============================================\n");
}
