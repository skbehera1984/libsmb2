/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
   Copyright (C) 2016 by Ronnie Sahlberg <ronniesahlberg@gmail.com>

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
#include <stdio.h>
#endif

#include <errno.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"


static int
smb2_encode_ioctl_request(struct smb2_context *smb2,
                               struct smb2_pdu *pdu,
                               struct smb2_ioctl_request *req)
{
        int len;
        uint8_t *buf;
        struct smb2_iovec *iov;

        len = SMB2_IOCTL_REQUEST_SIZE & 0xfffffffe;
        buf = malloc(len);
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate ioctl param buffer");
                return -1;
        }
        memset(buf, 0, len);

        uint32_t InputOffset = SMB2_HEADER_SIZE + sizeof(struct smb2_ioctl_request) - (1 * sizeof(uint8_t *));
        iov = smb2_add_iovector(smb2, &pdu->out, buf, len, free);

        smb2_set_uint16(iov, 0, SMB2_IOCTL_REQUEST_SIZE);
        smb2_set_uint16(iov, 2, req->reserved);
        smb2_set_uint32(iov, 4, req->ctl_code);
        smb2_set_uint64(iov, 8, req->file_id.persistent_id);
        smb2_set_uint64(iov, 16, req->file_id.volatile_id);
        smb2_set_uint32(iov, 24, InputOffset);
        smb2_set_uint32(iov, 28, req->input_count);
        smb2_set_uint32(iov, 32, req->max_input_response);
        smb2_set_uint32(iov, 36, InputOffset);
        smb2_set_uint32(iov, 40, req->output_count);
        smb2_set_uint32(iov, 44, req->max_output_response);
        smb2_set_uint32(iov, 48, req->flags);
        smb2_set_uint32(iov, 52, req->reserved2);

        buf = malloc(req->input_count);
        if (buf == NULL) {
                smb2_set_error(smb2, "Failed to allocate ioctl payload");
                return -1;
        }
        memset(buf, 0, req->input_count);

        iov = smb2_add_iovector(smb2, &pdu->out, buf, req->input_count, free);
        memcpy(iov->buf, req->input_buffer, req->input_count);

        return 0;
}

struct smb2_pdu *
smb2_cmd_ioctl_async(struct smb2_context *smb2,
                          struct smb2_ioctl_request *req,
                          smb2_command_cb cb, void *cb_data)
{
        struct smb2_pdu *pdu;

        pdu = smb2_allocate_pdu(smb2, SMB2_IOCTL, cb, cb_data);
        if (pdu == NULL) {
                return NULL;
        }

        if (smb2_encode_ioctl_request(smb2, pdu, req)) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        if (smb2_pad_to_64bit(smb2, &pdu->out) != 0) {
                smb2_free_pdu(smb2, pdu);
                return NULL;
        }

        /* Adjust credit charge for large payloads */
        uint32_t actual_payload = MAX((req->input_count + req->output_count),
                                      (req->max_input_response + req->max_output_response));
        if (smb2->supports_multi_credit) {
                pdu->header.credit_charge =
                        (actual_payload - 1) / 65536 + 1; // 3.1.5.2 of [MS-SMB2]
        }

        return pdu;
}

#define IOV_OFFSET (rep->output_offset - SMB2_HEADER_SIZE - \
                    (SMB2_IOCTL_REPLY_SIZE & 0xfffe))

int
smb2_process_ioctl_fixed(struct smb2_context *smb2,
                              struct smb2_pdu *pdu)
{
        struct smb2_ioctl_reply *rep;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];
        uint16_t struct_size;

        rep = malloc(sizeof(*rep));
        if (rep == NULL) {
                smb2_set_error(smb2, "Failed to allocate buffer for ioctl response");
                return -1;
        }
        pdu->payload = rep;

        smb2_get_uint16(iov, 0, &struct_size);
        if (struct_size != SMB2_IOCTL_REPLY_SIZE ||
            (struct_size & 0xfffe) != iov->len) {
                smb2_set_error(smb2, "Unexpected size of IOCTL reply. "
                                     "Expected %d, got %d",
                               SMB2_IOCTL_REPLY_SIZE,
                               (int)iov->len);
                return -1;
        }

        smb2_get_uint16(iov,  2, &rep->reserved);
        smb2_get_uint32(iov,  4, &rep->ctl_code);
        smb2_get_uint64(iov,  8, &rep->file_id.persistent_id);
        smb2_get_uint64(iov, 16, &rep->file_id.volatile_id);
        smb2_get_uint32(iov, 24, &rep->input_offset);
        smb2_get_uint32(iov, 28, &rep->input_count);
        smb2_get_uint32(iov, 32, &rep->output_offset);
        smb2_get_uint32(iov, 36, &rep->output_count);
        smb2_get_uint32(iov, 40, &rep->flags);
        smb2_get_uint32(iov, 44, &rep->reserved2);

        if (rep->output_count == 0) {
                smb2_set_error(smb2, "No output buffer in Ioctl response");
                return -1;
        }
        if (rep->output_offset < SMB2_HEADER_SIZE +
            (SMB2_IOCTL_REPLY_SIZE & 0xfffe)) {
                smb2_set_error(smb2, "Output buffer overlaps with Ioctl reply header");
                return -1;
        }

        /* Return the amount of data that the output buffer will take up.
         * Including any padding before the output buffer itself.
         */
        return IOV_OFFSET + rep->output_count;
}

int
smb2_process_ioctl_variable(struct smb2_context *smb2,
                                 struct smb2_pdu *pdu)
{
        struct smb2_ioctl_reply *rep = pdu->payload;
        struct smb2_iovec *iov = &smb2->in.iov[smb2->in.niov - 1];

        rep->output_buffer = &iov->buf[IOV_OFFSET];

        return 0;
}
