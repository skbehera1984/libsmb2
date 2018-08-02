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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>
#include <poll.h>
#include <stdio.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"
#include "dcerpc.h"

struct sync_cb_data {
	int is_finished;
	int status;
	void *ptr;
};

static int wait_for_reply(struct smb2_context *smb2,
                          struct sync_cb_data *cb_data)
{
        while (!cb_data->is_finished) {
                struct pollfd pfd;

		pfd.fd = smb2_get_fd(smb2);
		pfd.events = smb2_which_events(smb2);

		if (poll(&pfd, 1, 1000) < 0) {
			smb2_set_error(smb2, "Poll failed");
			return -1;
		}
                if (pfd.revents == 0) {
                        continue;
                }
		if (smb2_service(smb2, pfd.revents) < 0) {
			smb2_set_error(smb2, "smb2_service failed with : "
                                       "%s\n", smb2_get_error(smb2));
                        return -1;
		}
	}

        return 0;
}

static void connect_cb(struct smb2_context *smb2, int status,
                       void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

/*
 * Connect to the server and mount the share.
 */
int smb2_connect_share(struct smb2_context *smb2,
                       const char *server,
                       const char *share,
                       const char *user)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_connect_share_async(smb2, server, share, user,
                                     connect_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_connect_share_async failed. %s",
                               smb2_get_error(smb2));
		return -ENOMEM;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -EIO;
        }

	return cb_data.status;
}

/*
 * Disconnect from share
 */
int smb2_disconnect_share(struct smb2_context *smb2)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_disconnect_share_async(smb2, connect_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_disconnect_share_async failed");
		return -ENOMEM;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -EIO;
        }

	return cb_data.status;
}

/*
 * opendir()
 */
static void opendir_cb(struct smb2_context *smb2, int status,
                       void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->ptr = command_data;
}

struct smb2dir *smb2_opendir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_opendir_async(smb2, path,
                               opendir_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_opendir_async failed");
		return NULL;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

	return cb_data.ptr;
}

/*
 * open()
 */
static void open_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->ptr = command_data;
}

struct smb2fh *
smb2_open_file(struct smb2_context *smb2,
               const char *path,
               uint8_t  security_flags,
               uint64_t smb_create_flags,
               uint32_t desired_access,
               uint32_t file_attributes,
               uint32_t share_access,
               uint32_t create_disposition,
               uint32_t create_options
              )
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;

        if (smb2_open_file_async(smb2, path,
                                 security_flags,
                                 SMB2_IMPERSONATION_IMPERSONATION,
                                 smb_create_flags,
                                 desired_access,
                                 file_attributes,
                                 share_access,
                                 create_disposition,
                                 create_options,
                                 open_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_open_file_async failed. Error - %s",
                               smb2_get_error(smb2));
                return NULL;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

        //return cb_data.status;
        return cb_data.ptr;
}

struct smb2fh *smb2_open(struct smb2_context *smb2, const char *path, int flags)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_open_async(smb2, path, flags,
                               open_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_open_async failed");
		return NULL;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

	return cb_data.ptr;
}

/* open_pipe()
 */
struct smb2fh *smb2_open_pipe(struct smb2_context *smb2, const char *pipe)
{
        struct   sync_cb_data cb_data;
        cb_data.is_finished = 0;

        if (pipe == NULL) {
                smb2_set_error(smb2, "smb2_open_pipe:no pipe path provided");
                return NULL;
        }

        if (smb2_open_pipe_async(smb2, pipe, open_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_open_pipe_async failed : %s",
                               smb2_get_error(smb2));
                return NULL;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

        return cb_data.ptr;
}

/*
 * close()
 */
static void close_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

int smb2_close(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;

        if (smb2_close_async(smb2, fh, close_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_close_async failed");
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        return cb_data.status;
}

/*
 * fsync()
 */
static void fsync_cb(struct smb2_context *smb2, int status,
                     void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

int smb2_fsync(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_fsync_async(smb2, fh, fsync_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_fsync_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

/*
 * pread()
 */
static void generic_status_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
}

int smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
               uint8_t *buf, uint32_t count, uint64_t offset)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_pread_async(smb2, fh, buf, count, offset,
                             generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_pread_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh,
                uint8_t *buf, uint32_t count, uint64_t offset)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_pwrite_async(smb2, fh, buf, count, offset,
                              generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_pwrite_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_read(struct smb2_context *smb2, struct smb2fh *fh,
              uint8_t *buf, uint32_t count)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_read_async(smb2, fh, buf, count,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_read_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_write(struct smb2_context *smb2, struct smb2fh *fh,
               uint8_t *buf, uint32_t count)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_write_async(smb2, fh, buf, count,
                             generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_write_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_unlink(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_unlink_async(smb2, path,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_unlink_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_rmdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_rmdir_async(smb2, path,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_rmdir_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_mkdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_mkdir_async(smb2, path,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_mkdir_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh,
               struct smb2_stat_64 *st)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_fstat_async(smb2, fh, st,
                             generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_fstat_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_stat(struct smb2_context *smb2, const char *path,
              struct smb2_stat_64 *st)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_stat_async(smb2, path, st,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_stat_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_query_file_all_info(struct smb2_context *smb2,
                             const char *path,
                             struct smb2_file_info_all *all_info)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2_query_file_all_info_async(smb2, path,
                                           all_info,
                                           generic_status_cb,
                                           &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getallinfo_async failed");
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        return cb_data.status;
}

int smb2_rename(struct smb2_context *smb2, const char *oldpath,
                const char *newpath)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_rename_async(smb2, oldpath, newpath,
                            generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_rename_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_statvfs(struct smb2_context *smb2, const char *path,
                 struct smb2_statvfs *st)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_statvfs_async(smb2, path, st,
                               generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_statvfs_async failed");
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }
	return cb_data.status;
}

int smb2_truncate(struct smb2_context *smb2, const char *path,
                  uint64_t length)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_truncate_async(smb2, path, length,
                                generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_truncate_async failed. %s",
                               smb2_get_error(smb2));
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

int smb2_ftruncate(struct smb2_context *smb2, struct smb2fh *fh,
                   uint64_t length)
{
        struct sync_cb_data cb_data;

	cb_data.is_finished = 0;

	if (smb2_ftruncate_async(smb2, fh, length,
                                 generic_status_cb, &cb_data) != 0) {
		smb2_set_error(smb2, "smb2_ftruncate_async failed. %s",
                               smb2_get_error(smb2));
		return -1;
	}

	if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

	return cb_data.status;
}

static void echo_cb(struct smb2_context *smb2, int status,
                    void *command_data, void *private_data)
{
    struct sync_cb_data *cb_data = private_data;

    cb_data->is_finished = 1;
    cb_data->status = status;
}

/*
 * Send SMB2_ECHO command to the server
 */
int smb2_echo(struct smb2_context *smb2)
{
    struct sync_cb_data cb_data;

    if (smb2->is_connected == 0)
    {
        smb2_set_error(smb2, "Not Connected to Server");
        return -ENOMEM;
    }

	cb_data.is_finished = 0;

    if (smb2_echo_async(smb2, echo_cb, &cb_data) != 0)
    {
        smb2_set_error(smb2, "smb2_echo failed");
        return -ENOMEM;
    }

    if (wait_for_reply(smb2, &cb_data) < 0)
    {
        return -EIO;
    }

    return cb_data.status;
}

//#define DEBUG

int
smb2_get_security(struct smb2_context *smb2,
                  const char *path,
                  uint8_t **buf,
                  uint32_t *buf_len)
{
        int sts = 0;
        struct sync_cb_data cb_data;
        struct smb2_security_descriptor *sd = NULL;

        uint8_t *relative_sec = NULL;
        uint32_t relative_sec_size = 1024;

        if (smb2->is_connected == 0)
        {
                smb2_set_error(smb2, "Not Connected to Server");
                return -ENOMEM;
        }

        cb_data.is_finished = 0;

        if (smb2_get_security_async(smb2, path, &sd,
                                    generic_status_cb, &cb_data) != 0)
        {
                smb2_set_error(smb2, "smb2_get_security_async failedi : %s",
                               smb2_get_error(smb2));
                return -ENOMEM;
        }

        if (wait_for_reply(smb2, &cb_data) < 0)
        {
                return -EIO;
        }

#ifdef DEBUG
        print_security_descriptor(sd);
#endif

        relative_sec = (uint8_t *) calloc(1, relative_sec_size);
        if (relative_sec == NULL) {
                smb2_set_error(smb2, "smb2_get_security: No memory to get security descriptor");
                return -ENOMEM;
        }
retry:
        if ((sts = smb2_encode_security_descriptor(smb2, sd,
                                                   relative_sec,
                                                   &relative_sec_size)) < 0) {
                if (sts == -9) {
                        relative_sec_size *= 2;
                        relative_sec = (uint8_t *) realloc(relative_sec, relative_sec_size);
                        if (relative_sec == NULL) {
                                smb2_set_error(smb2, "smb2_get_security: failed to allocate memory");
                                return -ENOMEM;
                        }
                        goto retry;
                }

                smb2_set_error(smb2, "smb2_get_security: "
                                     "failed to encode security descriptor : %s",
                                     smb2_get_error(smb2));
                return -ENOMEM;
        }

        smb2_free_data(smb2, sd); sd = NULL;

        *buf = relative_sec;
        *buf_len = relative_sec_size;

        return cb_data.status;
}

int
smb2_set_security(struct smb2_context *smb2,
                  const char *path,
                  uint8_t *buf,
                  uint32_t buf_len)
{
        struct sync_cb_data cb_data;

        if (smb2->is_connected == 0)
        {
                smb2_set_error(smb2, "Not Connected to Server");
                return -ENOMEM;
        }

        cb_data.is_finished = 0;

#ifdef DEBUG
        struct smb2_iovec vec;
        struct smb2_security_descriptor *secdesc = NULL;
        vec.buf = buf;
        vec.len = buf_len;

        secdesc = (struct smb2_security_descriptor *)
                          smb2_alloc_init(smb2, sizeof(struct smb2_security_descriptor));
        if (smb2_decode_security_descriptor(smb2, secdesc, secdesc, &vec)) {
                smb2_set_error(smb2, "could not decode security "
                                      "descriptor. %s",
                               smb2_get_error(smb2));
                return -1;
        }
        print_security_descriptor(secdesc);
        smb2_free_data(smb2, secdesc); secdesc = NULL;
#endif

        if (smb2_set_security_async(smb2, path, buf, buf_len,
                                    generic_status_cb, &cb_data) != 0)
        {
                smb2_set_error(smb2, "smb2_set_security_async failed : %s",
                               smb2_get_error(smb2));
                return -ENOMEM;
        }

        if (wait_for_reply(smb2, &cb_data) < 0)
        {
                return -EIO;
        }


        return cb_data.status;
}

/*
 * Send SMB2_IOCTL command to the server
  */
int smb2_ioctl(struct smb2_context *smb2, struct smb2fh *fh,
               uint32_t ioctl_ctl, uint32_t ioctl_flags,
               uint8_t *input_buffer, uint32_t input_count,
               uint8_t *output_buffer, uint32_t *output_count)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2_ioctl_async(smb2, fh,
                             ioctl_ctl, ioctl_flags,
                             input_buffer, input_count,
                             output_buffer, output_count,
                             generic_status_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_ioctl_async failed : %s", smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        return cb_data.status;
}

/* share_enum()
 */
int smb2_list_shares(struct smb2_context *smb2,
                     const char *server,
                     const char *user,
                     uint32_t   shinfo_type,
                     struct smb2_shareinfo **shares,
                     int *numshares
                    )
{
        int status = 0;
        struct smb2fh *fh = NULL;
        uint8_t write_buf[1024] = {0};
        uint32_t write_count = 0;
        uint8_t read_buf[1024] ={0};
        struct rpc_bind_request bind_req;
        struct context_item dcerpc_ctx;

        struct rpc_header rsp_hdr;
        struct rpc_bind_response ack;
        struct rpc_bind_nack_response nack;

        uint16_t max_xmit_frag = 0;
        uint16_t max_recv_frag = 0;

        char serverName[4096] = {0};

        if (server == NULL) {
                smb2_set_error(smb2, "smb2_list_shares:server not specified");
                return -1;
        }
        if (user == NULL) {
                smb2_set_error(smb2, "smb2_list_shares:user not specified");
                return -1;
        }

        if (shares == NULL || numshares == NULL) {
                smb2_set_error(smb2, "smb2_list_shares:No memory allocated for share listing");
                return -1;
        }

        smb2->use_cached_creds = 1;
        if (smb2_connect_share(smb2, server, "IPC$", user) !=0) {
                smb2_set_error(smb2, "smb2_connect_share_async failed. %s",
                               smb2_get_error(smb2));
                return -ENOMEM;
        }

        fh = smb2_open_pipe(smb2, "srvsvc");
        if (fh == NULL) {
                smb2_set_error(smb2, "smb2_list_shares: failed to open SRVSVC pipe: %s",
                               smb2_get_error(smb2));
                return -1;
        }

        dcerpc_create_bind_req(&bind_req, 1);
        dcerpc_init_context(&dcerpc_ctx, 1,
                            INTERFACE_VERSION_MAJOR,
                            INTERFACE_VERSION_MINOR,
                            TRANSFER_SYNTAX_VERSION_MAJOR,
                            TRANSFER_SYNTAX_VERSION_MINOR);

        write_count = sizeof(struct rpc_bind_request) + sizeof(struct context_item);
        memcpy(write_buf, &bind_req, sizeof(struct rpc_bind_request));
        memcpy(write_buf+sizeof(struct rpc_bind_request), &dcerpc_ctx, sizeof(struct context_item));
        status = smb2_write(smb2, fh, write_buf, write_count);
        if (status < 0) {
                smb2_set_error(smb2, "failed to send dcerpc bind request");
                return -1;
        }

        status = smb2_read(smb2, fh, read_buf, 1024);
        if (status < 0) {
                smb2_set_error(smb2, "dcerpc bind failed");
                return -1;
        }

        if (dcerpc_get_response_header(read_buf, status, &rsp_hdr) < 0) {
                smb2_set_error(smb2, "failed to parse dcerpc response header");
                return -1;
        }

        if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDNACK) {
                if (dcerpc_get_bind_nack_response(read_buf, status, &nack) < 0) {
                        smb2_set_error(smb2, "failed to parse dcerpc BINDNACK response");
                        return -1;
                }
                smb2_set_error(smb2, "dcerpc BINDNACK reason : %s", dcerpc_get_reject_reason(nack.reject_reason));
                return -1;
        } else if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDACK) {
                if (dcerpc_get_bind_ack_response(read_buf, status, &ack) < 0) {
                        smb2_set_error(smb2, "failed to parse dcerpc BINDACK response");
                        return -1;
                }
                /* save the max xmit and recv frag details */
                max_xmit_frag = ack.max_xmit_frag;
                max_recv_frag = ack.max_recv_frag;
        }

        if (sprintf(&serverName[0], "\\\\%s", server) < 0) {
                smb2_set_error(smb2, "Failed to create NetrShareEnum request");
                return -1;
        }

        uint32_t resumeHandlePtr = 0;
        uint32_t resumeHandle = 0;
        uint32_t shares_read = 0;
        uint32_t total_share_count = 0;

        do {
                /* we need to do this in loop till we get all shares */
                uint32_t srvs_sts = 0;
                int last_frag = 1;
                uint8_t  netShareEnumBuf[1024] = {0};
                uint32_t netShareEnumBufLen = 1024;
                struct NetrShareEnumRequest *srvs_req = NULL;
                uint32_t payloadlen = 0;
                uint32_t offset = 0;

#define MAX_BUF_SIZE	(64 * 1024)
                uint8_t  output_buf[MAX_BUF_SIZE] = {0};
                uint32_t output_count = 64 * 4096;
                uint8_t  *resp = NULL;
                uint32_t share_count = 0;

                struct NetrShareEnumResponse dce_rep = {{0}};

                payloadlen = netShareEnumBufLen;
                srvs_req = (struct NetrShareEnumRequest *)&netShareEnumBuf[0];
                payloadlen -= sizeof(struct NetrShareEnumRequest);
                offset += sizeof(struct NetrShareEnumRequest);

                if (dcerpc_create_NetrShareEnumRequest_payload(smb2,
                               serverName,
                               shinfo_type,
                               resumeHandle,
                               netShareEnumBuf+offset,
                               &payloadlen) < 0) {
                        return -1;
                }

                offset += payloadlen;
                dcerpc_create_NetrShareEnumRequest(smb2, srvs_req, payloadlen);

                if (offset > max_xmit_frag) {
                        smb2_set_error(smb2, "smb2_list_shares: IOCTL Payload size is "
                                             "larger than max_xmit_frag");
                        return -1;
                }

                status = smb2_ioctl(smb2, fh,
                                    FSCTL_PIPE_TRANSCEIVE,
                                    SMB2_0_IOCTL_IS_FSCTL,
                                    netShareEnumBuf, offset,
                                    output_buf, &output_count);
                if (status < 0) {
                        smb2_set_error(smb2, "smb2_list_shares: smb2_ioctl failed : %s",
                                       smb2_get_error(smb2));
                        return -1;
                }

                /* Response parsing */
                resp = &output_buf[0];
                offset = 0;

                if (dcerpc_parse_NetrShareEnumResponse(smb2,
                                                       resp,
                                                       output_count,
                                                       &dce_rep) < 0) {
                        smb2_set_error(smb2,
                                       "dcerpc_parse_NetrShareEnumResponse failed : %s",
                                       smb2_get_error(smb2));
                        return -1;
                }

                last_frag = dce_rep.dceRpcHdr.packet_flags & RPC_FLAG_LAST_FRAG;
                /* read the complete dcerpc data - all frags */
                while (!last_frag) {
                        uint8_t *readbuf = NULL;
                        uint32_t frag_len = 0;
                        struct NetrShareEnumResponse resp2 = {{0}};
                        readbuf = (uint8_t *)calloc(1, max_recv_frag);
                        if (readbuf == NULL) {
                                smb2_set_error(smb2, "failed to allocate readbuf");
                                return -1;
                        }
                        smb2_lseek(smb2, fh, 0, SEEK_SET, NULL);
                        status = smb2_read(smb2, fh,
                                           readbuf,
                                           max_recv_frag);
                        if (status < 0) {
                                smb2_set_error(smb2, "failed to read remaining frags");
                                free(readbuf); readbuf = NULL;
                                return -1;
                        }
                        if (dcerpc_parse_NetrShareEnumResponse(smb2,
                                                               readbuf,
                                                               status,
                                                               &resp2) < 0) {
                                smb2_set_error(smb2,
                                               "dcerpc_parse_NetrShareEnumResponse-2 failed : %s",
                                               smb2_get_error(smb2));
                                free(readbuf); readbuf = NULL;
                                return -1;
                        }
                        last_frag = resp2.dceRpcHdr.packet_flags & RPC_FLAG_LAST_FRAG;
                        frag_len = status - sizeof(struct NetrShareEnumResponse);

                        if ((output_count + frag_len) > MAX_BUF_SIZE) {
                                smb2_set_error(smb2, "smb2_list_shares : 64K is not sufficient to hold shares data");
                                free(readbuf); readbuf = NULL;
                                return -1;
                        }

                        /* what if all fragments add up to > 64K?
                         * should output_buf be malloc-ed and resized?
                         */
                        /*Append the buffer*/
                        memcpy(&output_buf[output_count],
                               readbuf+sizeof(struct NetrShareEnumResponse),
                               frag_len);
                        output_count += frag_len;

                        free(readbuf);
                }

                payloadlen = output_count;
                offset += sizeof(struct NetrShareEnumResponse);
                payloadlen -= sizeof(struct NetrShareEnumResponse);

                srvs_sts = srvsvc_get_NetrShareEnum_status(smb2,
                                                           resp+offset,
                                                           payloadlen);
                if ( srvs_sts != 0x00000000 ) {
                        smb2_set_error(smb2,
                                       "SRVSVC NetrShareEnum Failed with error %x",
                                       srvs_sts);
                        break;
                }
                payloadlen -= sizeof(uint32_t);

                if (srvsvc_parse_NetrShareEnum_payload(smb2,
                                                       resp+offset,
                                                       payloadlen,
                                                       &share_count,
                                                       &total_share_count,
                                                       &resumeHandlePtr,
                                                       &resumeHandle,
                                                       shares) < 0) {
                        smb2_set_error(smb2,
                                       "srvsvc_parse_NetrShareEnum_payload failed : %s",
                                       smb2_get_error(smb2));
                        return -1;
                }
                shares_read += share_count;
        } while (shares_read < total_share_count);

        /* close the pipe  & disconnect */
        smb2_close(smb2, fh);
        smb2_disconnect_share(smb2);
        return status;
}

int
smb2_set_file_basic_info(struct smb2_context *smb2,
                         const char *path,
                         struct smb2_file_basic_info *info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;

        if (info == NULL) {
                smb2_set_error(smb2, "%s : no info to set");
                return -1;
        }
#if 0
        struct smb2_stat_64 *st
		info.creation_time.tv_sec =  st->smb2_crtime;
		info.creation_time.tv_usec = st->smb2_crtime_nsec/1000;
		info.last_access_time.tv_sec =  st->smb2_atime;
		info.last_access_time.tv_usec = st->smb2_atime_nsec/1000;
		info.last_write_time.tv_sec =  st->smb2_mtime;
		info.last_write_time.tv_usec = st->smb2_mtime_nsec/1000;
		info.change_time.tv_sec =  st->smb2_ctime;
		info.change_time.tv_usec = st->smb2_ctime_nsec/1000;

        if (st->smb2_type == SMB2_TYPE_DIRECTORY) {
                info.file_attributes &= SMB2_FILE_ATTRIBUTE_DIRECTORY;
        }
#endif
        if (smb2_set_file_basic_info_async(smb2, path, info,
                                           generic_status_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "%s failed : %s", __func__, smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        return cb_data.status;
}
