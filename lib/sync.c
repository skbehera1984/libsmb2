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
	int       is_finished;
	uint32_t  status;
	void      *ptr;
};

static void
sync_cb(struct smb2_context *smb2, uint32_t status,
        void *command_data, void *private_data)
{
        struct sync_cb_data *cb_data = private_data;

        cb_data->is_finished = 1;
        cb_data->status = status;
        cb_data->ptr = command_data;
}

static int wait_for_reply(struct smb2_context *smb2,
                          struct sync_cb_data *cb_data)
{
        while (!cb_data->is_finished) {
                struct pollfd pfd;

                pfd.fd = smb2_get_fd(smb2);
                pfd.events = smb2_which_events(smb2);

                if (pfd.fd == -1) {
                        smb2_set_error(smb2, "Socket Not Connected");
                        return -1;
                }

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

/*
 * Connect to the server and mount the share.
 */
uint32_t
smb2_connect_share(struct smb2_context *smb2,
                   const char *server,
                   const char *share,
                   const char *user)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2_connect_share_async(smb2, server, share, user,
                                     sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_connect_share_async failed. %s",
                               smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

/*
 * Disconnect from share
 */
uint32_t
smb2_disconnect_share(struct smb2_context *smb2)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        /* check to see if connected or just need to close the fd */
        if (smb2->is_connected != 1) {
                if (smb2->fd != -1) {
                        close(smb2->fd);
                        smb2->fd = -1;
                }
                return SMB2_STATUS_SUCCESS;
        }

        if (smb2_disconnect_share_async(smb2, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_disconnect_share_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

/*
 * opendir()
 */
smb2dir *smb2_querydir(struct smb2_context *smb2,
                       const char *path,
                       const char *pattern)
{
        struct sync_cb_data cb_data;
        struct smb2fh *fh = NULL;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return NULL;
        }

        if (path == NULL) {
                path = "";
        }

        fh = smb2_open_file(smb2, path, 0, 0,
                            SMB2_FILE_LIST_DIRECTORY | SMB2_FILE_READ_ATTRIBUTES,
                            SMB2_FILE_ATTRIBUTE_DIRECTORY,
                            SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE,
                            SMB2_FILE_OPEN,
                            SMB2_FILE_DIRECTORY_FILE);
        if (fh == NULL) {
                smb2_set_error(smb2, "smb2_opendir failed - %s", smb2_get_error(smb2));
                return NULL;
        }

        if (smb2_querydir_async(smb2, fh, pattern, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_querydir_async failed");
                return NULL;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

        smb2_close(smb2, fh);

        smb2_set_ntstatus(smb2, cb_data.status);

        return cb_data.ptr;
}

smb2dir *
smb2_fquerydir(struct smb2_context *smb2,
               struct smb2fh *fh,
               const char* pattern)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return NULL;
        }

        if (fh == NULL) {
                smb2_set_error(smb2, "Directory NOT opened to query");
                return NULL;
        }

        if (smb2_querydir_async(smb2, fh, pattern, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_fquerydir:smb2_querydir_async failed");
                return NULL;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

        smb2_set_ntstatus(smb2, cb_data.status);

        return cb_data.ptr;
}

/*
 * open()
 */
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

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return NULL;
        }

        if (smb2_open_file_async(smb2, path,
                                 security_flags,
                                 SMB2_IMPERSONATION_IMPERSONATION,
                                 smb_create_flags,
                                 desired_access,
                                 file_attributes,
                                 share_access,
                                 create_disposition,
                                 create_options,
                                 sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_open_file_async failed. Error - %s",
                               smb2_get_error(smb2));
                return NULL;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

        smb2_set_ntstatus(smb2, cb_data.status);

        return cb_data.ptr;
}

struct smb2fh *smb2_open(struct smb2_context *smb2, const char *path, int flags)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return NULL;
        }

        if (smb2_open_async(smb2, path, flags, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_open_async failed");
                return NULL;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

        smb2_set_ntstatus(smb2, cb_data.status);

        return cb_data.ptr;
}

/* open_pipe()
 */
struct smb2fh *smb2_open_pipe(struct smb2_context *smb2, const char *pipe)
{
        struct   sync_cb_data cb_data;
        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return NULL;
        }

        if (pipe == NULL) {
                smb2_set_error(smb2, "smb2_open_pipe:no pipe path provided");
                return NULL;
        }

        if (smb2_open_pipe_async(smb2, pipe, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_open_pipe_async failed : %s",
                               smb2_get_error(smb2));
                return NULL;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return NULL;
        }

        smb2_set_ntstatus(smb2, cb_data.status);

        return cb_data.ptr;
}

/*
 * close()
 */
uint32_t smb2_close(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_close_async(smb2, fh, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_close_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

/*
 * fsync()
 */
uint32_t smb2_fsync(struct smb2_context *smb2, struct smb2fh *fh)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_fsync_async(smb2, fh, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_fsync_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

/*
 * pread()
 */
uint32_t smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
                    uint8_t *buf, uint32_t count, uint64_t offset)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;
        fh->byte_count = 0;
        fh->bytes_remaining = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (count ==0) {
                /* don't send a 0 byte read, the server doesn't reply */
                return SMB2_STATUS_SUCCESS;
        }

        if (smb2_pread_async(smb2, fh, buf, count, offset,
                             sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_pread_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh,
                     uint8_t *buf, uint32_t count, uint64_t offset)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;
        fh->byte_count = 0;
        fh->bytes_remaining = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (count ==0) {
                /* don't send a 0 byte write, the server doesn't reply */
                return SMB2_STATUS_SUCCESS;
        }

        if (smb2_pwrite_async(smb2, fh, buf, count, offset,
                              sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_pwrite_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_read(struct smb2_context *smb2, struct smb2fh *fh,
                   uint8_t *buf, uint32_t count)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;
        fh->byte_count = 0;
        fh->bytes_remaining = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (count ==0) {
                /* don't send a 0 byte read, the server doesn't reply */
                return SMB2_STATUS_SUCCESS;
        }

        if (smb2_read_async(smb2, fh, buf, count, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_read_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_write(struct smb2_context *smb2, struct smb2fh *fh,
                    uint8_t *buf, uint32_t count)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;
        fh->byte_count = 0;
        fh->bytes_remaining = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (count ==0) {
                /* don't send a 0 byte write, the server doesn't reply */
                return SMB2_STATUS_SUCCESS;
        }

        if (smb2_write_async(smb2, fh, buf, count, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_write_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_unlink(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_unlink_async(smb2, path, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_unlink_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_rmdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_rmdir_async(smb2, path, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_rmdir_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_mkdir(struct smb2_context *smb2, const char *path)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_mkdir_async(smb2, path, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_mkdir_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh,
                    struct smb2_stat_64 *st)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_fstat_async(smb2, fh, st, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_fstat_async failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_stat(struct smb2_context *smb2, const char *path,
                   struct smb2_stat_64 *st)
{
        struct sync_cb_data cb_data;
	    cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_ALL_INFORMATION;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s", smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        st->smb2_type = SMB2_TYPE_FILE;
        if (info.u_info.all_info.basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
                st->smb2_type = SMB2_TYPE_DIRECTORY;
        }
        st->smb2_nlink      = info.u_info.all_info.standard.number_of_links;
        st->smb2_ino        = info.u_info.all_info.index_number;
        st->smb2_size       = info.u_info.all_info.standard.end_of_file;
        st->smb2_atime      = info.u_info.all_info.basic.last_access_time.tv_sec;
        st->smb2_atime_nsec = info.u_info.all_info.basic.last_access_time.tv_usec * 1000;
        st->smb2_mtime      = info.u_info.all_info.basic.last_write_time.tv_sec;
        st->smb2_mtime_nsec = info.u_info.all_info.basic.last_write_time.tv_usec * 1000;
        st->smb2_ctime      = info.u_info.all_info.basic.change_time.tv_sec;
        st->smb2_ctime_nsec = info.u_info.all_info.basic.change_time.tv_usec * 1000;
        st->smb2_crtime      = info.u_info.all_info.basic.creation_time.tv_sec;
        st->smb2_crtime_nsec = info.u_info.all_info.basic.creation_time.tv_usec * 1000;

        return cb_data.status;
}

uint32_t smb2_statvfs(struct smb2_context *smb2, const char *path,
                      struct smb2_statvfs *st)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILESYSTEM;
        info.file_info_class = SMB2_FILE_FS_FULL_SIZE_INFORMATION;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s", smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        memset(st, 0, sizeof(struct smb2_statvfs));
        st->f_bsize = st->f_frsize = info.u_info.fs_full_size_info.bytes_per_sector *
                                     info.u_info.fs_full_size_info.sectors_per_allocation_unit;
        st->f_blocks = info.u_info.fs_full_size_info.total_allocation_units;
        st->f_bfree = st->f_bavail = info.u_info.fs_full_size_info.caller_available_allocation_units;

        return cb_data.status;
}

uint32_t
smb2_getinfo_all(struct smb2_context *smb2,
                 const char *path,
                 struct smb2_file_info_all *all_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_ALL_INFORMATION;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s", smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        all_info->smb2_type = SMB2_TYPE_FILE;
        if (info.u_info.all_info.basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
                all_info->smb2_type = SMB2_TYPE_DIRECTORY;
        }
        all_info->smb2_ino           = info.u_info.all_info.index_number;
        all_info->ea_size            = info.u_info.all_info.ea_size;

        all_info->smb2_atime         = info.u_info.all_info.basic.last_access_time.tv_sec;
        all_info->smb2_atime_nsec    = info.u_info.all_info.basic.last_access_time.tv_usec * 1000;
        all_info->smb2_mtime         = info.u_info.all_info.basic.last_write_time.tv_sec;
        all_info->smb2_mtime_nsec    = info.u_info.all_info.basic.last_write_time.tv_usec * 1000;
        all_info->smb2_ctime         = info.u_info.all_info.basic.change_time.tv_sec;
        all_info->smb2_ctime_nsec    = info.u_info.all_info.basic.change_time.tv_usec * 1000;
        all_info->smb2_crtime        = info.u_info.all_info.basic.creation_time.tv_sec;
        all_info->smb2_crtime_nsec   = info.u_info.all_info.basic.creation_time.tv_usec * 1000;
        all_info->file_attributes    = info.u_info.all_info.basic.file_attributes;

        all_info->smb2_size          = info.u_info.all_info.standard.end_of_file;
        all_info->smb2_nlink         = info.u_info.all_info.standard.number_of_links;
        all_info->allocation_size    = info.u_info.all_info.standard.allocation_size;
        all_info-> end_of_file       = info.u_info.all_info.standard.end_of_file;
        all_info-> delete_pending    = info.u_info.all_info.standard.delete_pending;
        all_info-> directory         = info.u_info.all_info.standard.directory;

        return cb_data.status;
}

uint32_t
smb2_fgetinfo_all(struct smb2_context *smb2,
                  struct smb2fh *fh,
                  struct smb2_file_info_all *all_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_ALL_INFORMATION;

        if (smb2_fgetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s", smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        all_info->smb2_type = SMB2_TYPE_FILE;
        if (info.u_info.all_info.basic.file_attributes & SMB2_FILE_ATTRIBUTE_DIRECTORY) {
                all_info->smb2_type = SMB2_TYPE_DIRECTORY;
        }
        all_info->smb2_ino           = info.u_info.all_info.index_number;
        all_info->ea_size            = info.u_info.all_info.ea_size;

        all_info->smb2_atime         = info.u_info.all_info.basic.last_access_time.tv_sec;
        all_info->smb2_atime_nsec    = info.u_info.all_info.basic.last_access_time.tv_usec * 1000;
        all_info->smb2_mtime         = info.u_info.all_info.basic.last_write_time.tv_sec;
        all_info->smb2_mtime_nsec    = info.u_info.all_info.basic.last_write_time.tv_usec * 1000;
        all_info->smb2_ctime         = info.u_info.all_info.basic.change_time.tv_sec;
        all_info->smb2_ctime_nsec    = info.u_info.all_info.basic.change_time.tv_usec * 1000;
        all_info->smb2_crtime        = info.u_info.all_info.basic.creation_time.tv_sec;
        all_info->smb2_crtime_nsec   = info.u_info.all_info.basic.creation_time.tv_usec * 1000;
        all_info->file_attributes    = info.u_info.all_info.basic.file_attributes;

        all_info->smb2_size          = info.u_info.all_info.standard.end_of_file;
        all_info->smb2_nlink         = info.u_info.all_info.standard.number_of_links;
        all_info->allocation_size    = info.u_info.all_info.standard.allocation_size;
        all_info-> end_of_file       = info.u_info.all_info.standard.end_of_file;
        all_info-> delete_pending    = info.u_info.all_info.standard.delete_pending;
        all_info-> directory         = info.u_info.all_info.standard.directory;

        return cb_data.status;
}

uint32_t
smb2_setinfo_basic(struct smb2_context *smb2,
                   const char *path,
                   struct smb2_file_basic_info *basic_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (basic_info == NULL) {
                smb2_set_error(smb2, "%s : no info to set");
                return SMB2_STATUS_INVALID_ARGUMENT;
        }

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_BASIC_INFORMATION;
        info.u_info.basic_info = *basic_info;

        if (smb2_setinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "%s failed : %s", __func__, smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

		if (wait_for_reply(smb2, &cb_data) < 0) {
				return SMB2_STATUS_SOCKET_ERROR;
		}

		return cb_data.status;
}

uint32_t
smb2_fsetinfo_basic(struct smb2_context *smb2,
                    struct smb2fh *fh,
                    struct smb2_file_basic_info *basic_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (basic_info == NULL) {
                smb2_set_error(smb2, "%s : no info to set");
                return SMB2_STATUS_INVALID_ARGUMENT;
        }

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_BASIC_INFORMATION;
        info.u_info.basic_info = *basic_info;

        if (smb2_fsetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "%s failed : %s", __func__, smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

		if (wait_for_reply(smb2, &cb_data) < 0) {
				return SMB2_STATUS_SOCKET_ERROR;
		}

		return cb_data.status;
}

uint32_t smb2_rename(struct smb2_context *smb2,
                     const char *oldpath,
                     const char *newpath)
{
        struct sync_cb_data cb_data;
        smb2_file_info info;
        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_RENAME_INFORMATION;
        info.u_info.rename_info.replace_if_exist = 0;
        info.u_info.rename_info.file_name = discard_const(newpath);

        if (smb2_setinfo_async(smb2, oldpath, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_rename  failed");
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_truncate(struct smb2_context *smb2,
                       const char *path,
                       uint64_t length)
{
        struct sync_cb_data cb_data;
        smb2_file_info info;
        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_END_OF_FILE_INFORMATION;
        info.u_info.eof_info.end_of_file = length;

        if (smb2_setinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_truncate failed. %s",
                               smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t smb2_ftruncate(struct smb2_context *smb2,
                        struct smb2fh *fh,
                        uint64_t length)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_ftruncate_async(smb2, fh, length, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_ftruncate_async failed. %s",
                               smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

/*
 * Send SMB2_ECHO command to the server
 */
uint32_t smb2_echo(struct smb2_context *smb2)
{
    struct sync_cb_data cb_data;

    if (smb2->is_connected == 0)
    {
        smb2_set_error(smb2, "Not Connected to Server");
        return SMB2_STATUS_CONNECTION_DISCONNECTED;
    }

	cb_data.is_finished = 0;

    if (smb2_echo_async(smb2, sync_cb, &cb_data) != 0)
    {
        smb2_set_error(smb2, "smb2_echo failed");
        return SMB2_STATUS_PAYLOAD_FAILED;
    }

    if (wait_for_reply(smb2, &cb_data) < 0)
    {
        return SMB2_STATUS_SOCKET_ERROR;
    }

    return cb_data.status;
}

//#define DEBUG

uint32_t
smb2_get_security(struct smb2_context *smb2,
                  const char *path,
                  uint8_t **buf,
                  uint32_t *buf_len)
{
        int sts = 0;
        struct sync_cb_data cb_data;
        smb2_file_info info;

        uint8_t *relative_sec = NULL;
        uint32_t relative_sec_size = 1024;

        if (smb2->is_connected == 0)
        {
                smb2_set_error(smb2, "Not Connected to Server");
                return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        cb_data.is_finished = 0;

        info.info_type = SMB2_0_INFO_SECURITY;
        info.u_info.security_info = NULL;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s", smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0)
        {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        if (cb_data.status != SMB2_STATUS_SUCCESS) {
                return cb_data.status;
        }

#ifdef DEBUG
        print_security_descriptor(info.u_info.security_info);
#endif

        relative_sec = (uint8_t *) calloc(1, relative_sec_size);
        if (relative_sec == NULL) {
                smb2_set_error(smb2, "smb2_get_security: No memory to get security descriptor");
                return -ENOMEM;
        }
retry:
        if ((sts = smb2_encode_security_descriptor(smb2, info.u_info.security_info,
                                                   relative_sec,
                                                   &relative_sec_size)) < 0) {
                if (sts == -9) {
                        relative_sec_size *= 2;
                        relative_sec = (uint8_t *) realloc(relative_sec, relative_sec_size);
                        if (relative_sec == NULL) {
                                smb2_set_error(smb2, "smb2_get_security: failed to allocate memory");
                                return SMB2_STATUS_NO_MEMORY;
                        }
                        goto retry;
                }

                smb2_set_error(smb2, "smb2_get_security: "
                                     "failed to encode security descriptor : %s",
                                     smb2_get_error(smb2));
                return SMB2_STATUS_INTERNAL_ERROR;
        }

        smb2_free_security_descriptor(smb2, info.u_info.security_info);
        info.u_info.security_info= NULL;

        *buf = relative_sec;
        *buf_len = relative_sec_size;

        return cb_data.status;
}

uint32_t
smb2_fget_security(struct smb2_context *smb2,
                   struct smb2fh *fh,
                   uint8_t **buf,
                   uint32_t *buf_len)
{
        int sts = 0;
        struct sync_cb_data cb_data;
        smb2_file_info info;

        uint8_t *relative_sec = NULL;
        uint32_t relative_sec_size = 1024;

        if (smb2->is_connected == 0)
        {
                smb2_set_error(smb2, "Not Connected to Server");
                return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        cb_data.is_finished = 0;

        info.info_type = SMB2_0_INFO_SECURITY;
        info.u_info.security_info = NULL;

        if (smb2_fgetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s", smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0)
        {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        if (cb_data.status != SMB2_STATUS_SUCCESS) {
                return cb_data.status;
        }

#ifdef DEBUG
        print_security_descriptor(info.u_info.security_info);
#endif

        relative_sec = (uint8_t *) calloc(1, relative_sec_size);
        if (relative_sec == NULL) {
                smb2_set_error(smb2, "smb2_get_security: No memory to get security descriptor");
                return -ENOMEM;
        }
retry:
        if ((sts = smb2_encode_security_descriptor(smb2, info.u_info.security_info,
                                                   relative_sec,
                                                   &relative_sec_size)) < 0) {
                if (sts == -9) {
                        relative_sec_size *= 2;
                        relative_sec = (uint8_t *) realloc(relative_sec, relative_sec_size);
                        if (relative_sec == NULL) {
                                smb2_set_error(smb2, "smb2_get_security: failed to allocate memory");
                                return SMB2_STATUS_NO_MEMORY;
                        }
                        goto retry;
                }

                smb2_set_error(smb2, "smb2_get_security: "
                                     "failed to encode security descriptor : %s",
                                     smb2_get_error(smb2));
                return SMB2_STATUS_INTERNAL_ERROR;
        }

        smb2_free_security_descriptor(smb2, info.u_info.security_info);
        info.u_info.security_info= NULL;

        *buf = relative_sec;
        *buf_len = relative_sec_size;

        return cb_data.status;
}

uint32_t
smb2_set_security(struct smb2_context *smb2,
                  const char *path,
                  uint8_t *buf,
                  uint32_t buf_len)
{
        struct sync_cb_data cb_data;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
                smb2_set_error(smb2, "Not Connected to Server");
                return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        cb_data.is_finished = 0;

#ifdef DEBUG
        struct smb2_iovec vec;
        struct smb2_security_descriptor *secdesc = NULL;
        vec.buf = buf;
        vec.len = buf_len;

        secdesc = (struct smb2_security_descriptor *)malloc(sizeof(struct smb2_security_descriptor));
        if (smb2_decode_security_descriptor(smb2, secdesc, &vec)) {
                smb2_set_error(smb2, "could not decode security "
                                      "descriptor. %s",
                               smb2_get_error(smb2));
                return SMB2_STATUS_INTERNAL_ERROR;
        }
        print_security_descriptor(secdesc);
        smb2_free_security_descriptor(smb2, secdesc); secdesc = NULL;
#endif

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_SECURITY;
        info.file_info_class = 0;
        info.u_info.sec_info.secbuf = buf;
        info.u_info.sec_info.secbuf_len = buf_len;

        if (smb2_setinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0)
        {
                smb2_set_error(smb2, "smb2_set_security_async failed : %s",
                               smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0)
        {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

uint32_t
smb2_fset_security(struct smb2_context *smb2,
                   struct smb2fh *fh,
                   uint8_t *buf,
                   uint32_t buf_len)
{
        struct sync_cb_data cb_data;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
                smb2_set_error(smb2, "Not Connected to Server");
                return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        cb_data.is_finished = 0;

#ifdef DEBUG
        struct smb2_iovec vec;
        struct smb2_security_descriptor *secdesc = NULL;
        vec.buf = buf;
        vec.len = buf_len;

        secdesc = (struct smb2_security_descriptor *)malloc(sizeof(struct smb2_security_descriptor));
        if (smb2_decode_security_descriptor(smb2, secdesc, &vec)) {
                smb2_set_error(smb2, "could not decode security "
                                      "descriptor. %s",
                               smb2_get_error(smb2));
                return SMB2_STATUS_INTERNAL_ERROR;
        }
        print_security_descriptor(secdesc);
        smb2_free_security_descriptor(smb2, secdesc); secdesc = NULL;
#endif

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_SECURITY;
        info.file_info_class = 0;
        info.u_info.sec_info.secbuf = buf;
        info.u_info.sec_info.secbuf_len = buf_len;

        if (smb2_fsetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0)
        {
                smb2_set_error(smb2, "smb2_set_security_async failed : %s",
                               smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0)
        {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        return cb_data.status;
}

/*
 * Send SMB2_IOCTL command to the server
  */
uint32_t
smb2_ioctl(struct smb2_context *smb2, struct smb2fh *fh,
           uint32_t ioctl_ctl, uint32_t ioctl_flags,
           uint8_t *input_buffer, uint32_t input_count,
           uint8_t *output_buffer, uint32_t *output_count)
{
        struct sync_cb_data cb_data;

        cb_data.is_finished = 0;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (smb2_ioctl_async(smb2, fh,
                             ioctl_ctl, ioctl_flags,
                             input_buffer, input_count,
                             output_buffer, output_count,
                             sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_ioctl_async failed : %s", smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
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
        uint32_t  status = 0;
        struct    smb2fh *fh = NULL;
        uint8_t   ioctl_IN[1024] = {0};
        uint32_t  ioctl_IN_Cnt = 0;
        uint8_t   ioctl_OUT[1024] ={0};
        uint32_t  ioctl_OUT_Cnt = 1024;
        struct    rpc_bind_request bind_req;
        struct    context_item dcerpc_ctx;

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
                smb2_disconnect_share(smb2);
                return -1;
        }

        dcerpc_create_bind_req(&bind_req, 1);
        dcerpc_init_context(&dcerpc_ctx, CONTEXT_SRVSVC);

        ioctl_IN_Cnt = sizeof(struct rpc_bind_request) + sizeof(struct context_item);
        memcpy(ioctl_IN, &bind_req, sizeof(struct rpc_bind_request));
        memcpy(ioctl_IN+sizeof(struct rpc_bind_request), &dcerpc_ctx, sizeof(struct context_item));

        /* We can achieve BIND doing write and read on the PIPE too, similar to SMB1 */
        status = smb2_ioctl(smb2, fh,
                            FSCTL_PIPE_TRANSCEIVE,
                            SMB2_0_IOCTL_IS_FSCTL,
                            ioctl_IN, ioctl_IN_Cnt,
                            ioctl_OUT, &ioctl_OUT_Cnt);
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "smb2_list_shares: smb2_ioctl failed for BIND : %s", smb2_get_error(smb2));
                smb2_close(smb2, fh);
                smb2_disconnect_share(smb2);
                return -1;
        }

        if (dcerpc_get_response_header(ioctl_OUT, ioctl_OUT_Cnt, &rsp_hdr) < 0) {
                smb2_set_error(smb2, "failed to parse dcerpc response header");
                smb2_close(smb2, fh);
                smb2_disconnect_share(smb2);
                return -1;
        }

        if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDNACK) {
                if (dcerpc_get_bind_nack_response(ioctl_OUT, ioctl_OUT_Cnt, &nack) < 0) {
                        smb2_set_error(smb2, "failed to parse dcerpc BINDNACK response");
                        smb2_close(smb2, fh);
                        smb2_disconnect_share(smb2);
                        return -1;
                }
                smb2_set_error(smb2, "dcerpc BINDNACK reason : %s", dcerpc_get_reject_reason(nack.reject_reason));
                smb2_close(smb2, fh);
                smb2_disconnect_share(smb2);
                return -1;
        } else if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDACK) {
                if (dcerpc_get_bind_ack_response(ioctl_OUT, ioctl_OUT_Cnt, &ack) < 0) {
                        smb2_set_error(smb2, "failed to parse dcerpc BINDACK response");
                        smb2_close(smb2, fh);
                        smb2_disconnect_share(smb2);
                        return -1;
                }
                /* save the max xmit and recv frag details */
                max_xmit_frag = ack.max_xmit_frag;
                max_recv_frag = ack.max_recv_frag;
        }

        if (sprintf(&serverName[0], "\\\\%s", server) < 0) {
                smb2_set_error(smb2, "Failed to create NetrShareEnum request");
                smb2_close(smb2, fh);
                smb2_disconnect_share(smb2);
                return -1;
        }

        uint32_t resumeHandlePtr = 0;
        uint32_t resumeHandle = 0;
        uint32_t shares_read = 0;
        uint32_t total_share_count = 0;
        uint8_t  *sharesBuff = NULL;
        uint32_t sharesBuffLen = 0;

        uint8_t *fragmentBuf = NULL;

        do {
                /* we need to do this in loop till we get all shares */
                uint32_t srvs_sts = 0;
                int last_frag = 1;
                uint8_t  netShareEnumBuf[1024] = {0};
                uint32_t netShareEnumBufLen = 1024;
                struct DceRpcOperationRequest *dceOpReq = NULL;
                uint32_t payloadlen = 0;
                uint32_t offset = 0;

#define MAX_BUF_SIZE	(64 * 1024)
                uint8_t  output_buf[MAX_BUF_SIZE] = {0};
                uint32_t output_count = MAX_BUF_SIZE;
                uint32_t share_count = 0;

                struct DceRpcOperationResponse dceOpRes = {{0}};

                payloadlen = netShareEnumBufLen;
                dceOpReq = (struct DceRpcOperationRequest *)&netShareEnumBuf[0];
                payloadlen -= sizeof(struct DceRpcOperationRequest);
                offset += sizeof(struct DceRpcOperationRequest);

                if (srvsvc_create_NetrShareEnumRequest(smb2,
                                                       serverName,
                                                       shinfo_type,
                                                       resumeHandle,
                                                       netShareEnumBuf+offset,
                                                       &payloadlen) < 0) {
                        goto error;
                }

                offset += payloadlen;
                /* opnum - 15 - for share enumeration */
                dcerpc_create_Operation_Request(smb2, dceOpReq, DCE_OP_SHARE_ENUM, payloadlen);

                if (offset > max_xmit_frag) {
                        smb2_set_error(smb2, "smb2_list_shares: IOCTL Payload size is "
                                             "larger than max_xmit_frag");
                        goto error;
                }

                status = smb2_ioctl(smb2, fh,
                                    FSCTL_PIPE_TRANSCEIVE,
                                    SMB2_0_IOCTL_IS_FSCTL,
                                    netShareEnumBuf, offset,
                                    output_buf, &output_count);
                if (status != SMB2_STATUS_SUCCESS) {
                        smb2_set_error(smb2, "smb2_list_shares: smb2_ioctl failed : %s",
                                       smb2_get_error(smb2));
                        goto error;
                }
                offset = 0;

                /* save the shares data */
                sharesBuff = (uint8_t*) malloc(output_count);
                if (sharesBuff == NULL) {
                        smb2_set_error(smb2, "Failed to allocate shares buffer");
                        goto error;
                }
                memcpy(sharesBuff, &output_buf[0], output_count);
                sharesBuffLen += output_count;

                /* Response parsing */
                if (dcerpc_parse_Operation_Response(smb2, sharesBuff, sharesBuffLen, &dceOpRes, &status) < 0) {
                        smb2_set_error(smb2,
                                       "dcerpc_parse_Operation_Response failed : %x", status);
                        goto error;
                }

                last_frag = dceOpRes.dceRpcHdr.packet_flags & RPC_FLAG_LAST_FRAG;
                /* read the complete dcerpc data - all frags */
                while (!last_frag) {
                        uint32_t bytes_read = 0;
                        uint32_t frag_len = 0;
                        struct DceRpcOperationResponse dceOpRes2 = {{0}};

                        fragmentBuf = (uint8_t *)calloc(1, max_recv_frag);
                        if (fragmentBuf == NULL) {
                                smb2_set_error(smb2, "failed to allocate fragmentBuf");
                                goto error;
                        }
                        smb2_lseek(smb2, fh, 0, SEEK_SET, NULL);
                        status = smb2_read(smb2, fh,
                                           fragmentBuf,
                                           max_recv_frag);
                        if (status != SMB2_STATUS_SUCCESS && status != SMB2_STATUS_END_OF_FILE) {
                                smb2_set_error(smb2, "failed to read remaining frags");
                                goto error;
                        }
                        bytes_read = fh->byte_count;
                        if (dcerpc_parse_Operation_Response(smb2,
                                                            fragmentBuf,
                                                            bytes_read,
                                                            &dceOpRes2,
                                                            &status) < 0) {
                                smb2_set_error(smb2,
                                               "dcerpc_parse_Operation_Response -2 failed : %x", status);
                                goto error;
                        }
                        last_frag = dceOpRes2.dceRpcHdr.packet_flags & RPC_FLAG_LAST_FRAG;
                        frag_len = bytes_read - sizeof(struct DceRpcOperationResponse);

                        /* Extend the buffer and Append data */
                        sharesBuff = (uint8_t*)realloc(sharesBuff, sharesBuffLen+frag_len);
                        if (sharesBuff == NULL) {
                                smb2_set_error(smb2, "smb2_list_shares : Failed to re-allocate sharesBuff");
                                goto error;
                        }
                        memcpy(&sharesBuff[sharesBuffLen],
                               fragmentBuf+sizeof(struct DceRpcOperationResponse),
                               frag_len);
                        sharesBuffLen += frag_len;

                        free(fragmentBuf); fragmentBuf= NULL;
                }

                offset = 0;
                payloadlen = sharesBuffLen;
                offset += sizeof(struct DceRpcOperationResponse);
                payloadlen -= sizeof(struct DceRpcOperationResponse);

                srvs_sts = srvsvc_get_NetrShareEnum_status(smb2,
                                                           sharesBuff+offset,
                                                           payloadlen);
                if ( srvs_sts != 0x00000000 ) {
                        smb2_set_error(smb2,
                                       "SRVSVC NetrShareEnum Failed with error %x",
                                       srvs_sts);
                        goto error;
                }
                payloadlen -= sizeof(uint32_t);

                if (srvsvc_parse_NetrShareEnumResponse(smb2,
                                                       sharesBuff+offset,
                                                       payloadlen,
                                                       &share_count,
                                                       &total_share_count,
                                                       &resumeHandlePtr,
                                                       &resumeHandle,
                                                       shares) < 0) {
                        smb2_set_error(smb2,
                                       "srvsvc_parse_NetrShareEnumResponse failed : %s",
                                       smb2_get_error(smb2));
                        goto error;
                }
                shares_read += share_count;
        } while (shares_read < total_share_count);

        free(sharesBuff); sharesBuff = NULL;
        /* close the pipe  & disconnect */
        smb2_close(smb2, fh);
        smb2_disconnect_share(smb2);
        return 0;

error:
        if (sharesBuff) {
            free(sharesBuff);
        }
        if (fragmentBuf) {
            free(fragmentBuf);
        }
        /* close the pipe  & disconnect */
        smb2_close(smb2, fh);
        smb2_disconnect_share(smb2);
        return -1;
}

uint32_t
smb2_getinfo_basic(struct smb2_context *smb2,
                      const char *path,
                      struct smb2_file_basic_info *basic_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_BASIC_INFORMATION;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s",
                smb2_get_error(smb2));
                return SMB2_STATUS_PAYLOAD_FAILED;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return SMB2_STATUS_SOCKET_ERROR;
        }

        *basic_info = info.u_info.basic_info;

        return cb_data.status;
}

uint32_t
smb2_fgetinfo_basic(struct smb2_context *smb2,
                       struct smb2fh *fh,
                       struct smb2_file_basic_info *basic_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_BASIC_INFORMATION;

        if (smb2_fgetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s",
                smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        *basic_info = info.u_info.basic_info;
        return cb_data.status;
}

uint32_t
smb2_getinfo_standard(struct smb2_context *smb2,
                      const char *path,
                      struct smb2_file_standard_info *standard_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_STANDARD_INFORMATION;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s",
                smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        *standard_info = info.u_info.standard_info;
        return cb_data.status;
}

uint32_t
smb2_fgetinfo_standard(struct smb2_context *smb2,
                       struct smb2fh *fh,
                       struct smb2_file_standard_info *standard_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_STANDARD_INFORMATION;

        if (smb2_fgetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s",
                smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        *standard_info = info.u_info.standard_info;
        return cb_data.status;
}

uint32_t
smb2_getinfo_extended(struct smb2_context *smb2,
                      const char *path,
                      struct smb2_file_extended_info **extended_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
        info.u_info.extended_info = NULL;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s",
                smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        if (cb_data.status == SMB2_STATUS_SUCCESS) {
                *extended_info = info.u_info.extended_info;
        }
        return cb_data.status;
}

uint32_t
smb2_fgetinfo_extended(struct smb2_context *smb2,
                       struct smb2fh *fh,
                       struct smb2_file_extended_info **extended_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
        info.u_info.extended_info = NULL;

        if (smb2_fgetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s",
                smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        if (cb_data.status == SMB2_STATUS_SUCCESS) {
                *extended_info = info.u_info.extended_info;
        }
        return cb_data.status;
}

static uint32_t
smb2_get_file_extended_size(struct smb2_file_extended_info *info,
                            const int count)
{
        uint32_t size = 0;
        int entries = 0;
        struct smb2_file_extended_info* tmp_info = info;

        while (entries < count) {
                size += sizeof(struct smb2_file_full_ea_info)-
                        (2*sizeof(uint8_t*));
                size += tmp_info->name_len + 1;
                size += tmp_info->value_len;

                if ((size & 0x03) != 0) {
                        uint32_t padlen = 0;
                        padlen = 4 - (size & 0x03);
                        size += padlen;
                }
                tmp_info++;
                entries++;
        };

        return size;
}

uint32_t
smb2_setinfo_extended(struct smb2_context *smb2,
                      const char *path,
                      struct smb2_file_extended_info* extended_info,
                      const int count)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (extended_info == NULL) {
                smb2_set_error(smb2, "%s : no info to set");
                return -1;
        }

        uint32_t eabuf_size = smb2_get_file_extended_size(extended_info, count);

        struct smb2_file_full_extended_info full_extended_info;
        full_extended_info.eabuf = (uint8_t*)malloc(eabuf_size);
        full_extended_info.eabuf_len = 0;
        smb2_encode_file_extended_info(smb2, extended_info, count,
                                       full_extended_info.eabuf,
                                       &full_extended_info.eabuf_len);

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
        info.u_info.full_extended_info = full_extended_info;

        if (smb2_setinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "%s failed : %s", __func__,
                               smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        return cb_data.status;
}

uint32_t
smb2_fsetinfo_extended(struct smb2_context *smb2,
                       struct smb2fh *fh,
                       struct smb2_file_extended_info* extended_info,
                       const int count)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        if (extended_info == NULL) {
                smb2_set_error(smb2, "%s : no info to set");
                return -1;
        }

        uint32_t eabuf_size = smb2_get_file_extended_size(extended_info, count);

        struct smb2_file_full_extended_info full_extended_info;
        full_extended_info.eabuf = (uint8_t*)malloc(eabuf_size);
        full_extended_info.eabuf_len = 0;
        smb2_encode_file_extended_info(smb2, extended_info, count,
                                       full_extended_info.eabuf,
                                       &full_extended_info.eabuf_len);

        memset(&info, 0, sizeof(smb2_file_info));
        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_FULL_EA_INFORMATION;
        info.u_info.full_extended_info = full_extended_info;

        if (smb2_fsetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "%s failed : %s", __func__,
                               smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        return cb_data.status;
}

uint32_t
smb2_getinfo_stream(struct smb2_context *smb2,
                    const char *path,
                    struct smb2_file_stream_info **stream_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_STREAM_INFORMATION;
        info.u_info.stream_info = NULL;

        if (smb2_getinfo_async(smb2, path, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_getinfo_async failed - %s",
                smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        if (cb_data.status == SMB2_STATUS_SUCCESS) {
                *stream_info = info.u_info.stream_info;
        }
        return cb_data.status;
}

uint32_t
smb2_fgetinfo_stream(struct smb2_context *smb2,
                     struct smb2fh *fh,
                     struct smb2_file_stream_info **stream_info)
{
        struct sync_cb_data cb_data;
        cb_data.is_finished = 0;
        smb2_file_info info;

        if (smb2->is_connected == 0)
        {
            smb2_set_error(smb2, "Not Connected to Server");
            return SMB2_STATUS_CONNECTION_DISCONNECTED;
        }

        info.info_type = SMB2_0_INFO_FILE;
        info.file_info_class = SMB2_FILE_STREAM_INFORMATION;
        info.u_info.stream_info = NULL;

        if (smb2_fgetinfo_async(smb2, fh, &info, sync_cb, &cb_data) != 0) {
                smb2_set_error(smb2, "smb2_fgetinfo_async failed - %s",
                smb2_get_error(smb2));
                return -1;
        }

        if (wait_for_reply(smb2, &cb_data) < 0) {
                return -1;
        }

        if (cb_data.status == SMB2_STATUS_SUCCESS) {
                *stream_info = info.u_info.stream_info;
        }
        return cb_data.status;
}

/* lookUpSid()
 */
int smb2_lookUpSid(struct smb2_context *smb2,
                   const char          *user,
                   const char          *domain,
                   const char          *server,
                   uint8_t            **sid)
{
#define	MAX_IN_BUF_SIZE		(1 * 1024)
#define	MAX_OUT_BUF_SIZE	(64 * 1024)
        uint32_t   status = 0;
        struct     smb2fh *fh = NULL;
        uint8_t    dceRpcBuf[MAX_IN_BUF_SIZE] = {0};
        uint32_t   bindReqSize = 0;
        struct     rpc_bind_request bind_req;
        struct     context_item dcerpc_ctx;

        struct rpc_header rsp_hdr;
        struct rpc_bind_response ack;
        struct rpc_bind_nack_response nack;

        uint16_t max_xmit_frag = 0;
        uint16_t max_recv_frag = 0;

        struct DceRpcOperationRequest *dceOpReq = NULL;
        struct DceRpcOperationResponse dceOpRes2 = {{0}};
        uint32_t offset = 0;
        uint32_t bytes_used = 0;

        uint8_t  output_buf[MAX_OUT_BUF_SIZE] = {0};
        uint32_t output_count = MAX_OUT_BUF_SIZE;

        PolicyHandle pHandle = {0};

        if (server == NULL) {
                smb2_set_error(smb2, "smb2_lookUpSid:server not specified");
                return -1;
        }
        if (user == NULL) {
                smb2_set_error(smb2, "smb2_lookUpSid:user not specified");
                return -1;
        }
        if (domain == NULL) {
                smb2_set_error(smb2, "smb2_lookUpSid:domain not specified");
                return -1;
        }

        smb2->use_cached_creds = 1;
        if (smb2_connect_share(smb2, server, "IPC$", user) !=0) {
                smb2_set_error(smb2, "smb2_connect_share_async failed. %s",
                               smb2_get_error(smb2));
                return -ENOMEM;
        }

        fh = smb2_open_pipe(smb2, "lsarpc");
        if (fh == NULL) {
                smb2_set_error(smb2, "smb2_lookUpSid: failed to open LSARPC pipe: %s",
                               smb2_get_error(smb2));
                smb2_disconnect_share(smb2);
                return -1;
        }

        dcerpc_create_bind_req(&bind_req, 1);
        dcerpc_init_context(&dcerpc_ctx, CONTEXT_LSARPC);

        bindReqSize = sizeof(struct rpc_bind_request) + sizeof(struct context_item);
        memcpy(dceRpcBuf, &bind_req, sizeof(struct rpc_bind_request));
        memcpy(dceRpcBuf+sizeof(struct rpc_bind_request), &dcerpc_ctx, sizeof(struct context_item));

        status = smb2_ioctl(smb2, fh,
                            FSCTL_PIPE_TRANSCEIVE,
                            SMB2_0_IOCTL_IS_FSCTL,
                            dceRpcBuf, bindReqSize,
                            output_buf, &output_count);
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "smb2_lookUpSid: smb2_ioctl failed for bind: %s", smb2_get_error(smb2));
                goto error;
        }

        if (dcerpc_get_response_header(output_buf, output_count, &rsp_hdr) < 0) {
                smb2_set_error(smb2, "smb2_lookUpSid: failed to parse dcerpc response header");
                goto error;
        }

        if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDNACK) {
                if (dcerpc_get_bind_nack_response(output_buf, output_count, &nack) < 0) {
                        smb2_set_error(smb2, "smb2_lookUpSid:failed to parse dcerpc BINDNACK response");
                        goto error;
                }
                smb2_set_error(smb2, "smb2_lookUpSid:dcerpc BINDNACK reason : %s", dcerpc_get_reject_reason(nack.reject_reason));
                goto error;
        } else if (rsp_hdr.packet_type == RPC_PACKET_TYPE_BINDACK) {
                if (dcerpc_get_bind_ack_response(output_buf, output_count, &ack) < 0) {
                        smb2_set_error(smb2, "smb2_lookUpSid: failed to parse dcerpc BINDACK response");
                        goto error;
                }
                /* save the max xmit and recv frag details */
                max_xmit_frag = ack.max_xmit_frag;
                max_recv_frag = ack.max_recv_frag;
                max_recv_frag = max_recv_frag;
        }

        memset(&dceRpcBuf[0], 0, MAX_IN_BUF_SIZE);
        memset(&output_buf[0], 0, MAX_OUT_BUF_SIZE);
        output_count = MAX_OUT_BUF_SIZE;

        /* BIND is done send OpenPolicy request */
        dceOpReq = (struct DceRpcOperationRequest *)&dceRpcBuf[0];
        offset += sizeof(struct DceRpcOperationRequest);

        lsarpc_create_OpenPolicy2Req(smb2, server, RIGHT_TO_LOOKUP_NAMES,
                                     dceRpcBuf+offset, MAX_IN_BUF_SIZE-offset, &bytes_used);
        offset += bytes_used;

        /* opnum - 44 - for OpenPolicy2 */
        dcerpc_create_Operation_Request(smb2, dceOpReq, DCE_OP_OPEN_POLICY2, bytes_used);

        if (offset > max_xmit_frag) {
                smb2_set_error(smb2, "smb2_lookUpSid: IOCTL Payload size is larger than max_xmit_frag");
                goto error;
        }

        status = smb2_ioctl(smb2, fh,
                            FSCTL_PIPE_TRANSCEIVE,
                            SMB2_0_IOCTL_IS_FSCTL,
                            dceRpcBuf, offset,
                            output_buf, &output_count);
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "smb2_lookUpSid: smb2_ioctl failed for OpenPolicy2: %s", smb2_get_error(smb2));
                goto error;
        }
        if (dcerpc_parse_Operation_Response(smb2,
                                            output_buf,
                                            output_count,
                                            &dceOpRes2,
                                            &status) < 0) {
                smb2_set_error(smb2, "smb2_lookUpSid: failed to parse dcerpc response for OpenPolicy2 : %x", status);
                goto error;
        }

        offset = 0;
        offset +=sizeof(struct DceRpcOperationResponse);

        if (lsarpc_parse_OpenPolicy2Res(smb2, output_buf+offset,
                                        output_count-offset,
                                        &pHandle,
                                        &status) < 0) {
                smb2_set_error(smb2, "smb2_lookUpSid: lsarpc_parse_OpenPolicy2Res failed : %x", status);
                goto error;
        }

        /* LookUp names now */
        memset(&dceRpcBuf[0], 0, MAX_IN_BUF_SIZE);
        memset(&output_buf[0], 0, MAX_OUT_BUF_SIZE);
        output_count = MAX_OUT_BUF_SIZE;
        offset = 0;

        dceOpReq = (struct DceRpcOperationRequest *)&dceRpcBuf[0];
        offset += sizeof(struct DceRpcOperationRequest);

        if (lsarpc_create_LookUpNamesReq(smb2, &pHandle, user, domain,
                                         dceRpcBuf+offset, MAX_IN_BUF_SIZE-offset, &bytes_used) < 0) {
                smb2_set_error(smb2, "smb2_lookUpSid: Create LookupNames req failed");
                goto error;
        }
        offset += bytes_used;

        /* opnum - 14 - for LookupNames */
        dcerpc_create_Operation_Request(smb2, dceOpReq, DCE_OP_LOOKUP_NAMES, bytes_used);

        if (offset > max_xmit_frag) {
                smb2_set_error(smb2, "smb2_lookUpSid: IOCTL Payload size is larger than max_xmit_frag");
                goto error;
        }

        status = smb2_ioctl(smb2, fh,
                            FSCTL_PIPE_TRANSCEIVE,
                            SMB2_0_IOCTL_IS_FSCTL,
                            dceRpcBuf, offset,
                            output_buf, &output_count);
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "smb2_lookUpSid: smb2_ioctl failed for LookupNames : %s", smb2_get_error(smb2));
                goto error;
        }
        if (dcerpc_parse_Operation_Response(smb2,
                                            output_buf,
                                            output_count,
                                            &dceOpRes2,
                                            &status) < 0) {
                smb2_set_error(smb2, "smb2_lookUpSid: failed to parse dcerpc response for LookupNames : %x", status);
                goto error;
        }

        offset = 0;
        offset +=sizeof(struct DceRpcOperationResponse);
        if (lsarpc_parse_LookupNamesRes(smb2,
                                        output_buf+offset,
                                        output_count-offset,
                                        sid,
                                        &status) < 0) {
                smb2_set_error(smb2, "smb2_lookUpSid:lsarpc_parse_LookupNamesRes failed : %x", status);
                goto error;
        }

        /* Close the policy handle */
        memset(&dceRpcBuf[0], 0, MAX_IN_BUF_SIZE);
        memset(&output_buf[0], 0, MAX_OUT_BUF_SIZE);
        output_count = MAX_OUT_BUF_SIZE;
        offset = 0;

#if 0
        dceOpReq = (struct DceRpcOperationRequest *)&dceRpcBuf[0];
        offset += sizeof(struct DceRpcOperationRequest);

        lsarpc_create_ClosePolicy2eq(smb2, &pHandle, dceRpcBuf+offset, MAX_IN_BUF_SIZE-offset, &bytes_used);
        offset += bytes_used;

        /* opnum - 0 - for ClosePolicy */
        dcerpc_create_Operation_Request(smb2, dceOpReq, DCE_OP_CLOSE_POLICY, bytes_used);

        if (offset > max_xmit_frag) {
                smb2_set_error(smb2, "smb2_lookUpSid: IOCTL Payload size is larger than max_xmit_frag");
                goto error;
        }

        status = smb2_ioctl(smb2, fh,
                            FSCTL_PIPE_TRANSCEIVE,
                            SMB2_0_IOCTL_IS_FSCTL,
                            dceRpcBuf, offset,
                            output_buf, &output_count);
        if (status != SMB2_STATUS_SUCCESS) {
                smb2_set_error(smb2, "smb2_lookUpSid: smb2_ioctl failed for close policy: %s",
                               smb2_get_error(smb2));
                goto error;
        }
        if (dcerpc_parse_Operation_Response(smb2,
                                            output_buf,
                                            output_count,
                                            &dceOpRes2,
                                            &status) < 0) {
                smb2_set_error(smb2, "smb2_lookUpSid:dcerpc_parse_Operation_Response failed : %x", status);
                goto error;
        }
#endif

        /* close the pipe & disconnect */
        smb2_close(smb2, fh);
        smb2_disconnect_share(smb2);
        return 0;

error:
        /* close the pipe & disconnect */
        smb2_close(smb2, fh);
        smb2_disconnect_share(smb2);

        if (*sid != NULL) {
            free(*sid);
        }

        return -1;
}
