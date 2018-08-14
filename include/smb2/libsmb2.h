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

#ifndef _LIBSMB2_H_
#define _LIBSMB2_H_

#ifdef __cplusplus
extern "C" {
#endif

struct smb2_context;

/*
 * Generic callback for completion of smb2_*_async().
 * command_data depends on status.
 */
typedef void (*smb2_command_cb)(struct smb2_context *smb2, uint32_t status,
                                void *command_data, void *cb_data);

/* Stat structure */
#define SMB2_TYPE_FILE      0x00000000
#define SMB2_TYPE_DIRECTORY 0x00000001
struct smb2_stat_64 {
        uint32_t smb2_type;
        uint32_t smb2_nlink;
        uint64_t smb2_ino;
        uint64_t smb2_size;
	uint64_t smb2_atime;
	uint64_t smb2_atime_nsec;
	uint64_t smb2_mtime;
	uint64_t smb2_mtime_nsec;
	uint64_t smb2_ctime;
	uint64_t smb2_ctime_nsec;
	uint64_t smb2_crtime;
	uint64_t smb2_crtime_nsec;
};

struct smb2_statvfs {
	uint32_t	f_bsize;
	uint32_t	f_frsize;
	uint64_t	f_blocks;
	uint64_t	f_bfree;
	uint64_t	f_bavail;
	uint32_t	f_files;
	uint32_t	f_ffree;
	uint32_t	f_favail;
	uint32_t	f_fsid;
	uint32_t	f_flag;
	uint32_t	f_namemax;
};

struct smb2_file_info_all {
        uint32_t smb2_type;

        uint32_t smb2_nlink;
        uint64_t smb2_ino;
        uint64_t smb2_size;

        uint64_t smb2_atime;
        uint64_t smb2_atime_nsec;
        uint64_t smb2_mtime;
        uint64_t smb2_mtime_nsec;
        uint64_t smb2_ctime;
        uint64_t smb2_ctime_nsec;
        uint64_t smb2_crtime;
        uint64_t smb2_crtime_nsec;

        uint32_t file_attributes;

        uint64_t allocation_size;
        uint64_t end_of_file;
        uint8_t delete_pending;
        uint8_t directory;

        uint32_t ea_size;
};

struct smb2_file_extended_info;

struct smb2_file_extended_info {
        uint8_t* name;
        uint8_t name_len;
        uint8_t* value;
        uint16_t value_len;
        struct smb2_file_extended_info *next;
};

struct smb2_file_full_extended_info {
        uint8_t *eabuf;
        uint32_t eabuf_len;
};

struct smb2_file_stream_info;

struct smb2_file_stream_info {
        char name[4096];
        uint64_t size;
        uint64_t allocation_size;
        struct smb2_file_stream_info *next;
};

typedef union _file_info_union {
        struct smb2_file_basic_info           basic_info;
        struct smb2_file_standard_info        standard_info;
        struct smb2_file_extended_info        *extended_info;
        struct smb2_file_stream_info          *stream_info;
        struct smb2_file_all_info             all_info;
        struct smb2_security_descriptor       *security_info;
        struct smb2_file_fs_size_info         fs_size_info;
        struct smb2_file_fs_device_info       fs_device_info;
        struct smb2_file_fs_control_info      fs_control_info;
        struct smb2_file_fs_full_size_info    fs_full_size_info;
        struct smb2_file_fs_sector_size_info  fs_sector_size_info;
        /* specific to SMB2_SET_INFO only */
        struct smb2_file_end_of_file_info     eof_info;
        struct smb2_file_rename_info          rename_info;
        struct smb2_file_security_info        sec_info;
        struct smb2_file_full_extended_info   full_extended_info;
} smb2_file_info_U;

typedef struct _file_info {
        uint8_t info_type;
        uint8_t file_info_class;
        smb2_file_info_U u_info;
} smb2_file_info;

struct smb2dirent {
        const char *name;
        uint64_t allocation_size;
        uint32_t attributes;
        uint32_t ea_size;
        struct smb2_stat_64 st;
};

#ifdef _MSC_VER
#include <winsock2.h>
typedef SOCKET t_socket;
#else
typedef int t_socket;
#endif

/*
 * Create an SMB2 context.
 * Function returns
 *  NULL : Failed to create a context.
 *  *nfs : A pointer to an smb2 context.
 */
struct smb2_context *smb2_init_context(void);

/*
 * Destroy an smb2 context.
 */
void smb2_destroy_context(struct smb2_context *smb2);

/*
 * The following three functions are used to integrate libsmb2 in an event
 * system.
 */
/*
 * Returns the file descriptor that libsmb2 uses.
 */
t_socket smb2_get_fd(struct smb2_context *smb2);
/*
 * Returns which events that we need to poll for for the smb2 file descriptor.
 */
int smb2_which_events(struct smb2_context *smb2);
/*
 * Called to process the events when events become available for the smb2
 * file descriptor.
 *
 * Returns:
 *  0 : Success
 * <0 : Unrecoverable failure. At this point the context can no longer be
 *      used and must be freed by calling smb2_destroy_context().
 *
 */
int smb2_service(struct smb2_context *smb2, int revents);

/*
 * Set the security mode for the connection.
 * This is a combination of the flags SMB2_NEGOTIATE_SIGNING_ENABLED
 * and  SMB2_NEGOTIATE_SIGNING_REQUIRED
 * Default is 0.
 */
void smb2_set_security_mode(struct smb2_context *smb2, uint16_t security_mode);

/*
 * Set the username that we will try to authenticate as.
 * Default is to try to authenticate as the current user.
 */
void smb2_set_user(struct smb2_context *smb2, const char *user);
/*
 * Set the password that we will try to authenticate as.
 * This function is only needed when libsmb2 is built --without-libkrb5
 */
void smb2_set_password(struct smb2_context *smb2, const char *password);
/*
 * Set the domain when authenticating.
 * This function is only needed when libsmb2 is built --without-libkrb5
 */
void smb2_set_domain(struct smb2_context *smb2, const char *domain);
/*
 * Set the workstation when authenticating.
 * This function is only needed when libsmb2 is built --without-libkrb5
 */
void smb2_set_workstation(struct smb2_context *smb2, const char *workstation);


/*
 * Returns the client_guid for this context.
 */
const char *smb2_get_client_guid(struct smb2_context *smb2);

enum smb2_sec {
        SMB2_SEC_UNDEFINED = 0,
        SMB2_SEC_NTLMSSP,
        SMB2_SEC_KRB5,
};

void smb2_set_auth_mode(struct smb2_context *smb2, enum smb2_sec mode);

uint32_t smb2_get_ntstatus(struct smb2_context *smb2);

void smb2_set_ntstatus(struct smb2_context *smb2, uint32_t sts);

/*
 * Asynchronous call to connect a TCP connection to the server
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * <0 if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Connection was successful. Command_data is NULL.
 *
 *   <0     : Failed to establish the connection. Command_data is NULL.
 */
int smb2_connect_async(struct smb2_context *smb2, const char *server,
                       smb2_command_cb cb, void *cb_data);

/*
 * Async call to connect to a share.
 * On unix, if user is NULL then default to the current user.
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the connection will be reported through the callback function.
 * -errno if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Connection was successful. Command_data is NULL.
 *
 *   -errno : Failed to connect to the share. Command_data is NULL.
 */
int smb2_connect_share_async(struct smb2_context *smb2,
                             const char *server,
                             const char *share,
                             const char *user,
                             smb2_command_cb cb, void *cb_data);

/*
 * Sync call to connect to a share.
 * On unix, if user is NULL then default to the current user.
 *
 * Returns:
 * 0      : Connected to the share successfully.
 * -errno : Failure.
 */
uint32_t smb2_connect_share(struct smb2_context *smb2,
                            const char *server,
                            const char *share,
                            const char *user);

/*
 * Async call to disconnect from a share/
 *
 * Returns:
 *  0 if the call was initiated and a connection will be attempted. Result of
 * the disconnect will be reported through the callback function.
 * -errno if there was an error. The callback function will not be invoked.
 *
 * Callback parameters :
 * status can be either of :
 *    0     : Connection was successful. Command_data is NULL.
 *
 *   -errno : Failed to disconnect the share. Command_data is NULL.
 */
int smb2_disconnect_share_async(struct smb2_context *smb2,
                                smb2_command_cb cb, void *cb_data);

/*
 * Sync call to disconnect from a share/
 *
 * Returns:
 * 0      : Disconnected from the share successfully.
 * -errno : Failure.
 */
uint32_t smb2_disconnect_share(struct smb2_context *smb2);

/*
 * This function returns a description of the last encountered error.
 */
const char *smb2_get_error(struct smb2_context *smb2);

struct smb2_url {
        const char *domain;
        const char *user;
        const char *server;
        const char *share;
        const char *path;
};

/* Convert an smb2/nt error code into a string */
const char *nterror_to_str(uint32_t status);

/* Convert an smb2/nt error code into an errno value */
int nterror_to_errno(uint32_t status);

/*
 * This function is used to parse an SMB2 URL into as smb2_url structure.
 * SMB2 URL format :
 * smb2://[<domain;][<username>@]<host>/<share>/<path>
 *
 * Function will return a pointer to an iscsi smb2 structure if successful,
 * or it will return NULL and set smb2_get_error() accordingly if there was
 * a problem with the URL.
 *
 * The returned structure is freed by calling smb2_destroy_url()
 */
struct smb2_url *smb2_parse_url(struct smb2_context *smb2, const char *url);
void smb2_destroy_url(struct smb2_url *url);

struct smb2_pdu;
/*
 * The functions are used when creating compound low level commands.
 * The general pattern for compound chains is
 * 1, pdu = smb2_cmd_*_async(smb2, ...)
 *
 * 2, next = smb2_cmd_*_async(smb2, ...)
 * 3, smb2_add_compound_pdu(smb2, pdu, next);
 *
 * 4, next = smb2_cmd_*_async(smb2, ...)
 * 5, smb2_add_compound_pdu(smb2, pdu, next);
 * ...
 * *, smb2_queue_pdu(smb2, pdu);
 *
 * See libnfs.c and smb2-raw-stat-async.c for examples on how to use
 * this interface.
 */
void smb2_add_compound_pdu(struct smb2_context *smb2,
                           struct smb2_pdu *pdu, struct smb2_pdu *next_pdu);
void smb2_free_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);
void smb2_queue_pdu(struct smb2_context *smb2, struct smb2_pdu *pdu);

/*
 * OPEN
 */
struct smb2fh {
        smb2_file_id file_id;
        int64_t offset;

        uint8_t oplock_level;
        uint32_t create_action;
        uint64_t creation_time;
        uint64_t lastAccess_time;
        uint64_t lastWrite_time;
        uint64_t change_time;
        uint64_t allocation_size;
        uint64_t end_of_file;
        uint32_t file_attributes;
};

/*
 * OPENDIR
 */
typedef struct _smb2dir smb2dir;

/*
 * Async opendir()
 *
 * Returns
 *  0 : The operation was initiated. Result of the operation will be reported
 * through the callback function.
 * <0 : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          Command_data is struct smb2dir.
 *          This structure is freed using smb2_closedir().
 * -errno : An error occured.
 *          Command_data is NULL.
 */
int smb2_querydir_async(struct smb2_context *smb2, struct smb2fh *fh,
                        smb2_command_cb cb, void *cb_data);

/*
 * Sync opendir()
 *
 * Returns NULL on failure.
 */
smb2dir *smb2_querydir(struct smb2_context *smb2, const char *path);

/*
 * closedir()
 */
/*
 * smb2_closedir() never blocks, thus no async version is needed.
 */
void smb2_closedir(struct smb2_context *smb2, smb2dir *smb2dir);

/*
 * readdir()
 */
/*
 * smb2_readdir() never blocks, thus no async version is needed.
 */
struct smb2dirent *smb2_readdir(struct smb2_context *smb2, smb2dir *smb2dir);

/*
 * rewinddir()
 */
/*
 * smb2_rewinddir() never blocks, thus no async version is needed.
 */
void smb2_rewinddir(struct smb2_context *smb2, smb2dir *smb2dir);

/*
 * telldir()
 */
/*
 * smb2_telldir() never blocks, thus no async version is needed.
 */
long smb2_telldir(struct smb2_context *smb2, smb2dir *smb2dir);

/*
 * seekdir()
 */
/*
 * smb2_seekdir() never blocks, thus no async version is needed.
 */
void smb2_seekdir(struct smb2_context *smb2, smb2dir *smb2dir, long loc);

/*
 * Async open()
 *
 * Opens or creates a file.
 * Supported flags are:
 * O_RDONLY
 * O_WRONLY
 * O_RDWR
 * O_SYNC
 * O_CREAT
 * O_EXCL
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          Command_data is struct smb2fh.
 *          This structure is freed using smb2_close().
 * -errno : An error occured.
 *          Command_data is NULL.
 */       
int smb2_open_async(struct smb2_context *smb2, const char *path, int flags,
                    smb2_command_cb cb, void *cb_data);

/*
 * Sync open()
 *
 * Returns NULL on failure.
 */
struct smb2fh *smb2_open(struct smb2_context *smb2, const char *path, int flags);

/* Async open_file()
 */
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
                     smb2_command_cb cb, void *cb_data);

/* Sync open_file()
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
               uint32_t create_options);

/* Async open_pipe()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 *          Command_data is struct smb2fh.
 *          This structure is freed using smb2_close().
 * -errno : An error occured.
 *          Command_data is NULL.
 */
int smb2_open_pipe_async(struct smb2_context *smb2,
                         const char *pipe,
                         smb2_command_cb cb,
                         void *cb_data);

/*
 * Sync open_pipe()
 *
 * Returns NULL on failure.
 */
struct smb2fh *smb2_open_pipe(struct smb2_context *smb2,
                              const char *pipe);

/*
 * CLOSE
 */
/*
 * Async close()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_close_async(struct smb2_context *smb2, struct smb2fh *fh,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync close()
 */
uint32_t smb2_close(struct smb2_context *smb2, struct smb2fh *fh);

/*
 * FSYNC
 */
/*
 * Async fsync()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_fsync_async(struct smb2_context *smb2, struct smb2fh *fh,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync fsync()
 */
uint32_t smb2_fsync(struct smb2_context *smb2, struct smb2fh *fh);

/*
 * GetMaxReadWriteSize
 * SMB2 servers have a maximum size for read/write data that they support.
 */
uint32_t smb2_get_max_read_size(struct smb2_context *smb2);
uint32_t smb2_get_max_write_size(struct smb2_context *smb2);

/*
 * PREAD
 */
/*
 * Async pread()
 * Use smb2_get_max_read_size to discover the maximum data size that the
 * server supports.
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Number of bytes read.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */       
int smb2_pread_async(struct smb2_context *smb2, struct smb2fh *fh,
                     uint8_t *buf, uint32_t count, uint64_t offset,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync pread()
 * Use smb2_get_max_read_size to discover the maximum data size that the
 * server supports.
 */
uint32_t smb2_pread(struct smb2_context *smb2, struct smb2fh *fh,
                    uint8_t *buf, uint32_t count, uint64_t offset);

/*
 * PWRITE
 */
/*
 * Async pwrite()
 * Use smb2_get_max_write_size to discover the maximum data size that the
 * server supports.
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Number of bytes written.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */       
int smb2_pwrite_async(struct smb2_context *smb2, struct smb2fh *fh,
                      uint8_t *buf, uint32_t count, uint64_t offset,
                      smb2_command_cb cb, void *cb_data);

/*
 * Sync pwrite()
 * Use smb2_get_max_write_size to discover the maximum data size that the
 * server supports.
 */
uint32_t smb2_pwrite(struct smb2_context *smb2, struct smb2fh *fh,
                     uint8_t *buf, uint32_t count, uint64_t offset);

/*
 * READ
 */
/*
 * Async read()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Number of bytes read.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_read_async(struct smb2_context *smb2, struct smb2fh *fh,
                    uint8_t *buf, uint32_t count,
                    smb2_command_cb cb, void *cb_data);

/*
 * Sync read()
 */
uint32_t smb2_read(struct smb2_context *smb2, struct smb2fh *fh,
                   uint8_t *buf, uint32_t count);

/*
 * WRITE
 */
/*
 * Async write()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *    >=0 : Number of bytes written.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_write_async(struct smb2_context *smb2, struct smb2fh *fh,
                     uint8_t *buf, uint32_t count,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync write()
 */
uint32_t smb2_write(struct smb2_context *smb2, struct smb2fh *fh,
                    uint8_t *buf, uint32_t count);

/*
 * Sync lseek()
 */
/*
 * smb2_seek() never blocks, thus no async version is needed.
 */
int64_t smb2_lseek(struct smb2_context *smb2, struct smb2fh *fh,
                   int64_t offset, int whence, uint64_t *current_offset);

/*
 * UNLINK
 */
/*
 * Async unlink()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_unlink_async(struct smb2_context *smb2, const char *path,
                      smb2_command_cb cb, void *cb_data);

/*
 * Sync unlink()
 */
uint32_t smb2_unlink(struct smb2_context *smb2, const char *path);

/*
 * RMDIR
 */
/*
 * Async rmdir()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_rmdir_async(struct smb2_context *smb2, const char *path,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync rmdir()
 */
uint32_t smb2_rmdir(struct smb2_context *smb2, const char *path);

/*
 * MKDIR
 */
/*
 * Async mkdir()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_mkdir_async(struct smb2_context *smb2, const char *path,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync mkdir()
 */
uint32_t smb2_mkdir(struct smb2_context *smb2, const char *path);

/*
 * Async getinfo()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success. Command_data is struct smb2_stat_64
 * -errno : An error occured.
 */
int
smb2_getinfo_async(struct smb2_context *smb2,
                   const char *path,
                   smb2_file_info *info,
                   smb2_command_cb cb, void *cb_data);

/*
 * FSTAT
 */
/*
 * Async fstat()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success. Command_data is struct smb2_stat_64
 * -errno : An error occured.
 */
int smb2_fstat_async(struct smb2_context *smb2, struct smb2fh *fh,
                     struct smb2_stat_64 *st,
                     smb2_command_cb cb, void *cb_data);
/*
 * Sync fstat()
 */
uint32_t smb2_fstat(struct smb2_context *smb2, struct smb2fh *fh,
                    struct smb2_stat_64 *st);

/*
 * Sync stat()
 */
uint32_t smb2_stat(struct smb2_context *smb2, const char *path,
                   struct smb2_stat_64 *st);

/*
 * Sync statvfs()
 */
uint32_t smb2_statvfs(struct smb2_context *smb2, const char *path,
                      struct smb2_statvfs *statvfs);

/*
 * Sync get_security()
 *
 * Returns:
 * 0      : successfully send the message and received a reply.
 * -errno : Failure.
 */
uint32_t smb2_get_security(struct smb2_context *smb2,
                           const char *path,
                           uint8_t **buf,
                           uint32_t *buf_len);

/*
 * Sync query_file_all_info()
 */
uint32_t
smb2_query_file_all_info(struct smb2_context *smb2,
                         const char *path,
                         struct smb2_file_info_all *all_info);

/*
 * Async setinfo()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 */
int
smb2_setinfo_async(struct smb2_context *smb2,
                   const char *path,
                   smb2_file_info *info,
                   smb2_command_cb cb, void *cb_data);


/*
 * Sync rename()
 */
uint32_t smb2_rename(struct smb2_context *smb2,
                     const char *oldpath,
                     const char *newpath);

/*
 * Sync truncate()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
uint32_t smb2_truncate(struct smb2_context *smb2,
                       const char *path,
                       uint64_t length);

/*
 * Async ftruncate()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 */
int smb2_ftruncate_async(struct smb2_context *smb2, struct smb2fh *fh,
                         uint64_t length, smb2_command_cb cb, void *cb_data);
/*
 * Sync ftruncate()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
uint32_t smb2_ftruncate(struct smb2_context *smb2,
                        struct smb2fh *fh,
                        uint64_t length);

/*
 * Sync set_security()
 *
 * Returns:
 * 0      : successfully send the message and received a reply.
 * -errno : Failure.
 */
uint32_t smb2_set_security(struct smb2_context *smb2,
                           const char *path,
                           uint8_t *buf,
                           uint32_t buf_len);

/* Sync set_file_basic_info()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
uint32_t
smb2_set_file_basic_info(struct smb2_context *smb2,
                         const char *path,
                         struct smb2_file_basic_info *info);

/*
 * Async echo()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 */
int smb2_echo_async(struct smb2_context *smb2,
                    smb2_command_cb cb, void *cb_data);

/*
 * Sync echo()
 *
 * Returns:
 * 0      : successfully send the message and received a reply.
 * -errno : Failure.
 */
uint32_t smb2_echo(struct smb2_context *smb2);

/*
 * IOCTL
 */
/*
 * Async ioctl()
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success.
 * -errno : An error occured.
 *
 * Command_data is always NULL.
 */
int smb2_ioctl_async(struct smb2_context *smb2, struct smb2fh *fh,
                     uint32_t ioctl_ctl, uint32_t ioctl_flags,
                     uint8_t *input_buffer, uint32_t input_count,
                     uint8_t *output_buffer, uint32_t *output_count,
                     smb2_command_cb cb, void *cb_data);

/*
 * Sync Ioctl()
 */
uint32_t smb2_ioctl(struct smb2_context *smb2, struct smb2fh *fh,
                    uint32_t ioctl_ctl, uint32_t ioctl_flags,
                    uint8_t *input_buffer, uint32_t input_count,
                    uint8_t *output_buffer, uint32_t *output_count);

#define SHARE_STYPE_DISKTREE    0x00000000
#define SHARE_STYPE_PRINTQ      0x00000001
#define SHARE_STYPE_DEVICE      0x00000002
#define SHARE_STYPE_IPC         0x00000003
#define SHARE_STYPE_TEMPORARY   0x40000000
#define SHARE_STYPE_SPECIAL     0x80000000
#define SHARE_STYPE_UNKNOWN     0xFFFFFFFF

#define SMB2_SHARE_NAME_MAX	257
#define SMB2_SHARE_REMARK_MAX	257

struct share_info_1 {
        char     *name;
        uint32_t type;
        char     *remark;
};

struct share_info_2 {
        char     *name;
        uint32_t type;
        char     *remark;
        uint32_t permissions;
        uint32_t max_uses;
        uint32_t current_uses;
        char     *path;
        char     *password;
};

union share_info {
        struct share_info_1 info1;
        struct share_info_2 info2;
};

struct smb2_shareinfo {
        uint32_t share_info_type;
        union share_info info;
        struct smb2_shareinfo *next;
};

/*
 * Sync list_shares()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
int
smb2_list_shares(struct smb2_context *smb2,
                 const char *server,
                 const char *user,
                 uint32_t   shinfo_type,
                 struct smb2_shareinfo **shares,
                 int *numshares);

/* Sync smb2_get_file_extended_info()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 *@@:API user must call smb2_free_file_extended_info()
 */
uint32_t
smb2_get_file_extended_info(struct smb2_context *smb2,
                            const char *path,
                            struct smb2_file_extended_info **extended_info);

/* Sync smb2_set_file_extended_info()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 */
uint32_t
smb2_set_file_extended_info(struct smb2_context *smb2,
                            const char *path,
                            struct smb2_file_extended_info *extended_info,
                            const int count);

void smb2_free_file_extended_info(struct smb2_context *smb2,
                                  struct smb2_file_extended_info *extended_info);

/* Sync smb2_get_file_stream_info()
 * Function returns
 *      0 : Success
 * -errno : An error occured.
 *@@:API user must call smb2_free_file_stream_info()
 */
uint32_t
smb2_get_file_stream_info(struct smb2_context *smb2,
                          const char *path,
                          struct smb2_file_stream_info **stream_info);

void smb2_free_file_stream_info(struct smb2_context *smb2,
                                struct smb2_file_stream_info *stream_info);

/* Low 2 bits desctibe the type */
#define SHARE_TYPE_DISKTREE  0
#define SHARE_TYPE_PRINTQ    1
#define SHARE_TYPE_DEVICE    2
#define SHARE_TYPE_IPC       3

#define SHARE_TYPE_TEMPORARY 0x40000000
#define SHARE_TYPE_HIDDEN    0x80000000

struct srvsvc_netshareinfo1 {
        char *name;
        uint32_t type;
	char *comment;
};

struct srvsvc_netsharectr1 {
        uint32_t count;
        struct srvsvc_netshareinfo1 *array;
};

struct srvsvc_netsharectr {
        uint32_t level;
        union {
                struct srvsvc_netsharectr1 ctr1;
        };
};

struct srvsvc_netshareenumall_req {
        struct ucs2 *server;
        uint32_t level;
        struct srvsvc_netsharectr *ctr;
        uint32_t max_buffer;
        uint32_t resume_handle;
};

struct srvsvc_netshareenumall_rep {
        uint32_t level;
        struct srvsvc_netsharectr *ctr;
        uint32_t total_entries;
        uint32_t resume_handle;

        uint32_t status;
};

/*
 * Async share_enum()
 * This function only works when connected to the IPC$ share.
 *
 * Returns
 *  0     : The operation was initiated. Result of the operation will be
 *          reported through the callback function.
 * -errno : There was an error. The callback function will not be invoked.
 *
 * When the callback is invoked, status indicates the result:
 *      0 : Success. Command_data is struct srvsvc_netshareenumall_rep *
 *          This pointer must be freed using smb2_free_data().
 * -errno : An error occured.
 */
int smb2_share_enum_async(struct smb2_context *smb2, const char *server,
                          smb2_command_cb cb, void *cb_data);

#ifdef __cplusplus
}
#endif

#endif /* !_LIBSMB2_H_ */
