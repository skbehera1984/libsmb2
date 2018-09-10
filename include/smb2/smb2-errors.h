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

/*
 * NTSTATUS fields
 */
#define SMB2_STATUS_SEVERITY_MASK    0xc0000000
#define SMB2_STATUS_SEVERITY_SUCCESS 0x00000000
#define SMB2_STATUS_SEVERITY_INFO    0x40000000
#define SMB2_STATUS_SEVERITY_WARNING 0x80000000
#define SMB2_STATUS_SEVERITY_ERROR   0xc0000000

#define SMB2_STATUS_CUSTOMER_MASK    0x20000000

#define SMB2_STATUS_FACILITY_MASK    0x0fff0000

#define SMB2_STATUS_CODE_MASK        0x0000ffff


/* Error codes */
#define SMB2_STATUS_SUCCESS                  0x00000000
#define SMB2_STATUS_NO_MORE_FILES            0x80000006
#define SMB2_STATUS_NO_MORE_EAS              0x80000012
#define SMB2_STATUS_INVALID_PARAMETER        0xC000000d
#define SMB2_STATUS_NO_SUCH_FILE             0xC000000F
#define SMB2_STATUS_END_OF_FILE              0xC0000011
#define SMB2_STATUS_MORE_PROCESSING_REQUIRED 0xC0000016
#define SMB2_STATUS_ACCESS_DENIED            0xC0000022
#define SMB2_STATUS_OBJECT_NAME_NOT_FOUND    0xC0000034
#define SMB2_STATUS_OBJECT_PATH_NOT_FOUND    0xC000003A
#define SMB2_STATUS_SHARING_VIOLATION        0xC0000043
#define SMB2_STATUS_NO_EAS_ON_FILE           0xC0000052
#define SMB2_STATUS_LOGON_FAILURE            0xC000006d
#define SMB2_STATUS_BAD_NETWORK_NAME         0xC00000CC
#define SMB2_STATUS_NOT_A_DIRECTORY          0xC0000103
#define SMB2_STATUS_FILE_CLOSED              0xC0000128

#define SMB2_STATUS_NO_MEMORY                0xC0000017

#define SMB2_STATUS_INVALID_CONNECTION       0xC0000140
#define SMB2_STATUS_CONNECTION_DISCONNECTED  0xC000020C
#define SMB2_STATUS_NO_USER_SESSION_KEY      0xC0000202
#define SMB2_STATUS_NOT_SUPPORTED            0xC00000BB

/* For Internal use */
#define SMB2_STATUS_INTERNAL_ERROR           0xABCDfffc
#define SMB2_STATUS_INVALID_ARGUMENT         0xABCDfffd
#define SMB2_STATUS_SOCKET_ERROR             0xABCDfffe
#define SMB2_STATUS_PAYLOAD_FAILED           0xABCDffff

#define SMB2_STATUS_UNINITIALIZED            0xFFFFFFFF
