#include "dcerpc.h"
#include <locale.h>

#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-private.h"
#include <slist.h>

static uint64_t global_call_id = 1;

#define SRVSVC_UUID_A	0x4b324fc8
#define SRVSVC_UUID_B	0x1670
#define SRVSVC_UUID_C	0x01d3
static const uint8_t SRVSVC_UUID_D[] = { 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88 };

#define TRANSFER_SYNTAX_NDR_UUID_A	0x8a885d04
#define TRANSFER_SYNTAX_NDR_UUID_B	0x1ceb
#define TRANSFER_SYNTAX_NDR_UUID_C	0x11c9
static const uint8_t TRANSFER_SYNTAX_NDR_UUID_D[] = { 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 };

uint8_t
get_byte_order_dr(struct rpc_data_representation data)
{
		return data.byte_order;
}

uint8_t
get_byte_order_hdr(struct rpc_header hdr)
{
        return hdr.data_rep.byte_order;
}

static void
set_context_uuid(struct context_uuid *ctx,
                 uint32_t a,
                 uint16_t b,
                 uint16_t c,
                 const uint8_t d[8]
                )
{
		unsigned int i = 0;
        ctx->a = htole32(a);
        ctx->b = htole16(b);
        ctx->c = htole16(c);
        for (i = 0; i < sizeof(ctx->d); ++i)
        {
            (ctx->d)[i] = d[i];
        }
}

static void
init_rpc_data_representation(struct rpc_data_representation *data)
{
        data->byte_order     = RPC_BYTE_ORDER_LE;
		data->char_encoding  = RPC_CHAR_ENCODING_ASCII;
		data->floating_point = RPC_FLOAT_ENCODING_IEEE;
		data->padding        = 0x00;
}

static void
init_rpc_header(struct rpc_header *hdr)
{
		hdr->version_major = 5;
		hdr->version_minor = 0;
		hdr->packet_type = 0;
		hdr->packet_flags = 0;
		init_rpc_data_representation(&(hdr->data_rep));
		hdr->frag_length = 0;
		hdr->auth_length = 0;
		hdr->call_id = 0;
}

static void
init_rpc_bind_request(struct rpc_bind_request *bnd)
{
        /* Constant values from ethereal. */
        init_rpc_header(&(bnd->dceRpcHdr));
		bnd->max_xmit_frag = 32 * 1024; /* was 4280 */
		bnd->max_recv_frag = 32 * 1024; /* was 4280 */
		bnd->assoc_group = 0;
		bnd->num_context_items = 0;
		memset(bnd->padding, 0, sizeof(bnd->padding));
}

void dcerpc_init_context(struct   context_item* ctx,
                         uint16_t context_id_number,
                         uint16_t interface_version_major,
                         uint16_t interface_version_minor,
                         uint16_t syntax_version_major,
                         uint16_t syntax_version_minor)
{
        union uuid srvsvc_id;
        union uuid syntax_id;

        ctx->context_id = htole16(context_id_number);
        ctx->num_trans_items = htole16(1);

        set_context_uuid(&srvsvc_id.s_id,
                         SRVSVC_UUID_A,
                         SRVSVC_UUID_B,
                         SRVSVC_UUID_C,
                         SRVSVC_UUID_D);
        memcpy(&(ctx->interface_uuid), &(srvsvc_id.id), 16);
        ctx->interface_version_major = htole16(interface_version_major);
        ctx->interface_version_minor = htole16(interface_version_minor);

        set_context_uuid(&syntax_id.s_id,
                         TRANSFER_SYNTAX_NDR_UUID_A,
                         TRANSFER_SYNTAX_NDR_UUID_B,
                         TRANSFER_SYNTAX_NDR_UUID_C,
                         TRANSFER_SYNTAX_NDR_UUID_D);
        memcpy(&(ctx->transfer_syntax), &(syntax_id.id), 16);
        ctx->syntax_version_major = htole16(syntax_version_major);
        ctx->syntax_version_minor = htole16(syntax_version_minor);
}

void dcerpc_create_bind_req(struct rpc_bind_request *bnd, int num_context_items)
{
        init_rpc_bind_request(bnd);
        bnd->dceRpcHdr.packet_type = RPC_PACKET_TYPE_BIND;
        bnd->dceRpcHdr.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
        bnd->dceRpcHdr.frag_length = sizeof(struct rpc_bind_request) +
                                     (num_context_items * sizeof(struct context_item));
        bnd->dceRpcHdr.call_id = global_call_id++;
        bnd->num_context_items = num_context_items; /* atleast one context */
}

int
dcerpc_get_response_header(uint8_t *buf,
                           uint32_t buf_len,
                           struct rpc_header *hdr)
{
        if (buf == NULL|| hdr == NULL) {
                return -1;
        }
        if (buf_len < sizeof(struct rpc_header)) {
                return -1;
        }
        memcpy(hdr, buf, sizeof(struct rpc_header));
        return 0;
}

int
dcerpc_get_bind_ack_response(uint8_t *buf, uint32_t buf_len,
                             struct rpc_bind_response *rsp)
{
        if (buf == NULL|| rsp == NULL) {
                return -1;
        }
        if (buf_len < sizeof(struct rpc_bind_response)) {
                return -1;
        }
        memcpy(rsp, buf, sizeof(struct rpc_bind_response));
        return 0;
}

int
dcerpc_get_bind_nack_response(uint8_t *buf,
                              uint32_t buf_len,
                              struct rpc_bind_nack_response *rsp)
{
        if (buf == NULL|| rsp == NULL) {
                return -1;
        }
        if (buf_len < sizeof(struct rpc_bind_nack_response)) {
                return -1;
        }
        memcpy(rsp, buf, sizeof(struct rpc_bind_nack_response));
        return 0;
}

const char *
dcerpc_get_reject_reason(uint16_t reason)
{
        switch (reason)
        {
                case RPC_REASON_NOT_SPECIFIED:
                        return "Reason not specified";
                case RPC_REASON_TEMPORARY_CONGESTION:
                        return "Temporary congestion";
                case RPC_REASON_LOCAL_LIMIT_EXCEEDED:
                        return "Local limit exceeded";
                case RPC_REASON_CALLED_PADDR_UNKNOWN:
                        return "Called paddr unknown";
                case RPC_REASON_BAD_PROTOCOL_VERSION:
                        return "Protocol version not supported";
                case RPC_REASON_DEFAULT_CTX_UNSUPPORTED:
                        return "Default context not supported";
                case RPC_REASON_USER_DATA_UNREADABLE:
                        return "User data not readable";
                case RPC_REASON_NO_PSAP_AVAILABLE:
                        return "No PSAP available";
                case RPC_REASON_AUTH_TYPE_NOT_RECOGNIZED:
                        return "Authentication type not recognized";
                case RPC_REASON_INVALID_CHECKSUM:
                        return "Invalid checksum";
                default: break;
        }
        return "UNKNOWN Reject Reason";
}

/******************************** SRVSVC ********************************/
static void
dcerpc_init_NetrShareEnumRequest(struct NetrShareEnumRequest *netr_req)
{
        init_rpc_header(&(netr_req->dceRpcHdr));
        netr_req->alloc_hint = 0;
        netr_req->context_id = 1;
        /* OPNUM - 15 must be translated */
        netr_req->opnum = htole16(15);
}

int
dcerpc_create_NetrShareEnumRequest(struct smb2_context *smb2,
                                   struct NetrShareEnumRequest *netr_req,
                                   uint32_t payload_size)
{
        dcerpc_init_NetrShareEnumRequest(netr_req);
        netr_req->dceRpcHdr.packet_type  = RPC_PACKET_TYPE_REQUEST;
        netr_req->dceRpcHdr.packet_flags = RPC_FLAG_FIRST_FRAG | RPC_FLAG_LAST_FRAG;
        netr_req->dceRpcHdr.frag_length  =  sizeof(struct NetrShareEnumRequest) + payload_size;
        netr_req->dceRpcHdr.call_id      =  global_call_id++;
        netr_req->alloc_hint             =  payload_size;/* some add 2 more bytes ?*/
        return 0;
}

int
dcerpc_parse_NetrShareEnumResponse(struct smb2_context *smb2,
                                   const uint8_t *buffer,
                                   const uint32_t buf_len,
                                   struct NetrShareEnumResponse *netr_rep)
{
        struct NetrShareEnumResponse *inrep = NULL;

        if (buf_len < sizeof(struct NetrShareEnumResponse)) {
                smb2_set_error(smb2, "response to small for NetrShareEnumResponse");
                return -1;
        }

        inrep = (struct NetrShareEnumResponse *)buffer;

        netr_rep->alloc_hint   = le32toh(inrep->alloc_hint);
        netr_rep->context_id   = le16toh(inrep->context_id);
        netr_rep->cancel_count = inrep->cancel_count;
        netr_rep->padding      = inrep->padding;

        netr_rep->dceRpcHdr.version_major = inrep->dceRpcHdr.version_major;
        netr_rep->dceRpcHdr.version_minor = inrep->dceRpcHdr.version_minor;
        netr_rep->dceRpcHdr.packet_type   = inrep->dceRpcHdr.packet_type;
        netr_rep->dceRpcHdr.packet_flags  = inrep->dceRpcHdr.packet_flags;
        netr_rep->dceRpcHdr.frag_length   = le16toh(inrep->dceRpcHdr.frag_length);
        netr_rep->dceRpcHdr.auth_length   = le16toh(inrep->dceRpcHdr.auth_length);
        netr_rep->dceRpcHdr.call_id       = le32toh(inrep->dceRpcHdr.call_id);

        netr_rep->dceRpcHdr.data_rep      = inrep->dceRpcHdr.data_rep;

        return 0;
}

static int
dcerpc_init_stringValue(struct smb2_context *smb2,
                        char     *string,
                        uint8_t  *buf,
                        uint32_t buf_len,
                        uint32_t *buf_used)
{
        struct ucs2 *name = NULL;
        struct   stringValue *stringVal = NULL;
        uint32_t size_required = 0;
        uint32_t offset = 0;
        uint32_t len = strlen(string)+1;

        size_required = sizeof(struct stringValue) + len*2;

        name = utf8_to_ucs2(string);
        if (name == NULL) {
                smb2_set_error(smb2, "dcerpc_init_stringValue:"
                                     "failed to convert server name to ucs2");
                return -1;
        }

        if (buf_len < size_required) {
                free(name);
                smb2_set_error(smb2, "dcerpc_init_stringValue:buffer too small");
                return -1;
        }

        stringVal = (struct stringValue *)buf;

        stringVal->max_length  = htole32(len);
        stringVal->offset      = 0;
        stringVal->length      = stringVal->max_length;
        offset += sizeof(struct stringValue);

        memcpy(buf+offset, &name->val[0], 2 * name->len);

        free(name);

        *buf_used = size_required;

        return 0;
}

static int
dcerpc_init_serverName(struct smb2_context *smb2,
                       uint32_t refid,
                       char     *name,
                       uint8_t  *buf,
                       uint32_t  buf_len,
                       uint32_t *buf_used)
{
        struct serverName *srv = NULL;
        uint32_t offset = 0;
        uint32_t size_name = 0;

        srv = (struct serverName *)buf;

        srv->referent_id = htole32(refid);
        offset += sizeof(uint32_t);

        if (dcerpc_init_stringValue(smb2, name, buf+offset,
                                    buf_len - offset, &size_name) < 0) {
                return -1;
        }
        offset += size_name;

        *buf_used = offset;

        return 0;
}

static int
dcerpc_init_InfoStruct(struct smb2_context *smb2,
                       uint32_t infolevel, uint32_t id,
                       uint32_t entries, uint32_t arrayId,
                       uint8_t *buffer, uint32_t buf_len)
{
        struct InfoStruct *info = NULL;

        info = (struct InfoStruct *)buffer;

        info->info_level   = htole32(infolevel);
        info->switch_value = info->info_level;
        info->referent_id  = htole32(id);
        info->num_entries  = htole32(entries);
        info->array_referent_id = htole32(arrayId);
        return 0;
}

int
dcerpc_create_NetrShareEnumRequest_payload(struct smb2_context *smb2,
                                           char       *server_name,
                                           uint64_t   resumeHandle,
                                           uint8_t    *buffer,
                                           uint32_t   *buffer_len)
{
        uint32_t  buf_len = 0;
        uint32_t  offset = 0;
        uint32_t  size_used = 0;
        uint32_t  padlen = 0;
        uint32_t  *PreferedMaximumLength = NULL;
        uint32_t  preferred_max_length = 0xffffffff;
        uint32_t  *ResumeHandle = NULL;

        buf_len = *buffer_len;

        if (dcerpc_init_serverName(smb2, 0x0026e53c, server_name,
                                   buffer, buf_len, &size_used) < 0) {
                return -1;
        }

        offset += size_used;

        /* padding of 0 or more bytes are needed after the name buf */
        if ((size_used & 0x07) != 0) {
                padlen = 8 - (size_used & 0x07);
                offset += padlen;
        }

        if (dcerpc_init_InfoStruct(smb2, 1, 0x01fbf3e8, 0, 0,
                                   buffer+offset, buf_len - offset) <0) {
                 return -1;
        }
        offset += sizeof(struct InfoStruct);

        PreferedMaximumLength = (uint32_t *)(buffer+offset);
        *PreferedMaximumLength = htole32(preferred_max_length);
        offset += sizeof(uint32_t);

        ResumeHandle = (uint32_t *) (buffer+offset);
        *ResumeHandle = htole32(resumeHandle);
        offset += sizeof(uint32_t);

        *buffer_len = offset;

        return 0;
}

uint32_t
srvsvc_get_NetrShareEnum_status(struct smb2_context *smb2,
                                const uint8_t *buffer,
                                const uint32_t buf_len)
{
        uint32_t sts = 0;

        uint32_t *pstatus = (uint32_t *) (buffer +(buf_len - 4));
        sts = le32toh(*pstatus);

        return sts;
}

static int
srvsvc_parse_NetrShareEnum_InfoStruct(struct smb2_context *smb2,
                                      const uint8_t *buffer,
                                      const uint32_t buf_len,
                                      struct InfoStruct *info)
{
        struct InfoStruct *rsp_info = NULL;

        if (buf_len < sizeof(struct InfoStruct)) {
                smb2_set_error(smb2, "response too small for InfoStruct");
                return -1;
        }

        rsp_info = (struct InfoStruct *)buffer;

        info->info_level = le32toh(rsp_info->info_level);
        info->switch_value = le32toh(rsp_info->switch_value);
        info->referent_id = le32toh(rsp_info->referent_id);
        info->num_entries = le32toh(rsp_info->num_entries);
        info->array_referent_id = le32toh(rsp_info->array_referent_id);

        return 0;
}

static int
srvsvc_parse_NetrShareEnum_buffer(struct smb2_context *smb2,
                                  const uint8_t *in_buffer,
                                  uint32_t in_buffer_len,
                                  uint32_t buffer_consumed,
                                  const uint32_t share_count,
                                  struct smb2_shareinfo **shares,
                                  uint32_t *total_entries,
                                  uint32_t *resumeHandle)
{
        const uint8_t *buffer = NULL;
        uint32_t buffer_offset = 0;
        const uint8_t *payload = NULL;
        uint32_t payload_offset = 0;
        int i = 0;

        buffer = in_buffer + buffer_consumed;
        payload = buffer + (share_count * sizeof (struct ShareInfo1));

        for (i = 0; i < share_count; i++) {
                struct ShareInfo1 share_info, *infoptr = NULL;
                struct stringValue share_name, *name_ptr = NULL;
                struct stringValue share_remark, *remark_ptr = NULL;
                char *shi_name = NULL;
                char *shi_remark = NULL;
                uint32_t padlen = 0;
                struct smb2_shareinfo *shi01 = NULL;

                shi01 = (struct smb2_shareinfo *)calloc(1, sizeof(struct smb2_shareinfo));
                if (shi01 == NULL) {
                        return -1;
                }

                infoptr = (struct ShareInfo1 *) (buffer + buffer_offset);
                share_info.name_referent_id   = le32toh(infoptr->name_referent_id);
                share_info.type               = le32toh(infoptr->type);
                share_info.remark_referent_id = le32toh(infoptr->remark_referent_id);
                buffer_offset += sizeof(struct ShareInfo1);

                /* the payload buffer is 4 byte multiple.
                 * while packing each element it is padded if not multiple of 4 byte.
                 * the buffer size count starts from the payload.
                 */
                padlen = 0;
                if ((payload_offset & 0x03) != 0) {
                        padlen = 4 - (payload_offset & 0x03);
                        payload_offset += padlen;
                }

                name_ptr = (struct stringValue *) (payload + payload_offset);
                share_name.max_length = le32toh(name_ptr->max_length);
                share_name.offset     = le32toh(name_ptr->offset);
                share_name.length     = le32toh(name_ptr->length);
                payload_offset += sizeof(struct stringValue);

                shi_name = ucs2_to_utf8((uint16_t *)(payload+payload_offset),
                                        share_name.length);

                payload_offset += (2 * share_name.length);

                padlen = 0;
                if ((payload_offset & 0x03) != 0) {
                        padlen = 4 - (payload_offset & 0x03);
                        payload_offset += padlen;
                }

                remark_ptr = (struct stringValue *) (payload + payload_offset);
                share_remark.max_length = le32toh(remark_ptr->max_length);
                share_remark.offset     = le32toh(remark_ptr->offset);
                share_remark.length     = le32toh(remark_ptr->length);
                payload_offset += sizeof(struct stringValue);

                if (share_remark.length > 1) {
                        shi_remark = ucs2_to_utf8((uint16_t *)(payload+payload_offset),
                                                  share_remark.length);
                }
                payload_offset += (2 * share_remark.length);

                /* Fill the details */
                shi01->type = share_info.type;
                shi01->name = shi_name;
                shi01->remark = shi_remark;
                shi01->next = NULL;

                /*add the entity */
                SMB2_LIST_ADD_END(shares, shi01)
        }

        buffer_offset += buffer_consumed + payload_offset;
        if ((buffer_offset & 0x03) != 0) {
                uint32_t padlen = 4 - (buffer_offset & 0x03);
                buffer_offset += padlen;
        }

        *total_entries = le32toh(*(uint32_t *)(in_buffer+buffer_offset));
        buffer_offset += sizeof(uint32_t);

        *resumeHandle  = le32toh(*(uint32_t *)(in_buffer+buffer_offset));

        return 0;
}

int
srvsvc_parse_NetrShareEnum_payload(struct smb2_context *smb2,
                                   const uint8_t *buffer,
                                   const uint32_t buf_len,
                                   uint32_t *num_entries,
                                   uint32_t *total_entries,
                                   uint32_t *resumeHandle,
                                   struct smb2_shareinfo **shares)
{
        uint32_t offset = 0;
        struct InfoStruct info;

        if (srvsvc_parse_NetrShareEnum_InfoStruct(smb2,
                                                  buffer, buf_len,
                                                  &info) < 0) {
                return -1;
        }

        offset += sizeof(struct InfoStruct);
        offset += sizeof(uint32_t); /* Size - num array elements */

        *num_entries = info.num_entries;

        if (srvsvc_parse_NetrShareEnum_buffer(smb2,
                                              buffer,
                                              buf_len,
                                              offset,
                                              info.num_entries,
                                              shares,
                                              total_entries,
                                              resumeHandle) < 0) {
                return -1;
        }

        return 0;
}
