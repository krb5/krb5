/*
 * Copyright (c) 2004, 2008, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef GSSAPI_EXT_H_
#define GSSAPI_EXT_H_

#include <gssapi/gssapi.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Solaris extensions
 */
int KRB5_CALLCONV gssd_pname_to_uid
	(char *,
	 gss_OID,
	 gss_OID,
	 uid_t *);

int KRB5_CALLCONV __gss_userok
	(const gss_name_t /*name*/,
	 const char * /*username*/);

/*
 * GGF extensions
 */
typedef struct gss_buffer_set_desc_struct {
    size_t count;
    gss_buffer_desc *elements;
} gss_buffer_set_desc, *gss_buffer_set_t;

#define GSS_C_NO_BUFFER_SET ((gss_buffer_set_t) 0)

OM_uint32 KRB5_CALLCONV gss_create_empty_buffer_set
	(OM_uint32 * /*minor_status*/,
	 gss_buffer_set_t * /*buffer_set*/);

OM_uint32 KRB5_CALLCONV gss_add_buffer_set_member
	(OM_uint32 * /*minor_status*/,
	 const gss_buffer_t /*member_buffer*/,
	 gss_buffer_set_t * /*buffer_set*/);

OM_uint32 KRB5_CALLCONV gss_release_buffer_set
	(OM_uint32 * /*minor_status*/,
	 gss_buffer_set_t * /*buffer_set*/);

OM_uint32 KRB5_CALLCONV gss_inquire_sec_context_by_oid
	(OM_uint32 * /*minor_status*/,
	 const gss_ctx_id_t /*context_handle*/,
	 const gss_OID /*desired_object*/,
	 gss_buffer_set_t * /*data_set*/);

OM_uint32 KRB5_CALLCONV gss_inquire_cred_by_oid
	(OM_uint32 * /*minor_status*/,
	 const gss_cred_id_t /*cred_handle*/,
	 const gss_OID /*desired_object*/,
	 gss_buffer_set_t * /*data_set*/);

OM_uint32 KRB5_CALLCONV gss_set_sec_context_option
	(OM_uint32 * /*minor_status*/,
	 gss_ctx_id_t * /*cred_handle*/,
	 const gss_OID /*desired_object*/,
	 const gss_buffer_t /*value*/);

/* XXX do these really belong in this header? */
OM_uint32 KRB5_CALLCONV gssspi_set_cred_option
	(OM_uint32 * /*minor_status*/,
	 gss_cred_id_t /*cred*/,
	 const gss_OID /*desired_object*/,
	 const gss_buffer_t /*value*/);

OM_uint32 KRB5_CALLCONV gssspi_mech_invoke
	(OM_uint32 * /*minor_status*/,
	 const gss_OID /*desired_mech*/,
	 const gss_OID /*desired_object*/,
	 gss_buffer_t /*value*/);

/*
 * SSPI extensions
 */
#define GSS_C_DCE_STYLE			0x1000
#define GSS_C_IDENTIFY_FLAG		0x2000
#define GSS_C_EXTENDED_ERROR_FLAG	0x4000

typedef struct gss_iov_buffer_desc_struct {
    OM_uint32 type;
    OM_uint32 flags;
    gss_buffer_desc buffer;
} gss_iov_buffer_desc, *gss_iov_buffer_t;

#define GSS_C_NO_IOV_BUFFER		    ((gss_iov_buffer_t)0)

#define GSS_IOV_BUFFER_TYPE_EMPTY	    0
#define GSS_IOV_BUFFER_TYPE_DATA	    1	/* Packet data */
#define GSS_IOV_BUFFER_TYPE_HEADER	    2	/* Mechanism header */
#define GSS_IOV_BUFFER_TYPE_MECH_PARAMS	    3	/* Mechanism specific parameters */
#define GSS_IOV_BUFFER_TYPE_TRAILER	    7	/* Mechanism trailer */
#define GSS_IOV_BUFFER_TYPE_PADDING	    9	/* Padding */
#define GSS_IOV_BUFFER_TYPE_STREAM	    10	/* Complete wrap token */

#define GSS_IOV_BUFFER_FLAG_ALLOCATE	    1	/* indicates GSS can allocate */
#define GSS_IOV_BUFFER_FLAG_ALLOCATED	    2	/* indicates caller should free */
#define GSS_IOV_BUFFER_FLAG_SIGN_ONLY	    4	/* indicates associated data */

/*
 * Sign and optionally encrypt a sequence of buffers. The buffers
 * shall be ordered HEADER | DATA | PADDING | TRAILER. Suitable
 * space for the header, padding and trailer should be provided
 * by calling gss_wrap_iov_length(), or the ALLOCATE flag should
 * be set on those buffers.
 *
 * Encryption is in-place. SIGN_ONLY buffers are untouched. Only
 * a single PADDING buffer should be provided. The order of the
 * buffers in memory does not matter. Buffers in the IOV should
 * be arranged in the order above, and in the case of multiple
 * DATA buffers the sender and receiver should agree on the
 * order.
 *
 * With GSS_C_DCE_STYLE it is acceptable to not provide PADDING
 * and TRAILER, but the caller must guarantee the plaintext data
 * being encrypted is correctly padded, otherwise an error will
 * be returned.
 */
OM_uint32 KRB5_CALLCONV gss_wrap_iov
(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    size_t,		/* iov_count */
    gss_iov_buffer_desc *);    /* iov */

/*
 * Verify and optionally decrypt a sequence of buffers. To process
 * a GSS-API message without separate buffer, pass STREAM | DATA.
 * Upon return DATA will contain the decrypted or integrity
 * protected message. Only a single DATA buffer may be provided
 * with this usage. DATA by default will point into STREAM, but if
 * the ALLOCATE flag is set a copy will be returned.
 *
 * Otherwise, decryption is in-place. SIGN_ONLY buffers are
 * untouched.
 */
OM_uint32 KRB5_CALLCONV gss_unwrap_iov
(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,       /* context_handle */
    int *,		/* conf_state */
    gss_qop_t *,	/* qop_state */
    size_t,		/* iov_count */
    gss_iov_buffer_desc *);    /* iov */

/*
 * Query HEADER, PADDING and TRAILER buffer lengths. DATA buffers
 * should be provided so the correct padding length can be determined.
 */
OM_uint32 KRB5_CALLCONV gss_wrap_iov_length
(
    OM_uint32 *,	/* minor_status */
    gss_ctx_id_t,	/* context_handle */
    int,		/* conf_req_flag */
    gss_qop_t,		/* qop_req */
    int *,		/* conf_state */
    size_t,		/* iov_count */
    gss_iov_buffer_desc *); /* iov */

/*
 * Release buffers that have the ALLOCATED flag set.
 */
OM_uint32 KRB5_CALLCONV gss_release_iov_buffer
(
    OM_uint32 *,	/* minor_status */
    size_t,		/* iov_count */
    gss_iov_buffer_desc *); /* iov */

#ifdef __cplusplus
}
#endif

#endif /* GSSAPI_EXT_H_ */
