/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _GSSAPI_KRB5_H_
#define _GSSAPI_KRB5_H_

#ifndef macintosh
#include <gssapi/gssapi_generic.h>
#else
#include <gssapi_generic.h>
#endif
#include <krb5.h>

extern const gss_OID_desc * const gss_mech_krb5;
extern const gss_OID_desc * const gss_mech_krb5_old;
extern const gss_OID_set_desc * const gss_mech_set_krb5;
extern const gss_OID_set_desc * const gss_mech_set_krb5_old;
extern const gss_OID_set_desc * const gss_mech_set_krb5_both;

extern const gss_OID_desc * const gss_nt_krb5_name;
extern const gss_OID_desc * const gss_nt_krb5_principal;

extern const gss_OID_desc krb5_gss_oid_array[];

#define gss_krb5_nt_general_name	gss_nt_krb5_name
#define gss_krb5_nt_principal		gss_nt_krb5_principal
#define gss_krb5_nt_service_name	gss_nt_service_name
#define gss_krb5_nt_user_name		gss_nt_user_name
#define gss_krb5_nt_machine_uid_name	gss_nt_machine_uid_name
#define gss_krb5_nt_string_uid_name	gss_nt_string_uid_name

OM_uint32 gss_krb5_get_tkt_flags 
	PROTOTYPE((OM_uint32 *minor_status,
		   gss_ctx_id_t context_handle,
		   krb5_flags *ticket_flags));

OM_uint32 gss_krb5_copy_ccache
	PROTOTYPE((OM_uint32 *minor_status,
		   gss_cred_id_t cred_handle,
		   krb5_ccache out_ccache));

/* this is for backward compatibility only.  It is declared here for
   completeness, but should not be used */

OM_uint32 krb5_gss_set_backward_mode
        PROTOTYPE((OM_uint32 *minor_status,
                   int mode));

#endif /* _GSSAPI_KRB5_H_ */
