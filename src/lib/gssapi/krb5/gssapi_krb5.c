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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * $Id$
 */

#include "gssapiP_krb5.h"

/** exported constants defined in gssapi_krb5{,_nx}.h **/

/* these are bogus, but will compile */

/*
 * The OID of the draft krb5 mechanism, assigned by IETF, is:
 * 	iso(1) org(3) dod(5) internet(1) security(5)
 *	kerberosv5(2) = 1.3.5.1.5.2
 * The OID of the krb5_name type is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) krb5_name(1) = 1.2.840.113554.1.2.2.1
 * The OID of the krb5_principal type is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) krb5_principal(2) = 1.2.840.113554.1.2.2.2
 * The OID of the proposed standard krb5 mechanism is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5(2) = 1.2.840.113554.1.2.2
 * The OID of the proposed standard krb5 v2 mechanism is:
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	krb5v2(3) = 1.2.840.113554.1.2.3
 *	
 */

/*
 * Encoding rules: The first two values are encoded in one byte as 40
 * * value1 + value2.  Subsequent values are encoded base 128, most
 * significant digit first, with the high bit (\200) set on all octets
 * except the last in each value's encoding.
 */

const gss_OID_desc krb5_gss_oid_array[] = {
   /* this is the official, rfc-specified OID */
   {9, "\052\206\110\206\367\022\001\002\002"},
   /* this is the unofficial, wrong OID */
   {5, "\053\005\001\005\002"},
   /* this is the v2 assigned OID */
   {9, "\052\206\110\206\367\022\001\002\003"},
   /* these two are name type OID's */
   {10, "\052\206\110\206\367\022\001\002\002\001"},
   {10, "\052\206\110\206\367\022\001\002\002\002"},
   { 0, 0 }
};

const gss_OID_desc * const gss_mech_krb5 = krb5_gss_oid_array+0;
const gss_OID_desc * const gss_mech_krb5_old = krb5_gss_oid_array+1;
const gss_OID_desc * const gss_mech_krb5_v2 = krb5_gss_oid_array+2;
const gss_OID_desc * const gss_nt_krb5_name = krb5_gss_oid_array+3;
const gss_OID_desc * const gss_nt_krb5_principal = krb5_gss_oid_array+4;

static const gss_OID_set_desc oidsets[] = {
   {1, (gss_OID) krb5_gss_oid_array+0},
   {1, (gss_OID) krb5_gss_oid_array+1},
   {2, (gss_OID) krb5_gss_oid_array+0},
   {1, (gss_OID) krb5_gss_oid_array+2},
   {3, (gss_OID) krb5_gss_oid_array+0},
};

const gss_OID_set_desc * const gss_mech_set_krb5 = oidsets+0;
const gss_OID_set_desc * const gss_mech_set_krb5_old = oidsets+1;
const gss_OID_set_desc * const gss_mech_set_krb5_both = oidsets+2;
const gss_OID_set_desc * const gss_mech_set_krb5_v2 = oidsets+3;
const gss_OID_set_desc * const gss_mech_set_krb5_v1v2 = oidsets+4;

void *kg_vdb = NULL;

/** default credential support */

/* default credentials */

static gss_cred_id_t defcred = GSS_C_NO_CREDENTIAL;

/* XXX what happens when the default credentials expire or are invalidated? */

OM_uint32
kg_get_defcred(minor_status, cred)
     OM_uint32 *minor_status;
     gss_cred_id_t *cred;
{
   if (defcred == GSS_C_NO_CREDENTIAL) {
      OM_uint32 major;

      if ((major = krb5_gss_acquire_cred(minor_status, 
					 (gss_name_t) NULL, GSS_C_INDEFINITE, 
					 GSS_C_NULL_OID_SET, GSS_C_INITIATE, 
					 &defcred, NULL, NULL)) &&
	  GSS_ERROR(major)) {
	 defcred = GSS_C_NO_CREDENTIAL;
	 return(major);
      }
   }

   *cred = defcred;
   *minor_status = 0;
   return(GSS_S_COMPLETE);
}

OM_uint32
kg_release_defcred(minor_status)
     OM_uint32 *minor_status;
{
   if (defcred == GSS_C_NO_CREDENTIAL) {
      *minor_status = 0;
      return(GSS_S_COMPLETE);
   }

   return(krb5_gss_release_cred(minor_status, &defcred));
}

OM_uint32
kg_get_context(minor_status, context)
   OM_uint32 *minor_status;
   krb5_context *context;
{
   static krb5_context kg_context = NULL;
   krb5_error_code code;

   if (!kg_context) {
	   if ((code = krb5_init_context(&kg_context)))
		   goto fail;
	   if ((code = krb5_ser_context_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_auth_context_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_ccache_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_rcache_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_keytab_init(kg_context)))
		   goto fail;
	   if ((code = krb5_ser_auth_context_init(kg_context)))
	       goto fail;
   }
   *context = kg_context;
   *minor_status = 0;
   return GSS_S_COMPLETE;
   
fail:
   *minor_status = (OM_uint32) code;
   return GSS_S_FAILURE;
}
