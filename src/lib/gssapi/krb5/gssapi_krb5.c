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
 * $Id$
 */

#include "gssapiP_krb5.h"

/** exported constants defined in gssapi_krb5.h **/

/* these are bogus, but will compile */

static const gss_OID_desc oids[] = {
   /* this OID is from Ted.  It's not official yet, but it's close. */
   {5, "\053\005\001\005\002"},
   {2, "\002\002"},
   {2, "\002\003"},
};

const_gss_OID gss_mech_krb5 = oids+0;
const_gss_OID gss_nt_krb5_name = oids+1;
const_gss_OID gss_nt_krb5_principal = oids+2;

static const gss_OID_set_desc oidsets[] = {
   {1, (gss_OID) oids},
};

const gss_OID_set_desc * const gss_mech_set_krb5 = oidsets+0;

void *kg_vdb = NULL;

/** default credential support */

/* default credentials */

static gss_cred_id_t defcred = GSS_C_NO_CREDENTIAL;

/* XXX what happens when the default credentials expire or are invalidated? */

OM_uint32
kg_get_defcred(OM_uint32 *minor_status, gss_cred_id_t *cred)
{
   if (defcred == GSS_C_NO_CREDENTIAL) {
      OM_uint32 major;

      if ((major = krb5_gss_acquire_cred(minor_status, GSS_C_NO_NAME,
					 GSS_C_INDEFINITE, GSS_C_NULL_OID_SET,
					 GSS_C_INITIATE, &defcred, NULL,
					 NULL)) &&
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
kg_release_defcred(OM_uint32 *minor_status)
{
   if (defcred == GSS_C_NO_CREDENTIAL) {
      *minor_status = 0;
      return(GSS_S_COMPLETE);
   }

   return(krb5_gss_release_cred(minor_status, &defcred));
}
