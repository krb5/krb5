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

#include "gssapiP_krb5.h"
#ifdef USE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/* get credentials corresponding to a key in the krb5 keytab.
   If the default name is requested, return the name in output_princ.
     If output_princ is non-NULL, the caller will use or free it, regardless
     of the return value.
   If successful, set the keytab-specific fields in cred
   */

static OM_uint32 
acquire_accept_cred(context, minor_status, desired_name, output_princ, cred)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     krb5_principal *output_princ;
     krb5_gss_cred_id_rec *cred;
{
   krb5_error_code code;
   krb5_principal princ;
   krb5_keytab kt;
   krb5_keytab_entry entry;
   krb5_kt_cursor cur;

   *output_princ = NULL;
   cred->keytab = NULL;

   /* open the default keytab */

   if (code = krb5_kt_default(context, &kt)) {
      *minor_status = code;
      return(GSS_S_CRED_UNAVAIL);
   }

   /* figure out what principal to use.  If the default name is
      requested, use the default sn2princ output */

   if (desired_name == (gss_name_t) NULL) {
      if (code = krb5_sname_to_principal(context, NULL, NULL, KRB5_NT_SRV_HST,
					 &princ)) {
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      *output_princ = princ;
   } else {
      princ = (krb5_principal) desired_name;
   }

   /* iterate over the keytab searching for the principal */

   if (code = krb5_kt_start_seq_get(context, kt, &cur)) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   while (!(code = krb5_kt_next_entry(context, kt, &entry, &cur))) {
      if (krb5_principal_compare(context, entry.principal, princ)) {
	 code = 0;
	 krb5_kt_free_entry(context, &entry);
	 break;
      } 
      krb5_kt_free_entry(context, &entry);
   }

   if (code == KRB5_KT_END) {
      /* this means that the principal wasn't in the keytab */
      (void)krb5_kt_end_seq_get(context, kt, &cur);
      *minor_status = KG_KEYTAB_NOMATCH;
      return(GSS_S_CRED_UNAVAIL);
   } else if (code) {
      /* this means some error occurred reading the keytab */
      (void)krb5_kt_end_seq_get(context, kt, &cur);
      *minor_status = code;
      return(GSS_S_FAILURE);
   } else {
      /* this means that we found a matching entry */
      if (code = krb5_kt_end_seq_get(context, kt, &cur)) {
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
   }

   /* hooray.  we made it */

   cred->keytab = kt;
   return(GSS_S_COMPLETE);
}

/* get credentials corresponding to the default credential cache.
   If the default name is requested, return the name in output_princ.
     If output_princ is non-NULL, the caller will use or free it, regardless
     of the return value.
   If successful, set the ccache-specific fields in cred.
   */

static OM_uint32 
acquire_init_cred(context, minor_status, desired_name, output_princ, cred)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     krb5_principal *output_princ;
     krb5_gss_cred_id_rec *cred;
{
   krb5_error_code code;
   krb5_ccache ccache;
   krb5_principal princ;
   krb5_flags flags;
   krb5_cc_cursor cur;
   krb5_creds creds;
   int got_endtime;

   cred->ccache = NULL;

   /* open the default credential cache */

   if (code = krb5_cc_default(context, &ccache)) {
      *minor_status = code;
      return(GSS_S_CRED_UNAVAIL);
   }

   /* turn off OPENCLOSE mode while extensive frobbing is going on */

   flags = 0;		/* turns off OPENCLOSE mode */
   if (code = krb5_cc_set_flags(context, ccache, flags)) {
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   /* get out the principal name and see if it matches */

   if (code = krb5_cc_get_principal(context, ccache, &princ)) {
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   if (desired_name != (gss_name_t) NULL) {
      if (! krb5_principal_compare(context, princ, (krb5_principal) desired_name)) {
	 (void)krb5_free_principal(context, princ);
	 (void)krb5_cc_close(context, ccache);
	 *minor_status = KG_CCACHE_NOMATCH;
	 return(GSS_S_CRED_UNAVAIL);
      }
      (void)krb5_free_principal(context, princ);
      princ = (krb5_principal) desired_name;
   } else {
      *output_princ = princ;
   }

   /* iterate over the ccache, find the tgt */

   if (code = krb5_cc_start_seq_get(context, ccache, &cur)) {
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   }

   /* this is hairy.  If there's a tgt for the principal's local realm
      in here, that's what we want for the expire time.  But if
      there's not, then we want to use the first key.  */

   got_endtime = 0;

   while (!(code = krb5_cc_next_cred(context, ccache, &cur, &creds))) {
      if ((creds.server->length == 2) &&
	  (strcmp(creds.server->realm.data, princ->realm.data) == 0) &&
	  (strcmp((char *) creds.server->data[0].data, "krbtgt") == 0) &&
	  (strcmp((char *) creds.server->data[1].data,
		  princ->realm.data) == 0)) {
	 cred->tgt_expire = creds.times.endtime;
	 got_endtime = 1;
	 *minor_status = 0;
	 code = 0;
	 krb5_free_cred_contents(context, &creds);
	 break;
      }
      if (got_endtime == 0) {
	 cred->tgt_expire = creds.times.endtime;
	 got_endtime = 1;
	 *minor_status = KG_TGT_MISSING;
      }
      krb5_free_cred_contents(context, &creds);
   }

   if (code && code != KRB5_CC_END) {
      /* this means some error occurred reading the ccache */
      (void)krb5_cc_end_seq_get(context, ccache, &cur);
      (void)krb5_cc_close(context, ccache);
      *minor_status = code;
      return(GSS_S_FAILURE);
   } else {
      /* this means that we found an endtime to use. */
      if (code = krb5_cc_end_seq_get(context, ccache, &cur)) {
	 (void)krb5_cc_close(context, ccache);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
      flags = KRB5_TC_OPENCLOSE;	/* turns on OPENCLOSE mode */
      if (code = krb5_cc_set_flags(context, ccache, flags)) {
	 (void)krb5_cc_close(context, ccache);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
   }

   /* the credentials match and are valid */

   cred->ccache = ccache;
   /* minor_status is set while we are iterating over the ccache */
   return(GSS_S_COMPLETE);
}
   
/*ARGSUSED*/
OM_uint32
krb5_gss_acquire_cred(context, minor_status, desired_name, time_req,
		      desired_mechs, cred_usage, output_cred_handle,
		      actual_mechs, time_rec)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_name_t desired_name;
     OM_uint32 time_req;
     gss_OID_set desired_mechs;
     gss_cred_usage_t cred_usage;
     gss_cred_id_t *output_cred_handle;
     gss_OID_set *actual_mechs;
     OM_uint32 *time_rec;
{
   int i;
   krb5_gss_cred_id_t cred;
   gss_OID_set mechs;
   OM_uint32 ret;
   krb5_error_code code;

   /* make sure all outputs are valid */

   *output_cred_handle = NULL;
   if (actual_mechs)
      *actual_mechs = NULL;
   if (time_rec)
      *time_rec = 0;

   /* validate the name */

   /*SUPPRESS 29*/
   if ((desired_name != (gss_name_t) NULL) &&
       (! kg_validate_name(desired_name))) {
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_CALL_BAD_STRUCTURE|GSS_S_BAD_NAME);
   }

   /* verify that the requested mechanism set is the default, or
      contains krb5 */

   if (desired_mechs != GSS_C_NULL_OID_SET) {
      for (i=0; i<desired_mechs->count; i++)
	 if (g_OID_equal(gss_mech_krb5, &(desired_mechs->elements[i])))
	    break;
      if (i == desired_mechs->count) {
	 *minor_status = 0;
	 return(GSS_S_BAD_MECH);
      }
   }

   /* create the gss cred structure */

   if ((cred =
	(krb5_gss_cred_id_t) xmalloc(sizeof(krb5_gss_cred_id_rec))) == NULL) {
      *minor_status = ENOMEM;
      return(GSS_S_FAILURE);
   }

   cred->usage = cred_usage;
   cred->princ = NULL;

   cred->keytab = NULL;
   cred->ccache = NULL;

   if ((cred_usage != GSS_C_INITIATE) &&
       (cred_usage != GSS_C_ACCEPT) &&
       (cred_usage != GSS_C_BOTH)) {
      xfree(cred);
      *minor_status = (OM_uint32) G_BAD_USAGE;
      return(GSS_S_FAILURE);
   }

   /* if requested, acquire credentials for accepting */
   /* this will fill in cred->princ if the desired_name is not specified */

   if ((cred_usage == GSS_C_ACCEPT) ||
       (cred_usage == GSS_C_BOTH))
      if ((ret = acquire_accept_cred(context, minor_status, desired_name,
				     &(cred->princ), cred))
	  != GSS_S_COMPLETE) {
	 if (cred->princ)
	    krb5_free_principal(context, cred->princ);
	 xfree(cred);
	 /* minor_status set by acquire_accept_cred() */
	 return(ret);
      }

   /* if requested, acquire credentials for initiation */
   /* this will fill in cred->princ if it wasn't set above, and
      the desired_name is not specified */

   if ((cred_usage == GSS_C_INITIATE) ||
       (cred_usage == GSS_C_BOTH))
      if ((ret =
	   acquire_init_cred(context, minor_status,
			     cred->princ?(gss_name_t)cred->princ:desired_name,
			     &(cred->princ), cred))
	  != GSS_S_COMPLETE) {
	 if (cred->keytab)
	    krb5_kt_close(context, cred->keytab);
	 if (cred->princ)
	    krb5_free_principal(context, cred->princ);
	 xfree(cred);
	 /* minor_status set by acquire_init_cred() */
	 return(ret);
      }

   /* if the princ wasn't filled in already, fill it in now */

   if (!cred->princ)
      if (code = krb5_copy_principal(context, (krb5_principal) desired_name,
				     &(cred->princ))) {
	 if (cred->ccache)
	    (void)krb5_cc_close(context, cred->ccache);
	 if (cred->keytab)
	    (void)krb5_kt_close(context, cred->keytab);
	 xfree(cred);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

   /*** at this point, the cred structure has been completely created */

   /* compute time_rec */

   if (cred_usage == GSS_C_ACCEPT) {
      if (time_rec)
	 *time_rec = GSS_C_INDEFINITE;
   } else {
      krb5_timestamp now;

      if (code = krb5_timeofday(context, &now)) {
	 if (cred->ccache)
	    (void)krb5_cc_close(context, cred->ccache);
	 if (cred->keytab)
	    (void)krb5_kt_close(context, cred->keytab);
	 if (cred->princ)
	    krb5_free_principal(context, cred->princ);
	 xfree(cred);
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }

      if (time_rec)
	 *time_rec = cred->tgt_expire - now;
   }

   /* create mechs */

   if (actual_mechs) {
      if (! g_copy_OID_set(gss_mech_set_krb5, &mechs)) {
	 if (cred->ccache)
	    (void)krb5_cc_close(context, cred->ccache);
	 if (cred->keytab)
	    (void)krb5_kt_close(context, cred->keytab);
	 if (cred->princ)
	    krb5_free_principal(context, cred->princ);
	 xfree(cred);
	 *minor_status = ENOMEM;
	 return(GSS_S_FAILURE);
      }
   }

   /* intern the credential handle */

   if (! kg_save_cred_id((gss_cred_id_t) cred)) {
      free(mechs->elements);
      free(mechs);
      if (cred->ccache)
	 (void)krb5_cc_close(context, cred->ccache);
      if (cred->keytab)
	 (void)krb5_kt_close(context, cred->keytab);
      if (cred->princ)
	 krb5_free_principal(context, cred->princ);
      xfree(cred);
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_FAILURE);
   }

   /* return success */

   *minor_status = 0;
   *output_cred_handle = (gss_cred_id_t) cred;
   if (actual_mechs)
      *actual_mechs = mechs;

   return(GSS_S_COMPLETE);
}

/* V2 interface */
OM_uint32
krb5_gss_add_cred(context, minor_status, input_cred_handle,
		  desired_name, desired_mech, cred_usage,
		  initiator_time_req, acceptor_time_req,
		  output_cred_handle, actual_mechs, 
		  initiator_time_rec, acceptor_time_rec)
    krb5_context	context;
    OM_uint32		*minor_status;
    gss_cred_id_t	input_cred_handle;
    gss_name_t		desired_name;
    gss_OID		desired_mech;
    gss_cred_usage_t	cred_usage;
    OM_uint32		initiator_time_req;
    OM_uint32		acceptor_time_req;
    gss_cred_id_t	*output_cred_handle;
    gss_OID_set		*actual_mechs;
    OM_uint32		*initiator_time_rec;
    OM_uint32		*acceptor_time_rec;
{
    /*
     * This does not apply to our single-mechanism implementation.  Until we
     * come up with a better error code, return failure.
     */
    *minor_status = 0;
    return(GSS_S_FAILURE);
}

