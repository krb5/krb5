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
#ifndef NO_PASSWORD
#include <pwd.h>
#endif

#ifdef USE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

/*
 * errors:
 * GSS_S_BAD_NAMETYPE	if the type is bogus
 * GSS_S_BAD_NAME	if the type is good but the name is bogus
 * GSS_S_FAILURE	if memory allocation fails
 */

OM_uint32
krb5_gss_import_name(context, minor_status, input_name_buffer, 
		     input_name_type, output_name)
     krb5_context context;
     OM_uint32 *minor_status;
     gss_buffer_t input_name_buffer;
     gss_OID input_name_type;
     gss_name_t *output_name;
{
   krb5_principal princ;
   krb5_error_code code;
   char *stringrep;
#ifndef NO_PASSWORD
   struct passwd *pw;
#endif
   /* set up default returns */

   *output_name = NULL;
   *minor_status = 0;

   /* Go find the appropriate string rep to pass into parse_name */

   if ((input_name_type != GSS_C_NULL_OID) &&
       g_OID_equal(input_name_type, gss_nt_service_name)) {
      char *tmp, *service, *host;

      if ((tmp =
	   (char *) xmalloc(strlen(input_name_buffer->value)+1)) == NULL) {
	 *minor_status = ENOMEM;
	 return(GSS_S_FAILURE);
      }

      strcpy(tmp, input_name_buffer->value);

      service = tmp;
      if ((host = strchr(tmp, '@')) == NULL) {
	 xfree(tmp);
	 *minor_status = (OM_uint32) G_BAD_SERVICE_NAME;
	 return(GSS_S_BAD_NAME);
      }
      *host = '\0';
      host++;

      code = krb5_sname_to_principal(context, host, service, KRB5_NT_SRV_HST,
				     &princ);

      xfree(tmp);
   } else if ((input_name_type != GSS_C_NULL_OID) &&
	      (g_OID_equal(input_name_type, gss_nt_krb5_principal))) {
      krb5_principal input;

      if (input_name_buffer->length != sizeof(krb5_principal)) {
	 *minor_status = (OM_uint32) G_WRONG_SIZE;
	 return(GSS_S_BAD_NAME);
      }

      input = *((krb5_principal *) input_name_buffer->value);

      if (code = krb5_copy_principal(context, input, &princ)) {
	 *minor_status = code;
	 return(GSS_S_FAILURE);
      }
   } else {
      stringrep = NULL;

      if ((input_name_type == GSS_C_NULL_OID) ||
	  g_OID_equal(input_name_type, gss_nt_krb5_name) ||
	  g_OID_equal(input_name_type, gss_nt_user_name)) {
	 stringrep = (char *) input_name_buffer->value;
#ifndef NO_PASSWORD
      } else if (g_OID_equal(input_name_type, gss_nt_machine_uid_name)) {
	 if (pw = getpwuid(*((uid_t *) input_name_buffer->value)))
	    stringrep = pw->pw_name;
	 else
	    *minor_status = (OM_uint32) G_NOUSER;
      } else if (g_OID_equal(input_name_type, gss_nt_string_uid_name)) {
	 if (pw = getpwuid((uid_t) atoi(input_name_buffer->value)))
	    stringrep = pw->pw_name;
	 else
	    *minor_status = (OM_uint32) G_NOUSER;
#endif
      } else {
	 return(GSS_S_BAD_NAMETYPE);
      }

      /* at this point, stringrep is set, or if not, *minor_status is. */

      if (stringrep)
	 code = krb5_parse_name(context, (char *) stringrep, &princ);
      else
	 return(GSS_S_BAD_NAME);
   }

   /* at this point, a krb5 function has been called to set princ.  code
      contains the return status */

   if (code) {
      *minor_status = (OM_uint32) code;
      return(GSS_S_BAD_NAME);
   }

   /* save the name in the validation database */

   if (! kg_save_name((gss_name_t) princ)) {
      krb5_free_principal(context, princ);
      *minor_status = (OM_uint32) G_VALIDATE_FAILED;
      return(GSS_S_FAILURE);
   }

   /* return it */

   *output_name = (gss_name_t) princ;
   return(GSS_S_COMPLETE);
}
