#include "gssapiP_krb5.h"

OM_uint32 KRB5_CALLCONV 
gss_krb5_copy_ccache(minor_status, cred_handle, out_ccache)
     OM_uint32 *minor_status;
     gss_cred_id_t cred_handle;
     krb5_ccache out_ccache;
{
   OM_uint32 stat;
   krb5_gss_cred_id_t k5creds;
   krb5_cc_cursor cursor;
   krb5_creds creds;
   krb5_error_code code;
   krb5_context context;

   /* validate the cred handle */
   stat = krb5_gss_validate_cred(minor_status, cred_handle);
   if (stat)
       return(stat);
   
   k5creds = (krb5_gss_cred_id_t) cred_handle;
   if (k5creds->usage == GSS_C_ACCEPT) {
       *minor_status = (OM_uint32) G_BAD_USAGE;
       return(GSS_S_FAILURE);
   }

   if (GSS_ERROR(kg_get_context(minor_status, &context)))
       return (GSS_S_FAILURE);

   code = krb5_cc_start_seq_get(context, k5creds->ccache, &cursor);
   if (code) {
       *minor_status = code;
       return(GSS_S_FAILURE);
   }
   while (!code && !krb5_cc_next_cred(context, k5creds->ccache, &cursor, &creds)) 
       code = krb5_cc_store_cred(context, out_ccache, &creds);
   krb5_cc_end_seq_get(context, k5creds->ccache, &cursor);

   if (code) {
       *minor_status = code;
       return(GSS_S_FAILURE);
   } else {
       *minor_status = 0;
       return(GSS_S_COMPLETE);
   }
}
