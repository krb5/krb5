/** @example  cc_set_config.c
 *
 *  Demo for krb5_cc_set_config function
 */
#include <k5-int.h>

krb5_error_code
func(krb5_context context, krb5_ccache id,
     krb5_const_principal principal, const char *key)
{
   krb5_data config_data;

   config_data.data = "yes";
   config_data.length = strlen(config_data.data);
   return  krb5_cc_set_config(context, id, principal, key, &config_data);
}
