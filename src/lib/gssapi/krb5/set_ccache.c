#include "gssapiP_krb5.h"

OM_uint32
gss_krb5_ccache_name(minor_status, name, out_name)
	OM_uint32 *minor_status;
	const char *name;
	const char **out_name;
{
	krb5_context context;
    krb5_error_code retval;

	if (GSS_ERROR(kg_get_context(minor_status, &context)))
		return (GSS_S_FAILURE);

	if (out_name)
		*out_name = krb5_cc_default_name(context);
	if (name) {
		retval = krb5_cc_set_default_name(context, name);
		if (retval) {
			*minor_status = retval;
			return GSS_S_FAILURE;
		}
	}
	return GSS_S_COMPLETE;
}
		

	

