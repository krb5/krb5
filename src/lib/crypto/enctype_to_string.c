#include "k5-int.h"
#include "etypes.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_enctype_to_string(enctype, buffer, buflen)
    krb5_enctype	enctype;
    char		FAR * buffer;
    size_t		buflen;
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype) {
	    if ((strlen(krb5_enctypes_list[i].out_string)+1) > buflen)
		return(ENOMEM);

	    strcpy(buffer, krb5_enctypes_list[i].out_string);
	    return(0);
	}
    }

    return(EINVAL);
}
