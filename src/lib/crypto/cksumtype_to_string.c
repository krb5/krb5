#include "k5-int.h"
#include "cksumtypes.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_cksumtype_to_string(cksumtype, buffer, buflen)
    krb5_cksumtype	cksumtype;
    char		FAR * buffer;
    size_t		buflen;
{
    int i;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype) {
	    if ((strlen(krb5_cksumtypes_list[i].out_string)+1) > buflen)
		return(ENOMEM);

	    strcpy(buffer, krb5_cksumtypes_list[i].out_string);
	    return(0);
	}
    }

    return(EINVAL);
}
