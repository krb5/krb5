#include "k5-int.h"
#include "cksumtypes.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_cksumtype(string, cksumtypep)
    char		FAR * string;
    krb5_cksumtype	FAR * cksumtypep;
{
    int i;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (strcasecmp(krb5_cksumtypes_list[i].in_string, string) == 0) {
	    *cksumtypep = krb5_cksumtypes_list[i].ctype;
	    return(0);
	}
    }

    return(EINVAL);
}
