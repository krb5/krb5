#include "k5-int.h"
#include "etypes.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_enctype(string, enctypep)
    char		FAR * string;
    krb5_enctype	FAR * enctypep;
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (strcasecmp(krb5_enctypes_list[i].in_string, string) == 0) {
	    *enctypep = krb5_enctypes_list[i].etype;
	    return(0);
	}
    }

    return(EINVAL);
}
