#include "k5-int.h"
#include "etypes.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_c_encrypt_length(context, enctype, inputlen, length)
     krb5_context context;
     krb5_enctype enctype;
     size_t inputlen;
     size_t *length;
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    (*(krb5_enctypes_list[i].encrypt_len))
	(krb5_enctypes_list[i].enc, krb5_enctypes_list[i].hash,
	 inputlen, length);

    return(0);
}
