#include "k5-int.h"
#include "cksumtypes.h"

krb5_error_code
krb5_c_checksum_length(context, cksumtype, length)
     krb5_context context;
     krb5_cksumtype cksumtype;
     size_t *length;
{
    int i;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    if (krb5_cksumtypes_list[i].keyhash)
	(*(krb5_cksumtypes_list[i].keyhash->hash_size))(length);
    else
	(*(krb5_cksumtypes_list[i].hash->hash_size))(length);

    return(0);
}
	
