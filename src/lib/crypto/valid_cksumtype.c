#include "k5-int.h"
#include "cksumtypes.h"

krb5_boolean valid_cksumtype(ctype)
     krb5_cksumtype ctype;
{
    int i;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == ctype)
	    return(1);
    }

    return(0);
}
