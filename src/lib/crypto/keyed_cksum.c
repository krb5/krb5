#include "k5-int.h"
#include "cksumtypes.h"

krb5_boolean is_keyed_cksum(ctype)
     krb5_cksumtype ctype;
{
    int i;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == ctype) {
	    if (krb5_cksumtypes_list[i].keyhash ||
		(krb5_cksumtypes_list[i].flags &
		 KRB5_CKSUMFLAG_DERIVE))
		return(1);
	    else
		return(0);
	}
    }

    /* ick, but it's better than coredumping, which is what the
       old code would have done */
    return(-1);
}
