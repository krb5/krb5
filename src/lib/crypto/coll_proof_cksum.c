#include "k5-int.h"
#include "cksumtypes.h"

krb5_boolean is_coll_proof_cksum(ctype)
     krb5_cksumtype ctype;
{
    int i;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == ctype)
	    return((krb5_cksumtypes_list[i].flags &
		    KRB5_CKSUMFLAG_NOT_COLL_PROOF)?0:1);
    }

    /* ick, but it's better than coredumping, which is what the
       old code would have done */
    return(0);
}
