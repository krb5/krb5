#include "k5-int.h"
#include "etypes.h"

krb5_boolean valid_enctype(etype)
     krb5_enctype etype;
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == etype)
	    return(1);
    }

    return(0);
}
