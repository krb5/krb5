#include "k5-int.h"
#include "etypes.h"

krb5_error_code
krb5_c_enctype_compare(context, e1, e2, similar)
     krb5_context context;
     krb5_enctype e1;
     krb5_enctype e2;
     krb5_boolean *similar;
{
    int i, j;

    for (i=0; i<krb5_enctypes_length; i++) 
	if (krb5_enctypes_list[i].etype == e1)
	    break;

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    for (j=0; j<krb5_enctypes_length; j++) 
	if (krb5_enctypes_list[j].etype == e2)
	    break;

    if (j == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    *similar = 
	((krb5_enctypes_list[i].enc == krb5_enctypes_list[j].enc) &&
	 (krb5_enctypes_list[i].str2key == krb5_enctypes_list[j].str2key));

    return(0);
}
