#include "k5-int.h"
#include "etypes.h"
#include "cksumtypes.h"

static int etype_match(e1, e2)
     krb5_enctype e1, e2;
{
    int i1, i2;

    for (i1=0; i1<krb5_enctypes_length; i1++) 
	if (krb5_enctypes_list[i1].etype == e1)
	    break;

    for (i2=0; i2<krb5_enctypes_length; i2++) 
	if (krb5_enctypes_list[i2].etype == e2)
	    break;

    return((i1 < krb5_enctypes_length) &&
	   (i2 < krb5_enctypes_length) &&
	   (krb5_enctypes_list[i1].enc == krb5_enctypes_list[i2].enc));
}

krb5_error_code
krb5_c_keyed_checksum_types(context, enctype, count, cksumtypes)
     krb5_context context;
     krb5_enctype enctype;
     unsigned int *count;
     krb5_cksumtype **cksumtypes;
{
    unsigned int i, c;

    c = 0;
    for (i=0; i<krb5_cksumtypes_length; i++) {
	if ((krb5_cksumtypes_list[i].keyhash &&
	     etype_match(krb5_cksumtypes_list[i].keyed_etype, enctype)) ||
	    (krb5_cksumtypes_list[i].flags & KRB5_CKSUMFLAG_DERIVE)) {
	    c++;
	}
    }

    *count = c;

    if ((*cksumtypes = (krb5_cksumtype *) malloc(c*sizeof(krb5_cksumtype)))
	== NULL)
	return(ENOMEM);

    c = 0;
    for (i=0; i<krb5_cksumtypes_length; i++) {
	if ((krb5_cksumtypes_list[i].keyhash &&
	     etype_match(krb5_cksumtypes_list[i].keyed_etype, enctype)) ||
	    (krb5_cksumtypes_list[i].flags & KRB5_CKSUMFLAG_DERIVE)) {
	    (*cksumtypes)[c] = krb5_cksumtypes_list[i].ctype;
	    c++;
	}
    }

    return(0);
}

void
krb5_free_cksumtypes(context, val)
    krb5_context context;
    krb5_cksumtype FAR * val;
{
    if (val)
	krb5_xfree(val);
    return;
}

