#include "k5-int.h"
#include "cksumtypes.h"

krb5_error_code
krb5_c_verify_checksum(context, key, usage, data, cksum, valid)
     krb5_context context;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *data;
     krb5_const krb5_checksum *cksum;
     krb5_boolean *valid;
{
    int i;
    size_t hashsize;
    krb5_error_code ret;
    krb5_data indata;
    krb5_checksum computed;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksum->checksum_type)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    /* if there's actually a verify function, call it */

    indata.length = cksum->length;
    indata.data = cksum->contents;

    if (krb5_cksumtypes_list[i].keyhash &&
	krb5_cksumtypes_list[i].keyhash->verify)
	return((*(krb5_cksumtypes_list[i].keyhash->verify))(key, 0, data,
							    &indata, valid));

    /* otherwise, make the checksum again, and compare */

    if (ret = krb5_c_checksum_length(context, cksum->checksum_type, &hashsize))
	return(ret);

    if (cksum->length != hashsize)
	return(KRB5_BAD_MSIZE);

    computed.length = hashsize;
    if ((computed.contents = (krb5_octet *) malloc(computed.length)) == NULL)
	return(ENOMEM);

    if (ret = krb5_c_make_checksum(context, cksum->checksum_type, key, usage,
				   data, &computed)) {
	free(computed.contents);
	return(ret);
    }

    *valid = (memcmp(computed.contents, cksum->contents, hashsize) == 0);

    free(computed.contents);

    return(0);
}
