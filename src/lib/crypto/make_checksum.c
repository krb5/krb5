#include "k5-int.h"
#include "cksumtypes.h"

krb5_error_code
krb5_c_make_checksum(context, cksumtype, key, usage, input, cksum)
     krb5_context context;
     krb5_cksumtype cksumtype;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *input;
     krb5_checksum *cksum;
{
    int i;
    krb5_data data;
    krb5_error_code ret;
    size_t cksumlen;

    for (i=0; i<krb5_cksumtypes_length; i++) {
	if (krb5_cksumtypes_list[i].ctype == cksumtype)
	    break;
    }

    if (i == krb5_cksumtypes_length)
	return(KRB5_BAD_ENCTYPE);

    (*(krb5_cksumtypes_list[i].hash->hash_size))(&cksumlen);

    cksum->length = cksumlen;

    if ((cksum->contents = (krb5_octet *) malloc(cksum->length)) == NULL)
	return(ENOMEM);

    data.length = cksum->length;
    data.data = cksum->contents;

    if (krb5_cksumtypes_list[i].keyhash) {
	ret = (*(krb5_cksumtypes_list[i].keyhash->hash))(key, 0, input, &data);
    } else if (krb5_cksumtypes_list[i].flags & KRB5_CKSUMFLAG_DERIVE) {
	ret = krb5_dk_make_checksum(krb5_cksumtypes_list[i].hash,
				    key, usage, input, &data);
    } else {
	ret = (*(krb5_cksumtypes_list[i].hash->hash))(1, input, &data);
    }

    if (ret) {
	memset(cksum->contents, 0, cksum->length);
	free(cksum->contents);
    } else {
	cksum->magic = KV5M_CHECKSUM;
	cksum->checksum_type = cksumtype;
    }

    return(ret);
}
