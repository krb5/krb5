#include "k5-int.h"
#include "etypes.h"

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_c_decrypt(context, key, usage, ivec, input, output)
     krb5_context context;
     krb5_const krb5_keyblock *key;
     krb5_keyusage usage;
     krb5_const krb5_data *ivec;
     krb5_const krb5_enc_data *input;
     krb5_data *output;
{
    int i;

    for (i=0; i<krb5_enctypes_length; i++) {
	if (krb5_enctypes_list[i].etype == key->enctype)
	    break;
    }

    if (i == krb5_enctypes_length)
	return(KRB5_BAD_ENCTYPE);

    if ((input->enctype != ENCTYPE_UNKNOWN) &&
	(krb5_enctypes_list[i].etype != input->enctype))
	return(KRB5_BAD_ENCTYPE);

    return((*(krb5_enctypes_list[i].decrypt))
	   (krb5_enctypes_list[i].enc, krb5_enctypes_list[i].hash,
	    key, usage, ivec, &input->ciphertext, output));
}
