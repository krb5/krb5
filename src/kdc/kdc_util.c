/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Utility functions for the KDC implementation.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kdc_util_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/krb5_err.h>

#include "kdc_util.h"

#include <errno.h>
#include <krb5/ext-proto.h>

extern krb5_cs_table_entry *csarray[];
extern int max_cryptosystem;		/* max entry in array */

/*
 * concatenate first two authdata arrays, returning an allocated replacement.
 * The replacement should be freed with krb5_free_authdata().
 */
krb5_error_code
concat_authorization_data(first, second, output)
krb5_authdata **first;
krb5_authdata **second;
krb5_authdata ***output;
{
    register int i, j;
    register krb5_authdata **ptr, **retdata;

    /* count up the entries */
    for (i = 0, ptr = first; *ptr; ptr++,i++);
    for (ptr = second; *ptr; ptr++,i++);
    
    retdata = (krb5_authdata **)malloc((i+1)*sizeof(*retdata));
    if (!retdata)
	return ENOMEM;
    retdata[i] = 0;			/* null-terminated array */
    for (i = 0, j = 0, ptr = first; j < 2 ; ptr = second, j++)
	while (*ptr) {
	    /* now walk & copy */
	    retdata[i] = (krb5_authdata *)malloc(sizeof(*retdata[i]));
	    if (!retdata[i]) {
		/* XXX clean up */
		return ENOMEM;
	    }
	    *retdata[i] = **ptr;
	    if (!(retdata[i]->contents =
		  (krb5_octet *)malloc(retdata[i]->length))) {
		/* XXX clean up */
		return ENOMEM;
	    }
	    bcopy((char *)(*ptr)->contents, (char *) retdata[i]->contents,
		  retdata[i]->length);

	    ptr++;
	    i++;
	}
    *output = retdata;
    return 0;
}

krb5_boolean
realm_compare(realmname, princ)
krb5_data *realmname;
krb5_principal princ;
{
    return(strncmp(realmname->data, princ[0]->data,
		   min(realmname->length, princ[0]->length)) ? FALSE : TRUE);
}

krb5_error_code
decrypt_tgs_req(tgs_req)
krb5_tgs_req *tgs_req;
{
    krb5_error_code retval;
    krb5_data scratch;
    krb5_encrypt_block eblock;
    krb5_tgs_req_enc_part *local_encpart;

    /* parse the request using krb5_rd_req, somehow munging the header
       into its input form. */
    if (tgs_req->enc_part.length) {
	/* decrypt encrypted part, attach to enc_part2 */

	if (!valid_etype(tgs_req->etype)) /* XXX wrong etype to use? */
	    return KRB5KDC_ERR_ETYPE_NOSUPP;

	scratch.length = tgs_req->enc_part.length;
	if (!(scratch.data = malloc(tgs_req->enc_part.length))) {
	    return(ENOMEM);
	}
	/* put together an eblock for this encryption */

	eblock.crypto_entry = csarray[tgs_req->etype]->system; /* XXX */
	/* do any necessary key pre-processing */
	if (retval = (*eblock.crypto_entry->process_key)(&eblock,
							 tgs_req->header->ticket->enc_part2->session)) {
	    free(scratch.data);
	    return(retval);
	}

	/* call the encryption routine */
	if (retval =
	    (*eblock.crypto_entry->decrypt_func)((krb5_pointer) tgs_req->enc_part.data,
						 (krb5_pointer) scratch.data,
						 scratch.length, &eblock)) {
	    (void) (*eblock.crypto_entry->finish_key)(&eblock);
	    free(scratch.data);
	    return retval;
	}

#define clean_scratch() {bzero(scratch.data, scratch.length); free(scratch.data);}

	if (retval = (*eblock.crypto_entry->finish_key)(&eblock)) {
	    clean_scratch();
	    return retval;
	}
	if (retval = decode_krb5_tgs_req_enc_part(&scratch, &local_encpart)) {
	    clean_scratch();
	    return retval;
	}
	clean_scratch();
#undef clean_scratch

	tgs_req->enc_part2 = local_encpart;
    }
    return 0;
}
