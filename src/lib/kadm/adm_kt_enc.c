/*
 * lib/kadm/adm_kt_enc.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/*
 * adm_kt_enc.c	- Encode keytab entry according to protocol.
 */
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"


/*
 * krb5_adm_ktent_to_proto()	- Convert a keytab entry into an external
 *				  list of reply components.
 *
 * Successful callers must free the storage for complistp and complistp->data
 * either manually or by using krb5_free_adm_data().
 */
krb5_error_code
krb5_adm_ktent_to_proto(kcontext, ktentp, ncompp, complistp)
    krb5_context	kcontext;
    krb5_keytab_entry	*ktentp;
    krb5_int32		*ncompp;
    krb5_data		**complistp;
{
    krb5_error_code	kret;
    krb5_data		*clist;
    krb5_int32		nents;

    kret = ENOMEM;
    nents = 0;
    if (clist = (krb5_data *) malloc((size_t) KRB5_ADM_KT_NCOMPS *
				     sizeof(krb5_data))) {
	memset((char *) clist, 0, ((size_t) KRB5_ADM_KT_NCOMPS *
				   sizeof(krb5_data)));
	/*
	 * Fill in the principal field.
	 */
	if (kret = krb5_unparse_name(kcontext,
				     ktentp->principal,
				     &clist[KRB5_ADM_KT_PRINCIPAL].data))
	    goto done;
	clist[KRB5_ADM_KT_PRINCIPAL].length =
	    strlen(clist[KRB5_ADM_KT_PRINCIPAL].data);
	nents++;

	/*
	 * Fill in timestamp.
	 */
	if (kret = krb5_timeofday(kcontext, &ktentp->timestamp))
	    goto done;
	if (clist[KRB5_ADM_KT_TIMESTAMP].data = 
	    (char *) malloc(sizeof(krb5_ui_4))) {
	    clist[KRB5_ADM_KT_TIMESTAMP].length = sizeof(krb5_ui_4);
	    clist[KRB5_ADM_KT_TIMESTAMP].data[0] =
		(char) ((ktentp->timestamp >> 24) & 0xff);
	    clist[KRB5_ADM_KT_TIMESTAMP].data[1] =
		(char) ((ktentp->timestamp >> 16) & 0xff);
	    clist[KRB5_ADM_KT_TIMESTAMP].data[2] =
		(char) ((ktentp->timestamp >> 8) & 0xff);
	    clist[KRB5_ADM_KT_TIMESTAMP].data[3] =
		(char) (ktentp->timestamp & 0xff);
	    nents++;
	}
	else {
	    kret = ENOMEM;
	    goto done;
	}

	/*
	 * Fill in vno.
	 */
	if (clist[KRB5_ADM_KT_VNO].data = 
	    (char *) malloc(sizeof(krb5_ui_4))) {
	    clist[KRB5_ADM_KT_VNO].length = sizeof(krb5_ui_4);
	    clist[KRB5_ADM_KT_VNO].data[0] = (ktentp->vno >> 24) & 0xff;
	    clist[KRB5_ADM_KT_VNO].data[1] = (ktentp->vno >> 16) & 0xff;
	    clist[KRB5_ADM_KT_VNO].data[2] = (ktentp->vno >> 8) & 0xff;
	    clist[KRB5_ADM_KT_VNO].data[3] = ktentp->vno & 0xff;
	    nents++;
	}
	else {
	    kret = ENOMEM;
	    goto done;
	}

	/*
	 * Fill in key_enctype.
	 */
	if (clist[KRB5_ADM_KT_KEY_ENCTYPE].data = 
	    (char *) malloc(sizeof(krb5_ui_4))) {
	    clist[KRB5_ADM_KT_KEY_ENCTYPE].length = sizeof(krb5_ui_4);
	    clist[KRB5_ADM_KT_KEY_ENCTYPE].data[0] =
		(ktentp->key.enctype >> 24) & 0xff;
	    clist[KRB5_ADM_KT_KEY_ENCTYPE].data[1] =
		(ktentp->key.enctype >> 16) & 0xff;
	    clist[KRB5_ADM_KT_KEY_ENCTYPE].data[2] =
		(ktentp->key.enctype >> 8) & 0xff;
	    clist[KRB5_ADM_KT_KEY_ENCTYPE].data[3] =
		ktentp->key.enctype & 0xff;
	    nents++;
	}
	else {
	    kret = ENOMEM;
	    goto done;
	}

	/*
	 * Fill in key_key.
	 */
	if (clist[KRB5_ADM_KT_KEY_KEY].data = 
	    (char *) malloc((size_t) ktentp->key.length)) {
	    memcpy(clist[KRB5_ADM_KT_KEY_KEY].data,
		   ktentp->key.contents,
		   (size_t) ktentp->key.length);
	    clist[KRB5_ADM_KT_KEY_KEY].length = ktentp->key.length;
	    nents++;
	    kret = 0;
	}
	else
	    kret = ENOMEM;
    }
 done:
    if (kret) {
	if (clist) {
	    int i;
	    for (i=0; i<KRB5_ADM_KT_NCOMPS; i++) {
		if (clist[i].data) {
		    memset(clist[i].data, 0, (size_t) clist[i].length);
		    krb5_xfree(clist[i].data);
		}
	    }
	    krb5_xfree(clist);
	}
	clist = (krb5_data *) NULL;
	nents = 0;
    }
    *complistp = clist;
    *ncompp = nents;
    return(kret);
}
