/*
 * lib/kadm/adm_kt_dec.c
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
 * adm_kt_dec.c	- Decode keytab entry according to protocol.
 */
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

/*
 * krb5_adm_proto_to_ktent()	- Convert a list of reply components to
 *				  a keytab entry according to procotol.
 *
 * Successful callers of this routine should free ktentp->principal
 * and ktentp->key.contents.
 */
krb5_error_code
krb5_adm_proto_to_ktent(kcontext, ncomp, complist, ktentp)
    krb5_context	kcontext;
    krb5_int32		ncomp;
    krb5_data		*complist;
    krb5_keytab_entry	*ktentp;
{
    krb5_error_code	kret;
    char		*v;

    /*
     * Clear out the keytab entry.
     */
    memset((char *) ktentp, 0, sizeof(krb5_keytab_entry));

    /*
     * Figure out how many components we have.  We expect KRB5_ADM_KT_NCOMPS
     * components.
     */
    if (ncomp != KRB5_ADM_KT_NCOMPS)
	return(EINVAL);

    /* Parse the supplied principal name */
    if (kret = krb5_parse_name(kcontext,
			       complist[KRB5_ADM_KT_PRINCIPAL].data,
			       &ktentp->principal))
	goto done;

    /* Parse the supplied timestamp */
    if (complist[KRB5_ADM_KT_TIMESTAMP].length < sizeof(krb5_timestamp)) {
	kret = EINVAL;
	goto done;
    }
    v = complist[KRB5_ADM_KT_TIMESTAMP].data;
    ktentp->timestamp = (krb5_timestamp)
	(((krb5_int32) ((unsigned char) v[0]) << 24) +
	 ((krb5_int32) ((unsigned char) v[1]) << 16) +
	 ((krb5_int32) ((unsigned char) v[2]) << 8) +
	 ((krb5_int32) ((unsigned char) v[3])));

    /* Parse the supplied vno */
    if (complist[KRB5_ADM_KT_VNO].length < sizeof(krb5_kvno)) {
	kret = EINVAL;
	goto done;
    }
    v = complist[KRB5_ADM_KT_VNO].data;
    ktentp->vno = (krb5_kvno)
	(((krb5_int32) ((unsigned char) v[0]) << 24) +
	 ((krb5_int32) ((unsigned char) v[1]) << 16) +
	 ((krb5_int32) ((unsigned char) v[2]) << 8) +
	 ((krb5_int32) ((unsigned char) v[3])));

    /* Parse the supplied key_enctype */
    if (complist[KRB5_ADM_KT_KEY_ENCTYPE].length < sizeof(krb5_enctype)) {
	kret = EINVAL;
	goto done;
    }
    v = complist[KRB5_ADM_KT_KEY_ENCTYPE].data;
    ktentp->key.enctype = (krb5_enctype)
	(((krb5_int32) ((unsigned char) v[0]) << 24) +
	 ((krb5_int32) ((unsigned char) v[1]) << 16) +
	 ((krb5_int32) ((unsigned char) v[2]) << 8) +
	 ((krb5_int32) ((unsigned char) v[3])));

    /* Finally, shuck the key contents */
    if (ktentp->key.contents = (krb5_octet *)
	malloc((size_t) complist[KRB5_ADM_KT_KEY_KEY].length)) {
	ktentp->key.length = complist[KRB5_ADM_KT_KEY_KEY].length;
	memcpy(ktentp->key.contents,
	       complist[KRB5_ADM_KT_KEY_KEY].data,
	       (size_t) ktentp->key.length);
	kret = 0;
    }
    else
	kret = ENOMEM;
	
 done:
    if (kret) {
	if (ktentp->principal)
	    krb5_free_principal(kcontext, ktentp->principal);
	if (ktentp->key.contents) {
	    memset((char *) ktentp->key.contents, 0,
		   (size_t) ktentp->key.length);
	    krb5_xfree(ktentp->key.contents);
	}
	memset((char *) ktentp, 0, sizeof(krb5_keytab_entry));
    }
    return(kret);
}
