/*
 * lib/kadm/keysalt.c
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
 * keysalt.c	- Routines to handle key/salt tuples.
 */
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

static const char default_tupleseps[]	= ", \t";
static const char default_ksaltseps[]	= ":.";

/*
 * krb5_keysalt_is_present()	- Determine if a key/salt pair is present
 *				  in a list of key/salt tuples.
 *
 *	Salttype may be negative to indicate a search for only a keytype.
 */
krb5_boolean
krb5_keysalt_is_present(ksaltlist, nksalts, keytype, salttype)
    krb5_key_salt_tuple	*ksaltlist;
    krb5_int32		nksalts;
    krb5_keytype	keytype;
    krb5_int32		salttype;
{
    krb5_boolean	foundit;
    int			i;

    foundit = 0;
    if (ksaltlist) {
	for (i=0; i<nksalts; i++) {
	    if ((ksaltlist[i].ks_keytype == keytype) &&
		((ksaltlist[i].ks_salttype == salttype) ||
		 (salttype < 0))) {
		foundit = 1;
		break;
	    }
	}
    }
    return(foundit);
}

/*
 * krb5_keysalt_iterate()	- Do something for each unique key/salt
 *				  combination.
 *
 * If ignoresalt set, then salttype is ignored.
 */
krb5_error_code
krb5_keysalt_iterate(ksaltlist, nksalt, ignoresalt, iterator, arg)
    krb5_key_salt_tuple	*ksaltlist;
    krb5_int32		nksalt;
    krb5_boolean	ignoresalt;
    krb5_error_code	(*iterator) KRB5_NPROTOTYPE((krb5_key_salt_tuple *,
						     krb5_pointer));
    krb5_pointer	arg;
{
    int			i;
    krb5_error_code	kret;
    krb5_key_salt_tuple	scratch;

    kret = 0;
    for (i=0; i<nksalt; i++) {
	scratch.ks_keytype = ksaltlist[i].ks_keytype;
	scratch.ks_salttype = (ignoresalt) ? -1 : ksaltlist[i].ks_salttype;
	if (!krb5_keysalt_is_present(ksaltlist,
				     i,
				     scratch.ks_keytype,
				     scratch.ks_salttype)) {
	    if (kret = (*iterator)(&scratch, arg))
		break;
	}
    }
    return(kret);
}

/*
 * krb5_string_to_keysalts()	- Convert a string representation to a list
 *				  of key/salt tuples.
 */
krb5_error_code
krb5_string_to_keysalts(string, tupleseps, ksaltseps, dups, ksaltp, nksaltp)
    char		*string;
    const char		*tupleseps;
    const char		*ksaltseps;
    krb5_boolean	dups;
    krb5_key_salt_tuple	**ksaltp;
    krb5_int32		*nksaltp;
{
    krb5_error_code	kret;
    char 		*kp, *sp, *ep;
    char		sepchar, trailchar;
    krb5_keytype	ktype;
    krb5_int32		stype;
    krb5_key_salt_tuple	*savep;
    const char		*tseplist;
    const char		*ksseplist;
    const char		*septmp;
    
    kret = 0;
    kp = string;
    tseplist = (tupleseps) ? tupleseps : default_tupleseps;
    ksseplist = (ksaltseps) ? ksaltseps : default_ksaltseps;
    while (kp) {
	/* Attempt to find a separator */
	ep = (char *) NULL;
	if (*tseplist) {
	    septmp = tseplist;
	    for (ep = strchr(kp, (int) *septmp);
		 *(++septmp) && !ep;
		 ep = strchr(kp, (int) *septmp));
	}

	if (ep) {
	    trailchar = *ep;
	    *ep = '\0';
	    ep++;
	}
	/*
	 * kp points to something (hopefully) of the form:
	 *	<keytype><ksseplist><salttype>
	 *	or
	 *	<keytype>
	 */
	sp = (char *) NULL;
	/* Attempt to find a separator */
	septmp = ksseplist;
	for (sp = strchr(kp, (int) *septmp);
	     *(++septmp) && !sp;
	     ep = strchr(kp, (int) *septmp));

	if (sp) {
	    /* Separate keytype from salttype */
	    sepchar = *sp;
	    *sp = '\0';
	    sp++;
	}
	else
	    stype = -1;

	/*
	 * Attempt to parse keytype and salttype.  If we parse well
	 * then make sure that it specifies a unique key/salt combo
	 */
	if (!krb5_string_to_keytype(kp, &ktype) &&
	    (!sp || !krb5_string_to_salttype(sp, &stype)) &&
	    (dups ||
	     !krb5_keysalt_is_present(*ksaltp, *nksaltp, ktype, stype))) {

	    /* Squirrel away old keysalt array */
	    savep = *ksaltp;

	    /* Get new keysalt array */
	    if (*ksaltp = (krb5_key_salt_tuple *)
		malloc(((*nksaltp)+1) * sizeof(krb5_key_salt_tuple))) {

		/* Copy old keysalt if appropriate */
		if (savep) {
		    memcpy(*ksaltp, savep,
			   (*nksaltp) * sizeof(krb5_key_salt_tuple));
		    krb5_xfree(savep);
		}

		/* Save our values */
		(*ksaltp)[(*nksaltp)].ks_keytype = ktype;
		(*ksaltp)[(*nksaltp)].ks_salttype = stype;
		(*nksaltp)++;
	    }
	    else {
		*ksaltp = savep;
		break;
	    }
	}
	if (sp)
	    sp[-1] = sepchar;
	if (ep)
	    ep[-1] = trailchar;
	kp = ep;
    }
    return(kret);
}


