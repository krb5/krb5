/*
 * lib/krb5/os/an_to_ln.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 *
 * krb5_aname_to_localname()
 */

#include "k5-int.h"

#ifndef min
#define min(a,b) ((a) > (b) ? (b) : (a))
#endif /* min */

int krb5_lname_username_fallback = 1;
extern char *krb5_lname_file;

#ifndef _MSDOS    

static krb5_error_code dbm_an_to_ln();
static krb5_error_code username_an_to_ln();

/*
 Converts an authentication name to a local name suitable for use by
 programs wishing a translation to an environment-specific name (e.g.
 user account name).

 lnsize specifies the maximum length name that is to be filled into
 lname.
 The translation will be null terminated in all non-error returns.

 returns system errors, NOT_ENOUGH_SPACE
*/

krb5_error_code
krb5_aname_to_localname(context, aname, lnsize, lname)
    krb5_context context;
	krb5_const_principal aname;
	const int lnsize;
	char *lname;
{
	struct stat statbuf;

	if (!stat(krb5_lname_file,&statbuf))
		return dbm_an_to_ln(context, aname, lnsize, lname);
	if (krb5_lname_username_fallback)
		return username_an_to_ln(context, aname, lnsize, lname);
	return KRB5_LNAME_CANTOPEN;
}

/*
 * Implementation:  This version uses a DBM database, indexed by aname,
 * to generate a lname.
 *
 * The entries in the database are normal C strings, and include the trailing
 * null in the DBM datum.size.
 */
static krb5_error_code
dbm_an_to_ln(context, aname, lnsize, lname)
    krb5_context context;
    krb5_const_principal aname;
    const int lnsize;
    char *lname;
{
    DBM *db;
    krb5_error_code retval;
    datum key, contents;
    char *princ_name;

    if (retval = krb5_unparse_name(context, aname, &princ_name))
	return(retval);
    key.dptr = princ_name;
    key.dsize = strlen(princ_name)+1;	/* need to store the NULL for
					   decoding */

    db = dbm_open(krb5_lname_file, O_RDONLY, 0600);
    if (!db) {
	krb5_xfree(princ_name);
	return KRB5_LNAME_CANTOPEN;
    }

    contents = dbm_fetch(db, key);

    krb5_xfree(princ_name);

    if (contents.dptr == NULL) {
	retval = KRB5_LNAME_NOTRANS;
    } else {
	strncpy(lname, contents.dptr, lnsize);
	if (lnsize < contents.dsize)
	    retval = KRB5_CONFIG_NOTENUFSPACE;
	else if (lname[contents.dsize-1] != '\0')
	    retval = KRB5_LNAME_BADFORMAT;
	else
	    retval = 0;
    }
    /* can't close until we copy the contents. */
    (void) dbm_close(db);
    return retval;
}
#endif /* _MSDOS */

/*
 * Implementation:  This version checks the realm to see if it is the local
 * realm; if so, and there is exactly one non-realm component to the name,
 * that name is returned as the lname.
 */
static krb5_error_code
username_an_to_ln(context, aname, lnsize, lname)
    krb5_context context;
    krb5_const_principal aname;
    const int lnsize;
    char *lname;
{
    krb5_error_code retval;
    char *def_realm;
    int realm_length;

    realm_length = krb5_princ_realm(context, aname)->length;
    
    if (retval = krb5_get_default_realm(context, &def_realm)) {
	return(retval);
    }
    if (((size_t) realm_length != strlen(def_realm)) ||
        (memcmp(def_realm, krb5_princ_realm(context, aname)->data, realm_length))) {
        free(def_realm);
        return KRB5_LNAME_NOTRANS;
    }

    if (krb5_princ_size(context, aname) != 1) {
        if (krb5_princ_size(context, aname) == 2 ) {
           /* Check to see if 2nd component is the local realm. */
           if ( strncmp(krb5_princ_component(context, aname,1)->data,def_realm,
                        realm_length) ||
                realm_length != krb5_princ_component(context, aname,1)->length)
                return KRB5_LNAME_NOTRANS;
        }
        else
           /* no components or more than one component to non-realm part of name
           --no translation. */
            return KRB5_LNAME_NOTRANS;
    }

    free(def_realm);
    strncpy(lname, krb5_princ_component(context, aname,0)->data, 
	    min(krb5_princ_component(context, aname,0)->length,lnsize));
    if (lnsize < krb5_princ_component(context, aname,0)->length ) {
	retval = KRB5_CONFIG_NOTENUFSPACE;
    } else {
	lname[krb5_princ_component(context, aname,0)->length] = '\0';
	retval = 0;
    }
    return retval;
}

#ifdef _MSDOS

krb5_error_code
krb5_aname_to_localname(context, aname, lnsize, lname)
    krb5_context context;
	krb5_const_principal aname;
	const int lnsize;
	char *lname;
{
	if (krb5_lname_username_fallback)
		return username_an_to_ln(context, aname, lnsize, lname);
	return KRB5_LNAME_CANTOPEN;
}

#endif /* _MSDOS */
