/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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

#if !defined(lint) && !defined(SABER)
static char rcsid_an_to_ln_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/osconf.h>

#include <krb5/krb5.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>

#ifdef USE_DBM_LNAME
#include <krb5/dbm.h>
#include <krb5/sysincl.h>
#endif

#ifndef min
#define min(a,b) ((a) > (b) ? (b) : (a))
#endif /* min */

/*
 Converts an authentication name to a local name suitable for use by
 programs wishing a translation to an environment-specific name (e.g.
 user account name).

 lnsize specifies the maximum length name that is to be filled into
 lname.
 The translation will be null terminated in all non-error returns.

 returns system errors, NOT_ENOUGH_SPACE
*/

#ifdef USE_DBM_LNAME
extern char *krb5_lname_file;

/*
 * Implementation:  This version uses a DBM database, indexed by aname,
 * to generate a lname.
 *
 * The entries in the database are normal C strings, and include the trailing
 * null in the DBM datum.size.
 */
krb5_error_code
krb5_aname_to_localname(aname, lnsize, lname)
krb5_const_principal aname;
const int lnsize;
char *lname;
{
    DBM *db;
    krb5_error_code retval;
    datum key, contents;
    char *princ_name;

    if (retval = krb5_unparse_name(aname, &princ_name))
	return(retval);
    key.dptr = princ_name;
    key.dsize = strlen(princ_name)+1;	/* need to store the NULL for
					   decoding */

    db = dbm_open(krb5_lname_file, O_RDONLY, 0600);
    if (!db) {
	xfree(princ_name);
	return KRB5_LNAME_CANTOPEN;
    }

    contents = dbm_fetch(db, key);

    xfree(princ_name);

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
#else
/*
 * Implementation:  This version checks the realm to see if it is the local
 * realm; if so, and there is exactly one non-realm component to the name,
 * that name is returned as the lname.
 */
krb5_error_code
krb5_aname_to_localname(aname, lnsize, lname)
krb5_const_principal aname;
const int lnsize;
char *lname;
{
    krb5_error_code retval;
    char *def_realm;
    int realm_length;

    if (!aname[1] || aname[2]) {
	/* no components or more than one component to non-realm part of name
	   --no translation. */
	return KRB5_LNAME_NOTRANS;
    }

    realm_length = krb5_princ_realm(aname)->length;
    
    if (retval = krb5_get_default_realm(&def_realm)) {
	return(retval);
    }

    if ((realm_length != strlen(def_realm)) ||
	(memcmp(def_realm, krb5_princ_realm(aname)->data, realm_legth))) {
	free(def_realm);
	return KRB5_LNAME_NOTRANS;
    }	
    free(def_realm);
    strncpy(lname, aname[1]->data, min(aname[1]->length,lnsize));
    if (lnsize < aname[1]->length+1) {
	retval = KRB5_CONFIG_NOTENUFSPACE;
    } else {
	lname[aname[1]->length] = '\0';
	retval = 0;
    }
    return retval;
}
#endif
