/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_parse_name() routine.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_parse_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <stdio.h>
#include <krb5/libos-proto.h>

#include <errno.h>

/*
 converts a single-string representation of the name to the multi-part
 principal format used in the protocols.

 *principal will point to allocated storage which should be freed by
 the caller (using krb5_free_principal) after use.

 Conventions:  / is used to separate components.  If @ is present in the
 string, then the rest of the string after it represents the realm name.
 Otherwise the local realm name is used.

 returns system errors XXX
 */

#define REALM_SEP	'@'
#define	COMPONENT_SEP	'/'
#define	MAXRLMSZ	256		/* XXX! */


static char *
strsave(string)
const char *string;
{
    register char *cp;
    cp = malloc(strlen(string)+1);
    if (cp)
	(void) strcpy(cp, string);
    return(cp);
}

krb5_error_code
krb5_parse_name(name, principal)
const register char *name;
krb5_principal *principal;
{
    const register char *realmptr, *cp, *endcomponent;
    register char *realmname;
    krb5_principal retprinc;
    int ncomponents;
    register int i;
    krb5_error_code retval;

    realmptr = index(name, REALM_SEP);
    if (realmptr)
	realmname = strsave(realmptr+1);
    else {
	realmptr = name + strlen(name);
	realmname = malloc(MAXRLMSZ);
	if (!realmname)
	    return(ENOMEM);
	if (retval = krb5_get_default_realm(MAXRLMSZ, realmname)) {
	    xfree(realmname);
	    return(retval);
	}
    }

    /* count components, but only up to 1st @ */
    for (ncomponents = 1, cp = name;
	 cp < realmptr && (cp = index(cp, COMPONENT_SEP)) && cp < realmptr;
	 ncomponents++, cp++);

    /* +1 for realm, +1 for null pointer at end */
    retprinc = (krb5_data **) calloc(ncomponents+2, sizeof(krb5_data *));
    if (!retprinc) {
	xfree(realmname);
	return(ENOMEM);
    }
    retprinc[ncomponents+1] = 0;
    for (i = 0; i <= ncomponents; i++) {
	if (!(retprinc[i] = (krb5_data *) malloc(sizeof(krb5_data)))) {
	    for (i--; i >= 0; i--)
		xfree(retprinc[i]);
	    xfree(retprinc);
	    xfree(realmname);
	    return(ENOMEM);
	}
    }
    retprinc[0]->length = strlen(realmname);
    retprinc[0]->data = realmname;

    /* cp points to the beginning of the current component,
       endcomponent points to the end of the current component divider or
           is beyond the realm divider, or is null (no more component
	   dividers).
       */
    
    /* XXX this is broken */
    for (ncomponents = 1, cp = name,
	 endcomponent = index(name, COMPONENT_SEP);
	 cp && cp <= realmptr; 
	 ncomponents++) {

	if (endcomponent && endcomponent < realmptr) {
	    retprinc[ncomponents]->length = endcomponent - cp;
	} else {
		retprinc[ncomponents]->length = realmptr - cp;
	}
	if (!(retprinc[ncomponents]->data =
	    malloc(retprinc[ncomponents]->length+1))) {
	    /* ut oh...clean up */
	    xfree(retprinc[ncomponents]);
	    for (ncomponents--; ncomponents >= 0; ncomponents--) {
		xfree(retprinc[ncomponents]->data);
		xfree(retprinc[ncomponents]);
	    }
	    xfree(retprinc);
	    return(ENOMEM);
	}
	strncpy(retprinc[ncomponents]->data, cp,
		retprinc[ncomponents]->length);
	retprinc[ncomponents]->data[retprinc[ncomponents]->length] = '\0';
	if (endcomponent) {
	    cp = endcomponent + 1;	/* move past divider */
	    endcomponent = index(cp, COMPONENT_SEP);
	} else
	    cp = 0;
    }
    *principal = retprinc;
    return 0;
}
