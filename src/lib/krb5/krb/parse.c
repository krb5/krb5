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
#ifdef __STDC__
#include <stdlib.h>
#else
extern char *malloc(), *index(), *calloc();
#endif /* __STDC__ */

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


#define xfree(val) free((char *)val)

static char *
strsave(string)
char *string;
{
    register char *cp;
    cp = malloc(strlen(string)+1);
    if (cp)
	(void) strcpy(cp, string);
    return(cp);
}

krb5_error_code
krb5_parse_name(name, principal)
register char *name;
krb5_principal *principal;
{
    register char *cp1, *cp2, *cp3;
    register char *realmname;
    krb5_principal retprinc;
    int ncomponents;
    register int i;
    krb5_error_code retval;

    cp1 = index(name, REALM_SEP);
    if (cp1)
	realmname = strsave(cp1+1);
    else {
	cp1 = name + strlen(name);
	realmname = malloc(MAXRLMSZ);
	if (!realmname)
	    return(ENOMEM);
	if (retval = krb5_get_default_realm(MAXRLMSZ, realmname)) {
	    xfree(realmname);
	    return(retval);
	}
    }

    /* count components, but only up to 1st @ */
    for (ncomponents = 1, cp2 = name;
	 cp2 < cp1 && (cp2 = index(cp2, COMPONENT_SEP)) && cp2 < cp1;
	 ncomponents++, cp2++);

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
    retprinc[0]->length = strlen(realmname)+1;
    retprinc[0]->data = realmname;

    /* cp2 points to the beginning of the current component,
       cp3 points to the end of the current component divider or
           is beyond the realm divider, or is null (no more component
	   dividers).
       */
    
    /* XXX this is broken */
    for (ncomponents = 1, cp2 = name, cp3 = index(name, COMPONENT_SEP);
	 cp2 && cp2 <= cp1; 
	 ncomponents++, cp3 = index(cp2, COMPONENT_SEP)) {

	if (cp3 && cp3 < cp1) {
	    retprinc[ncomponents]->length = cp3 - cp2;
	} else {
	    if (cp3)
		retprinc[ncomponents]->length = cp1 - cp2;
	    else
		retprinc[ncomponents]->length = strlen(cp2);
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
	strncpy(retprinc[ncomponents]->data, cp2,
		retprinc[ncomponents]->length);
	retprinc[ncomponents]->data[retprinc[ncomponents]->length] = '\0';
	if (cp3)
	    cp2 = cp3 + 1;			/* move past divider */
	else
	    cp2 = 0;
    }
    *principal = retprinc;
    return 0;
}
