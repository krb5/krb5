/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_parse_name() routine.
 *
 * Rewritten by Theodore Ts'o to properly handle arbitrary quoted
 * characters in the principal name.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_parse_c [] =
"$Id$";
#endif	/* !lint & !SABER */


#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>

/*
 * converts a single-string representation of the name to the
 * multi-part principal format used in the protocols.
 *
 * principal will point to allocated storage which should be freed by 
 * the caller (using krb5_free_principal) after use.
 * 
 * Conventions:  / is used to separate components.  If @ is present in the
 * string, then the rest of the string after it represents the realm name.
 * Otherwise the local realm name is used.
 * 
 * error return:
 *	KRB5_PARSE_MALFORMED	badly formatted string
 *
 * also returns system errors:
 *	ENOMEM	malloc failed/out of memory
 *
 * get_default_realm() is called; it may return other errors.
 */

#define REALM_SEP	'@'
#define	COMPONENT_SEP	'/'
#define QUOTECHAR	'\\'

#define FCOMPNUM	2


/*
 * May the fleas of a thousand camels infest the ISO, they who think
 * that arbitrarily large multi-component names are a Good Thing.....
 */
krb5_error_code
krb5_parse_name(name, nprincipal)
	const char	*name;
	krb5_principal	*nprincipal;
{
	register const char	*cp;
	register char	*q;
	register i,c,size;
	int		components = 0;
	const char	*parsed_realm = NULL;
	int		fcompsize[FCOMPNUM];
	static char	*default_realm = NULL;
	krb5_data	**principal;
	krb5_error_code retval;
	
	/*
	 * Pass 1.  Find out how many components there are to the name,
	 * and get string sizes for the first FCOMPNUM components.
	 */
	size = 0;
	for (i=1,cp = name; c = *cp; cp++) {
		if (c == QUOTECHAR) {
			cp++;
			if (!(c = *cp))
				/*
				 * QUOTECHAR can't be at the last
				 * character of the name!
				 */
				return(KRB5_PARSE_MALFORMED);
			size++;
			continue;
		} else if (c == COMPONENT_SEP) {
			if (parsed_realm)
				/*
				 * Shouldn't see a component separator
				 * after we've parsed out the realm name!
				 */
				return(KRB5_PARSE_MALFORMED);
			if (i < FCOMPNUM) {
				fcompsize[i] = size;
			}
			size = 0;
			i++;
		} else if (c == REALM_SEP) {
			if (!*(cp+1)) 
				/*
				 * Null Realm names are not allowed!
				 */
				return(KRB5_PARSE_MALFORMED);
			parsed_realm = cp+1;
			if (i < FCOMPNUM) {
				fcompsize[i] = size;
			}
			size = 0;
		} else
			size++;
	}
	if (parsed_realm)
		fcompsize[0] = size;
	else if (i < FCOMPNUM) 
		fcompsize[i] = size;
	components = i;
	/*
	 * Now, we allocate the principal structure and all of its
	 * component pieces
	 */
	principal = (krb5_principal)
		malloc(sizeof(krb5_data *) * (components+2));
	if (!principal) {
		return(ENOMEM);
	}
	for (i = 0; i <= components; i++) {
		if (!(principal[i] =
		      (krb5_data *) malloc(sizeof(krb5_data)))) {
			for (i--; i >= 0; i--) 
				xfree(principal[i]);
			xfree(principal);
			return (ENOMEM);
		}
	}
	principal[components+1] = NULL;
	/*
	 * If a realm was not found, then we need to find the defualt
	 * realm....
	 */
	if (!parsed_realm) {
		if (!default_realm &&
		    (retval = krb5_get_default_realm(&default_realm)))
			return(retval);
		principal[0]->length = fcompsize[0] = strlen(default_realm);
	}
	/*
	 * Pass 2.  Happens only if there were more than FCOMPNUM
	 * component; if this happens, someone should be shot
	 * immediately.  Nevertheless, we will attempt to handle said
	 * case..... <martyred sigh>
	 */
	if (components >= FCOMPNUM) {
		size = 0;
		parsed_realm = NULL;
		for (i=1,cp = name; c = *cp; cp++) {
			if (c == QUOTECHAR) {
				cp++;
				size++;
			} else if (c == COMPONENT_SEP) {
				principal[i]->length = size;
				size = 0;
				i++;
			} else if (c == REALM_SEP) {
				principal[i]->length = size;
				size = 0;
				parsed_realm = cp+1;
			} else
				size++;
		}
		if (parsed_realm)
			principal[0]->length = size;
		else
			principal[i]->length = size;
		if (i != components) {
			fprintf(stderr,
				"Programming error in krb5_parse_name!");
			exit(1);
		}
	} else {
		/*
		 * If there were fewer than FCOMPSIZE components (the
		 * usual case), then just copy the sizes to the
		 * principal structure
		 */
		for (i=0; i <= components; i++)
			principal[i]->length = fcompsize[i];
	}
	/*	
	 * Now, we need to allocate the space for the strings themselves.....
	 */
	for (i=0; i <= components; i++) {
		if (!(principal[i]->data = malloc(principal[i]->length + 1))) {
			for (i--; i >= 0; i--)
				xfree(principal[i]->data);
			for (i=0; i <= components; i++)
				xfree(principal[i]);
			xfree(principal);
			return(ENOMEM);
		}
	}
	
	/*
	 * Pass 3.  Now we go through the string a *third* time, this
	 * time filling in the krb5_principal structure which we just
	 * allocated.
	 */
	q = principal[1]->data;
	for (i=1,cp = name; c = *cp; cp++) {
		if (c == QUOTECHAR) {
			cp++;
			switch (c = *cp) {
			case 'n':
				*q++ = '\n';
				break;
			case 't':
				*q++ = '\t';
				break;
			case 'b':
				*q++ = '\b';
				break;
			case '0':
				*q++ = '\0';
				break;
			default:
				*q++ = c;
			}
		} else if ((c == COMPONENT_SEP) || (c == REALM_SEP)) {
			i++;
			*q++ = '\0';
			if (c == COMPONENT_SEP) 
				q = principal[i]->data;
			else
				q = principal[0]->data;
		} else
			*q++ = c;
	}
	*q++ = '\0';
	if (!parsed_realm)
		strcpy(principal[0]->data, default_realm);
	/*
	 * Alright, we're done.  Now stuff a pointer to this monstrosity
	 * into the return variable, and let's get out of here.
	 */
	*nprincipal = principal;
	return(0);
}


