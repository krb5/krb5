/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_unparse_name() routine
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_unparse_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/krb5_err.h>
#include <krb5/ext-proto.h>

#include <errno.h>

/*
 converts the multi-part
 principal format used in the protocols to a single-string representation
 of the name.

 the name returned is in allocated storage and should be freed by the caller
 when finished.

 Conventions: / is used to separate components; @ is used to separate
 the realm from the rest of the name.  If any component besides the realm has
 a / or @ in it, an error is returned.

 returns system errors XXX
 */

#define REALM_SEP	'@'
#define	COMPONENT_SEP	'/'
#define	REALM_SEP_STRING	"@"
#define	COMPONENT_SEP_STRING	"/"

krb5_error_code
krb5_unparse_name(principal, name)
const krb5_principal principal;
register char **name;
{
    register char *cp;
    register int i;
    int totalsize = 0;

    /* check for invalid elements of components; don't need to check
       realm, which is first component */
    for (i = 1; principal[i]; i++) {
	for (cp = principal[i]->data;
	     cp < principal[i]->data + principal[i]->length; cp++)
	    if (*cp == REALM_SEP || *cp == COMPONENT_SEP)
		return KRB5_PARSE_ILLCHAR;
	totalsize += principal[i]->length + 1;	/* + 1 for separator */
    }
    totalsize += principal[0]->length;	/* no +1 since we need only n-1 seps
					   for n components */

    *name = malloc(totalsize+1);	/* room for null */
    if (!*name)
	return ENOMEM;

    (void) bzero(*name, totalsize+1);

    for (i = 1; principal[i]; i++) {
	strncat(*name, principal[i]->data, principal[i]->length);
	if (principal[i+1])		/* don't append sep to last elt */
	    strcat(*name, COMPONENT_SEP_STRING);
    }

    strcat(*name, REALM_SEP_STRING);
    strncat(*name, principal[0]->data, principal[0]->length);

    return 0;
}
