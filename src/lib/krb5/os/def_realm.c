/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_get_default_realm() function.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_def_realm_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

#include <stdio.h>

/*
 Retrieves the default realm to be used if no user-specified realm is
 available.  [e.g. to interpret a user-typed principal name with the
 realm omitted for convenience]

 lnsize specifies the maximum length name that is to be filled into
 lrealm.

 returns system errors, NOT_ENOUGH_SPACE
*/

/*
 * Implementation:  the default realm is stored in a configuration file,
 * named by krb5_config_file;  the first token in this file is taken as
 * the default local realm name.
 */

extern char *krb5_config_file;		/* extern so can be set at
					   load/runtime */
krb5_error_code
krb5_get_default_realm(lnsize, lrealm)
const int lnsize;
char *lrealm;
{
    FILE *config_file;
    char realmbuf[BUFSIZ];
    krb5_error_code retval;

    if (!(config_file = fopen(krb5_config_file, "r")))
	/* can't open */
	return KRB5_CONFIG_CANTOPEN;

    if (fscanf(config_file, "%s", realmbuf) != 1)
	retval = KRB5_CONFIG_BADFORMAT;
    else {
	strncpy(lrealm, realmbuf, lnsize);
	if (lnsize < strlen(realmbuf))
	    retval = KRB5_CONFIG_NOTENUFSPACE;
	else
	    retval = 0;
    }
    (void) fclose(config_file);
    return retval;
}
