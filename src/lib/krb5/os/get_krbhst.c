/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb5_get_krbhst() function.
 */

#if !defined(lint) && !defined(SABER)
static char get_krbhst_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <stdio.h>

/*
 Figures out the Kerberos server names for the given realm, filling in a
 pointer to an argv[] style list of names, terminated with a null pointer.
 
 If the realm is unknown, the filled-in pointer is set to NULL.

 The pointer array and strings pointed to are all in allocated storage,
 and should be freed by the caller when finished.

 returns system errors
*/

/*
 * Implementation:  the server names for given realms are stored in a
 * configuration file, 
 * named by krb5_config_file;  the first token (on the first line) in
 * this file is taken as the default local realm name.
 * 
 * Each succeeding line has a realm name as the first token, and a server name
 * as a second token.  Additional tokens may be present on the line, but
 * are ignored by this function.
 *
 * All lines which begin with the desired realm name will have the
 * hostname added to the list returned.
 */

extern char *krb5_config_file;		/* extern so can be set at
					   load/runtime */

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
krb5_get_krbhst(realm, hostlist)
krb5_data *realm;
char ***hostlist;
{
    FILE *config_file;
    char filebuf[BUFSIZ];
    krb5_error_code retval;
    char *cp;
    register char **rethlist = 0;
    int hlsize = 1;
    int hlindex = 0;

    if (!(config_file = fopen(krb5_config_file, "r")))
	/* can't open */
	return KRB5_CONFIG_CANTOPEN;

    if (fgets(filebuf, sizeof(filebuf), config_file) == NULL)
	retval = KRB5_CONFIG_BADFORMAT;
    else {
	retval = 0;
	rethlist = (char **)calloc(hlsize, sizeof (*rethlist));
	for (;;) {
	    if (fgets(filebuf, sizeof(filebuf), config_file) == NULL)
		break;
	    if (strncmp(filebuf, realm->data, realm->length))
		continue;		/* no match */

	    /* +1 to get beyond trailing space */
	    if (strlen(filebuf) < realm->length + 1) {
		/* no hostname on config line */
		retval = KRB5_CONFIG_BADFORMAT;
		break;
	    }
	    rethlist[hlindex] = strsave(&filebuf[realm->length+1]);
	    if (!rethlist[hlindex]) {
		for (--hlindex; hlindex >= 0; hlindex--)
		    free(rethlist[hlindex]);
		free((char *) rethlist);
		rethlist = 0;
		retval = ENOMEM;
		break;
	    }
	    /* chop off remainder of line */
	    if (cp = index(rethlist[hlindex], ' '))
		*cp = '\0';
	    if (cp = index(rethlist[hlindex], '\t'))
		*cp = '\0';
	    if (cp = index(rethlist[hlindex], '\n'))
		*cp = '\0';
	    if (++hlindex >= hlsize) {
		/* need larger pointer array */
		hlsize *= 2;
		rethlist = (char **)realloc((char *)rethlist,
					    hlsize * sizeof(*rethlist));
		if (!rethlist) {
		    /* XXX clean up the old saved strings?
		       realloc might possibly trash them if it fails? */
		    retval = ENOMEM;
		    break;
		}
	    }
	    rethlist[hlindex] = 0;
	}
    }
    (void) fclose(config_file);

    if (hlindex == 0) {
	free((char *)rethlist);
	rethlist = 0;
	retval = KRB5_REALM_UNKNOWN;
    }
    *hostlist = rethlist;

    return retval;
}

