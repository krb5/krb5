#ident  "@(#)krb5_pname_to_uid.c 1.2     95/05/11 SMI"
/*
 *  krb5 mechanism specific routine for pname_to_uid 
 *
 *  Copyright 1995 Sun Microsystems, Inc.
 */

#include <gssapi/gssapi.h>
#include <pwd.h>
#include <sys/types.h>

extern char *strpbrk(const char *s1, const char *s2);
extern struct passwd *getpwnam(const char *name);

int
krb5_pname_to_uid(pname, name_type, mech_type, uid)

char * pname;
gss_OID name_type;
gss_OID mech_type;
uid_t * uid;
{

	struct passwd	*pw;
	char		*pname_copy, *prefix, *suffix, *default_realm = NULL,
			*temp;
	unsigned char	krb5principalname[] =
			  {"\052\206\110\206\367\022\001\002\002\001"};

/*
 * check that the name_type is the Kerberos Principal Name form
 * [1.2.840.113554.1.2.2.1] or NULL. 
 */

	if(name_type->length !=0)
		if((name_type->length != 10)
			||
		   (memcmp(name_type->elements, krb5principalname, 10) != 0))
			return(0);
/* take care of the special case of "root.<hostname>@realm */

	if(strncmp(pname, "root.", 5) == 0) {
		*uid = 0;
		return(1);
	}
		
/* get the name and realm parts of the Kerberos Principal Name */

	pname_copy = (char *) malloc(strlen(pname)+1);
	strcpy(pname_copy, pname);
	prefix = pname_copy;
	suffix = pname_copy;

	/* find last occurance of "@" */

	temp = (char *) !NULL;
	while(temp != NULL)
		suffix = (((temp = strpbrk(suffix, "@")) == NULL) ?
							suffix : temp+1);

	if(suffix != pname_copy)
		*(suffix-1) = '\0';

/* Make sure the name is in the local realm */

	if(suffix != pname_copy) {
		krb5_get_default_realm(&default_realm);
		if(default_realm == NULL ||
					strcmp(default_realm, suffix) != 0) {
			free(pname_copy);
			return(0);
		}
	}

/*
 * call getpwnam() and return uid result if successful.
 * Otherwise, return failure.
 */

	if(pw = getpwnam(prefix)) {
		*uid = pw->pw_uid;
		free(pname_copy);
		return(1);
	} else {
		free(pname_copy);
		return(0);
	}
}
