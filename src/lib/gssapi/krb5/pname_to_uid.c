/* #ident  "@(#)krb5_pname_to_uid.c 1.2     95/05/11 SMI" */

/*
 *  krb5 mechanism specific routine for pname_to_uid 
 *
 *  Copyright 1995 Sun Microsystems, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Sun Microsystems not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. Sun Microsystems makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * SUN MICROSYSTEMS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SUN MICROSYSTEMS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "gssapiP_krb5.h"
#if !defined(_MSDOS) && !defined(_MACINTOSH)
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#endif	/* !_MSDOS && !_MACINTOSH */

/* 
 * This function will probably get replaced with the gsscred stuff...
 */

int
krb5_pname_to_uid(context, pname, name_type, mech_type, uid)
krb5_context context;
char * pname;
gss_OID name_type;
gss_OID mech_type;
uid_t * uid;
{
#if defined(_MSDOS) || defined(_MACINTOSH)
	return (0);		/* failure */
#else

	struct passwd	*pw;
	static unsigned char	krb5principalname[] =
			  {"\052\206\110\206\367\022\001\002\002\001"};
	krb5_principal  principal;
	char lname[256];
	krb5_error_code stat;

/*
 * check that the name_type is the Kerberos Principal Name form
 * [1.2.840.113554.1.2.2.1] or NULL. 
 */
	if(name_type->length !=0)
		if((name_type->length != 10) ||
		   (memcmp(name_type->elements, krb5principalname, 10) != 0))
			return(0);
		
	/* get the name and realm parts of the Kerberos Principal Name */

	if (krb5_parse_name(context, pname, &principal)) {
		return(0);
	}

	stat = krb5_aname_to_localname(context, principal,
							sizeof(lname), lname);
	krb5_free_principal(context, principal);

	if (stat)
		return(0);

/*
 * call getpwnam() and return uid result if successful.
 * Otherwise, return failure.
 */

	if(pw = getpwnam(lname)) {
		*uid = pw->pw_uid;
		return(1);
	} else {
		return(0);
	}
	
#endif
}
