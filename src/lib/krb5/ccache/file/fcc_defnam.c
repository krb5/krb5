/*
 * Ooops.  This file is completely unncessesary, I think.  <sigh>
 *
 * Barr3y
 */

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for krb5_fcc_default_name.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_defnam_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"


static char krb5_default_name_string[KRB5_FCC_MAXLEN] = "";

/*
 * Effects:
 * 
 * Forms the default credential cache name for the current user, which
 * is defined in the following way.  If it is set, the environment
 * variable "KRB5CCACHE" will be used (up to the maximum number of
 * characters of a legal operating system defined path).  Otherwise
 * TKT_ROOT (from fcc.h) and the user's uid are concatenated to
 * produce the ticket file name (e.g., "/tmp/tkt123").  The pointer
 * returned is to static storage; the name must be copied elsewhere.
 */

char *
krb5_fcc_default_name ()
{
     char *krb5ccache, *getenv();
     int len;

     /* Is the environment variable defined? */
     krb5ccache = getenv("KRB5CCACHE");
     if (krb5ccache != NULL) {
	  len = strlen(krb5ccache);
	  len = (len < sizeof(krb5_default_name_string) ? len :
		 sizeof(krb5_default_name_string));
	  
	  strncpy(krb5_default_name_string, krb5ccache, len);
	  krb5_default_name_string[len] = '\0';
     }

     /* No.  Use TKT_ROOT and uid */
     else {
	  /* It'd be nice if we didn't have to pull in printf */
	  sprintf(krb5_default_name_string, "%s%d", TKT_ROOT, getuid());
     }

     return krb5_default_name_string;
}
