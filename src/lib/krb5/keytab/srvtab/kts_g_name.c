/*
 * lib/krb5/keytab/srvtab/kts_g_name.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 * Get the name of the file containing a srvtab-based keytab.
 */

#include "k5-int.h"
#include "ktsrvtab.h"

krb5_error_code
krb5_ktsrvtab_get_name(context, id, name, len)
    krb5_context context;
    krb5_keytab id;
    char *name;
    int len;
  /* 
   * This routine returns the name of the name of the file associated with
   * this srvtab-based keytab.  The name is prefixed with PREFIX:, so that
   * trt will happen if the name is passed back to resolve.
   */
{
    memset(name, 0, len);

    if (len < strlen(id->ops->prefix)+2)
	return(KRB5_KT_NAME_TOOLONG);
    strcpy(name, id->ops->prefix);
    name += strlen(id->ops->prefix);
    name[0] = ':';
    name++;
    len -= strlen(id->ops->prefix)+1;

    if (len < strlen(KTFILENAME(id)+1))
	return(KRB5_KT_NAME_TOOLONG);
    strcpy(name, KTFILENAME(id));
    /* strcpy will NUL-terminate the destination */

    return(0);
}
