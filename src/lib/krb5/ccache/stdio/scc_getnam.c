/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_get_name.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_getnam_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "scc.h"

/*
 * Requires:
 * id is a file credential cache
 * 
 * Returns:
 * The name of the file cred cache id.
 */
char *
krb5_scc_get_name (id)
   krb5_ccache id;
{
     return (char *) ((krb5_scc_data *) id->data)->filename;
}
