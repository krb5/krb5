/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_get_name.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_getnam_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "fcc.h"

/*
 * Requires:
 * id is a file credential cache
 * 
 * Returns:
 * The name of the file cred cache id.
 */
char *
krb5_fcc_get_name (id)
   krb5_ccache id;
{
     return (char *) ((krb5_fcc_data *) id->data)->filename;
}
