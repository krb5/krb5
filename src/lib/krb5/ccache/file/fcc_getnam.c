/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_get_name.
 */

#ifndef	lint
static char fcc_resolve_c[] = "$Id$";
#endif	lint

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
     return (char *) id->data->filename;
}
