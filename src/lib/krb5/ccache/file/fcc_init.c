/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_initialize.
 */

#ifndef	lint
static char fcc_resolve_c[] = "$Id$";
#endif	/* lint */

#include <krb5/copyright.h>

#include "fcc.h"

/*
 * Modifies:
 * id
 *
 * Effects:
 * Creates/refreshes the file cred cache id.  If the cache exists, its
 * contents ae destroyed.
 *
 * Errors:
 * system errors
 * permission errors
 */
krb5_error
krb5_fcc_initialize(id, princ)
   krb5_ccache id;
   krb5_principal princ;
{
     int ret;

     ret = open(id->data->filename, O_CREAT | O_TRUNC | O_RDWR, 0);
     if (ret < 0)
	  return errno;
     id->data->fd = ret;

     ret = fchmod(id->data->fd, S_IREAD | S_IWRITE);
     if (ret == -1)
	  return ret;

     krb5_fcc_write_principal(id, princ);

#ifdef OPENCLOSE
     close(id->data->fd);
#endif

     return KRB5_OK;
}


