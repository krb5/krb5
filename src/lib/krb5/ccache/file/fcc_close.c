/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_close.
 */

#ifndef	lint
static char fcc_resolve_c[] = "$Id$";
#endif	/* lint */

#include <krb5/copyright.h>

/*
 * Modifies:
 * id
 *
 * Effects:
 * Closes the file cache, invalidates the id, and frees any resources
 * associated with the cache.
 *
 * Errors:
 * system errors
 * permission errors
 */
krb5_error
krb5_fcc_close(krb5_ccache id)
{
     int ret;

#ifdef OPENCLOSE
#else
     close(id->data->fd);
#endif
     
     ret = unlink(id->data->filename);
     if (ret < 0)
	  return errno;

     free(id->data->filename);
     free(id->data);
     free(id);

     return KRB5_OK;
}
