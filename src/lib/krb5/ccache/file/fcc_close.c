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

#if !defined(lint) && !defined(SABER)
static char fcc_resolve_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "fcc.h"

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
krb5_error_code
krb5_fcc_close(id)
   krb5_ccache id;
{
     int ret;

#ifdef OPENCLOSE
#else
     close(((krb5_fcc_data *) id->data)->fd);
#endif
     
     ret = unlink(((krb5_fcc_data *) id->data)->filename);
     if (ret < 0)
	  return errno;

     free(((krb5_fcc_data *) id->data)->filename);
     free(((krb5_fcc_data *) id->data));
     free(id);

     return KRB5_OK;
}
