/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_resolve.
 */

#ifndef	lint
static char fcc_resolve_c[] = "$Id$";
#endif	lint

#include <krb5/copyright.h>

#include "fcc.h"

extern struct krb5_cc_ops krb5_fcc_ops;

/*
 * Requires:
 * residual is a legal path name, and a null-terminated string
 *
 * Modifies:
 * id
 * 
 * Effects:
 * creates a file-based cred cache that will reside in the file
 * residual.  The cache is not opened, but the filename is reserved.
 * 
 * Returns:
 * A filled in krb5_ccache structure "id".
 *
 * Errors:
 * KRB5_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * permission errors
 */
krb5_error
krb5_fcc_resolve (id, residual)
   krb5_ccache id;
   char *residual;
{
     int ret;
     
     id = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (id == NULL)
	  return KRB5_NOMEM;

     id->data = (char *) malloc(sizeof(krb5_fcc_data));
     if (id->data == NULL) {
	  free(id);
	  return KRB5_NOMEM;
     }

     id->data->filename = (char *) malloc(strlen(residual) + 1);
     if (id->data->filename == NULL) {
	  free(id->data);
	  free(id);
	  return KRB5_NOMEM;
     }

     /* Copy the virtual operation pointers into id */
     bcopy((char *) &krb5_fcc_ops, id->ops, sizeof(struct _krb5_ccache));

     /* Set up the filename */
     strcpy(id->data->filename, residual);

     /* Make sure the file name is reserved */
     ret = open(id->data->filename, O_CREAT | O_EXCL, 0);
     if (ret == -1 && errno != EEXIST)
	  return ret;
     else {
	  close(ret);
	  return KRB5_OK;
     }
}
