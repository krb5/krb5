/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_generate_new.
 */

#ifndef	lint
static char fcc_resolve_c[] = "$Id$";
#endif	lint

#include "fcc.h"

#include <krb5/copyright.h>

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from fcc.h).
 * The cache is not opened, but the new filename is reserved.
 *  
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 */
krb5_err
krb5_fcc_generate_new (krb5_ccache id)
{
     char scratch[100];  /* XXX Is this large enough */
     
     /* Allocate memory */
     id = (krb_ccache) malloc(sizeof(struct _krb5_ccache));
     if (id == NULL)
	  return KRB5_NOMEM;

     sprintf(scratch, "%sXXXXXX", TKT_ROOT);
     mktemp(scratch);

     id->data = malloc(sizeof(krb5_fcc_data));
     if (id->data == NULL) {
	  free(id);
	  return KRB5_NOMEM;
     }

     id->data->filename = malloc(strlen(scratch) + 1);
     if (id->data->filename == NULL) {
	  free(id->data);
	  free(id);
	  return KRB5_NOMEM;
     }

     /* Set up the filename */
     strcpy(id->data->filename, scratch);

     /* Copy the virtual operation pointers into id */
     bcopy((char *) &krb5_fcc_ops, id->ops, sizeof(struct _krb5_ccache));

     /* Make sure the file name is reserved */
     ret = open(id->data->filename, O_CREAT | O_EXCL, 0);
     if (ret == -1 && errno != EEXIST)
	  return ret;
     else {
	  close(ret);
	  return KRB5_OK;
     }
}
