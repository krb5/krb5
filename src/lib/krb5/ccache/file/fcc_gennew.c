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

#if !defined(lint) && !defined(SABER)
static char fcc_resolve_c[] = "$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"

#include <krb5/copyright.h>

extern krb5_cc_ops krb5_fcc_ops;

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
krb5_error_code
krb5_fcc_generate_new (id)
   krb5_ccache id;
   
{
     int ret;
     char scratch[100];  /* XXX Is this large enough */
     
     /* Allocate memory */
     id = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (id == NULL)
	  return KRB5_NOMEM;

     sprintf(scratch, "%sXXXXXX", TKT_ROOT);
     mktemp(scratch);

     id->data = (krb5_fcc_data *) malloc(sizeof(krb5_fcc_data));
     if (((krb5_fcc_data *) id->data) == NULL) {
	  free(id);
	  return KRB5_NOMEM;
     }

     ((krb5_fcc_data *) id->data)->filename = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_fcc_data *) id->data)->filename == NULL) {
	  free(((krb5_fcc_data *) id->data));
	  free(id);
	  return KRB5_NOMEM;
     }

     /* Set up the filename */
     strcpy(((krb5_fcc_data *) id->data)->filename, scratch);

     /* Copy the virtual operation pointers into id */
     bcopy((char *) &krb5_fcc_ops, id->ops, sizeof(krb5_cc_ops));

     /* Make sure the file name is reserved */
     ret = open(((krb5_fcc_data *) id->data)->filename, O_CREAT| O_EXCL,0600);
     if (ret == -1)
	  return ret;
     else {
	  close(ret);
	  return KRB5_OK;
     }
}
