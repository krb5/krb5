/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_generate_new.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_resolve_c[] = "$Id$";
#endif /* !lint && !SABER */

#include "scc.h"

#include <krb5/copyright.h>

extern krb5_cc_ops krb5_scc_ops;

/*
 * Effects:
 * Creates a new file cred cache whose name is guaranteed to be
 * unique.  The name begins with the string TKT_ROOT (from scc.h).
 * The cache is not opened, but the new filename is reserved.
 *  
 * Returns:
 * The filled in krb5_ccache id.
 *
 * Errors:
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * system errors (from open)
 */
krb5_error_code
krb5_scc_generate_new (id)
   krb5_ccache *id;
{
     krb5_ccache lid;
     FILE *f;
     char scratch[100];  /* XXX Is this large enough */
     
     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_scc_ops;

     sprintf(scratch, "%sXXXXXX", TKT_ROOT);
     mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_scc_data));
     if (lid->data == NULL) {
	  xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_scc_data *) lid->data)->filename = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_scc_data *) lid->data)->filename == NULL) {
	  xfree(((krb5_scc_data *) lid->data));
	  xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_scc_data *) lid->data)->flags = 0;
     
     /* Set up the filename */
     strcpy(((krb5_scc_data *) lid->data)->filename, scratch);

     /* Make sure the file name is useable */
     f = fopen (((krb5_scc_data *) lid->data)->filename, "w+");
     if (!f)
	 return krb5_scc_interpret (errno);
     else {
	 fclose(f);
	 *id = lid;
	 return KRB5_OK;
     }
}
