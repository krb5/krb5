/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * This file contains the source code for krb5_fcc_generate_new.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_resolve_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"

#include <krb5/osconf.h>

#ifdef KRB5_USE_INET
#include <netinet/in.h>
#else
 #error find some way to use net-byte-order file version numbers.
#endif

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
 * KRB5_CC_NOMEM - there was insufficient memory to allocate the
 * 		krb5_ccache.  id is undefined.
 * system errors (from open)
 */
krb5_error_code
krb5_fcc_generate_new (id)
   krb5_ccache *id;
{
     krb5_ccache lid;
     int ret;
     krb5_error_code    retcode = 0;
     char scratch[sizeof(TKT_ROOT)+6+1]; /* +6 for the scratch part, +1 for
					    NUL */
     
     /* Allocate memory */
     lid = (krb5_ccache) malloc(sizeof(struct _krb5_ccache));
     if (lid == NULL)
	  return KRB5_CC_NOMEM;

     lid->ops = &krb5_fcc_ops;

     (void) strcpy(scratch, TKT_ROOT);
     (void) strcat(scratch, "XXXXXX");
     mktemp(scratch);

     lid->data = (krb5_pointer) malloc(sizeof(krb5_fcc_data));
     if (lid->data == NULL) {
	  xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     /*
      * The file is initially closed at the end of this call...
      */
     ((krb5_fcc_data *) lid->data)->fd = -1;

     ((krb5_fcc_data *) lid->data)->filename = (char *)
	  malloc(strlen(scratch) + 1);
     if (((krb5_fcc_data *) lid->data)->filename == NULL) {
	  xfree(((krb5_fcc_data *) lid->data));
	  xfree(lid);
	  return KRB5_CC_NOMEM;
     }

     ((krb5_fcc_data *) lid->data)->flags = 0;
     
     /* Set up the filename */
     strcpy(((krb5_fcc_data *) lid->data)->filename, scratch);

     /* Make sure the file name is reserved */
     ret = open(((krb5_fcc_data *) lid->data)->filename,
		O_CREAT | O_EXCL | O_WRONLY, 0);
     if (ret == -1) {
	  retcode = krb5_fcc_interpret(errno);
          goto err_out;
     } else {
	  krb5_int16 fcc_fvno = htons(KRB5_FCC_FVNO);
	  int errsave, cnt;

	  /* Ignore user's umask, set mode = 0600 */
	  fchmod(ret, S_IREAD | S_IWRITE);
	  if ((cnt = write(ret, (char *)&fcc_fvno, sizeof(fcc_fvno)))
	      != sizeof(fcc_fvno)) {
	      errsave = errno;
	      (void) close(ret);
	      (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	      retcode = (cnt == -1) ? krb5_fcc_interpret(errsave) : KRB5_CC_IO;
              goto err_out;
	  }
	  if (close(ret) == -1) {
	      errsave = errno;
	      (void) unlink(((krb5_fcc_data *) lid->data)->filename);
	      retcode = krb5_fcc_interpret(errsave);
              goto err_out;
	  }

	  *id = lid;
	  return KRB5_OK;
     }

err_out:
     xfree(((krb5_fcc_data *) lid->data)->filename);
     xfree(((krb5_fcc_data *) lid->data));
     xfree(lid);
     return retcode;
}
