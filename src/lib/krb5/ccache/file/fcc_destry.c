/*
 * lib/krb5/ccache/file/fcc_destry.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
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
 * This file contains the source code for krb5_fcc_destroy.
 */


#include <errno.h>
#include "fcc.h"

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
krb5_error_code krb5_fcc_destroy(id)
   krb5_ccache id;
{
     struct stat buf;
     unsigned long size;
     char zeros[BUFSIZ];
     register int ret, i;
     
     if (OPENCLOSE(id)) {
	  ret = open(((krb5_fcc_data *) id->data)->filename, O_RDWR, 0);
	  if (ret < 0) {
	      ret = krb5_fcc_interpret(errno);
	      goto cleanup;
	  }
	  ((krb5_fcc_data *) id->data)->fd = ret;
     }
     else
	  lseek(((krb5_fcc_data *) id->data)->fd, 0, SEEK_SET);

     ret = unlink(((krb5_fcc_data *) id->data)->filename);
     if (ret < 0) {
	 ret = krb5_fcc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 goto cleanup;
     }
     
     ret = fstat(((krb5_fcc_data *) id->data)->fd, &buf);
     if (ret < 0) {
	 ret = krb5_fcc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 goto cleanup;
     }

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;

     memset(zeros, 0, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (write(((krb5_fcc_data *) id->data)->fd, zeros, BUFSIZ) < 0) {
	      ret = krb5_fcc_interpret(errno);
	      if (OPENCLOSE(id)) {
		  (void) close(((krb5_fcc_data *)id->data)->fd);
		  ((krb5_fcc_data *) id->data)->fd = -1;
	      }
	      goto cleanup;
	  }

     if (write(((krb5_fcc_data *) id->data)->fd, zeros, size % BUFSIZ) < 0) {
	 ret = krb5_fcc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 goto cleanup;
     }

     ret = close(((krb5_fcc_data *) id->data)->fd);
     ((krb5_fcc_data *) id->data)->fd = -1;

     if (ret)
	 ret = krb5_fcc_interpret(errno);

  cleanup:
     krb5_xfree(((krb5_fcc_data *) id->data)->filename);
     krb5_xfree(id->data);
     krb5_xfree(id);

     return ret;
}
