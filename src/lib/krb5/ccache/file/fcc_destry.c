/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_destroy.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_destry_c[] =
"$Id$";
#endif /* !lint && !SABER */


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
	  if (ret < 0)
	       return krb5_fcc_interpret(errno);
	  ((krb5_fcc_data *) id->data)->fd = ret;
     }
     else
	  lseek(((krb5_fcc_data *) id->data)->fd, 0, L_SET);

     ret = unlink(((krb5_fcc_data *) id->data)->filename);
     if (ret < 0) {
	 ret = krb5_fcc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 return ret;
     }
     
     ret = fstat(((krb5_fcc_data *) id->data)->fd, &buf);
     if (ret < 0) {
	 ret = krb5_fcc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 return ret;
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
	      return ret;
	  }

     if (write(((krb5_fcc_data *) id->data)->fd, zeros, size % BUFSIZ) < 0) {
	 ret = krb5_fcc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *) id->data)->fd = -1;
	 }
	 return ret;
     }

     ret = close(((krb5_fcc_data *) id->data)->fd);
     ((krb5_fcc_data *) id->data)->fd = -1;

     if (ret)
	 ret = krb5_fcc_interpret(errno);

     return ret;
}
