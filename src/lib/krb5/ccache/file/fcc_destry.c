/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_destroy.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_destry_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

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
     int ret, i;
     
#ifdef OPENCLOSE
     ((krb5_fcc_data *) id->data)->fd = open(((krb5_fcc_data *) id->data)->
					     filename, O_RDWR, 0);
     if (((krb5_fcc_data *) id->data)->fd < 0)
	  return errno;
#else
     lseek(((krb5_fcc_data *) id->data)->fd, 0, L_SET);
#endif
     ret = unlink(((krb5_fcc_data *) id->data)->filename);
     if (ret < 0)
	 return errno;
     
     ret = fstat(((krb5_fcc_data *) id->data)->fd, &buf);
     if (ret < 0)
	  return errno;

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;

     bzero(zeros, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (write(((krb5_fcc_data *) id->data)->fd, zeros, BUFSIZ) < 0)
	       return errno;

     if (write(((krb5_fcc_data *) id->data)->fd, zeros, size % BUFSIZ) < 0)
	  return errno;

#ifdef OPENCLOSE
     close(((krb5_fcc_data *) id->data)->fd);
#endif

     return KRB5_OK;
}
