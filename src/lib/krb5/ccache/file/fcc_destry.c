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

#ifndef	lint
static char fcc_destry_c[] = "$Id$";
#endif	lint

#include <krb5/copyright.h>

/*
 * Effects:
 * Destroys the contents of id.
 *
 * Errors:
 * system errors
 */
krb5_error
krb5_fcc_destroy(id)
   krb5_ccache id;
{
     struct stat buf;
     unsigned long size;
     char zeros[BUFSIZ];
     int ret;
     
#ifdef OPENCLOSE
     id->data->fd = open(id->data->filename, O_RDWR, 0);
     if (id->data->fd < 0)
	  return errno;
#else
     lseek(id->data->fd, 0, L_SET);
#endif

     ret = fstat(id->data->fd, &buf);
     if (ret < 0)
	  return errno;

     /* XXX This may not be legal XXX */
     size = (unsigned long) buf.st_size;

     bzero(zeros, BUFSIZ);
     for (i=0; i < size / BUFSIZ; i++)
	  if (write(id->data->fd, zeros, BUFSIZ) < 0)
	       return errno;

     if (write(id->data->fd, zeros, size % BUFSIZ) < 0)
	  return errno;

#ifdef OPENCLOSE
     close(id->data->fd);
#endif
}
