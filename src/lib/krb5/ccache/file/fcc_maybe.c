/*
 * $Source$
 * $Author$
 *
 * Copyright 1990, 1991 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for conditional open/close calls.
 */

#include "fcc.h"
#include <netinet/in.h>			/* XXX ip only? */

krb5_error_code
krb5_fcc_close_file (id)
    krb5_ccache id;
{
     int ret;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;

     if (data->fd == -1) {
	 abort ();			/* XXX? */
     }
     ret = close (data->fd);
     data->fd = -1;
     return (ret == -1) ? krb5_fcc_interpret (errno) : 0;
}

krb5_error_code
krb5_fcc_open_file (id, mode)
    krb5_ccache id;
    int mode;
{
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_int16 fcc_fvno = htons(KRB5_FCC_FVNO);
     int fd;
     int open_flag;

     if (data->fd != -1) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) close (data->fd);
	  data->fd = -1;
     }
     switch(mode) {
     case FCC_OPEN_AND_ERASE:
	 open_flag = O_CREAT|O_TRUNC|O_RDWR;
	 break;
     case FCC_OPEN_RDWR:
	 open_flag = O_RDWR;
	 break;
     case FCC_OPEN_RDONLY:
     default:
	 open_flag = O_RDONLY;
	 break;
     }

     fd = open (data->filename, open_flag, 0600);
     if (fd == -1)
	  return krb5_fcc_interpret (errno);

     if (mode == FCC_OPEN_AND_ERASE) {
	 /* write the version number */
	 int errsave, cnt;

	 if ((cnt = write(fd, (char *)&fcc_fvno, sizeof(fcc_fvno))) !=
	     sizeof(fcc_fvno)) {
	     errsave = errno;
	     (void) close(fd);
	     return (cnt == -1) ? krb5_fcc_interpret(errsave) : KRB5_CC_IO;
	 }
     } else {
	 /* verify a valid version number is there */
	 if (read(fd, (char *)&fcc_fvno, sizeof(fcc_fvno)) !=
	     sizeof(fcc_fvno)) {
	     (void) close(fd);
	     return KRB5_CCACHE_BADVNO;
	 }
	 if (fcc_fvno != htons(KRB5_FCC_FVNO)) {
	     (void) close(fd);
	     return KRB5_CCACHE_BADVNO;
	 }
     }
     data->fd = fd;
     return 0;
}
