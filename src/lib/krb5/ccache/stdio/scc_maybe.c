/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for conditional open/close calls.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_maybe_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "scc.h"
#include <netinet/in.h>			/* XXX ip only? */

krb5_error_code
krb5_scc_close_file (id)
    krb5_ccache id;
{
     krb5_scc_data *data;
     int ret;

     data = (krb5_scc_data *) id->data;
     if (data->file == (FILE *) NULL) {
	 abort ();
     }
#ifdef ultrix
     errno = 0;
#endif
     ret = fflush (data->file);
#ifdef ultrix
     /* their LIBC refuses to allow an fflush() of a read-only buffer!
	We patch around it by only calling it an error if errno is set by a
	(failed) syscall */
     if (ret == EOF && !errno) ret = 0;
#endif
     bzero (data->stdio_buffer, sizeof (data->stdio_buffer));
     if (ret == EOF) {
	  int errsave = errno;
	  (void) fclose (data->file);
	  data->file = 0;
	  return krb5_scc_interpret (errsave);
     }
     ret = fclose (data->file);
     data->file = 0;
     return ret ? krb5_scc_interpret (errno) : 0;
}

krb5_error_code
krb5_scc_open_file (id, mode)
    krb5_ccache id;
    int mode;
{
     krb5_int16 scc_fvno = htons(KRB5_SCC_FVNO);
     krb5_scc_data *data;
     FILE *f;
     char *open_flag;

     data = (krb5_scc_data *) id->data;
     if (data->file) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) fclose (data->file);
	  data->file = 0;
     }
     switch(mode) {
     case SCC_OPEN_AND_ERASE:
	 open_flag = "w+";
	 break;
     case SCC_OPEN_RDWR:
	 open_flag = "r+";
	 break;
     case SCC_OPEN_RDONLY:
     default:
	 open_flag = "r";
	 break;
     }

     f = fopen (data->filename, open_flag);
     if (!f)
	  return krb5_scc_interpret (errno);
     setbuf (f, data->stdio_buffer);
#if 0 /* alternative, not requiring sizeof stdio_buffer == BUFSIZ */
     setvbuf(f, data->stdio_buffer, _IOFBF, sizeof (data->stdio_buffer));
#endif

     if (mode == SCC_OPEN_AND_ERASE) {
	 /* write the version number */
	 int errsave;

	 if (!fwrite((char *)&scc_fvno, sizeof(scc_fvno), 1, f)) {
	     errsave = errno;
	     (void) fclose(f);
	     return krb5_scc_interpret(errsave);
	 }
     } else {
	 /* verify a valid version number is there */
	 if (!fread((char *)&scc_fvno, sizeof(scc_fvno), 1, f)) {
	     (void) fclose(f);
	     return KRB5_CCACHE_BADVNO;
	 }
	 if (scc_fvno != htons(KRB5_SCC_FVNO)) {
	     (void) fclose(f);
	     return KRB5_CCACHE_BADVNO;
	 }
     }
     data->file = f;
     return 0;
}
