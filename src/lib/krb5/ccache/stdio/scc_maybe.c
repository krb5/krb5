/*
 * lib/krb5/ccache/stdio/scc_maybe.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Copyright 1995 by Cygnus Support.
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
 * This file contains the source code for conditional open/close calls.
 */

#include "scc.h"
#include "k5-int.h"

int krb5_scc_default_format = KRB5_SCC_DEFAULT_FVNO;

krb5_error_code
krb5_scc_close_file (context, id)
   krb5_context context;
    krb5_ccache id;
{
     krb5_scc_data *data;
     int ret;
     krb5_error_code retval;

     data = (krb5_scc_data *) id->data;
     if (data->file == (FILE *) NULL)
	 return KRB5_FCC_INTERNAL;
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
     memset (data->stdio_buffer, 0, sizeof (data->stdio_buffer));
     if (ret == EOF) {
	  int errsave = errno;
	  (void) krb5_unlock_file(context, fileno(data->file));
	  (void) fclose (data->file);
	  data->file = 0;
	  return krb5_scc_interpret (context, errsave);
     }
     retval = krb5_unlock_file(context, fileno(data->file));
     ret = fclose (data->file);
     data->file = 0;
     if (retval)
	 return retval;
     else
     return ret ? krb5_scc_interpret (context, errno) : 0;
}

krb5_error_code
krb5_scc_open_file (context, id, mode)
   krb5_context context;
    krb5_ccache id;
    int mode;
{
     char fvno_bytes[2];	/* In nework standard byte order, big endian */
     krb5_scc_data *data;
     FILE *f;
     char *open_flag;
     krb5_error_code retval;

     data = (krb5_scc_data *) id->data;
     if (data->file) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) krb5_unlock_file(context, fileno(data->file));
	  (void) fclose (data->file);
	  data->file = 0;
     }
#ifdef ANSI_STDIO
     switch(mode) {
     case SCC_OPEN_AND_ERASE:
	 open_flag = "wb+";
	 break;
     case SCC_OPEN_RDWR:
	 open_flag = "rb+";
	 break;
     case SCC_OPEN_RDONLY:
     default:
	 open_flag = "rb";
	 break;
     }
#else
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
#endif

     f = fopen (data->filename, open_flag);
     if (!f)
	  return krb5_scc_interpret (context, errno);
#ifdef HAS_SETVBUF
     setvbuf(f, data->stdio_buffer, _IOFBF, sizeof (data->stdio_buffer));
#else
     setbuf (f, data->stdio_buffer);
#endif
     switch (mode) {
     case SCC_OPEN_RDONLY:
	 if ((retval = krb5_lock_file(context,fileno(f),KRB5_LOCKMODE_SHARED))){
	     (void) fclose(f);
	     return retval;
	 }
	 break;
     case SCC_OPEN_RDWR:
     case SCC_OPEN_AND_ERASE:
	 if ((retval = krb5_lock_file(context, fileno(f), 
				      KRB5_LOCKMODE_EXCLUSIVE))) {
	     (void) fclose(f);
	     return retval;
	 }
	 break;
     }
     if (mode == SCC_OPEN_AND_ERASE) {
	 /* write the version number */
	 int errsave;

	 fvno_bytes[0] = krb5_scc_default_format >> 8;
	 fvno_bytes[1] = krb5_scc_default_format & 0xFF;
	 data->version = krb5_scc_default_format;
	 if (!fwrite((char *)fvno_bytes, sizeof(fvno_bytes), 1, f)) {
	     errsave = errno;
	     (void) krb5_unlock_file(context, fileno(f));
	     (void) fclose(f);
	     return krb5_scc_interpret(context, errsave);
	 }
     } else {
	 /* verify a valid version number is there */
	 if (!fread((char *)fvno_bytes, sizeof(fvno_bytes), 1, f)) {
	     (void) krb5_unlock_file(context, fileno(f));
	     (void) fclose(f);
	     return KRB5_CCACHE_BADVNO;
	 }
	 data->version = (fvno_bytes[0] << 8) + fvno_bytes[1];
	 if ((data->version != KRB5_SCC_FVNO_1) &&
	     (data->version != KRB5_SCC_FVNO_2) &&
	     (data->version != KRB5_SCC_FVNO_3) &&
	     (data->version != KRB5_SCC_FVNO_4)) {
	     (void) krb5_unlock_file(context, fileno(f));
	     (void) fclose(f);
	     return KRB5_CCACHE_BADVNO;
	 }
	if (data->version == KRB5_SCC_FVNO_4) {
	    char buf[1024];
	    int len;

	    if (!fread((char *)fvno_bytes, sizeof(fvno_bytes), 1, f)) {
	     	(void) krb5_unlock_file(context, fileno(f));
	     	(void) fclose(f);
	     	return KRB5_CCACHE_BADVNO;
	    }
	    if (len = (fvno_bytes[0] << 8) + fvno_bytes[1]) {
	    	if (!fread(buf, len, 1, f)) {
	     	    (void) krb5_unlock_file(context, fileno(f));
	     	    (void) fclose(f);
	     	    return KRB5_CCACHE_BADVNO;
		}
	    }
	}
    }
    data->file = f;
    return 0;
}
