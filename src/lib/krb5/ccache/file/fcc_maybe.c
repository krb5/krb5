/*
 * lib/krb5/ccache/file/fcc_maybe.c
 *
 * Copyright 1990, 1991 by the Massachusetts Institute of Technology.
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
 * This file contains the source code for conditional open/close calls.
 */

#define NEED_SOCKETS    /* Only for ntohs, etc. */
#define NEED_LOWLEVEL_IO
#include "k5-int.h"

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
          
#include "fcc.h"

#ifdef HAVE_NETINET_IN_H
#if !defined(_WINSOCKAPI_) && !defined(HAVE_MACSOCK_H)
#include <netinet/in.h>
#endif
#else
 #error find some way to use net-byte-order file version numbers.
#endif

krb5_error_code
krb5_fcc_close_file (context, id)
   krb5_context context;
    krb5_ccache id;
{
     int ret;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_error_code retval;

     if (data->fd == -1)
	 return KRB5_FCC_INTERNAL;

     retval = krb5_unlock_file(context, data->fd);
     ret = close (data->fd);
     data->fd = -1;
     if (retval)
	 return retval;
     else
     return (ret == -1) ? krb5_fcc_interpret (context, errno) : 0;
}

krb5_error_code
krb5_fcc_open_file (context, id, mode)
    krb5_context context;
    krb5_ccache id;
    int mode;
{
     krb5_os_context os_ctx = (krb5_os_context)context->os_context;
     krb5_fcc_data *data = (krb5_fcc_data *)id->data;
     krb5_ui_2 fcc_fvno;
     krb5_ui_2 fcc_flen;
     krb5_ui_2 fcc_tag;
     krb5_ui_2 fcc_taglen;
     int fd;
     int open_flag, lock_flag;
     krb5_error_code retval = 0;

     if (data->fd != -1) {
	  /* Don't know what state it's in; shut down and start anew.  */
	  (void) krb5_unlock_file(context, data->fd);
	  (void) close (data->fd);
	  data->fd = -1;
     }
     data->mode = mode;
     switch(mode) {
     case FCC_OPEN_AND_ERASE:
	 unlink(data->filename);
	 open_flag = O_CREAT|O_EXCL|O_TRUNC|O_RDWR;
	 break;
     case FCC_OPEN_RDWR:
	 open_flag = O_RDWR;
	 break;
     case FCC_OPEN_RDONLY:
     default:
	 open_flag = O_RDONLY;
	 break;
     }

     fd = THREEPARAMOPEN (data->filename, open_flag | O_BINARY, 0600);
     if (fd == -1)
	  return krb5_fcc_interpret (context, errno);

     if (data->mode == FCC_OPEN_RDONLY)
	lock_flag = KRB5_LOCKMODE_SHARED;
     else 
	lock_flag = KRB5_LOCKMODE_EXCLUSIVE;

     if ((retval = krb5_lock_file(context, fd, lock_flag))) {
	 (void) close(fd);
	 return retval;
     }
	 
     if (mode == FCC_OPEN_AND_ERASE) {
	 /* write the version number */
	 int cnt;

	 fcc_fvno = htons(context->fcc_default_format);
	 data->version = context->fcc_default_format;
	 if ((cnt = write(fd, (char *)&fcc_fvno, sizeof(fcc_fvno))) !=
	     sizeof(fcc_fvno)) {
	     retval = ((cnt == -1) ? krb5_fcc_interpret(context, errno) :
		       KRB5_CC_IO);
	     goto done;
	 }

	 data->fd = fd;
	 
	 if (data->version == KRB5_FCC_FVNO_4) {
	     /* V4 of the credentials cache format allows for header tags */

	     fcc_flen = 0;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
		 fcc_flen += (2*sizeof(krb5_ui_2) + 2*sizeof(krb5_int32));

	     /* Write header length */
	     retval = krb5_fcc_store_ui_2(context, id, (krb5_int32)fcc_flen);
	     if (retval) goto done;

	     if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID) {
		 /* Write time offset tag */
		 fcc_tag = FCC_TAG_DELTATIME;
		 fcc_taglen = 2*sizeof(krb5_int32);
		 
		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_tag);
		 if (retval) goto done;
		 retval = krb5_fcc_store_ui_2(context,id,(krb5_int32)fcc_taglen);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->time_offset);
		 if (retval) goto done;
		 retval = krb5_fcc_store_int32(context,id,os_ctx->usec_offset);
		 if (retval) goto done;
	     }
	 }
	 goto done;
     }

     /* verify a valid version number is there */
     if (read(fd, (char *)&fcc_fvno, sizeof(fcc_fvno)) !=
	 sizeof(fcc_fvno)) {
	 retval = KRB5_CC_FORMAT;
	 goto done;
     }
     if ((fcc_fvno != htons(KRB5_FCC_FVNO_4)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_3)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_2)) &&
	 (fcc_fvno != htons(KRB5_FCC_FVNO_1)))
     {
	 retval = KRB5_CCACHE_BADVNO;
	 goto done;
     }

     data->version = ntohs(fcc_fvno);
     data->fd = fd;

     if (data->version == KRB5_FCC_FVNO_4) {
	 char buf[1024];

	 if (krb5_fcc_read_ui_2(context, id, &fcc_flen) ||
	     (fcc_flen > sizeof(buf)))
	 {
	     retval = KRB5_CC_FORMAT;
	     goto done;
	 }

	 while (fcc_flen) {
	     if ((fcc_flen < (2 * sizeof(krb5_ui_2))) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_tag) ||
		 krb5_fcc_read_ui_2(context, id, &fcc_taglen) ||
		 (fcc_taglen > (fcc_flen - 2*sizeof(krb5_ui_2))))
	     {
		 retval = KRB5_CC_FORMAT;
		 goto done;
	     }

	     switch (fcc_tag) {
	     case FCC_TAG_DELTATIME:
		 if (fcc_taglen != 2*sizeof(krb5_int32)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 if (!(context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) ||
		     (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID))
		 {
		     if (krb5_fcc_read(context, id, buf, fcc_taglen)) {
			 retval = KRB5_CC_FORMAT;
			 goto done;
		     }
		     break;
		 }
		 if (krb5_fcc_read_int32(context, id, &os_ctx->time_offset) ||
		     krb5_fcc_read_int32(context, id, &os_ctx->usec_offset))
		 {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 os_ctx->os_flags =
		     ((os_ctx->os_flags & ~KRB5_OS_TOFFSET_TIME) |
		      KRB5_OS_TOFFSET_VALID);
		 break;
	     default:
		 if (fcc_taglen && krb5_fcc_read(context,id,buf,fcc_taglen)) {
		     retval = KRB5_CC_FORMAT;
		     goto done;
		 }
		 break;
	     }
	     fcc_flen -= (2*sizeof(krb5_ui_2) + fcc_taglen);
	 }
     }

done:
     if (retval) {
	 data->fd = -1;
	 (void) krb5_unlock_file(context, fd);
	 (void) close(fd);
     }
     return retval;
}
