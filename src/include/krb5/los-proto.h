/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * Function prototypes for Kerberos V5 library (libos)
 */

#include <krb5/copyright.h>

#ifndef __KRB5_LIBOS_PROTO__
#define __KRB5_LIBOS_PROTO__

/* requires <stdio.h> */

/* libos.spec */
krb5_error_code krb5_read_password
	PROTOTYPE((char *prompt,
		   char *prompt2,
		   char *return_pwd,
		   int size_return ));
krb5_error_code krb5_lock_file
	PROTOTYPE((FILE *filep,
		   char *,
		   int mode ));
krb5_error_code krb5_unlock_file
	PROTOTYPE((FILE *filep,
		   char * ));
krb5_error_code krb5_timeofday
	PROTOTYPE((krb5_int32 *timeret ));
krb5_error_code krb5_ms_timeofday
	PROTOTYPE((krb5_int32 *seconds,
		   krb5_int16 *milliseconds ));
int krb5_net_read
	PROTOTYPE((int fd,
		   char *buf,
		   int len ));
int krb5_net_write
	PROTOTYPE((int fd,
		   char *buf,
		   int len ));

#endif /* __KRB5_LIBOS_PROTO__ */
