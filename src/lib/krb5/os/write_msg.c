/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * convenience sendauth/recvauth functions
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_sendauth_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/los-proto.h>
#include <com_err.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

krb5_error_code
krb5_write_message(fdp, outbuf)
	krb5_pointer	fdp;
	krb5_data	*outbuf;
{
	krb5_int32	len;
	int		fd = *( (int *) fdp);

	len = htonl(outbuf->length);
	if (krb5_net_write(fd, (char *)&len, 4) < 0) {
		return(errno);
	}
	if (len && (krb5_net_write(fd, outbuf->data, outbuf->length) < 0)) {
		return(errno);
	}
	return(0);
}




