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
 * Write a message to the network
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_read_msg_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/los-proto.h>
#include <krb5/ext-proto.h>
#include <com_err.h>
#include <errno.h>

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

krb5_error_code
krb5_read_message(fdp, inbuf)
	krb5_pointer fdp;
	krb5_data	*inbuf;
{
	krb5_int32	len, len2;
	char		*buf = NULL;
	int		fd = *( (int *) fdp);
	
	if ((len2 = krb5_net_read(fd, (char *)&len, 4)) != 4)
		return((len2 < 0) ? errno : ECONNABORTED);
	inbuf->length = len = ntohl(len);
	if (len) {
		/*
		 * We may want to include a sanity check here someday....
		 */
		if (!(buf = malloc(len))) {
			return(ENOMEM);
		}
		if ((len2 = krb5_net_read(fd, buf, len)) != len) {
			xfree(buf);
			return((len2 < 0) ? errno : ECONNABORTED);
		}
	}
	inbuf->data = buf;
	return(0);
}

