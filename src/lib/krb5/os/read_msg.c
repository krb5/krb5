/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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

