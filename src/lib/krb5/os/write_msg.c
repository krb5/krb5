/*
 * lib/krb5/os/write_msg.c
 *
 * Copyright 1991, 2009 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * convenience sendauth/recvauth functions
 */

#include "k5-int.h"
#include <errno.h>
#include "os-proto.h"

krb5_error_code
krb5_write_message(krb5_context context, krb5_pointer fdp, krb5_data *outbuf)
{
	krb5_int32	len;
	int		fd = *( (int *) fdp);
	sg_buf		sg[2];

	len = htonl(outbuf->length);
	SG_SET(&sg[0], &len, 4);
	SG_SET(&sg[1], outbuf->data, outbuf->length);
	if (krb5int_net_writev(context, fd, sg, 2) < 0) {
	    return errno;
	}
	return(0);
}
