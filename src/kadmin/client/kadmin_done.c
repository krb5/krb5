/*
 * kadmin/client/kadmin_done.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 */

/* 
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 */


/*
 * kadmin_done
 * Perform Remote Kerberos Administrative Functions
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <com_err.h>

#include <krb5/adm_defs.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>

krb5_error_code
kadm_done(context, my_creds, rep_ret, local_addr, foreign_addr, 
	  local_socket, seqno)
    krb5_context context;
    krb5_creds *my_creds;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_address *local_addr, *foreign_addr;
    int *local_socket;
    krb5_int32 *seqno;
{
    krb5_data msg_data, inbuf;
    krb5_error_code retval;     /* return code */
    char buf[16];

    inbuf.data = buf;

    inbuf.data[0] = KADMIN;
    inbuf.data[1] = COMPLETE;
    inbuf.data[2] = SENDDATA2;
    inbuf.data[3] = 0xff;
    (void) memset( inbuf.data + 4, 0, 4);
    inbuf.length = 16;

    if ((retval = krb5_mk_priv(context, &inbuf,
			ETYPE_DES_CBC_CRC,
			&my_creds->keyblock, 
			local_addr, 
			foreign_addr,
			*seqno,
			KRB5_PRIV_DOSEQUENCE|KRB5_PRIV_NOTIME,
			0,
			0,
			&msg_data))) {
        fprintf(stderr, "Error during Second Message Encoding: %s!\n",
			error_message(retval));
        return(1);
    }

    /* write private message to server */
    if (krb5_write_message(context, local_socket, &msg_data)) {
	free(msg_data.data);
        fprintf(stderr, "Write Error During Second Message Transmission!\n");
        return(1);
    } 
    free(msg_data.data);
    return(0);
}
