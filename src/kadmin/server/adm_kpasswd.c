/*
 * kadmin/server/adm_kpasswd.c
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
  adm_kpasswd.c
*/

#include <sys/types.h>
#include <syslog.h>
#include <sys/wait.h>
#include <stdio.h>
#include <com_err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif
 
#include <krb5/krb5.h>
#include <krb5/kdb.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/adm_defs.h>
#include "adm_extern.h"
 
extern krb5_encrypt_block master_encblock;
extern krb5_keyblock master_keyblock;
 
struct cpw_keyproc_arg {
    krb5_keyblock *key;
};
 
krb5_error_code
adm5_kpasswd(context, prog, request_type, client_creds, retbuf, otype)
    krb5_context context;
    char *prog;
    kadmin_requests *request_type;
    krb5_ticket *client_creds;
    char *retbuf;
    int *otype;
{
    char completion_msg[520];
    krb5_error_code retval;

    switch (request_type->oper_code) {
    case CHGOPER:
	*otype = 3;
	syslog(LOG_AUTH | LOG_INFO,
	       "adm_kpasswd: kpasswd change received");
	retval = adm5_change(context, "adm5_kpasswd", 
			     client_server_info.client,
			     client_creds);

	switch(retval) {
	case 0:
	    retbuf[0] = KPASSWD;
	    retbuf[1] = CHGOPER;
	    retbuf[2] = KPASSGOOD;
	    retbuf[3] = '\0';
	    break;

	case 1:
	    retbuf[0] = KPASSWD;
	    retbuf[1] = CHGOPER;
	    retbuf[2] = KPASSBAD;
	    retbuf[3] = '\0';
	    sprintf((char *)retbuf +3, "%s", 
		    kadmind_kpasswd_response[retval]);
	    sprintf(completion_msg,
		    "kpasswd change from %s FAILED: %s", 
		    inet_ntoa(client_server_info.client_name.sin_addr),
		    kadmind_kpasswd_response[retval]);
	    syslog(LOG_AUTH | LOG_INFO, completion_msg);
	    goto finish;

	default:
	    retbuf[0] = KPASSWD;
	    retbuf[1] = CHGOPER;
	    retbuf[2] = KUNKNOWNERR;
	    retbuf[3] = '\0';
	    sprintf(completion_msg, "kpasswd change from %s FAILED", 
		    inet_ntoa(client_server_info.client_name.sin_addr));
	    syslog(LOG_AUTH | LOG_INFO, completion_msg);
	    retval = 255;
	    goto finish;
	}		/* switch (retval) */
	break;

    default:
	retbuf[0] = KPASSWD;
	retbuf[1] = KUNKNOWNOPER;
	retbuf[2] = '\0';
	sprintf(completion_msg, "kpasswd %s from %s FAILED", 
		"Unknown or Non-Implemented Operation Type!",
		inet_ntoa(client_server_info.client_name.sin_addr ));
	syslog(LOG_AUTH | LOG_INFO, completion_msg);
	retval = 255;
	goto finish;
    }			/* switch (request_type->oper_code) */
    
finish:
	return(retval);
}
