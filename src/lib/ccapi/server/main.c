#include <stdarg.h>
#include <stdio.h>
#include "CredentialsCache.h"
#include "msg.h"
#include "rpc_auth.h"

/* This object module is platform dependent. */

int main( int argc, char *argv[] )
{
    cc_int32 code;
    int      running = 1;

    /* we need a set of functions we want to support.
     * so we can provide an abstract platform independent
     * interface.
     */

    code = ccs_serv_initialize();
    if (code) {
	/* ok.  we failed to initialize the ccs data structures.
	 * terminate service start.  Log the result.  
	 */
	fprintf(stderr, "ccs_serv_initialize failure: %d\n", code);
	return -1;
    }

    /* initialize the IPC mechanism for this platform */

    /* implement a message loop that receives in-bound requests
     * processes them, and sends back responses.
     */
    while ( running ) {
	cc_msg_t * req_msg, *resp_msg;
	cc_auth_info_t* auth_info;
	cc_session_info_t* session_info;
	char * data;
	int    len;

	/* accept IPC request */

	/* unflatten input stream to msg */
	code = cci_msg_unflatten(data, len, &req_msg);

	/* process request */
	code = ccs_serv_process_msg(req_msg, auth_info, session_info, &resp_msg);

	code = cci_msg_flatten(resp_msg, NULL); 

	/* send response (resp_msg->flat, resp_msg->flat_len) */

	/* cleanup */
	cci_msg_destroy(req_msg);
	cci_msg_destroy(resp_msg);
    }

    /* de-register IPC mechanism */

    /* cleanup ccs resources */
    ccs_serv_cleanup();

    /* exit */
    return 0;
}
