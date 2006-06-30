#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include "CredentialsCache.h"
#include "msg.h"
#include "migServer.h"

#include <Kerberos/kipc_server.h>

int main (int argc, const char *argv[])
{
    cc_int32 code = 0;
    int running = 1;

    openlog (argv[0], LOG_CONS | LOG_PID, LOG_AUTH);
    syslog (LOG_INFO, "Starting up.");   

    if (!code) {
        code = ccs_serv_initialize();
    }
    
    if (!code) {
        code = kipc_server_run_server (ccapi_server);
    }
    
    /* cleanup ccs resources */
    ccs_serv_cleanup();

    syslog (LOG_NOTICE, "Exiting: %s (%d)", kipc_error_string (code), code);

    /* exit */
    return code ? 1 : 0;
}
