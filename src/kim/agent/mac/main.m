#import <Cocoa/Cocoa.h>

#import "ServerDemux.h"
#import "k5_mig_server.h"
#include <Kerberos/kipc_server.h>
#include <syslog.h>


int main(int argc, const char *argv[])
{
    int err = 0;
    NSAutoreleasePool *pool = NULL;
    
    openlog (argv[0], LOG_CONS | LOG_PID, LOG_AUTH);
    syslog (LOG_INFO, "Starting up.");   

    pool = [[NSAutoreleasePool alloc] init];

    [NSApplication sharedApplication];
    [NSBundle loadNibNamed: @"MainMenu" owner: NSApp];
    
    err = k5_ipc_server_listen_loop ();
    
    syslog (LOG_NOTICE, "Exiting: %s (%d)", kipc_error_string (err), err);
    
    return err;
}
