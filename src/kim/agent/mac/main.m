#import <Cocoa/Cocoa.h>
#import "k5_mig_server.h"

int main(int argc, const char *argv[])
{
    int err = 0;
    
    err = k5_ipc_server_initialize (argc, argv);
    
    if (!err) {
        err = NSApplicationMain(argc, argv);
    }
    
    if (!err) {
        err = k5_ipc_server_cleanup (argc, argv);
    }
    
    return err;
}
