#include <Kerberos/Kerberos.h>



int main (void) 
{
    KLStatus		err;
    KLPrincipal		principal;
    char 			*principalName;
    char			*cacheName;
    
    printf ("Testing KLAcquireNewTickets (nil)...\n");

    err = KLAcquireNewTickets (nil, &principal, &cacheName);
    if (err == klNoErr) {
        err = KLGetStringFromPrincipal (principal, kerberosVersion_V5, &principalName);
        if (err == klNoErr) {
            printf ("Got tickets for '%s' in cache '%s'\n", principalName, cacheName);
            KLDisposeString (principalName);
        } else {
            printf ("KLGetStringFromPrincipal() returned (err = %ld)\n", err); 
        }
        KLDisposeString (cacheName);
        
        printf ("Testing KLChangePassword (principal)...\n");
        
        err = KLChangePassword (principal);
        if (err != klNoErr) {
            printf ("KLChangePassword() returned (err = %ld)\n", err);
        }
        
        KLDisposePrincipal (principal);
    } else {
        printf ("KLAcquireNewTickets() returned (err = %ld)\n", err);
    }
    
    printf ("All done testing!\n");  
    return 0;  
}