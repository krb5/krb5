/*+*************************************************************************
** 
** K5stream
** 
** Emulates the kstream package in Kerberos 4
** 
***************************************************************************/

#include <stdio.h>
#include <io.h>
#include <malloc.h>
#include "telnet.h"
#include "k5stream.h"
#include "auth.h"

int 
kstream_destroy (kstream ks) {
    if (ks != NULL) {
        auth_destroy (ks);                       /* Destroy authorizing */

        closesocket (ks->fd);                    /* Close the socket??? */
        free (ks);
    }
    return 0;
}

void 
kstream_set_buffer_mode (kstream ks, int mode) {
}


kstream 
kstream_create_from_fd (int fd,
				const struct kstream_crypt_ctl_block __far *ctl,
				kstream_ptr data)
{
    kstream ks;
    int n;

    ks = malloc (sizeof(kstream *));
    if (ks == NULL)
        return NULL;

    ks->fd = fd;

    n = auth_init (ks, data);                   /* Initialize authorizing */
    if (n) {
        free (ks);
        return NULL;
    }

    return ks;
}

int 
kstream_write (kstream ks, void __far *p_data, size_t p_len) {
    int n;

    n = send (ks->fd, p_data, p_len, 0);        /* Write the data */
    
    return n;                                   /* higher layer does retries */
}

