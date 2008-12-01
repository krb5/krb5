/*
 * change_password.c
 *
 * Copyright 1987, 1988, 2002 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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
 */

#include <string.h>
#include <stdlib.h>

#include "krb.h"
#include "krb4int.h"
#include "kadm.h"
#include "prot.h"

/*
 * krb_change_password(): This disgusting function handles changing passwords
 * in a krb4-only environment.  
 * -1783126240
 * THIS IS NOT A NORMAL KRB4 API FUNCTION!  DON'T USE IN PORTABLE CODE!
 */

int KRB5_CALLCONV
krb_change_password(char *principal, char *instance, char *realm, 
		    char *oldPassword, char *newPassword)
{
    int		err;
    des_cblock	key;
    KRB_UINT32	tempKey;
    size_t	sendSize;
    u_char	*sendStream;
    size_t	receiveSize;
    u_char	*receiveStream;
    Kadm_Client	client_parm;
    u_char	*p;

    err = 0;
    
    /* Check inputs: */
    if (principal == NULL || instance == NULL || realm == NULL ||
        oldPassword == NULL || newPassword == NULL) {
        return KFAILURE;
    }
    
    /*
     * Get tickets to change the old password and shove them in the
     * client_parm
     */
    err = krb_get_pw_in_tkt_creds(principal, instance, realm, 
				  PWSERV_NAME, KADM_SINST, 1,
				  oldPassword, &client_parm.creds);
    if (err != KSUCCESS)
	goto cleanup;

    /* Now create the key to send to the server */
    /* Use this and not mit_password_to_key so that we don't prompt */
    des_string_to_key(newPassword, key);

    /* Create the link to the server */
    err = kadm_init_link(PWSERV_NAME, KRB_MASTER, realm, &client_parm, 1);
    if (err != KADM_SUCCESS)
	goto cleanup;

    /* Connect to the KDC */
    err = kadm_cli_conn(&client_parm);
    if (err != KADM_SUCCESS)
	goto cleanup;

    /* possible problem with vts_long on a non-multiple of four boundary */
    sendSize = 0;		/* start of our output packet */
    sendStream = malloc(1);	/* to make it reallocable */
    if (sendStream == NULL)
	goto disconnect;
    sendStream[sendSize++] = CHANGE_PW;

    /* change key to stream */
    /* This looks backwards but gets inverted on the server side. */
    p = key + 4;
    KRB4_GET32BE(tempKey, p);
    sendSize += vts_long(tempKey, &sendStream, (int)sendSize);
    p = key;
    KRB4_GET32BE(tempKey, p);
    sendSize += vts_long(tempKey, &sendStream, (int)sendSize);
    tempKey = 0;

    if (newPassword) {
	sendSize += vts_string(newPassword, &sendStream, (int)sendSize);
    }

    /* send the data to the kdc */
    err = kadm_cli_send(&client_parm, sendStream, sendSize,
			&receiveStream, &receiveSize);
    free(sendStream);
    if (receiveSize > 0)
	/* If there is a string from the kdc, free it - we don't care */
	free(receiveStream);
    if (err != KADM_SUCCESS)
	goto disconnect;

disconnect:	
    /* Disconnect */
    kadm_cli_disconn(&client_parm);

cleanup:
    memset(&client_parm.creds.session, 0, sizeof(client_parm.creds.session));
    memset(&key, 0, sizeof(key));
    return err;
}
