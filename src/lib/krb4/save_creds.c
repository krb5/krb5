/*
 * save_creds.c
 *
 * Copyright 1985, 1986, 1987, 1988, 2002 by the Massachusetts
 * Institute of Technology.  All Rights Reserved.
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

#include <stdio.h>
#include "krb.h"
#include "krb4int.h"

/*
 * This routine takes a ticket and associated info and calls
 * tf_save_cred() to store them in the ticket cache.  The peer
 * routine for extracting a ticket and associated info from the
 * ticket cache is krb_get_cred().  When changes are made to
 * this routine, the corresponding changes should be made
 * in krb_get_cred() as well.
 *
 * Returns KSUCCESS if all goes well, otherwise an error returned
 * by the tf_init() or tf_save_cred() routines.
 *
 * This used to just be called save_credentials, but when we formalized
 * the DOS/Mac interface, we created and exported krb_save_credentials
 * to avoid namespace pollution.
 */

int
krb4int_save_credentials_addr(service, instance, realm, session, lifetime, kvno,
                 ticket, issue_date, local_addr)
    char *service;		/* Service name */
    char *instance;		/* Instance */
    char *realm;		/* Auth domain */
    C_Block session;		/* Session key */
    int lifetime;		/* Lifetime */
    int kvno;			/* Key version number */
    KTEXT ticket;		/* The ticket itself */
    long issue_date;		/* The issue time */
    KRB_UINT32 local_addr;
{
    int tf_status;   /* return values of the tf_util calls */

    /* Open and lock the ticket file for writing */
    if ((tf_status = tf_init(TKT_FILE, W_TKT_FIL)) != KSUCCESS)
	return(tf_status);

    /* Save credentials by appending to the ticket file */
    tf_status = tf_save_cred(service, instance, realm, session,
			     lifetime, kvno, ticket, issue_date);
    (void) tf_close();
    return (tf_status);
}

int KRB5_CALLCONV
krb_save_credentials(
    char	*service,
    char	*instance,
    char	*realm,
    C_Block	session,
    int		lifetime,
    int		kvno,
    KTEXT	ticket,
    long	issue_date)
{
    return krb4int_save_credentials_addr(service, instance, realm,
					 session, lifetime, kvno,
					 ticket, issue_date, 0);
}
