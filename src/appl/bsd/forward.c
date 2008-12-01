/*
 * appl/bsd/forward.c
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#if defined(KERBEROS) || defined(KRB5)
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "k5-int.h"

#define SKIP_V4_PROTO /* To skip the krb4 prototypes */
#include "defines.h"

/* Decode, decrypt and store the forwarded creds in the local ccache. */
krb5_error_code
rd_and_store_for_creds(context, auth_context, inbuf, ticket, ccache)
    krb5_context context;
    krb5_auth_context auth_context;
    krb5_data *inbuf;
    krb5_ticket *ticket;
    krb5_ccache *ccache;
{
    krb5_creds ** creds;
    krb5_error_code retval;
    char ccname[35];

    *ccache  = NULL;

    retval = krb5_rd_cred(context, auth_context, inbuf, &creds, NULL);
    if (retval) 
	return(retval);

    /* Set the KRB5CCNAME ENV variable to keep sessions 
     * seperate. Use the process id of this process which is 
     * the rlogind or rshd. Set the environment variable as well.
     */
  
    sprintf(ccname, "FILE:/tmp/krb5cc_p%ld", (long) getpid());
    setenv("KRB5CCNAME", ccname, 1);
  
    retval = krb5_cc_resolve(context, ccname, ccache);
    if (retval) 
	goto cleanup;

    retval = krb5_cc_initialize(context, *ccache, ticket->enc_part2->client);
    if (retval)
	goto cleanup;

    retval = krb5_cc_store_cred(context, *ccache, *creds);
    if (retval) 
	goto cleanup;

cleanup:
    krb5_free_creds(context, *creds);
    return retval;
}

#endif /* KERBEROS */
