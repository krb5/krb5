/*
 * lib/krb5/os/hostaddr.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * This routine returns a list of krb5 addresses given a hostname.
 *
 */

#define NEED_SOCKETS
#include "k5-int.h"

krb5_error_code
krb5_os_hostaddr(context, name, ret_addrs)
    krb5_context context;
    const char *name;
    krb5_address ***ret_addrs;
{
    krb5_error_code 	retval;
    struct hostent 	*hp;
    krb5_address 	**addrs;
    int			i;

    if (!name || !(hp = gethostbyname(name)))
      return KRB5_ERR_BAD_HOSTNAME;

    /* Count elements */
    for(i=0; hp->h_addr_list[i]; i++);

    addrs = (krb5_address **) malloc ((i+1)*sizeof(*addrs));
    if (!addrs)
	return ENOMEM;

    memset(addrs, 0, (i+1)*sizeof(*addrs));
    
    for(i=0; hp->h_addr_list[i]; i++) {
	addrs[i] = (krb5_address *) malloc(sizeof(krb5_address));
	if (!addrs[i]) {
	    retval = ENOMEM;
	    goto errout;
	}
	addrs[i]->magic = KV5M_ADDRESS;
	addrs[i]->addrtype = hp->h_addrtype;
	addrs[i]->length   = hp->h_length;
	addrs[i]->contents = (unsigned char *)malloc(addrs[i]->length);
	if (!addrs[i]->contents) {
	    retval = ENOMEM;
	    goto errout;
	}
	memcpy ((char *)addrs[i]->contents, hp->h_addr_list[i],
		addrs[i]->length);
    }
    addrs[i] = 0;

    *ret_addrs = addrs;
    return 0;

errout:
    if (addrs)
	krb5_free_addresses(context, addrs);
    return retval;
	
}

