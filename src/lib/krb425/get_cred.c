/*
 * lib/krb425/get_cred.c
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
 *
 * krb_get_cred for krb425
 */


#include "krb425.h"

int
krb_get_cred(service, instance, realm, c)
char *service;
char *instance;
char *realm;
CREDENTIALS *c;
{
	static krb5_principal client_principal = 0;

	krb5_creds creds;
	krb5_error_code r;
	krb5_ticket *ticket;

	memset((char *)&creds, 0, sizeof(creds));
	if (r = krb5_build_principal(&creds.server,
				     strlen(realm), realm,
				     service,
				     instance,
				     0)) {
	    return(krb425error(r));
	}

	if (!_krb425_ccache)
		krb5_cc_default(&_krb425_ccache);
	if (!client_principal)
		krb5_cc_get_principal(_krb425_ccache, &client_principal);

	creds.client = client_principal;
	creds.times.endtime = 0;
	creds.keyblock.enctype = ENCTYPE_DES;

	r = krb5_get_credentials(0, _krb425_ccache, &creds);
	if (r)
	    return(krb425error(r));
	
#ifdef	EBUG
	{
		int i;
		i = 0;
		if (creds.server)
			while (creds.server[i]) {
				EPRINT("server: %d: ``%.*s''\n", i,
					creds.server[i]->length,
					creds.server[i]->data
						? creds.server[i]->data : "");
				++i;
			}
		i = 0;
		if (creds.client)
			while (creds.client[i]) {
				EPRINT("client: %d: ``%.*s''\n", i,
					creds.client[i]->length,
					creds.client[i]->data
						? creds.client[i]->data : "");
				++i;
			}
	}
#endif
	set_string(c->pname, ANAME_SZ, krb5_princ_component(creds.client, 0));
	if (creds.client->length > 1) {
	  set_string(c->pinst, INST_SZ, krb5_princ_component(creds.client, 1));
	}
	else {
	  c->pinst[0] = '\0';
	}
	set_string(c->realm, REALM_SZ, krb5_princ_realm(creds.server));
	set_string(c->service, ANAME_SZ, krb5_princ_component(creds.server, 0));
	set_string(c->instance, INST_SZ, krb5_princ_component(creds.server, 1));

	c->ticket_st.length = creds.ticket.length;
	memcpy((char *)c->ticket_st.dat,
	       (char *)creds.ticket.data,
	       min(c->ticket_st.length, MAX_KTXT_LEN));
	c->ticket_st.mbz = 0;

	memcpy((char*)c->session, (char *)creds.keyblock.contents,
	       sizeof(C_Block));

	c->issue_date = creds.times.starttime;
	c->lifetime = creds.times.endtime;

	decode_krb5_ticket(&creds.ticket, &ticket);
	c->kvno = ticket->enc_part.kvno;
	krb5_free_ticket(ticket);
	return(KSUCCESS);
}
