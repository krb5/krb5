/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * krb_get_cred for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_get_cred_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include "krb425.h"

int
krb_get_cred(service, instance, realm, c)
char *service;
char *instance;
char *realm;
CREDENTIALS *c;
{
	static krb5_principal client_principal = { 0 };

	krb5_creds creds;
	krb5_data *server[4];
	krb5_data srvdata[3];
	krb5_error_code r;
	krb5_ticket *ticket;

	set_data5(srvdata[0], realm);
	set_data5(srvdata[1], service);
	set_data5(srvdata[2], instance);

	server[0] = &srvdata[0];
	server[1] = &srvdata[1];
	server[2] = &srvdata[2];
	server[3] = 0;

	if (!_krb425_ccache)
		krb5_cc_default(&_krb425_ccache);
	if (!client_principal)
		krb5_cc_get_principal(_krb425_ccache, &client_principal);

	creds.client = client_principal;
	creds.server = server;
	creds.times.endtime = 0;
	creds.keyblock.keytype = KEYTYPE_DES;

	if (r = krb5_get_credentials(0, _krb425_ccache, &creds))
		return(krb425error(r));
	
#ifdef	EBUG
	{
		int i;
		i = 0;
		if (creds.server)
			while (creds.server[i]) {
				EPRINT "server: %d: ``%.*s''\n", i,
					creds.server[i]->length,
					creds.server[i]->data
						? creds.server[i]->data : "");
				++i;
			}
		i = 0;
		if (creds.client)
			while (creds.client[i]) {
				EPRINT "client: %d: ``%.*s''\n", i,
					creds.client[i]->length,
					creds.client[i]->data
						? creds.client[i]->data : "");
				++i;
			}
	}
#endif
	set_string(c->pname, ANAME_SZ, creds.client[1]);
	set_string(c->pinst, INST_SZ, creds.client[2]);
	
	set_string(c->realm, REALM_SZ, creds.server[0]);
	set_string(c->service, REALM_SZ, creds.server[1]);
	set_string(c->instance, REALM_SZ, creds.server[2]);

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
