/*
 * lib/krb425/rd_req.c
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
 * krb_rd_req for krb425
 */


#include "krb425.h"
#include <sys/param.h>

static krb5_error_code
setkey_key_proc(DECLARG(krb5_pointer,arg),
		DECLARG(krb5_principal,princ),
		DECLARG(krb5_kvno,kvno),
		DECLARG(krb5_keyblock **,retkey))
OLDDECLARG(krb5_pointer,arg)
OLDDECLARG(krb5_principal,princ)
OLDDECLARG(krb5_kvno,kvno)
OLDDECLARG(krb5_keyblock **,retkey)
{
    return krb5_copy_keyblock(&_krb425_servkey, retkey);
}

int
krb_rd_req(authent, service, instance, from_addr, ad, fn)
KTEXT authent;
char *service;
char *instance;
u_long from_addr;
AUTH_DAT *ad;
char *fn;
{
	krb5_address peer;
	krb5_tkt_authent *authdat;
	char addr[4];
	krb5_principal server;
	krb5_error_code r;
	krb5_data authe;
	extern int gethostname();
	int use_set_key = 0;
	char file_name[MAXPATHLEN];

	if (from_addr) {
		peer.addrtype = ADDRTYPE_INET;
		peer.length = 4;
		peer.contents = (krb5_octet *)addr;
		memcpy(addr, (char *)&from_addr + (sizeof(from_addr) - 4), 4);
	}

	if (!_krb425_local_realm)
		if (r = krb5_get_default_realm(&_krb425_local_realm))
			return(krb425error(r));

	if (!strcmp(instance, "*")) {
		static char hostname[64] = { 0 };

		if (!hostname[0]) {
			struct hostent *h;
	
			gethostname(hostname, sizeof(hostname));
			if (h = gethostbyname(hostname)) {
				char *p;

				strncpy(hostname, h->h_name, sizeof(hostname));
				hostname[sizeof(hostname)-1] = 0;
				p = hostname;
				do {
					if (isupper(*p)) *p=tolower(*p);
				} while (*p++);
			}
		}
		instance = hostname;
	}
	if (r = krb5_build_principal(&server,
				     strlen(_krb425_local_realm),
				     _krb425_local_realm,
				     service,
				     instance,
				     0)) {
	    return(krb425error(r));
	}
	
	authe.length = authent->length;
	authe.data = (char *)authent->dat;
	if (!fn) {
	    use_set_key = 1;
	    fn = (char *)0;
	} else if (!*fn) {
	    fn = (char *)0;
	} else {
	    strcpy(file_name, "FILE:");
	    strncpy(file_name + 5, fn, MAXPATHLEN-5);
	    file_name[sizeof(file_name)-1] = '\0';
	    fn = file_name;
	}
	    

#ifdef  EBUG
        EPRINT "Calling krb5_rd_req with:\n");
        EPRINT "        Realm   : "); show5(srvdata[0]); ENEWLINE
        EPRINT "        Service : "); show5(srvdata[1]); ENEWLINE
        EPRINT "        Instance: "); show5(srvdata[2]); ENEWLINE
	EPRINT "Authenenticator : %d bytes\n", authe.length);
	EPRINT "Filename        : %s\n", fn ? fn : "none given");
	if (from_addr) {
		EPRINT "Address type    : %s\n",
			peer.addrtype == ADDRTYPE_INET ? "inet" :
			peer.addrtype == ADDRTYPE_CHAOS ? "chaos" :
			peer.addrtype == ADDRTYPE_XNS ? "xns" :
			peer.addrtype == ADDRTYPE_ISO ? "iso" :
			peer.addrtype == ADDRTYPE_DDP ? "ddp" : "unknown type");
		EPRINT "Address length  : %d\n", peer.length);
		EPRINT "Address         :");
		{
			int x;
			for (x = 0; x < peer.length && x < 8; ++x)
				fprintf(stderr, " %d", peer.contents[x]);
			if (x < peer.length)
				fprintf(stderr, " (%d)", peer.length);
			fprintf(stderr, "\n");
		}
	}
#endif

/* ? : will break some compilers when dealing with function pointers */
	if (use_set_key)
		r = krb5_rd_req(&authe,
				server,
				from_addr ? &peer : 0,
				fn, setkey_key_proc,
				0, 0, &authdat);
	else
		r = krb5_rd_req(&authe,
				server,
				from_addr ? &peer : 0,
				fn, 0,
				0, 0, &authdat);
	krb5_free_principal(server);
	if (r) {
#ifdef	EBUG
		ERROR(r)
#endif
		return(krb425error(r));
	}

	ad->k_flags = 0;

#ifdef	EBUG
	r = 0;
	while (authdat->authenticator->client[r]) {
		EPRINT "Client[%d]: ", r); show5((*authdat->authenticator->client[r])); ENEWLINE
		++r;
	}
	r = 0;
	while (authdat->ticket->server[r]) {
		EPRINT "Server[%d]: ", r); show5((*authdat->ticket->server[r])); ENEWLINE
		++r;
	}
	r = 0;
#endif
	set_string(ad->pname, ANAME_SZ,
		   krb5_princ_component(authdat->authenticator->client, 0));

	if (authdat->authenticator->client->length > 1) {
     		set_string(ad->pinst, INST_SZ,
			   krb5_princ_component(authdat->authenticator->client,
						1));
	}
	else {
		ad->pinst[0] = '\0';
	}

	set_string(ad->prealm, REALM_SZ,
		   krb5_princ_realm(authdat->authenticator->client));
  
	ad->checksum = *(long *)authdat->authenticator->checksum->contents;

	if (authdat->ticket->enc_part2->session->enctype != ENCTYPE_DES) {
		r = KFAILURE;
		goto out;
	} else
		memcpy((char*)ad->session,
		       (char*)authdat->ticket->enc_part2->session->contents,
		       sizeof(C_Block));

	ad->life = authdat->ticket->enc_part2->times.endtime;
	ad->time_sec = authdat->authenticator->ctime;
	ad->address = 0;

	if (authdat->ticket->enc_part2->caddrs[0]->addrtype != ADDRTYPE_INET) {
		r = KFAILURE;
		goto out;
	} else
		memcpy((char*)&ad->address + sizeof(ad->address) - 4,
		       (char*)authdat->ticket->enc_part2->caddrs[0]->contents, 4);

	if (authdat->ticket->enc_part2->authorization_data &&
	    authdat->ticket->enc_part2->authorization_data[0]) {
		ad->reply.length = authdat->ticket->enc_part2->authorization_data[0]->length;
		memcpy((char*)ad->reply.dat,
		       (char*)authdat->ticket->enc_part2->authorization_data[0]->contents,
		       min(ad->reply.length, MAX_KTXT_LEN));
		ad->reply.mbz = 0;
	}
out:
	krb5_free_tkt_authent(authdat);
	return(r);
}
