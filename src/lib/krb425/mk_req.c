/*
 * $Source$
 * $Author$
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
 * krb_mk_req for krb425
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_mk_req_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include "krb425.h"

int
krb_mk_req(authent, service, instance, realm, checksum)
KTEXT authent;
char *service;
char *instance;
char *realm;
u_long checksum;
{
	krb5_principal server;
	krb5_error_code r;
	krb5_data outbuf;
	krb5_checksum ck;

	if (r = krb5_build_principal(&server,
				     strlen(realm), realm,
				     service,
				     instance,
				     0)) {
	    return(krb425error(r));
	}

	if (!_krb425_ccache)
		krb5_cc_default(&_krb425_ccache);

#ifdef	EBUG
	EPRINT "Calling krb5_mk_req with:\n");
	EPRINT "	Realm   : "); show5(srvdata[0]); ENEWLINE
	EPRINT "	Service : "); show5(srvdata[1]); ENEWLINE
	EPRINT "	Instance: "); show5(srvdata[2]); ENEWLINE
	EPRINT "	CheckSum: %08x\n", checksum);
#endif
	set_cksum(ck, checksum)
	
	r = krb5_mk_req((krb5_principal)server,
			(krb5_flags)0,
			&ck,
			_krb425_ccache,
			&outbuf);
#ifdef	EBUG
	if (r)
		ERROR(r)
#endif
	krb5_free_principal(server);
	if (!r) {
		if (outbuf.length > MAX_KTXT_LEN) {
#ifdef	EBUG
			EPRINT "Return to long (%d > %d)\n",
				outbuf.length, MAX_KTXT_LEN);
#endif
			krb5_xfree(outbuf.data);
			return(KFAILURE);
		}
		authent->length = outbuf.length;
		memcpy((char *)authent->dat, (char *)outbuf.data, outbuf.length);
		krb5_xfree(outbuf.data);
	}
	return(krb425error(r));
}
