/*
 * Copyright 1993 by Geer Zolot Associates.  All Rights Reserved.
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.  It
 * is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Geer Zolot Associates not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  Geer Zolot Associates makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 */

#if !defined(lint) && !defined(SABER)
static char rcs_id[] = "$Id$";
#endif

#include <stdio.h>
#include <krb5/krb5.h>
#include <krb.h>

#include "krb524.h"

/*
 * Convert a v5 ticket for server to a v4 ticket, using service key
 * skey for both.
 */
int krb524_convert_tkt_skey(krb5_ticket *v5tkt, KTEXT_ST *v4tkt,
			    krb5_keyblock *skey)
{
     char pname[ANAME_SZ], pinst[INST_SZ], prealm[REALM_SZ];
     char sname[ANAME_SZ], sinst[INST_SZ];
     krb5_enc_tkt_part *v5etkt;
     krb5_data *comp;
     int ret, lifetime;

     v5tkt->enc_part2 = NULL;
     if (ret = krb5_decrypt_tkt_part(skey, v5tkt)) {
	  krb5_free_ticket(v5tkt);
	  return ret;
     }
     v5etkt = v5tkt->enc_part2;

     if (ret = krb524_convert_princs(v5etkt->client, v5tkt->server,
				     pname, pinst, prealm, sname,
				     sinst)) {
	  krb5_free_enc_tkt_part(v5etkt);
	  v5tkt->enc_part2 = NULL;
	  return ret;
     }
     
     if (v5etkt->session->keytype != KEYTYPE_DES ||
	 v5etkt->session->length != sizeof(C_Block)) {
	  if (krb524_debug)
	       fprintf(stderr, "v5 session keyblock type %d length %d != "
		       "C_Block size %d\n", v5etkt->session->keytype,
		       v5etkt->session->length,
		       sizeof(C_Block));
	  krb5_free_enc_tkt_part(v5etkt);
	  v5tkt->enc_part2 = NULL;
	  return KRB524_BADKEY;
     }
     
     /* V4 has no concept of authtime or renew_till, so ignore them */
     /* V4 lifetime is 1 byte, in 5 minute increments */
     if (v5etkt->times.starttime == 0)
	  v5etkt->times.starttime = v5etkt->times.authtime;
     lifetime = 0xff &
	  ((v5etkt->times.endtime - v5etkt->times.authtime) / 300);

     /* XXX perhaps we should use the addr of the client host if */
     /* v5creds contains more than one addr.  Q: Does V4 support */
     /* non-INET addresses? */
     if (!v5etkt->caddrs || !v5etkt->caddrs[0] ||
	 v5etkt->caddrs[0]->addrtype != ADDRTYPE_INET) {
	  if (krb524_debug)
	       fprintf(stderr, "Invalid v5creds address information.\n");
	  krb5_free_enc_tkt_part(v5etkt);
	  v5tkt->enc_part2 = NULL;
	  return KRB524_BADADDR;
     }
     
     if (krb524_debug)
	printf("startime = %ld, authtime = %ld, lifetime = %ld\n",
	       (long) v5etkt->times.starttime,
	       (long) v5etkt->times.authtime,
	       (long) lifetime);

     /* XXX are there V5 flags we should map to V4 equivalents? */
     ret = krb_create_ticket(v4tkt,
			     0, /* flags */			     
			     pname,
			     pinst,
			     krb5_princ_realm(v5etkt->client),
			     *((unsigned long *)v5etkt->caddrs[0]->contents),
			     v5etkt->session->contents,
			     lifetime,
			     /* issue_data */
			     v5etkt->times.starttime,
			     sname,
			     sinst,
			     skey->contents);

     krb5_free_enc_tkt_part(v5etkt);
     v5tkt->enc_part2 = NULL;
     if (ret == KSUCCESS)
	  return 0;
     else
	  return KRB524_V4ERR;
}
