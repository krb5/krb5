
/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "krb5.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <krb.h>
#include <krb4-proto.h>
#include "krb524.h"

/*
 * Convert a v5 ticket for server to a v4 ticket, using service key
 * skey for both.
 */
int krb524_convert_tkt_skey(context, v5tkt, v4tkt, v5_skey, v4_skey)
     krb5_context context;
     krb5_ticket *v5tkt;
     KTEXT_ST *v4tkt;
     krb5_keyblock *v5_skey, *v4_skey;
{
     char pname[ANAME_SZ], pinst[INST_SZ], prealm[REALM_SZ];
     char sname[ANAME_SZ], sinst[INST_SZ];
     krb5_enc_tkt_part *v5etkt;
     int ret, lifetime;

     v5tkt->enc_part2 = NULL;
     if ((ret = krb5_decrypt_tkt_part(context, v5_skey, v5tkt))) {
	  krb5_free_ticket(context, v5tkt);
	  return ret;
     }
     v5etkt = v5tkt->enc_part2;

     if ((ret = krb524_convert_princs(context, v5etkt->client, v5tkt->server,
				     pname, pinst, prealm, sname,
				     sinst))) {
	  krb5_free_enc_tkt_part(context, v5etkt);
	  v5tkt->enc_part2 = NULL;
	  return ret;
     }
     
     if (v5etkt->session->enctype != ENCTYPE_DES_CBC_CRC ||
	 v5etkt->session->length != sizeof(C_Block)) {
	  if (krb524_debug)
	       fprintf(stderr, "v5 session keyblock type %d length %d != C_Block size %d\n",
		       v5etkt->session->enctype,
		       v5etkt->session->length,
		       sizeof(C_Block));
	  krb5_free_enc_tkt_part(context, v5etkt);
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
	  krb5_free_enc_tkt_part(context, v5etkt);
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
			     prealm,
			     *((unsigned long *)v5etkt->caddrs[0]->contents),
			     (char *) v5etkt->session->contents,
			     lifetime,
			     /* issue_data */
			     v5etkt->times.starttime,
			     sname,
			     sinst,
			     v4_skey->contents);

     krb5_free_enc_tkt_part(context, v5etkt);
     v5tkt->enc_part2 = NULL;
     if (ret == KSUCCESS)
	  return 0;
     else
	  return KRB524_V4ERR;
}
