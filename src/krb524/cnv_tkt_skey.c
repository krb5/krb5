/*
 * Copyright 2003  by the Massachusetts Institute of Technology.
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
 * permission.	Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

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

#include "k5-int.h"		/* we need krb5_context::clockskew */
#include <stdio.h>
#include <sys/types.h>

#ifdef _WIN32
#include "port-sockets.h"
#else
#include <sys/time.h>
#include <netinet/in.h>
#endif
#include <krb.h>
#include "krb524d.h"

static int krb524d_debug = 0;

/*
 * Convert a v5 ticket for server to a v4 ticket, using service key
 * skey for both.
 */
int krb524_convert_tkt_skey(context, v5tkt, v4tkt, v5_skey, v4_skey,
			    saddr)
     krb5_context context;
     krb5_ticket *v5tkt;
     KTEXT_ST *v4tkt;
     krb5_keyblock *v5_skey, *v4_skey;
     struct sockaddr_in *saddr;
{
     char pname[ANAME_SZ], pinst[INST_SZ], prealm[REALM_SZ];
     char sname[ANAME_SZ], sinst[INST_SZ], srealm[REALM_SZ];
     krb5_enc_tkt_part *v5etkt;
     int ret, lifetime, v4endtime;
     krb5_timestamp server_time;
     struct sockaddr_in *sinp = (struct sockaddr_in *)saddr;
     krb5_address kaddr;

     v5tkt->enc_part2 = NULL;
     if ((ret = krb5_decrypt_tkt_part(context, v5_skey, v5tkt))) {
	  return ret;
     }
     v5etkt = v5tkt->enc_part2;

     if (v5etkt->transited.tr_contents.length != 0) {
	 /* Some intermediate realms transited -- do we accept them?

	    Simple answer: No.

	    More complicated answer: Check our local config file to
	    see if the path is correct, and base the answer on that.
	    This denies the krb4 application server any ability to do
	    its own validation as krb5 servers can.

	    Fast answer: Not right now.  */
	  krb5_free_enc_tkt_part(context, v5etkt);
	  v5tkt->enc_part2 = NULL;
	  return KRB5KRB_AP_ERR_ILL_CR_TKT;
     }
     /* We could also encounter a case where luser@R1 gets a ticket
	for krbtgt/R3@R2, and then tries to convert it.  But the
	converted ticket would be one the v4 KDC code should reject
	anyways.  So we don't need to worry about it here.  */

     if ((ret = krb524_convert_princs(context, v5etkt->client, v5tkt->server,
				     pname, pinst, prealm, sname,
				     sinst, srealm))) {
	  krb5_free_enc_tkt_part(context, v5etkt);
	  v5tkt->enc_part2 = NULL;
	  return ret;
     }
     if ((v5etkt->session->enctype != ENCTYPE_DES_CBC_CRC &&
	  v5etkt->session->enctype != ENCTYPE_DES_CBC_MD4 &&
	  v5etkt->session->enctype != ENCTYPE_DES_CBC_MD5) ||
	 v5etkt->session->length != sizeof(C_Block)) {
	  if (krb524d_debug)
	       fprintf(stderr, "v5 session keyblock type %d length %d != C_Block size %d\n",
		       v5etkt->session->enctype,
		       v5etkt->session->length,
		       (int) sizeof(C_Block));
	  krb5_free_enc_tkt_part(context, v5etkt);
	  v5tkt->enc_part2 = NULL;
	  return KRB524_BADKEY;
     }
     
     /* V4 has no concept of authtime or renew_till, so ignore them */
     if (v5etkt->times.starttime == 0)
	  v5etkt->times.starttime = v5etkt->times.authtime;
     /* rather than apply fit an extended v5 lifetime into a v4 range,
	give out a v4 ticket with as much of the v5 lifetime is available
	"now" instead. */
     if ((ret = krb5_timeofday(context, &server_time))) {
         if (krb524d_debug)
	      fprintf(stderr, "krb5_timeofday failed!\n");
	 krb5_free_enc_tkt_part(context, v5etkt);
	 v5tkt->enc_part2 = NULL;
	 return ret;       
     }
     if ((server_time + context->clockskew >= v5etkt->times.starttime)
	 && (server_time - context->clockskew <= v5etkt->times.endtime)) {
	  lifetime = krb_time_to_life(server_time, v5etkt->times.endtime);
	  v4endtime = krb_life_to_time(server_time, lifetime);
	  /*
	   * Adjust start time backwards if the lifetime value
	   * returned by krb_time_to_life() maps to a longer lifetime
	   * than that of the original krb5 ticket.
	   */
	  if (v4endtime > v5etkt->times.endtime)
	      server_time -= v4endtime - v5etkt->times.endtime;
     } else {
          if (krb524d_debug)
	       fprintf(stderr, "v5 ticket time out of bounds\n");
	  krb5_free_enc_tkt_part(context, v5etkt);
	  v5tkt->enc_part2 = NULL;
	  if (server_time+context->clockskew < v5etkt->times.starttime)
	       return KRB5KRB_AP_ERR_TKT_NYV;
	  else if (server_time-context->clockskew > v5etkt->times.endtime)
	       return KRB5KRB_AP_ERR_TKT_EXPIRED;
	  else /* shouldn't happen, but just in case... */
	    return KRB5KRB_AP_ERR_TKT_NYV;
     }

     kaddr.addrtype = ADDRTYPE_INET;
     kaddr.length = sizeof(sinp->sin_addr);
     kaddr.contents = (krb5_octet *)&sinp->sin_addr;

     if (!krb5_address_search(context, &kaddr, v5etkt->caddrs)) {
	 if (krb524d_debug)
	     fprintf(stderr, "Invalid v5creds address information.\n");
	 krb5_free_enc_tkt_part(context, v5etkt);
	 v5tkt->enc_part2 = NULL;
	 return KRB524_BADADDR;
     }

     if (krb524d_debug)
	printf("startime = %ld, authtime = %ld, lifetime = %ld\n",
	       (long) v5etkt->times.starttime,
	       (long) v5etkt->times.authtime,
	       (long) lifetime);

     /* XXX are there V5 flags we should map to V4 equivalents? */
     if (v4_skey->enctype == ENCTYPE_DES_CBC_CRC) {
	 ret = krb_create_ticket(v4tkt,
				 0, /* flags */			     
				 pname,
				 pinst,
				 prealm,
				 sinp->sin_addr.s_addr,
				 (char *) v5etkt->session->contents,
				 lifetime,
				 /* issue_data */
				 server_time,
				 sname,
				 sinst,
				 v4_skey->contents);
     }
     else abort();
     krb5_free_enc_tkt_part(context, v5etkt);
     v5tkt->enc_part2 = NULL;
     if (ret == KSUCCESS)
	  return 0;
     else
	  return KRB524_V4ERR;
}
