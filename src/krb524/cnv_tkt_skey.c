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
#include <sys/time.h>
#include <netinet/in.h>
#include <krb.h>
#include "krb524.h"

/* rather than copying the cmu code, these values are derived from
   a calculation based on the table and comments found there.
   the expression (in elisp) is:
   (defun cmu-to-secs2 (j)
      (if (< j 128) (* j 5 60)
         (round (* 38400 (expt 1.06914489 (- j 128))))))
   and is low by one for 16 values but is exact for the others.
 */

static long cmu_seconds[] = 
{
  38400,  41055,  43894,  46929,  50174,  53643,  57352,  61318,
  65558,  70091,  74937,  80119,  85658,  91581,  97914,  104684,
  111922,  119661,  127935,  136781,  146239,  156350,  167161,  178720,
  191077,  204289,  218415,  233517,  249663,  266926,  285383,  305116,
  326213,  348769,  372885,  398668,  426233,  455705,  487215,  520903,
  556921,  595430,  636600,  680618,  727679,  777995,  831789,  889303,
  950794,  1016536,  1086825,  1161973,  1242317,  1328217,  1420057,  1518246,
  1623225,  1735463,  1855462,  1983757,  2120924,  2267575,  2424366, 2591999,
  0
};

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
     char sname[ANAME_SZ], sinst[INST_SZ];
     krb5_enc_tkt_part *v5etkt;
     int ret, lifetime, deltatime;
     krb5_timestamp server_time;
     struct sockaddr_in *sinp = (struct sockaddr_in *)saddr;
     krb5_address kaddr;

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
     /* rather than apply fit an extended v5 lifetime into a v4 range,
	give out a v4 ticket with as much of the v5 lifetime is available
	"now" instead. */
     if ((ret = krb5_timeofday(context, &server_time))) {
         if (krb524_debug)
	      fprintf(stderr, "krb5_timeofday failed!\n");
	 krb5_free_enc_tkt_part(context, v5etkt);
	 v5tkt->enc_part2 = NULL;
	 return ret;       
     }
     if (   (server_time+context->clockskew >= v5etkt->times.starttime)
	 && (server_time-context->clockskew <= v5etkt->times.endtime)) {
          deltatime = v5etkt->times.endtime - (server_time-context->clockskew);
	  lifetime = deltatime / 300;
	  /* if (lifetime > 255) lifetime = 255; */
	  if (lifetime > 127) {
	      /* use the CMU algorithm instead: */
	      long *clist = cmu_seconds;
	      while(*clist && *clist < deltatime) clist++;
	      lifetime = 128 + (clist - cmu_seconds);
	  }
     } else {
          if (krb524_debug)
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
     if (v4_skey->enctype == ENCTYPE_DES_CBC_CRC) {
	 ret = krb_create_ticket(v4tkt,
				 0, /* flags */			     
				 pname,
				 pinst,
				 prealm,
				 *((unsigned long *)kaddr.contents),
				 (char *) v5etkt->session->contents,
				 lifetime,
				 /* issue_data */
				 server_time,
				 sname,
				 sinst,
				 v4_skey->contents);
     } else {
	 /* Force enctype to be raw if using DES3. */
	 if (v4_skey->enctype == ENCTYPE_DES3_CBC_SHA1 ||
	     v4_skey->enctype == ENCTYPE_LOCAL_DES3_HMAC_SHA1)
	     v4_skey->enctype = ENCTYPE_DES3_CBC_RAW;
	 ret = krb_cr_tkt_krb5(v4tkt,
			       0, /* flags */			     
			       pname,
			       pinst,
			       prealm,
			       *((unsigned long *)kaddr.contents),
			       (char *) v5etkt->session->contents,
			       lifetime,
			       /* issue_data */
			       server_time,
			       sname,
			       sinst,
			       v4_skey);
     }

     krb5_free_enc_tkt_part(context, v5etkt);
     v5tkt->enc_part2 = NULL;
     if (ret == KSUCCESS)
	  return 0;
     else
	  return KRB524_V4ERR;
}
