/*
 *	appl/telnet/libtelnet/kerberos5.c
 */

/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* based on @(#)kerberos5.c	8.1 (Berkeley) 6/4/93 */

/*
 * Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */


#ifdef	KRB5
#include <arpa/telnet.h>
#include <errno.h>
#include <stdio.h>
#include "krb5.h"

#include "com_err.h"
#include <netdb.h>
#include <ctype.h>
#include <syslog.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif
#ifdef	HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
 
#include "encrypt.h"
#include "auth.h"
#include "misc.h"

extern int auth_debug_mode;
extern int net;

#ifdef	FORWARD
int forward_flags = 0;  /* Flags get set in telnet/main.c on -f and -F */

static void kerberos5_forward(Authenticator *);

#include "krb5forw.h"

#endif	/* FORWARD */

static unsigned char str_data[8192] = {IAC, SB, TELOPT_AUTHENTICATION, 0,
			  		AUTHTYPE_KERBEROS_V5, };
/*static unsigned char str_name[1024] = { IAC, SB, TELOPT_AUTHENTICATION,
					TELQUAL_NAME, };*/

#define	KRB_AUTH		0	/* Authentication data follows */
#define	KRB_REJECT		1	/* Rejected (reason might follow) */
#define	KRB_ACCEPT		2	/* Accepted */
#define	KRB_RESPONSE		3	/* Response for mutual auth. */

#ifdef	FORWARD
#define KRB_FORWARD     	4       /* Forwarded credentials follow */
#define KRB_FORWARD_ACCEPT     	5       /* Forwarded credentials accepted */
#define KRB_FORWARD_REJECT     	6       /* Forwarded credentials rejected */
#endif	/* FORWARD */

krb5_auth_context auth_context = 0;

static	krb5_data auth;
	/* telnetd gets session key from here */
static	krb5_ticket * ticket = NULL;
/* telnet matches the AP_REQ and AP_REP with this */

/* some compilers can't hack void *, so we use the Kerberos krb5_pointer,
   which is either void * or char *, depending on the compiler. */

#define Voidptr krb5_pointer

krb5_keyblock	*session_key = 0;
char *		telnet_srvtab = NULL;
char *		telnet_krb5_realm = NULL;

	static int
Data(ap, type, d, c)
	Authenticator *ap;
	int type;
	Voidptr d;
	int c;
{
        unsigned char *p = str_data + 4;
	unsigned char *cd = (unsigned char *)d;
	size_t spaceleft = sizeof(str_data) - 4;

	if (c == -1)
		c = strlen((char *)cd);

        if (auth_debug_mode) {
                printf("%s:%d: [%d] (%d)",
                        str_data[3] == TELQUAL_IS ? ">>>IS" : ">>>REPLY",
                        str_data[3],
                        type, c);
                printd(d, c);
                printf("\r\n");
        }
	*p++ = ap->type;
	*p++ = ap->way;
	*p++ = type;
	spaceleft -= 3;
        while (c-- > 0) {
		if ((*p++ = *cd++) == IAC) {
			*p++ = IAC;
			spaceleft--;
		}
		if ((--spaceleft < 4) && c) {
			errno = ENOMEM;
			return -1;
		}
        }
        *p++ = IAC;
        *p++ = SE;
	if (str_data[3] == TELQUAL_IS)
		printsub('>', &str_data[2], p - &str_data[2]);
        return(net_write(str_data, p - str_data));
}

krb5_context telnet_context = 0;
int
kerberos5_init(ap, server)
	Authenticator *ap;
	int server;
{
	krb5_error_code retval;
	
	if (server)
		str_data[3] = TELQUAL_REPLY;
	else
		str_data[3] = TELQUAL_IS;
	if (telnet_context == 0) {
		retval = krb5_init_context(&telnet_context);
		if (retval)
			return 0;
	}
	return(1);
}

void
kerberos5_cleanup()
{
    krb5_error_code retval;
    krb5_ccache ccache;
    char *ccname;
    
    if (telnet_context == 0)
	return;

    ccname = getenv("KRB5CCNAME");
    if (ccname) {
	retval = krb5_cc_resolve(telnet_context, ccname, &ccache);
	if (!retval)
	    retval = krb5_cc_destroy(telnet_context, ccache);
    }

    krb5_free_context(telnet_context);
    telnet_context = 0;
}


	int
kerberos5_send(ap)
	Authenticator *ap;
{
	krb5_error_code r;
	krb5_ccache ccache;
	krb5_creds creds;		/* telnet gets session key from here */
	krb5_creds * new_creds = 0;
	int ap_opts;
	char type_check[2];
	krb5_data check_data;

#ifdef	ENCRYPTION
	krb5_keyblock *newkey = 0;
#endif	/* ENCRYPTION */

        if (!UserNameRequested) {
                if (auth_debug_mode) {
                        printf(
			"telnet: Kerberos V5: no user name supplied\r\n");
                }
                return(0);
        }

	if ((r = krb5_cc_default(telnet_context, &ccache))) {
		if (auth_debug_mode) {
		    printf(
		    "telnet: Kerberos V5: could not get default ccache\r\n");
		}
		return(0);
	}

	memset((char *)&creds, 0, sizeof(creds));
	if ((r = krb5_sname_to_principal(telnet_context, RemoteHostName,
					 "host", KRB5_NT_SRV_HST,
					 &creds.server))) {
	    if (auth_debug_mode)
		printf("telnet: Kerberos V5: error while constructing service name: %s\r\n", error_message(r));
	    return(0);
	}

	if (telnet_krb5_realm != NULL) {
	    krb5_data rdata;

	    rdata.length = strlen(telnet_krb5_realm);
	    rdata.data = (char *) malloc(rdata.length + 1);
	    if (rdata.data == NULL) {
	        fprintf(stderr, "malloc failed\n");
		return(0);
	    }
	    strcpy(rdata.data, telnet_krb5_realm);
	    krb5_princ_set_realm(telnet_context, creds.server, &rdata);
	}

	if ((r = krb5_cc_get_principal(telnet_context, ccache,
				       &creds.client))) {
		if (auth_debug_mode) {
			printf(
			"telnet: Kerberos V5: failure on principal (%s)\r\n",
				error_message(r));
		}
		krb5_free_cred_contents(telnet_context, &creds);
		return(0);
	}

	creds.keyblock.enctype=ENCTYPE_DES_CBC_CRC;
	if ((r = krb5_get_credentials(telnet_context, 0,
				      ccache, &creds, &new_creds))) {
		if (auth_debug_mode) {
			printf(
			"telnet: Kerberos V5: failure on credentials(%s)\r\n",
			       error_message(r));
		}
		krb5_free_cred_contents(telnet_context, &creds);
		return(0);
	}

	if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL)
	    ap_opts = AP_OPTS_MUTUAL_REQUIRED;
	else
	    ap_opts = 0;

#ifdef ENCRYPTION
	ap_opts |= AP_OPTS_USE_SUBKEY;
#endif	/* ENCRYPTION */
	    
	if (auth_context) {
	    krb5_auth_con_free(telnet_context, auth_context);
	    auth_context = 0;
	}
	if ((r = krb5_auth_con_init(telnet_context, &auth_context))) {
	    if (auth_debug_mode) {
		printf("Kerberos V5: failed to init auth_context (%s)\r\n",
		       error_message(r));
	    }
	    return(0);
	}
	
	krb5_auth_con_setflags(telnet_context, auth_context,
			       KRB5_AUTH_CONTEXT_RET_TIME);
	
	type_check[0] = ap->type;
	type_check[1] = ap->way;
	check_data.magic = KV5M_DATA;
	check_data.length = 2;
	check_data.data = (char *) &type_check;

	r = krb5_mk_req_extended(telnet_context, &auth_context, ap_opts,
				 &check_data, new_creds, &auth);

#ifdef	ENCRYPTION
	krb5_auth_con_getsendsubkey(telnet_context, auth_context, &newkey);
	if (session_key) {
		krb5_free_keyblock(telnet_context, session_key);
		session_key = 0;
	}

	if (newkey) {
	    /* keep the key in our private storage, but don't use it
	       yet---see kerberos5_reply() below */
	    if ((newkey->enctype != ENCTYPE_DES_CBC_CRC) &&
		(newkey-> enctype != ENCTYPE_DES_CBC_MD5)) {
		if ((new_creds->keyblock.enctype == ENCTYPE_DES_CBC_CRC) ||
		    (new_creds->keyblock.enctype == ENCTYPE_DES_CBC_MD5))
		    /* use the session key in credentials instead */
		    krb5_copy_keyblock(telnet_context,&new_creds->keyblock,
				       &session_key);
		else
		    /* XXX ? */;
	    } else {
		krb5_copy_keyblock(telnet_context, newkey, &session_key);
	    }
	    krb5_free_keyblock(telnet_context, newkey);
	}
#endif	/* ENCRYPTION */
	krb5_free_cred_contents(telnet_context, &creds);
	krb5_free_creds(telnet_context, new_creds);
	if (r) {
		if (auth_debug_mode) {
			printf("telnet: Kerberos V5: mk_req failed (%s)\r\n",
			       error_message(r));
		}
		return(0);
	}

        if (!auth_sendname((unsigned char *) UserNameRequested, 
			   (int) strlen(UserNameRequested))) {
                if (auth_debug_mode)
                        printf("telnet: Not enough room for user name\r\n");
                return(0);
        }
	if (!Data(ap, KRB_AUTH, auth.data, auth.length)) {
		if (auth_debug_mode)
		    printf(
		    "telnet: Not enough room for authentication data\r\n");
		return(0);
	}
	if (auth_debug_mode) {
		printf("telnet: Sent Kerberos V5 credentials to server\r\n");
	}
	return(1);
}

	void
kerberos5_is(ap, data, cnt)
	Authenticator *ap;
	unsigned char *data;
	int cnt;
{
	int r = 0;
	krb5_principal server;
	krb5_keyblock *newkey = NULL;
	krb5_keytab keytabid = 0;
	krb5_data outbuf;
#ifdef ENCRYPTION
	Session_Key skey;
#endif
	char errbuf[320];
	char *name;
	char *getenv();
	krb5_data inbuf;
	krb5_authenticator *authenticator;

	if (cnt-- < 1)
		return;
	switch (*data++) {
	case KRB_AUTH:
		auth.data = (char *)data;
		auth.length = cnt;

		if (!r && !auth_context)
		    r = krb5_auth_con_init(telnet_context, &auth_context);
		if (!r) {
		    krb5_rcache rcache;
		    
		    r = krb5_auth_con_getrcache(telnet_context, auth_context,
						&rcache);
		    if (!r && !rcache) {
			r = krb5_sname_to_principal(telnet_context, 0, 0,
						    KRB5_NT_SRV_HST, &server);
			if (!r) {
			    r = krb5_get_server_rcache(telnet_context,
					krb5_princ_component(telnet_context,
							     server, 0),
						       &rcache);
			    krb5_free_principal(telnet_context, server);
			}
		    }
		    if (!r)
			r = krb5_auth_con_setrcache(telnet_context,
						    auth_context, rcache);
		}
		if (!r && telnet_srvtab)
		    r = krb5_kt_resolve(telnet_context, 
					telnet_srvtab, &keytabid);
		if (!r)
		    r = krb5_rd_req(telnet_context, &auth_context, &auth,
				    NULL, keytabid, NULL, &ticket);
		if (r) {
			(void) strcpy(errbuf, "krb5_rd_req failed: ");
			errbuf[sizeof(errbuf) - 1] = '\0';
			(void) strncat(errbuf, error_message(r), sizeof(errbuf) - 1 - strlen(errbuf));
			goto errout;
		}

		/*
		 * 256 bytes should be much larger than any reasonable
		 * first component of a service name especially since
		 * the default is of length 4.
		 */
		if (krb5_princ_size(telnet_context,ticket->server) < 1) {
		    (void) strcpy(errbuf, "malformed service name");
		    goto errout;
		}
		if (krb5_princ_component(telnet_context,ticket->server,0)->length < 256) {
		    char princ[256];
		    strncpy(princ,	
			    krb5_princ_component(telnet_context, ticket->server,0)->data,
			    krb5_princ_component(telnet_context, ticket->server,0)->length);
		    princ[krb5_princ_component(telnet_context, 
					       ticket->server,0)->length] = '\0';
		    if (strcmp("host", princ)) {
                        if(strlen(princ) < sizeof(errbuf) - 39) {
                            (void) sprintf(errbuf, "incorrect service name: \"%s\" != \"host\"",
                                           princ);
                        } else {
                            (void) sprintf(errbuf, "incorrect service name: principal != \"host\"");
                        }
			goto errout;
		    }
		} else {
		    (void) strcpy(errbuf, "service name too long");
		    goto errout;
		}

		r = krb5_auth_con_getauthenticator(telnet_context,
						   auth_context,
						   &authenticator);
		if (r) {
		    (void) strcpy(errbuf,
				  "krb5_auth_con_getauthenticator failed: ");
		    errbuf[sizeof(errbuf) - 1] = '\0';
		    (void) strncat(errbuf, error_message(r), sizeof(errbuf) - 1 - strlen(errbuf));
		    goto errout;
		}
		if ((ap->way & AUTH_ENCRYPT_MASK) == AUTH_ENCRYPT_ON &&
		    !authenticator->checksum) {
			(void) strcpy(errbuf,
				"authenticator is missing required checksum");
			goto errout;
		}
		if (authenticator->checksum) {
		    char type_check[2];
		    krb5_checksum *cksum = authenticator->checksum;
		    krb5_keyblock *key;

		    type_check[0] = ap->type;
		    type_check[1] = ap->way;

		    r = krb5_auth_con_getkey(telnet_context, auth_context,
					     &key);
		    if (r) {
			(void) strcpy(errbuf, "krb5_auth_con_getkey failed: ");
			errbuf[sizeof(errbuf) - 1] = '\0';
			(void) strncat(errbuf, error_message(r), sizeof(errbuf) - 1 - strlen(errbuf));
			goto errout;
		    }
		    r = krb5_verify_checksum(telnet_context,
					     cksum->checksum_type, cksum,
					     &type_check, 2, key->contents,
					     key->length);
		/*
		 * Note that krb5_verify_checksum() will fail if a pre-
		 * MIT Kerberos Beta 5 client is attempting to connect
		 * to this server (Beta 6 or later). There is not way to
		 * fix this without compromising encryption. It would be
		 * reasonable to add a -i option to telnetd to ignore
		 * checksums (like in klogind). Such an option is not
		 * present at this time.
		 */
		    if (r) {
			(void) strcpy(errbuf,
				      "checksum verification failed: ");
		        errbuf[sizeof(errbuf) - 1] = '\0';
			(void) strncat(errbuf, error_message(r), sizeof(errbuf) - 1 - strlen(errbuf));
			goto errout;
		    }
		    krb5_free_keyblock(telnet_context, key);
		}
		krb5_free_authenticator(telnet_context, authenticator);
		if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
		    /* do ap_rep stuff here */
		    if ((r = krb5_mk_rep(telnet_context, auth_context,
					 &outbuf))) {
			(void) strcpy(errbuf, "Make reply failed: ");
		        errbuf[sizeof(errbuf) - 1] = '\0';
			(void) strncat(errbuf, error_message(r), sizeof(errbuf) - 1 - strlen(errbuf));
			goto errout;
		    }

		    Data(ap, KRB_RESPONSE, outbuf.data, outbuf.length);
		} 
		if (krb5_unparse_name(telnet_context, 
				      ticket->enc_part2 ->client,
				      &name))
			name = 0;
		Data(ap, KRB_ACCEPT, name, name ? -1 : 0);
		if (auth_debug_mode) {
			printf(
			"telnetd: Kerberos5 identifies him as ``%s''\r\n",
							name ? name : "");
		}
                auth_finished(ap, AUTH_USER);
		
		if (name)
		    free(name);
		krb5_auth_con_getrecvsubkey(telnet_context, auth_context,
					      &newkey);
		if (session_key) {
		    krb5_free_keyblock(telnet_context, session_key);
		    session_key = 0;
		}
	    	if (newkey) {
		    krb5_copy_keyblock(telnet_context, newkey, &session_key);
		    krb5_free_keyblock(telnet_context, newkey);
		} else {
		    krb5_copy_keyblock(telnet_context,
				       ticket->enc_part2->session,
				       &session_key);
		}
		
#ifdef ENCRYPTION
		skey.type = SK_DES;
		skey.length = 8;
		skey.data = session_key->contents;
		encrypt_session_key(&skey, 1);
#endif
		break;
#ifdef	FORWARD
	case KRB_FORWARD:
		inbuf.length = cnt;
		inbuf.data = (char *)data;
		if ((r = krb5_auth_con_genaddrs(telnet_context, auth_context, 
			net, KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR)) || 
		    (r = rd_and_store_for_creds(telnet_context, auth_context,
			   &inbuf, ticket))) {

		    char kerrbuf[128];
		    
		    (void) strcpy(kerrbuf, "Read forwarded creds failed: ");
		    kerrbuf[sizeof(kerrbuf) - 1] = '\0';
		    (void) strncat(kerrbuf, error_message(r), 
			sizeof(kerrbuf) - 1 - strlen(kerrbuf));
		    Data(ap, KRB_FORWARD_REJECT, kerrbuf, -1);
		    if (auth_debug_mode)
		      printf(
			"telnetd: Could not read forwarded credentials\r\n");
		}
		else 
		  Data(ap, KRB_FORWARD_ACCEPT, 0, 0);
		  if (auth_debug_mode)
		    printf("telnetd: Forwarded credentials obtained\r\n");
		break;
#endif	/* FORWARD */
	default:
		if (auth_debug_mode)
			printf("telnetd: Unknown Kerberos option %d\r\n",
			data[-1]);
		Data(ap, KRB_REJECT, 0, 0);
		break;
	}
	return;
	
    errout:
	{
	    char eerrbuf[329];

	    strcpy(eerrbuf, "telnetd: ");
	    eerrbuf[sizeof(eerrbuf) - 1] = '\0';
	    strncat(eerrbuf, errbuf, sizeof(eerrbuf) - 1 - strlen(eerrbuf));
	    Data(ap, KRB_REJECT, eerrbuf, -1);
	}
	if (auth_debug_mode)
	    printf("telnetd: %s\r\n", errbuf);
	syslog(LOG_ERR, "%s", errbuf);
	if (auth_context) {
	    krb5_auth_con_free(telnet_context, auth_context);
	    auth_context = 0;
	}
	return;
}

	void
kerberos5_reply(ap, data, cnt)
	Authenticator *ap;
	unsigned char *data;
	int cnt;
{
#ifdef ENCRYPTION
        Session_Key skey;
#endif
	static int mutual_complete = 0;

	if (cnt-- < 1)
		return;
	switch (*data++) {
	case KRB_REJECT:
		if (cnt > 0) {
			printf("[ Kerberos V5 refuses authentication because %.*s ]\r\n",
				cnt, data);
		} else
			printf("[ Kerberos V5 refuses authentication ]\r\n");
		auth_send_retry();
		return;
	case KRB_ACCEPT:
		if (!mutual_complete) {
		    if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
			printf("[ Kerberos V5 accepted you, but didn't provide mutual authentication! ]\r\n");
			auth_send_retry();
			return;
		    }
#ifdef	ENCRYPTION
		    if (session_key) {
			skey.type = SK_DES;
			skey.length = 8;
			skey.data = session_key->contents;
			encrypt_session_key(&skey, 0);
		    }
#endif	/* ENCRYPTION */
		}
		if (cnt)
		    printf("[ Kerberos V5 accepts you as ``%.*s'' ]\r\n", cnt, data);
		else
		    printf("[ Kerberos V5 accepts you ]\r\n");
		auth_finished(ap, AUTH_USER);
#ifdef	FORWARD
		if (forward_flags & OPTS_FORWARD_CREDS)
		  kerberos5_forward(ap);
#endif	/* FORWARD */
		break;
	case KRB_RESPONSE:
		if ((ap->way & AUTH_HOW_MASK) == AUTH_HOW_MUTUAL) {
		    /* the rest of the reply should contain a krb_ap_rep */
		    krb5_ap_rep_enc_part *reply;
		    krb5_data inbuf;
		    krb5_error_code r;

		    inbuf.length = cnt;
		    inbuf.data = (char *)data;

		    if ((r = krb5_rd_rep(telnet_context, auth_context, &inbuf,
					 &reply))) {
			printf("[ Mutual authentication failed: %s ]\r\n",
			       error_message(r));
			auth_send_retry();
			return;
		    }
		    krb5_free_ap_rep_enc_part(telnet_context, reply);
#ifdef	ENCRYPTION
		    if (session_key) {
			skey.type = SK_DES;
			skey.length = 8;
			skey.data = session_key->contents;
			encrypt_session_key(&skey, 0);
		      }
#endif	/* ENCRYPTION */
		    mutual_complete = 1;
		}
		return;
#ifdef	FORWARD
	case KRB_FORWARD_ACCEPT:
		printf("[ Kerberos V5 accepted forwarded credentials ]\r\n");
		return;
	case KRB_FORWARD_REJECT:
		printf("[ Kerberos V5 refuses forwarded credentials because %.*s ]\r\n",
				cnt, data);
		return;
#endif	/* FORWARD */
	default:
		if (auth_debug_mode)
			printf("Unknown Kerberos option %d\r\n", data[-1]);
		return;
	}
	return;
}

	int
kerberos5_status(ap, name, level)
	Authenticator *ap;
	char *name;
	int level;
{
	if (level < AUTH_USER)
		return(level);

	/*
	 * Always copy in UserNameRequested if the authentication
	 * is valid, because the higher level routines need it.
	 * the name buffer comes from telnetd/telnetd{-ktd}.c
	 */
	if (UserNameRequested) {
		strncpy(name, UserNameRequested, 255);
		name[255] = '\0';
	}

	if (UserNameRequested &&
	    krb5_kuserok(telnet_context, ticket->enc_part2->client, 
			 UserNameRequested))
	{
		return(AUTH_VALID);
	} else
		return(AUTH_USER);
}

#define	BUMP(buf, len)		while (*(buf)) {++(buf), --(len);}
#define	ADDC(buf, len, c)	if ((len) > 0) {*(buf)++ = (c); --(len);}

	void
kerberos5_printsub(data, cnt, buf, buflen)
	unsigned char *data, *buf;
	int cnt;
	unsigned int buflen;
{
	char lbuf[32];
	register int i;

	buf[buflen-1] = '\0';		/* make sure its NULL terminated */
	buflen -= 1;

	switch(data[3]) {
	case KRB_REJECT:		/* Rejected (reason might follow) */
		strncpy((char *)buf, " REJECT ", buflen);
		goto common;

	case KRB_ACCEPT:		/* Accepted (name might follow) */
		strncpy((char *)buf, " ACCEPT ", buflen);
	common:
		BUMP(buf, buflen);
		if (cnt <= 4)
			break;
		ADDC(buf, buflen, '"');
		for (i = 4; i < cnt; i++)
			ADDC(buf, buflen, data[i]);
		ADDC(buf, buflen, '"');
		ADDC(buf, buflen, '\0');
		break;


	case KRB_AUTH:			/* Authentication data follows */
		strncpy((char *)buf, " AUTH", buflen);
		goto common2;

	case KRB_RESPONSE:
		strncpy((char *)buf, " RESPONSE", buflen);
		goto common2;

#ifdef	FORWARD
	case KRB_FORWARD:               /* Forwarded credentials follow */
		strncpy((char *)buf, " FORWARD", buflen);
		goto common2;

	case KRB_FORWARD_ACCEPT:               /* Forwarded credentials accepted */
		strncpy((char *)buf, " FORWARD_ACCEPT", buflen);
		goto common2;

	case KRB_FORWARD_REJECT:               /* Forwarded credentials rejected */
					       /* (reason might follow) */
		strncpy((char *)buf, " FORWARD_REJECT", buflen);
		goto common2;
#endif	/* FORWARD */

	default:
		sprintf(lbuf, " %d (unknown)", data[3]);
		strncpy((char *)buf, lbuf, buflen);
	common2:
		BUMP(buf, buflen);
		for (i = 4; i < cnt; i++) {
			sprintf(lbuf, " %d", data[i]);
			strncpy((char *)buf, lbuf, buflen);
			BUMP(buf, buflen);
		}
		break;
	}
}

#ifdef	FORWARD

static void
kerberos5_forward(ap)
     Authenticator *ap;
{
    krb5_error_code r;
    krb5_ccache ccache;
    krb5_principal client = 0;
    krb5_principal server = 0;
    krb5_data forw_creds;

    forw_creds.data = 0;

    if ((r = krb5_cc_default(telnet_context, &ccache))) {
	if (auth_debug_mode) 
	    printf("Kerberos V5: could not get default ccache - %s\r\n",
		   error_message(r));
	return;
    }

    if ((r = krb5_cc_get_principal(telnet_context, ccache, &client))) {
	if (auth_debug_mode) 
	    printf("Kerberos V5: could not get default principal - %s\r\n",
		   error_message(r));
	goto cleanup;
    }

    if ((r = krb5_sname_to_principal(telnet_context, RemoteHostName, "host",
				     KRB5_NT_SRV_HST, &server))) {
	if (auth_debug_mode) 
	    printf("Kerberos V5: could not make server principal - %s\r\n",
		   error_message(r));
	goto cleanup;
    }

    if ((r = krb5_auth_con_genaddrs(telnet_context, auth_context, net,
			    KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR))) {
	if (auth_debug_mode)
	    printf("Kerberos V5: could not gen local full address - %s\r\n",
		    error_message(r));
	goto cleanup;
    }

    if ((r = krb5_fwd_tgt_creds(telnet_context, auth_context, 0, client,
				server, ccache,
				forward_flags & OPTS_FORWARDABLE_CREDS,
				&forw_creds))) {
	if (auth_debug_mode) 
	    printf("Kerberos V5: error getting forwarded creds - %s\r\n",
	  	   error_message(r));
	goto cleanup;
    }
    
    /* Send forwarded credentials */
    if (!Data(ap, KRB_FORWARD, forw_creds.data, forw_creds.length)) {
	if (auth_debug_mode)
	    printf("Not enough room for authentication data\r\n");
    } else {
	if (auth_debug_mode)
	    printf("Forwarded local Kerberos V5 credentials to server\r\n");
    }
    
cleanup:
    if (client)
	krb5_free_principal(telnet_context, client);
    if (server)
	krb5_free_principal(telnet_context, server);
    if (forw_creds.data)
	free(forw_creds.data);
    krb5_cc_close(telnet_context, ccache);
}
#endif	/* FORWARD */

#endif /* KRB5 */
