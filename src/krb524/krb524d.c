/*
 * Copyright (C) 2002 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
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

#include <krb5.h>
#include <kadm5/admin.h>
#include <krb5/adm_proto.h>
#include <com_err.h>
#include <stdarg.h>

#include <assert.h>
#include <stdio.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <netinet/in.h>

#include <krb.h>
#include "krb524d.h"

#if defined(NEED_DAEMON_PROTO)
extern int daemon(int, int);
#endif

#define TIMEOUT 60
#define TKT_BUFSIZ 2048
#define MSGSIZE 8192

char *whoami;
int signalled = 0;
static int debug = 0;
void *handle = NULL;

int use_keytab, use_master;
int allow_v4_crossrealm = 0;
char *keytab = NULL;
krb5_keytab kt;

void init_keytab(krb5_context), 
    init_master(krb5_context, kadm5_config_params *),
    cleanup_and_exit(int, krb5_context);
krb5_error_code do_connection(int, krb5_context);
krb5_error_code lookup_service_key(krb5_context, krb5_principal, 
				   krb5_enctype, krb5_kvno, 
				   krb5_keyblock *, krb5_kvno *);
krb5_error_code  kdc_get_server_key(krb5_context, krb5_principal, 
				    krb5_keyblock *, krb5_kvno *,
				    krb5_enctype, krb5_kvno);

static krb5_error_code
handle_classic_v4 (krb5_context context, krb5_ticket *v5tkt,
		   struct sockaddr_in *saddr,
		   krb5_data *tktdata, krb5_kvno *v4kvno);
static krb5_error_code 
afs_return_v4(krb5_context, const krb5_principal , int *use_v5);

static void usage(context)
     krb5_context context;
{
     fprintf(stderr, "Usage: %s [-k[eytab]] [-m[aster] [-r realm]] [-nofork] [-p portnum]\n", whoami);
     cleanup_and_exit(1, context);
}

static RETSIGTYPE request_exit(signo)
     int signo;
{
     signalled = 1;
}

int (*encode_v4tkt)(KTEXT, char *, unsigned int *) = 0;

int main(argc, argv)
     int argc;
     char **argv;
{
     struct servent *serv;
     struct sockaddr_in saddr;
     struct timeval timeout;
     int ret, s, nofork;
     fd_set rfds;
     krb5_context context;
     krb5_error_code retval;
     kadm5_config_params config_params;
     unsigned long port = 0;

     whoami = ((whoami = strrchr(argv[0], '/')) ? whoami + 1 : argv[0]);

     retval = krb5_init_context(&context);
     if (retval) {
	     com_err(whoami, retval, "while initializing krb5");
	     exit(1);
     }

     {
	 krb5int_access k5int;
	 retval = krb5int_accessor(&k5int, KRB5INT_ACCESS_VERSION);
	 if (retval != 0) {
	     com_err(whoami, retval,
		     "while accessing krb5 library internal support");
	     exit(1);
	 }
	 encode_v4tkt = k5int.krb524_encode_v4tkt;
	 if (encode_v4tkt == NULL) {
	     com_err(whoami, 0,
		     "krb4 support disabled in krb5 support library");
	     exit(1);
	 }
     }

     argv++; argc--;
     use_master = use_keytab = nofork = 0;
     config_params.mask = 0;
     
     while (argc) {
       if (strncmp(*argv, "-X", 2) == 0) {
	 allow_v4_crossrealm = 1;
       }
       else if (strncmp(*argv, "-k", 2) == 0)
	       use_keytab = 1;
	  else if (strncmp(*argv, "-m", 2) == 0)
	       use_master = 1;
	  else if (strcmp(*argv, "-nofork") == 0)
	       nofork = 1;
	  else if (strcmp(*argv, "-r") == 0) {
	       argv++; argc--;
	       if (argc == 0 || !use_master)
		    usage(context);
	       config_params.mask |= KADM5_CONFIG_REALM;
	       config_params.realm = *argv;
	  }
	  else if (strcmp(*argv, "-p") == 0) {
	      char *endptr = 0;
	      argv++; argc--;
	      if (argc == 0)
		  usage (context);
	      if (port != 0) {
		  com_err (whoami, 0,
			   "port number may only be specified once");
		  exit (1);
	      }
	      port = strtoul (*argv, &endptr, 0);
	      if (*endptr != '\0' || port > 65535 || port == 0) {
		  com_err (whoami, 0,
			   "invalid port number %s, must be 1..65535\n",
			   *argv);
		  exit (1);
	      }
	  }
	  else
	       break;
	  argv++; argc--;
     }
     if (argc || use_keytab + use_master > 1 ||
	 use_keytab + use_master == 0) {
	  use_keytab = use_master = 0;
	  usage(context);
     }
     
     signal(SIGINT, request_exit);
     signal(SIGHUP, SIG_IGN);
     signal(SIGTERM, request_exit);

     krb5_klog_init(context, "krb524d", whoami, !nofork);

     if (use_keytab)
	  init_keytab(context);
     if (use_master)
	  init_master(context, &config_params);

     memset((char *) &saddr, 0, sizeof(struct sockaddr_in));
     saddr.sin_family = AF_INET;
     saddr.sin_addr.s_addr = INADDR_ANY;
     if (port == 0) {
	 serv = getservbyname(KRB524_SERVICE, "udp");
	 if (serv == NULL) {
	     com_err(whoami, 0, "service entry `%s' not found, using %d",
		     KRB524_SERVICE, KRB524_PORT);
	     saddr.sin_port = htons(KRB524_PORT);
	 } else
	     saddr.sin_port = serv->s_port;
     } else
	 saddr.sin_port = htons(port);
	  
     if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	  com_err(whoami, errno, "creating main socket");
	  cleanup_and_exit(1, context);
     }
     if ((ret = bind(s, (struct sockaddr *) &saddr,
		     sizeof(struct sockaddr_in))) < 0) {
	  com_err(whoami, errno, "binding main socket");
	  cleanup_and_exit(1, context);
     }
     if (!nofork && daemon(0, 0)) {
	 com_err(whoami, errno, "while detaching from tty");
	 cleanup_and_exit(1, context);
     }

     while (1) {
	  FD_ZERO(&rfds);
	  FD_SET(s, &rfds);
	  timeout.tv_sec = TIMEOUT;
	  timeout.tv_usec = 0;

	  ret = select(s+1, &rfds, NULL, NULL, &timeout);
	  if (signalled)
	       cleanup_and_exit(0, context);
	  else if (ret == 0) {
	       if (use_master) {
		    ret = kadm5_flush(handle);
		    if (ret && ret != KRB5_KDB_DBNOTINITED) {
			 com_err(whoami, ret, "closing kerberos database");
			 cleanup_and_exit(1, context);
		    }
	       }
	  } else if (ret < 0 && errno != EINTR) {
	       com_err(whoami, errno, "in select");
	       cleanup_and_exit(1, context);
	  } else if (FD_ISSET(s, &rfds)) {
	       if (debug)
		    printf("received packet\n");
	       if ((ret = do_connection(s, context))) {
		    com_err(whoami, ret, "handling packet");
	       }
	  } else
	       com_err(whoami, 0, "impossible situation occurred!");
     }

     cleanup_and_exit(0, context);
}

void cleanup_and_exit(ret, context)
     int ret;
     krb5_context context;
{
     if (use_master && handle) {
	  (void) kadm5_destroy(handle);
     }
     if (use_keytab && kt) krb5_kt_close(context, kt);
     krb5_klog_close(context);
     krb5_free_context(context);
     exit(ret);
}

void init_keytab(context)
     krb5_context context;
{
     int ret;
     use_keytab = 0;
     if (keytab == NULL) {
	  if ((ret = krb5_kt_default(context, &kt))) {
	       com_err(whoami, ret, "while opening default keytab");
	       cleanup_and_exit(1, context);
	  }
     } else {
	  if ((ret = krb5_kt_resolve(context, keytab, &kt))) {
	       com_err(whoami, ret, "while resolving keytab %s",
		       keytab);
	       cleanup_and_exit(1, context);
	  }
     }
     use_keytab = 1;		/* now safe to close keytab */
}

void init_master(context, params)
     krb5_context context;
     kadm5_config_params *params;
{
     int ret;

     use_master = 0;
     if ((ret = kadm5_init(whoami, NULL, KADM5_ADMIN_SERVICE, params,
			   KADM5_STRUCT_VERSION, KADM5_API_VERSION_2,
			   &handle))) {
	  com_err(whoami, ret, "initializing kadm5 library");
	  cleanup_and_exit(1, context);
     }
     use_master = 1;		/* now safe to close kadm5 */
}

krb5_error_code do_connection(s, context)
     int s;
     krb5_context context;
{
     struct sockaddr saddr;
     krb5_ticket *v5tkt = 0;
     krb5_data msgdata, tktdata;
     char msgbuf[MSGSIZE], tktbuf[TKT_BUFSIZ], *p;
     int ret;
     socklen_t saddrlen;
     krb5_int32 n; /* Must be 4 bytes */
     krb5_kvno v4kvno;

     msgdata.data = msgbuf;
     msgdata.length = MSGSIZE;
     tktdata.data = tktbuf;
     tktdata.length = TKT_BUFSIZ;
     saddrlen = sizeof(struct sockaddr);
     ret = recvfrom(s, msgdata.data, (int) msgdata.length, 0, &saddr, &saddrlen);
     if (ret < 0) {
       /* if recvfrom fails, we probably don't have a valid saddr to 
	  use for the reply, so don't even try to respond. */
       return errno;
     }
     if (debug)
	  printf("message received\n");

     if ((ret = decode_krb5_ticket(&msgdata, &v5tkt))) {
          switch (ret) {
	  case KRB5KDC_ERR_BAD_PVNO:
	  case ASN1_MISPLACED_FIELD:
	  case ASN1_MISSING_FIELD:
	  case ASN1_BAD_ID:
	  case KRB5_BADMSGTYPE:
	    /* don't even answer parse errors */
	    return ret;
	    break;
	  default:
	    /* try and recognize our own error packet */
	    if (msgdata.length == sizeof(krb5_int32))
	      return KRB5_BADMSGTYPE;
	    else
	      goto error;
	  }
     }
     if (debug)
	  printf("V5 ticket decoded\n");
     
     if( krb5_princ_size(context, v5tkt->server) >= 1
	 &&krb5_princ_component(context, v5tkt->server, 0)->length == 3
	 &&strncmp(krb5_princ_component(context, v5tkt->server, 0)->data,
		   "afs", 3) == 0) {
	 krb5_data *enc_part;
	 int use_v5;
	 if ((ret = afs_return_v4(context, v5tkt->server,
				  &use_v5)) != 0) 
	     goto error;
	 if ((ret = encode_krb5_enc_data( &v5tkt->enc_part, &enc_part)) != 0) 
	     goto error;
	 if (!(use_v5 )|| enc_part->length >= 344) {
	     krb5_free_data(context, enc_part);
	     if ((ret = handle_classic_v4(context, v5tkt,
					 (struct sockaddr_in *) &saddr, &tktdata,
					 &v4kvno)) != 0)
		 goto error;
	 } else {
	   KTEXT_ST fake_v4tkt;
	   fake_v4tkt.mbz = 0;
	   fake_v4tkt.length = enc_part->length;
	   memcpy(fake_v4tkt.dat, enc_part->data, enc_part->length);
	     v4kvno = (0x100-0x2b); /*protocol constant indicating  v5
				     * enc part only*/
	     krb5_free_data(context, enc_part);
	     ret = encode_v4tkt(&fake_v4tkt, tktdata.data, &tktdata.length);
	 }
     } else {
	 if ((ret = handle_classic_v4(context, v5tkt,
				     (struct sockaddr_in *) &saddr, &tktdata,
				     &v4kvno)) != 0)
	     goto error;
     }
     
	error:
     /* create the reply */
     p = msgdata.data;
     msgdata.length = 0;
     
     n = htonl(ret);
     memcpy(p, (char *) &n, sizeof(krb5_int32));
     p += sizeof(krb5_int32);
     msgdata.length += sizeof(krb5_int32);

     if (ret)
	  goto write_msg;

     n = htonl(v4kvno);
     memcpy(p, (char *) &n, sizeof(krb5_int32));
     p += sizeof(krb5_int32);
     msgdata.length += sizeof(krb5_int32);

     memcpy(p, tktdata.data, tktdata.length);
     p += tktdata.length;
     msgdata.length += tktdata.length;

write_msg:
     if (ret)
	  (void) sendto(s, msgdata.data, (int) msgdata.length, 0, &saddr, saddrlen);
     else
	  if (sendto(s, msgdata.data, msgdata.length, 0, &saddr, saddrlen)<0)
	       ret = errno;
     if (debug)
	  printf("reply written\n");
     if (v5tkt)
       krb5_free_ticket(context, v5tkt);
     
	       
     return ret;
}

krb5_error_code lookup_service_key(context, p, ktype, kvno, key, kvnop)
     krb5_context context;
     krb5_principal p;
     krb5_enctype ktype;
     krb5_kvno kvno;
     krb5_keyblock *key;
     krb5_kvno *kvnop;
{
     int ret;
     krb5_keytab_entry entry;

     if (use_keytab) {
	  if ((ret = krb5_kt_get_entry(context, kt, p, kvno, ktype, &entry)))
	       return ret;
	  *key = entry.key;
	  key->contents = malloc(key->length);
	  if (key->contents)
	      memcpy(key->contents, entry.key.contents, key->length);
	  else if (key->length) {
	      /* out of memory? */
	      ret = errno;
	      memset (key, 0, sizeof (*key));
	      return ret;
	  }

	  krb5_kt_free_entry(context, &entry);
	  return 0;
     } else if (use_master) {
	  return kdc_get_server_key(context, p, key, kvnop, ktype, kvno);
     }
     return 0;
}

krb5_error_code kdc_get_server_key(context, service, key, kvnop, ktype, kvno)
    krb5_context context;
    krb5_principal service;
    krb5_keyblock *key;
    krb5_kvno *kvnop;
    krb5_enctype ktype;
    krb5_kvno kvno;
{
    krb5_error_code ret;
    kadm5_principal_ent_rec server;
    
    if ((ret = kadm5_get_principal(handle, service, &server,
				   KADM5_KEY_DATA|KADM5_ATTRIBUTES)))
	 return ret;

    if (server.attributes & KRB5_KDB_DISALLOW_ALL_TIX
	|| server.attributes & KRB5_KDB_DISALLOW_SVR) {
	kadm5_free_principal_ent(handle, &server);
	return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
    }

    /*
     * We try kadm5_decrypt_key twice because in the case of a
     * ENCTYPE_DES_CBC_CRC key, we prefer to find a krb4 salt type
     * over a normal key.  Note this may create a problem if the
     * server key is passworded and has both a normal and v4 salt.
     * There is no good solution to this.
     */
    if ((ret = kadm5_decrypt_key(handle,
				 &server,
				 ktype,
				 (ktype == ENCTYPE_DES_CBC_CRC) ? 
				 KRB5_KDB_SALTTYPE_V4 : -1,
				 kvno,
				 key, NULL, kvnop)) &&
	(ret = kadm5_decrypt_key(handle,
				 &server,
				 ktype,
				 -1,
				 kvno,
				 key, NULL, kvnop))) {
	 kadm5_free_principal_ent(handle, &server);
	 return (KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    kadm5_free_principal_ent(handle, &server);
    return ret;
}

/*
 * We support two  kinds of v4 credentials.  There are real v4
 *   credentials, and  a Kerberos v5 enc part masquerading as a krb4
 *  credential to be used by modern AFS implementations; this function
 *  handles the classic v4 case.
 */

static krb5_error_code
handle_classic_v4 (krb5_context context, krb5_ticket *v5tkt,
		   struct sockaddr_in *saddr,
		   krb5_data *tktdata, krb5_kvno *v4kvno)
{
    krb5_error_code ret;
    krb5_keyblock v5_service_key, v4_service_key;
     KTEXT_ST v4tkt;

    v5_service_key.contents = NULL;
    v4_service_key.contents = NULL;
    
             if ((ret = lookup_service_key(context, v5tkt->server,
				   v5tkt->enc_part.enctype,
				   v5tkt->enc_part.kvno,
				   &v5_service_key, NULL)))
	  goto error;

     if ( (ret = lookup_service_key(context, v5tkt->server,
				   ENCTYPE_DES_CBC_CRC,
				   0,
				   &v4_service_key, v4kvno)))
	 goto error;

     if (debug)
	  printf("service key retrieved\n");
     if ((ret = krb5_decrypt_tkt_part(context, &v5_service_key, v5tkt))) {
       goto error;
     }

    if (!(allow_v4_crossrealm || krb5_realm_compare(context, v5tkt->server,
						    v5tkt->enc_part2->client))) {
ret =  KRB5KDC_ERR_POLICY ;
 goto error;
    }
    krb5_free_enc_tkt_part(context, v5tkt->enc_part2);
    v5tkt->enc_part2= NULL;

         ret = krb524_convert_tkt_skey(context, v5tkt, &v4tkt, &v5_service_key,
				   &v4_service_key,
				   (struct sockaddr_in *)saddr);
     if (ret)
	  goto error;

     if (debug)
	  printf("credentials converted\n");

     ret = encode_v4tkt(&v4tkt, tktdata->data, &tktdata->length);
     if (ret)
	  goto error;
     if (debug)
	  printf("v4 credentials encoded\n");

 error:
     if (v5tkt->enc_part2) {
	 krb5_free_enc_tkt_part(context, v5tkt->enc_part2);
	 v5tkt->enc_part2 = NULL;
     }

     if(v5_service_key.contents)
       krb5_free_keyblock_contents(context, &v5_service_key);
     if (v4_service_key.contents)
	 krb5_free_keyblock_contents(context, &v4_service_key);
     return ret;
}

/*
 * afs_return_v4: a predicate to determine whether we want to try
 * using the afs krb5 encrypted part encoding or whether we  just
 * return krb4.  Takes a principal, and checks the configuration file.
 */
static krb5_error_code 
afs_return_v4 (krb5_context context, const krb5_principal princ,
	       int *use_v5)
{
    krb5_error_code ret;
    char *unparsed_name;
    char *cp;
    krb5_data realm;
    assert(use_v5 != NULL);
    ret = krb5_unparse_name(context, princ, &unparsed_name);
        if (ret != 0)
	return ret;
/* Trim out trailing realm component into separate string.*/
    for (cp = unparsed_name; *cp != '\0'; cp++) {
	if (*cp == '\\') {
	    cp++; /* We trust unparse_name not to leave a singleton
		   * backslash*/
	    continue;
	}
	if (*cp == '@') {
	    *cp = '\0';
	    realm.data = cp+1;
	    realm.length = strlen((char *) realm.data);
	    	    break;
	}
    }
     krb5_appdefault_boolean(context, "afs_krb5",
				  &realm, unparsed_name, 1,
				  use_v5);
    krb5_free_unparsed_name(context, unparsed_name);
    return ret;
}
