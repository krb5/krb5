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

#include "k5-int.h"
#include "com_err.h"

#include <stdio.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netdb.h>

#include "adm.h"
#include <krb.h>
#include "krb524.h"

#define TIMEOUT 60
#define TKT_BUFSIZ 2048
#define MSGSIZE 8192

char *whoami;
int signalled = 0;
static int debug = 0;

int use_keytab;
char *keytab = NULL;
krb5_keytab kt;

int use_master;
krb5_principal master_princ;
krb5_encrypt_block master_encblock;
krb5_keyblock master_keyblock;

void init_keytab(), init_master(), cleanup_and_exit();
krb5_error_code do_connection(), lookup_service_key(), kdc_get_server_key();

void usage(context)
     krb5_context context;
{
     fprintf(stderr, "Usage: %s [-m[aster]] [-k[eytab]]\n", whoami);
     cleanup_and_exit(1, context);
}

RETSIGTYPE request_exit(signo)
     int signo;
{
     signalled = 1;
}

int krb5_free_keyblock_contents(context, key)
     krb5_context context;
     krb5_keyblock *key;
{
     memset(key->contents, 0, key->length);
     krb5_xfree(key->contents);
     return 0;
}

int main(argc, argv)
     int argc;
     char **argv;
{
     struct servent *serv;
     struct sockaddr_in saddr;
     struct timeval timeout;
     int ret, s;
     fd_set rfds;
     krb5_context context;
     
     krb5_init_context(&context);
     krb524_init_ets(context);

     whoami = ((whoami = strrchr(argv[0], '/')) ? whoami + 1 : argv[0]);

     argv++; argc--;
     use_master = use_keytab = 0;
     while (argc) {
	  if (strncmp(*argv, "-k", 2) == 0)
	       use_keytab = 1;
	  else if (strncmp(*argv, "-m", 2) == 0)
	       use_master = 1;
	  else
	       break;
	  argv++; argc--;
     }
     if (argc || use_keytab + use_master > 1 ||
	 use_keytab + use_master == 0)
	  usage(context);
     
     signal(SIGINT, request_exit);
     signal(SIGHUP, request_exit);
     signal(SIGTERM, request_exit);

     if (use_keytab)
	  init_keytab(context);
     if (use_master)
	  init_master(context);

     memset((char *) &saddr, 0, sizeof(struct sockaddr_in));
     saddr.sin_family = AF_INET;
     saddr.sin_addr.s_addr = INADDR_ANY;
     serv = getservbyname(KRB524_SERVICE, "udp");
     if (serv == NULL) {
	  com_err(whoami, 0, "service entry not found, using %d", KRB524_PORT);
	  saddr.sin_port = htons(KRB524_PORT);
     } else
	  saddr.sin_port = serv->s_port;
	  
     if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	  com_err(whoami, errno, "creating main socket");
	  cleanup_and_exit(1, context);
     }
     if ((ret = bind(s, (struct sockaddr *) &saddr,
		     sizeof(struct sockaddr_in))) < 0) {
	  com_err(whoami, errno, "binding main socket");
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
		    ret = krb5_db_fini(context);
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
     if (use_master) {
	  krb5_finish_key(context, &master_encblock);
	  memset((char *)&master_encblock, 0, sizeof(master_encblock));
	  (void) krb5_db_fini(context);
     }
     if (use_master) krb5_free_principal(context, master_princ);
     if (use_keytab) krb5_kt_close(context, kt);
     krb5_free_context(context);
     exit(ret);
}

void init_keytab(context)
     krb5_context context;
{
     int ret;
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
}

void init_master(context)
     krb5_context context;
{
     int ret;
     char *realm;
     
     if ((ret = krb5_get_default_realm(context, &realm))) {
	  com_err(whoami, ret, "getting default realm");
	  cleanup_and_exit(1, context);
     }
     if ((ret = krb5_db_setup_mkey_name(context, NULL, realm, (char **) 0,
				       &master_princ))) {
          free(realm);
	  com_err(whoami, ret, "while setting up master key name");
	  cleanup_and_exit(1, context);
     } else {
          free(realm);
     }

     master_keyblock.enctype = ENCTYPE_DES_CBC_MD5;
     krb5_use_enctype(context, &master_encblock, master_keyblock.enctype);
     if ((ret = krb5_db_fetch_mkey(context, master_princ, &master_encblock,
				  FALSE, /* non-manual type-in */
				  FALSE, /* irrelevant, given prev. arg */
				  (char *) NULL,
				  0, &master_keyblock))) {
	  com_err(whoami, ret, "while fetching master key");
	  cleanup_and_exit(1, context);
     }

     if ((ret = krb5_db_init(context))) {
	  com_err(whoami, ret, "while initializing master database");
	  cleanup_and_exit(1, context);
     }
     if ((ret = krb5_process_key(context, &master_encblock, 
				 &master_keyblock))) {
	  krb5_db_fini(context);
	  com_err(whoami, ret, "while processing master key");
	  cleanup_and_exit(1, context);
     }
}

krb5_error_code do_connection(s, context)
     int s;
     krb5_context context;
{
     struct sockaddr saddr;
     krb5_ticket *v5tkt;
     KTEXT_ST v4tkt;
     krb5_keyblock service_key;
     krb5_data msgdata, tktdata;
     char msgbuf[MSGSIZE], tktbuf[TKT_BUFSIZ], *p;
     int n, ret, saddrlen;
     
     msgdata.data = msgbuf;
     msgdata.length = MSGSIZE;

     saddrlen = sizeof(struct sockaddr);
     ret = recvfrom(s, msgdata.data, msgdata.length, 0, &saddr, &saddrlen);
     if (ret < 0) {
	  ret = errno;
	  goto error;
     }
     if (debug)
	  printf("message received\n");

     if ((ret = decode_krb5_ticket(&msgdata, &v5tkt)))
	  goto error;
     if (debug)
	  printf("V5 ticket decoded\n");
     
     /* XXX ENCTYPE_DES_CBC_MD5 shouldn't be hardcoded here.  Should be
        derived from the ticket. */
     if ((ret = lookup_service_key(context, v5tkt->server, ENCTYPE_DES_CBC_MD5, 
				  &service_key)))
	  goto error;
     if (debug)
	  printf("service key retrieved\n");

     ret = krb524_convert_tkt_skey(context, v5tkt, &v4tkt, &service_key);
     if (ret)
	  goto error;
     krb5_free_keyblock_contents(context, &service_key);
     krb5_free_ticket(context, v5tkt);
     if (debug)
	  printf("credentials converted\n");

     tktdata.data = tktbuf;
     tktdata.length = TKT_BUFSIZ;
     ret = encode_v4tkt(&v4tkt, tktdata.data, &tktdata.length);
     if (ret)
	  goto error;
     if (debug)
	  printf("v4 credentials encoded\n");

error:
     /* create the reply */
     p = msgdata.data;
     msgdata.length = 0;
     
     n = htonl(ret);
     memcpy(p, (char *) &n, sizeof(int));
     p += sizeof(int);
     msgdata.length += sizeof(int);

     if (ret)
	  goto write_msg;

     n = htonl(v5tkt->enc_part.kvno);
     memcpy(p, (char *) &n, sizeof(int));
     p += sizeof(int);
     msgdata.length += sizeof(int);

     memcpy(p, tktdata.data, tktdata.length);
     p += tktdata.length;
     msgdata.length += tktdata.length;

write_msg:
     if (ret)
	  (void) sendto(s, msgdata.data, msgdata.length, 0, &saddr, saddrlen);
     else
	  if (sendto(s, msgdata.data, msgdata.length, 0, &saddr, saddrlen)<0)
	       ret = errno;
     if (debug)
	  printf("reply written\n");
	       
     return ret;
}

krb5_error_code lookup_service_key(context, p, ktype, key)
     krb5_context context;
     krb5_principal p;
     krb5_enctype ktype;
     krb5_keyblock *key;
{
     int ret;
     krb5_keytab_entry entry;

     if (use_keytab) {
	  if ((ret = krb5_kt_get_entry(context, kt, p, 0, ktype, &entry)))
	       return ret;
	  memcpy(key, (char *) &entry.key, sizeof(krb5_keyblock));
	  return 0;
     } else if (use_master) {
	  if ((ret = krb5_db_init(context)))
	       return ret;
	  return kdc_get_server_key(context, p, key, NULL);
     }
     return 0;
}

/* taken from kdc/kdc_util.c, and modified somewhat */
krb5_error_code kdc_get_server_key(context, service, key, kvno)
    krb5_context context;
    krb5_principal service;
    krb5_keyblock *key;
    krb5_kvno *kvno;
{
    krb5_error_code ret;
    int nprincs;
    krb5_db_entry server;
    krb5_boolean more;
    int i, vno, ok_key;

    nprincs = 1;
    if ((ret = krb5_db_get_principal(context, service, &server, 
				     &nprincs, &more))) 
	return(ret);
     
    if (more) {
	krb5_db_free_principal(context, &server, nprincs);
	return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
    } else if (nprincs != 1) {
	krb5_db_free_principal(context, &server, nprincs);
	return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    /* convert server key into a real key (it is encrypted in the database) */
    for (vno = i = 0; i < server.n_key_data; i++) {
	if (vno < server.key_data[i].key_data_kvno) {
	    vno = server.key_data[i].key_data_kvno;
	    ok_key = i;
	}
    }
    ret = krb5_dbekd_decrypt_key_data(context, &master_encblock, 
				       &server.key_data[ok_key], key, NULL);
    krb5_db_free_principal(context, &server, nprincs);
    if (kvno)
	*kvno = vno;
    return ret;
}

