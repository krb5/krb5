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

#include <krb5.h>
#include <kadm5/admin.h>
#include <com_err.h>

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
#include "krb524.h"

#define TIMEOUT 60
#define TKT_BUFSIZ 2048
#define MSGSIZE 8192

char *whoami;
int signalled = 0;
static int debug = 0;
void *handle;

int use_keytab, use_master;
char *keytab = NULL;
krb5_keytab kt;

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

#if 0
/* this is in the kadm5 library */
int krb5_free_keyblock_contents(context, key)
     krb5_context context;
     krb5_keyblock *key;
{
     memset(key->contents, 0, key->length);
     krb5_xfree(key->contents);
     return 0;
}
#endif

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
     krb5_error_code retval;

     retval = krb5_init_context(&context);
     if (retval) {
	     com_err(argv[0], retval, "while initializing krb5");
	     exit(1);
     }

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
	 use_keytab + use_master == 0) {
	  use_keytab = use_master = 0;
	  usage(context);
     }
     
     signal(SIGINT, request_exit);
     signal(SIGHUP, SIG_IGN);
     signal(SIGTERM, request_exit);

     if (use_keytab)
	  init_keytab(context);
     if (use_master)
	  /* someday maybe there will be some config param options */
	  init_master(context, NULL);

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
     if (use_master) {
	  (void) kadm5_destroy(handle);
     }
     if (use_keytab) krb5_kt_close(context, kt);
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
     KTEXT_ST v4tkt;
     krb5_keyblock v5_service_key, v4_service_key;
     krb5_data msgdata, tktdata;
     char msgbuf[MSGSIZE], tktbuf[TKT_BUFSIZ], *p;
     int n, ret, saddrlen;

     /* Clear out keyblock contents so we don't accidentally free the stack.*/
     v5_service_key.contents = v4_service_key.contents = 0;

     msgdata.data = msgbuf;
     msgdata.length = MSGSIZE;

     saddrlen = sizeof(struct sockaddr);
     ret = recvfrom(s, msgdata.data, msgdata.length, 0, &saddr, &saddrlen);
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
	    if (msgdata.length == sizeof(int))
	      return KRB5_BADMSGTYPE;
	    else
	      goto error;
	  }
     }
     if (debug)
	  printf("V5 ticket decoded\n");
     
     if ((ret = lookup_service_key(context, v5tkt->server,
				   v5tkt->enc_part.enctype, 
				   &v5_service_key)))
	  goto error;

     if ((ret = lookup_service_key(context, v5tkt->server,
				   ENCTYPE_DES_CBC_CRC,
				   &v4_service_key)))
	  goto error;

     if (debug)
	  printf("service key retrieved\n");

     ret = krb524_convert_tkt_skey(context, v5tkt, &v4tkt, &v5_service_key,
				   &v4_service_key,
				   (struct sockaddr_in *)&saddr);
     if (ret)
	  goto error;

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
/* If we have keys to clean up, do so.*/
     if (v5_service_key.contents)
       krb5_free_keyblock_contents(context, &v5_service_key);
     if (v4_service_key.contents)
       krb5_free_keyblock_contents(context, &v4_service_key);
     if (v5tkt)
       krb5_free_ticket(context, v5tkt);
     
	       
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
	  return kdc_get_server_key(context, p, key, NULL, ktype);
     }
     return 0;
}

krb5_error_code kdc_get_server_key(context, service, key, kvno, ktype)
    krb5_context context;
    krb5_principal service;
    krb5_keyblock *key;
    krb5_kvno *kvno;
    krb5_enctype ktype;
{
    krb5_error_code ret;
    kadm5_principal_ent_rec server;
    
    if ((ret = kadm5_get_principal(handle, service, &server,
				   KADM5_KEY_DATA)))
	 return ret;

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
				 -1,
				 key, NULL, kvno)) &&
	(ret = kadm5_decrypt_key(handle,
				 &server,
				 ktype,
				 -1,
				 -1,
				 key, NULL, kvno))) {
	 kadm5_free_principal_ent(handle, &server);
	 return (KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    kadm5_free_principal_ent(handle, &server);
    return ret;
}
