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
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netdb.h>

#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/kdb.h>
#include <krb5/kdb_dbm.h>
#ifdef PROVIDE_DES_CBC_CRC
#include <krb5/mit-des.h>
#endif
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

void init_keytab(), init_master();
krb5_error_code do_connection(), lookup_service_key(), kdc_get_server_key();

void usage()
{
     fprintf(stderr, "Usage: %s [-m[aster]] [-k[eytab]]\n", whoami);
     cleanup_and_exit(1);
}

int request_exit()
{
     signalled = 1;
}

int krb5_free_keyblock_contents(krb5_keyblock *key)
{
     memset(key->contents, 0, key->length);
     krb5_xfree(key->contents);
     return 0;
}

main(int argc, char **argv)
{
     struct servent *serv;
     struct sockaddr_in saddr;
     struct timeval timeout;
     int ret, s, conn;
     fd_set rfds;
     
     krb5_init_ets();

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
	  usage();
     
     signal(SIGINT, request_exit);
     signal(SIGHUP, request_exit);
     signal(SIGTERM, request_exit);

     if (use_keytab)
	  init_keytab();
     if (use_master)
	  init_master();

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
	  cleanup_and_exit(1);
     }
     if ((ret = bind(s, (struct sockaddr *) &saddr,
		     sizeof(struct sockaddr_in))) < 0) {
	  com_err(whoami, errno, "binding main socket");
	  cleanup_and_exit(1);
     }
     
     timeout.tv_sec = TIMEOUT;
     timeout.tv_usec = 0;
     while (1) {
	  FD_ZERO(&rfds);
	  FD_SET(s, &rfds);

	  ret = select(s+1, &rfds, NULL, NULL, &timeout);
	  if (signalled)
	       cleanup_and_exit(0);
	  else if (ret == 0) {
	       if (use_master) {
		    ret = krb5_dbm_db_fini();
		    if (ret && ret != KRB5_KDB_DBNOTINITED) {
			 com_err(whoami, ret, "closing kerberos database");
			 cleanup_and_exit(1);
		    }
	       }
	  } else if (ret < 0 && errno != EINTR) {
	       com_err(whoami, errno, "in select");
	       cleanup_and_exit(1);
	  } else if (FD_ISSET(s, &rfds)) {
	       if (debug)
		    printf("received packet\n");
	       if (ret = do_connection(s)) {
		    com_err(whoami, ret, "handling packet");
	       }
	  } else
	       com_err(whoami, 0, "impossible situation occurred!");
     }

     return cleanup_and_exit(0);
}

int cleanup_and_exit(int ret)
{
     if (use_master) {
	  krb5_finish_key(&master_encblock);
	  memset((char *)&master_encblock, 0, sizeof(master_encblock));
	  (void) krb5_db_fini();
     }
     exit(ret);
}

void init_keytab()
{
     int ret;
     if (keytab == NULL) {
	  if (ret = krb5_kt_default(&kt)) {
	       com_err(whoami, ret, "while opening default keytab");
	       cleanup_and_exit(1);
	  }
     } else {
	  if (ret = krb5_kt_resolve(keytab, &kt)) {
	       com_err(whoami, ret, "while resolving keytab %s",
		       keytab);
	       cleanup_and_exit(1);
	  }
     }
}

void init_master()
{
     int ret;
     char *realm;
     
     if (ret = krb5_get_default_realm(&realm)) {
	  com_err(whoami, ret, "getting default realm");
	  cleanup_and_exit(1);
     }
     if (ret = krb5_db_setup_mkey_name(NULL, realm, (char **) 0,
				       &master_princ)) {
	  com_err(whoami, ret, "while setting up master key name");
	  cleanup_and_exit(1);
     }

#ifdef PROVIDE_DES_CBC_CRC
     master_encblock.crypto_entry = &mit_des_cryptosystem_entry;
#else
     error(You gotta figure out what cryptosystem to use in the KDC);
#endif

     master_keyblock.keytype = KEYTYPE_DES;
     if (ret = krb5_db_fetch_mkey(master_princ, &master_encblock,
				  FALSE, /* non-manual type-in */
				  FALSE, /* irrelevant, given prev. arg */
				  0, &master_keyblock)) {
	  com_err(whoami, ret, "while fetching master key");
	  cleanup_and_exit(1);
     }

     if (ret = krb5_db_init()) {
	  com_err(whoami, ret, "while initializing master database");
	  cleanup_and_exit(1);
     }
     if (ret = krb5_process_key(&master_encblock, &master_keyblock)) {
	  krb5_db_fini();
	  com_err(whoami, ret, "while processing master key");
	  cleanup_and_exit(1);
     }
}

krb5_error_code do_connection(int s)
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

     if (ret = decode_krb5_ticket(&msgdata, &v5tkt))
	  goto error;
     if (debug)
	  printf("V5 ticket decoded\n");
     
     if (ret = lookup_service_key(v5tkt->server, &service_key))
	  goto error;
     if (debug)
	  printf("service key retrieved\n");

     ret = krb524_convert_tkt_skey(v5tkt, &v4tkt, &service_key);
     if (ret)
	  goto error;
     krb5_free_keyblock_contents(&service_key);
     krb5_free_ticket(v5tkt);
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

krb5_error_code lookup_service_key(krb5_principal p, krb5_keyblock *key)
{
     int ret;
     krb5_keytab_entry entry;

     if (use_keytab) {
	  if (ret = krb5_kt_get_entry(kt, p, 0, &entry))
	       return ret;
	  memcpy(key, (char *) &entry.key, sizeof(krb5_keyblock));
	  return 0;
     } else if (use_master) {
	  if (ret = krb5_dbm_db_init())
	       return ret;
	  return kdc_get_server_key(p, key, NULL);
     }
}

/* taken from kdc/kdc_util.c, and modified somewhat */
krb5_error_code kdc_get_server_key(service, key, kvno)
   krb5_principal service;
   krb5_keyblock *key;
   krb5_kvno *kvno;
{
     krb5_error_code ret;
     int nprincs;
     krb5_db_entry server;
     krb5_boolean more;

     nprincs = 1;
     if (ret = krb5_db_get_principal(service, &server, &nprincs, &more)) 
	  return(ret);
     
     if (more) {
	  krb5_db_free_principal(&server, nprincs);
	  return(KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE);
     } else if (nprincs != 1) {
	  krb5_db_free_principal(&server, nprincs);
	  return(KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN);
     }

     /*
      * convert server.key into a real key (it is encrypted in the
      * database)
      */
     ret = KDB_CONVERT_KEY_OUTOF_DB(&server.key, key);
     if (kvno)
	  *kvno = server.kvno;
     krb5_db_free_principal(&server, nprincs);
     return ret;
}
