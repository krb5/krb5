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
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <des.h>
#include <krb.h>
#include <krb5/krb5.h>
#include <krb5/asn1.h>

#include "krb524.h"

#define KEYSIZE 8
#define CRED_BUFSIZ 2048

#define krb5_print_addrs

void do_local(krb5_creds *, krb5_keyblock *),
     do_remote(krb5_creds *, char *, krb5_keyblock *);

void print_key(char *msg, char *key)
{
     printf("%s: ", msg);
     C_Block_print(key);
     printf("\n");
}

void print_time(char *msg, int t)
{
     printf("%s: %d, %s", msg, t, ctime(&t));
}

void krb5_print_times(char *msg, krb5_ticket_times *t)
{
     printf("%s: Start: %d, %s", msg, t->starttime, ctime(&t->starttime));
     printf("%s: End: %d, %s", msg, t->endtime, ctime(&t->endtime));
     printf("%s: Auth: %d, %s", msg, t->authtime, ctime(&t->authtime));
     printf("%s: Renew: %d, %s", msg, t->renew_till, ctime(&t->renew_till));
}

void krb5_print_keyblock(char *msg, krb5_keyblock *key)
{
     printf("%s: Keytype: %d\n", msg, key->keytype);
     printf("%s: Length: %d\n", msg, key->length);
     printf("%s: Key: ", msg);
     C_Block_print(key->contents);
     printf("\n");
}

void krb5_print_ticket(krb5_data *ticket_data, krb5_keyblock *key)
{
     char *p;
     krb5_ticket *tkt;
     int ret;

     if (ret = decode_krb5_ticket(ticket_data, &tkt)) {
	  com_err("test", ret, "decoding ticket");
	  exit(1);
     }
     if (ret = krb5_decrypt_tkt_part(key, tkt)) {
	  com_err("test", ret, "decrypting V5 ticket for print");
	  exit(1);
     }
     
     krb5_unparse_name(tkt->server, &p);
     printf("Ticket: Server: %s\n", p);
     free(p);
     printf("Ticket: EType: %d\n", tkt->enc_part.etype);
     printf("Ticket: kvno: %d\n", tkt->enc_part.kvno);
     printf("Ticket: Flags: 0x%08x\n", tkt->enc_part2->flags);
     krb5_print_keyblock("Ticket: Session Keyblock",
			 tkt->enc_part2->session);
     krb5_unparse_name(tkt->enc_part2->client, &p);
     printf("Ticket: Client: %s\n", p);
     free(p);
     krb5_print_times("Ticket: Times", &tkt->enc_part2->times);
     printf("Ticket: Address 0: %08x\n",
	    *((unsigned long *) tkt->enc_part2->caddrs[0]->contents));
     
     krb5_free_ticket(tkt);
}

void krb5_print_creds(krb5_creds *creds, krb5_keyblock *secret_key)
{
     char *p, buf[BUFSIZ];
     
     krb5_unparse_name(creds->client, &p);
     printf("Client: %s\n", p);
     free(p);
     krb5_unparse_name(creds->server, &p);
     printf("Server: %s\n", p);
     free(p);
     krb5_print_keyblock("Session key", &creds->keyblock);
     krb5_print_times("Times", &creds->times);
     printf("is_skey: %s\n", creds->is_skey ? "True" : "False");
     printf("Flags: 0x%08x\n", creds->ticket_flags);
     krb5_print_addrs(creds->addresses);
     krb5_print_ticket(&creds->ticket, secret_key);
     /* krb5_print_ticket(&creds->second_ticket, secret_key); */
}

void krb4_print_ticket(KTEXT ticket, krb5_keyblock *secret_key)
{
     char pname[ANAME_SZ], pinst[INST_SZ], prealm[REALM_SZ];
     char sname[ANAME_SZ], sinst[INST_SZ];
     unsigned char flags;
     unsigned long addr, issue_time;
     C_Block session_key;
     int life;
     Key_schedule keysched;
     
     int ret;
     
     if (des_key_sched(secret_key->contents, keysched)) {
	  fprintf(stderr, "Bug in DES key somewhere.\n");
	  exit(1);
     }
     
     ret = decomp_ticket(ticket, &flags, pname, pinst, prealm, &addr,
			 session_key, &life, &issue_time, sname,
			 sinst,  secret_key->contents, keysched);
     if (ret != KSUCCESS) {
	  fprintf(stderr, "krb4 decomp_ticket failed\n");
	  exit(1);
     }
     printf("Ticket: Client: %s.%s@%s\n", pname, pinst, prealm);
     printf("Ticket: Service: %s.%s%\n", sname, sinst);
     printf("Ticket: Address: %08x\n", addr);
     print_key("Ticket: Session Key", session_key);
     printf("Ticket: Lifetime: %d\n", life);
     printf("Ticket: Issue Date: %d, %s", issue_time, ctime(&issue_time));
}

void krb4_print_creds(CREDENTIALS *creds, krb5_keyblock *secret_key)
{
     printf("Client: %s.%s@%s\n", creds->pname, creds->pinst,
	    creds->realm);
     printf("Service: %s.%s@%s\n", creds->service, creds->instance,
	    creds->realm);
     print_key("Session key", creds->session);
     printf("Lifetime: %d\n", creds->lifetime);
     printf("Key Version: %d\n", creds->kvno);
     print_time("Issue Date", creds->issue_date);
     krb4_print_ticket(&creds->ticket_st, secret_key);
}

usage()
{
     fprintf(stderr, "Usage: test [-remote server] client service\n");
     exit(1);
}

main(int argc, char **argv)
{
     krb5_principal client, server;
     krb5_ccache cc;
     krb5_creds v5creds;
     krb5_keyblock key;
     char keybuf[KEYSIZE], buf[BUFSIZ];
     int i, ret, local;
     char *remote;

     krb524_debug = 1;

     krb524_init_ets();

     local = 0;
     remote = NULL;
     argc--; argv++;
     while (argc) {
	  if (strcmp(*argv, "-local") == 0)
	       local++;
	  else if (strcmp(*argv, "-remote") == 0) {
	       argc--; argv++;
	       if (!argc)
		    usage();
	       remote = *argv;
	  }
	  else
	       break;
	  argc--; argv++;
     }
     if (argc != 2)
	  usage();

     if (ret = krb5_parse_name(argv[0], &client)) {
	  com_err("test", ret, "parsing client name");
	  exit(1);
     }
     if (ret = krb5_parse_name(argv[1], &server)) {
	  com_err("test", ret, "parsing server name");
	  exit(1);
     }
     if (ret = krb5_cc_default(&cc)) {
	  com_err("test", ret, "opening default credentials cache");
	  exit(1);
     }
     
     memset((char *) &v5creds, 0, sizeof(v5creds));
     v5creds.client = client;
     v5creds.server = server;
     v5creds.times.endtime = 0;
     v5creds.keyblock.keytype = KEYTYPE_DES;
     if (ret = krb5_get_credentials(0, cc, &v5creds)) {
	  com_err("test", ret, "getting V5 credentials");
	  exit(1);
     }

     /* We need the service key in order to locally decrypt both */
     /* tickets for testing */
     printf("Service's key: ");
     fflush(stdout);
     fgets(buf, BUFSIZ, stdin);
     for (i = 0; i < 8; i++) {
	  unsigned char c;
	  c = buf[2*i];
	  if (c >= '0' && c <= '9')
	       c -= '0';
	  else if (c >= 'a' && c <= 'z')
	       c = c - 'a' + 0xa;
	  keybuf[i] = c << 4;
	  c = buf[2*i+1];
	  if (c >= '0' && c <= '9')
	       c -= '0';
	  else if (c >= 'a' && c <= 'z')
	       c = c - 'a' + 0xa;
	  keybuf[i] += c;
     }
     
     key.keytype = KEYTYPE_DES;
     key.length = KEYSIZE; /* presumably */
     key.contents = keybuf;

     do_remote(&v5creds, remote, &key);
}

void do_remote(krb5_creds *v5creds, char *server, krb5_keyblock *key)
{
     struct sockaddr_in saddr;
     struct hostent *hp;
     CREDENTIALS v4creds;
     int ret;

     printf("\nV5 credentials:\n");
     krb5_print_creds(v5creds, key);

     if (strcmp(server, "kdc") != 0) {
	  hp = gethostbyname(server);
	  if (hp == NULL) {
	       fprintf(stderr, "test: host %s does not exist.\n", server);
	       exit(1);
	  }
	  memset((char *) &saddr, 0, sizeof(struct sockaddr_in));
	  saddr.sin_family = AF_INET;
	  bcopy(hp->h_addr, (char *) &saddr.sin_addr.s_addr,
		sizeof(struct in_addr));
	  
	  if (ret = krb524_convert_creds_addr(v5creds, &v4creds, &saddr)) {
	       com_err("test", ret, "converting credentials on %s",
		       server);
	       exit(1);
	  }
     } else {
	  if (ret = krb524_convert_creds_kdc(v5creds, &v4creds)) {
	       com_err("test", ret, "converting credentials via kdc");
	       exit(1);
	  }
     }
     
     printf("\nV4 credentials:\n");
     krb4_print_creds(&v4creds, key);
}
